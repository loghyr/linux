// SPDX-License-Identifier: GPL-2.0
/*
 * Chunk-encoded write path for the NFSv4 Flexfile Version 2 layout
 * driver.  When the lseg's coding_type has parity (RS_VANDERMONDE,
 * MOJETTE, XOR_PARITY, LINUX_MD_RAID, ...), a single user write
 * batch expands to k+m parallel DS writes: k data-shard slices of
 * the stripe, m parity-shard buffers produced by the encoder.
 *
 * The mirror-fanout at the pageio layer gives us k+m per-mirror
 * hdrs "for free": pg_get_mirror_count_write returns k+m and the
 * generic pgio path duplicates the request across N mirrors.  Our
 * per-mirror ffv2_write_pagelist():
 *   1. Reaches the shared stripe context stashed on the lseg.
 *   2. First mirror to arrive under encode_lock does the encode.
 *   3. Overrides hdr->args.pages with its shard's private page
 *      array, so the RPC WRITE ships shard bytes -- not user pages.
 *   4. Dispatches the WRITE via nfs_initiate_pgio.
 *
 * Serialization: only one chunked stripe assembles per lseg at a
 * time; concurrent writers see fls_stripe_busy set and fall back
 * to MDS-inband writes.  Multi-concurrent chunk-stripe support is
 * a follow-up commit and requires shifting stripe state off the
 * lseg (e.g. onto a per-inode radix tree keyed by stripe offset).
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 */

#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/nfs4.h>
#include <linux/nfs_common.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_page.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/sunrpc/metrics.h>

#include "../internal.h"
#include "../iostat.h"
#include "../nfs4_fs.h"
#include "../pnfs.h"
#include "flexfilesv2.h"
#include "flexfilesv2_xdr_chunk.h"

/*
 * Convert a "we can't dispatch here" exit into the correct
 * pnfs_try_status.  Normally return PNFS_NOT_ATTEMPTED so
 * pnfs_do_write() routes the payload via pnfs_write_through_mds
 * (pnfs.c).  When FFV2_FLAGS_NO_IO_THRU_MDS is set the draft
 * (:2198-2203) forbids MDS proxy; mark the lseg for return and force
 * fresh LAYOUTGET instead, matching the FFv1 pattern in
 * flexfilelayout.c.
 */
static inline enum pnfs_try_status
ffv2_write_fallback_to_mds(struct nfs_pgio_header *hdr)
{
	struct pnfs_layout_segment *lseg = hdr->lseg;

	if (ffv2_no_fallback_to_mds(lseg)) {
		pnfs_error_mark_layout_for_return(hdr->inode, lseg);
		return PNFS_TRY_AGAIN;
	}
	return PNFS_NOT_ATTEMPTED;
}

/* ffv2_stripe_ctx_put is defined further down and declared in
 * flexfilesv2.h (flexfilesv2_lifecycle.c also calls it).  The
 * CHUNK_WRITE dispatch below references it before the definition.
 */

/* --- CHUNK_WRITE private dispatch --------------------------------
 *
 * Wrapper struct + private rpc_call_ops + extracted per-mirror
 * dispatch helper. The caller remains on the safe fallback path
 * until the FINALIZE + COMMIT tail is present.
 */

/*
 * Composite wrapper carrying the CHUNK_WRITE wire composite plus
 * back-pointers the private release-cb needs.  The inner
 * ffv2_chunk_write_data (wire args + wire res + SEQUENCE) is passed
 * as rpc_message.rpc_argp so the wire encoder / decoder is unchanged;
 * the wrapper is passed as callback_data so the release-cb can drop
 * ctx / lseg refs.  The DS client ref is per shard (w->ds_clp) and
 * is dropped by the release-cb BEFORE the completion chain frees hdr
 * (matches pnfs_generic_rw_release ordering in fs/nfs/pnfs_nfs.c).
 *
 * The wrapping approach is required because the on-wire data struct
 * (in flexfilesv2_xdr_chunk.h) has no back-pointer fields.
 */
struct ffv2_chunk_write_dispatch {
	struct ffv2_chunk_write_data	wire;
	struct ffv2_stripe_ctx		*ctx;
	struct pnfs_layout_segment	*lseg;
	struct nfs_pgio_header		*hdr;
	/*
	 * Per-shard RPC state.  NOT hdr->task / hdr->ds_clp: a stripe
	 * dispatches k+m shards to k+m distinct data servers from one
	 * header, and neither the header's embedded rpc_task nor its
	 * single ds_clp can be shared across them.  Mirrors the
	 * CHUNK_READ fetch wrapper, which is already per-shard.
	 */
	struct rpc_task			task;
	struct nfs_client		*ds_clp;
};

/*
 * .rpc_call_prepare: allocate a session slot.  nfs4_setup_sequence
 * calls rpc_call_start internally when a slot is granted; on wait it
 * reschedules on slot_tbl_waitq without further action.  Callers
 * MUST NOT invoke rpc_call_start themselves in either case.
 */
static void ffv2_chunk_write_prepare(struct rpc_task *task, void *data)
{
	struct ffv2_chunk_write_dispatch *w = data;

	nfs4_setup_sequence(w->ds_clp, &w->wire.seq_args,
			    &w->wire.res.seq_res,
			    task);
}

/*
 * .rpc_call_done: return the session slot unconditionally first
 * (3a decoder guarantees sr_status populated per every exit
 * path; missing this leaks slots on rpc_exit and wedges the
 * session).  Then re-decide the failure disposition based on
 * this attempt's outcome: clear the stale bit, apply per-chunk
 * validation on success, or jump to the failure tail.
 *
 * Per-chunk validation per draft sec-CHUNK_WRITE :9062-9107 +
 * :9058-9070 short-write disposition:
 *   - nblocks != 1: op-shape violation (the dispatch sends one
 *     chunk per op); -EPROTO + failure.
 *   - block_status[0] != NFS4_OK: per-chunk failure; propagate the
 *     mapped errno (nfs4_stat_to_errno returns negative -- no
 *     leading '-').
 *   - committed < FILE_SYNC4: DS wrote weaker durability than
 *     requested; -EPROTO + failure.
 *   - count == 0 with block_status[0] == NFS4_OK: draft-legal short
 *     write; -EAGAIN so ffv2 re-encodes and reissues via the MDS
 *     fallback.  Under NO_IO_THRU_MDS there is no resend: the
 *     failure tail records -EAGAIN on the header and the write
 *     fails rather than being retried.
 *   - count > 1: impossible for a 1-chunk request (cwr_count counts
 *     successfully accepted chunks); -EPROTO + failure.
 *
 * Failure tail:
 *   - Always mark the lseg for return.  Any DS-observed failure --
 *     RPC-time, per-chunk, or op-shape -- invalidates the current
 *     pNFS state; without the mark, every subsequent write reuses
 *     the same lseg and repeats the fallback forever.
 *   - Set NFS_IOHDR_RESEND_MDS ONLY when the layout permits MDS
 *     proxy, and return: the resend owns the outcome from there.
 *   - With FFV2_FLAGS_NO_IO_THRU_MDS set the draft (:2198-2203)
 *     forbids the resend, so the header terminates here.  Normalize
 *     an unmapped NFS4ERR_* status to an errno, then record the
 *     failure with nfs_set_pgio_error so the generic write
 *     completion sees it -- tk_status alone is not enough.  The
 *     release-cb's guarded pnfs_write_done_resend_to_mds never
 *     fires on this path.
 */
static void ffv2_chunk_write_call_done(struct rpc_task *task, void *data)
{
	struct ffv2_chunk_write_dispatch *w = data;
	struct nfs_pgio_header *hdr = w->hdr;
	struct ffv2_chunk_write_res *res = &w->wire.res;

	/*
	 * Guard nfs4_sequence_done against a NULL sr_slot.
	 * .rpc_call_prepare invokes nfs4_setup_sequence which populates
	 * seq_res.sr_slot only on successful slot allocation; on some
	 * early failure paths (session teardown mid-flight, setup
	 * returning without a slot) the res stays zeroed from kzalloc
	 * and .rpc_call_done still fires unconditionally.
	 * nfs4_sequence_done would then dereference sr_slot at offset
	 * 8 (sr_slot->table) and page-fault.  FFv1's flexfilelayout.c
	 * conditionalizes the same call for the same reason.
	 */
	if (w->wire.res.seq_res.sr_slot)
		nfs4_sequence_done(task, &w->wire.res.seq_res);

	/* Defensive: re-decide from scratch on this attempt.  Ffv1
	 * pattern at flexfilelayout.c:1811 clears then reconsiders.
	 */
	clear_bit(NFS_IOHDR_RESEND_MDS, &hdr->flags);

	if (task->tk_status == 0) {
		if (res->nblocks != 1) {
			task->tk_status = -EPROTO;
			goto fail;
		}
		if (res->block_status[0] != NFS4_OK) {
			task->tk_status =
				nfs4_stat_to_errno(res->block_status[0]);
			goto fail;
		}
		if (res->committed < NFS_FILE_SYNC) {
			task->tk_status = -EPROTO;
			goto fail;
		}
		if (res->count != 1) {
			task->tk_status = (res->count == 0)
				? -EAGAIN	/* short write; resend */
				: -EPROTO;	/* impossible for 1-chunk op */
			goto fail;
		}
		/* Happy path: retained res fields (block_activated[0],
		 * owners[0], writeverf) will be consumed by the patch-5
		 * FINALIZE tail.  The temporary early-return path does not
		 * reach them from the write path.
		 */
		return;
	}
fail:
	pnfs_error_mark_layout_for_return(hdr->inode, hdr->lseg);
	if (!ffv2_no_fallback_to_mds(hdr->lseg)) {
		set_bit(NFS_IOHDR_RESEND_MDS, &hdr->flags);
		return;
	}

	/*
	 * No MDS fallback, so this header terminates here: the release
	 * cb skips the result copy, the resend, and the wb-chain
	 * hand-off, and hdr completes with tk_status carrying the
	 * error.
	 *
	 * nfs4_stat_to_errno() returns -NFS4ERR_* verbatim for codes it
	 * cannot map (fs/nfs_common/common.c), and those are not
	 * errnos.  Normalize before the value can reach
	 * mapping_set_error() and userspace.  Flexfiles v1 never has
	 * to: ff_layout_async_handle_error_v4() either retries or
	 * resets, so an unmapped status never reaches its header.
	 */
	if (task->tk_status <= -10000)
		task->tk_status = -EIO;

	/*
	 * Propagate into the header.  tk_status alone is not read by
	 * nfs_write_completion(): it tests NFS_IOHDR_ERROR, hdr->error
	 * and hdr->good_bytes, all of which only nfs_set_pgio_error()
	 * sets.  Without this call the failed write takes the success
	 * branch -- pages queued for COMMIT against an unpopulated
	 * writeverf, which mismatches and redirties them, and for
	 * O_DIRECT the bytes are reported to userspace as written.
	 * Same reasoning and same call as the FINALIZE / COMMIT tail in
	 * ffv2_chunk_wb_complete_hdr().
	 */
	nfs_set_pgio_error(hdr, task->tk_status, hdr->args.offset);
}

/*
 * .rpc_release: hoist hdr-derived pointers to locals BEFORE the
 * completion chain frees hdr.  Sequence:
 *
 *   1. Save locals (hdr, ctx, lseg -- ds_clp accessed via hdr one
 *      final time before completion).
 *   2. On success, copy wire.res fields into hdr BEFORE the
 *      completion chain fires.  Without this, nfs_writehdr_alloc's
 *      zero-init leaves hdr->verf.committed == NFS_UNSTABLE, so
 *      nfs_write_completion marks every request for commit with a
 *      zero verifier.  Guarded on !RESEND_MDS:
 *      pnfs_write_done_resend_to_mds re-encodes with fresh state and
 *      overwrites whatever's here.  The guard alone does not protect
 *      the failure path: skipping the copy still leaves committed ==
 *      NFS_UNSTABLE, which still selects that commit branch.  What
 *      keeps a failed write out of it is the nfs_set_pgio_error in
 *      ffv2_chunk_write_call_done's failure tail.
 *   3. On success, credit NFSIOS_SERVERWRITTENBYTES with the shard
 *      bytes accepted at this DS.  The normal write-done chain does
 *      this via nfs_writeback_done; the private path bypasses that
 *      chain, so mountstats would otherwise under-report every
 *      successful CHUNK_WRITE.  Counts shard bytes because
 *      res->count is what the DS accepted -- the (k+m)-mirror
 *      aggregation is the caller's concern.
 *   4. REDO-gated pnfs_write_done_resend_to_mds.  Under
 *      NO_IO_THRU_MDS the done-cb never sets RESEND_MDS, so this
 *      call is dead in that case.
 *   5. nfs_put_client(w->ds_clp) BEFORE the completion chain --
 *      matches pnfs_generic_rw_release order in fs/nfs/pnfs_nfs.c.
 *   6. hdr->completion_ops->completion(hdr) -- frees hdr; MUST NOT
 *      reference hdr after this.
 *   7. ffv2_stripe_ctx_put(ctx) then pnfs_put_lseg(lseg) --
 *      ctx-before-lseg because ctx->fls back-references lseg.
 *   8. kfree(wrapper) -- LAST.
 */
/*
 * On success, transfer ownership of hdr / ds_clp / lseg / ctx
 * from the dispatch wrapper `w` to a fresh ffv2_chunk_wb_ctx
 * and start the FINALIZE -> COMMIT chain (see
 * flexfilesv2_lifecycle.c).  wb_start's completion path owns
 * the final hdr completion + ds_clp put + lseg / ctx release.
 *
 * Returns true on successful hand-off (caller MUST skip the
 * standard cleanup path).  Returns false on any failure to
 * hand off (kzalloc / dispatch); the caller falls through to
 * the standard release path with the wb_ctx already freed.
 */
static bool ffv2_chunk_write_release_hand_off_wb(
	struct ffv2_chunk_write_dispatch *w)
{
	struct nfs_pgio_header *hdr = w->hdr;
	struct ffv2_chunk_wb_ctx *wb;
	int rc;

	wb = kzalloc_obj(*wb, GFP_NOFS);
	if (!wb) {
		/*
		 * Hand-off failure at the alloc step must NOT let the
		 * write complete as "n bytes durable" -- the wire write
		 * succeeded but FINALIZE never ran, so the DS chunk is
		 * orphaned and would be GC'd, producing silent data loss
		 * on a subsequent read of the same offset.  Surface the
		 * failure via nfs_set_pgio_error (which
		 * nfs_write_completion actually consumes -- tk_status
		 * alone is ignored on the private CHUNK path because we
		 * bypass pnfs_ld_write_done) AND mark the lseg for
		 * return so the layout refreshes on retry.
		 */
		nfs_set_pgio_error(hdr, -ENOMEM, hdr->args.offset);
		hdr->task.tk_status = -ENOMEM;
		pnfs_error_mark_layout_for_return(hdr->inode, w->lseg);
		return false;
	}

	wb->hdr = hdr;
	wb->ds_clp = w->ds_clp;
	wb->lseg = w->lseg;
	wb->ctx = w->ctx;
	wb->cred = hdr->cred;
	wb->fh = w->wire.fh;
	wb->stateid = w->wire.args.stateid;
	wb->offset = w->wire.args.offset;
	wb->count = 1;
	wb->owner = w->wire.res.owners[0];

	rc = ffv2_chunk_wb_start(wb);
	if (rc) {
		/* wb_start does NOT take ownership on failure; free the
		 * wb_ctx and let the caller fall through to its standard
		 * cleanup path.  Same rationale as the kzalloc-fail arm
		 * above -- surface the failure to userspace via
		 * nfs_set_pgio_error (nfs_write_completion consumes
		 * NFS_IOHDR_ERROR / hdr->error, NOT the tk_status write)
		 * AND mark the lseg for return.
		 */
		kfree(wb);
		nfs_set_pgio_error(hdr, rc, hdr->args.offset);
		hdr->task.tk_status = rc;
		pnfs_error_mark_layout_for_return(hdr->inode, w->lseg);
		return false;
	}
	return true;
}

static void ffv2_chunk_write_release(void *data)
{
	struct ffv2_chunk_write_dispatch *w = data;
	struct nfs_pgio_header *hdr = w->hdr;
	struct ffv2_stripe_ctx *ctx = w->ctx;
	struct pnfs_layout_segment *lseg = w->lseg;

	/*
	 * The RPC ran on w->task, so hdr->task.tk_status is untouched
	 * by it.  Fold this shard's status in before anything below
	 * reads it; first error wins.  With one shard per header this
	 * is a plain copy, and it stays correct once a stripe
	 * dispatches k+m shards into the same header.
	 */
	if (hdr->task.tk_status == 0 && w->task.tk_status != 0)
		hdr->task.tk_status = w->task.tk_status;

	/*
	 * Copy result fields + credit accounting ONLY on real success.
	 * The tk_status guard is required because the "layout permits
	 * MDS proxy" path correctly skips setting RESEND_MDS under
	 * FFV2_FLAGS_NO_IO_THRU_MDS on failure -- but !RESEND_MDS alone
	 * then also selects the NO_IO_THRU_MDS failure path.  Copying
	 * unpopulated wire fields there would write a zero writeverf +
	 * NFS_UNSTABLE committed into hdr, triggering
	 * nfs_write_completion's commit loop against a zero verifier.
	 *
	 * Skipping the copy is necessary but not sufficient: an
	 * untouched hdr->verf.committed is also NFS_UNSTABLE, so the
	 * same commit branch is selected either way.  The failure tail
	 * in ffv2_chunk_write_call_done calls nfs_set_pgio_error, which
	 * is what actually diverts a failed write to the error branch.
	 */
	if (!test_bit(NFS_IOHDR_RESEND_MDS, &hdr->flags) &&
	    hdr->task.tk_status == 0) {
		hdr->res.count = w->wire.args.payload_len;
		memcpy(&hdr->verf.verifier, &w->wire.res.writeverf,
		       sizeof(hdr->verf.verifier));
		hdr->verf.committed = w->wire.res.committed;
		nfs_add_stats(hdr->inode, NFSIOS_SERVERWRITTENBYTES,
			      hdr->res.count);
	}

	if (test_bit(NFS_IOHDR_RESEND_MDS, &hdr->flags) &&
	    !test_and_set_bit(NFS_IOHDR_REDO, &hdr->flags))
		hdr->task.tk_status = pnfs_write_done_resend_to_mds(hdr);

	/*
	 * Try to transfer to the FINALIZE -> COMMIT chain on real
	 * success (not RESEND_MDS, not tk_status != 0). When the
	 * RESEND_MDS path fires, or on hand-off failure (kzalloc /
	 * dispatch), fall through to the standard cleanup path below.
	 */
	if (!test_bit(NFS_IOHDR_RESEND_MDS, &hdr->flags) &&
	    hdr->task.tk_status == 0 &&
	    ffv2_chunk_write_release_hand_off_wb(w)) {
		/* Ownership transferred; the wb-chain's terminal
		 * callback owns nfs_put_client / hdr completion /
		 * lseg + ctx release.  Just free the dispatch
		 * wrapper here.
		 */
		kfree(w);
		return;
	}

	/* Put ds_clp BEFORE the completion chain frees hdr.
	 * pnfs_generic_rw_release at pnfs_nfs.c:24-30 has the same
	 * order.  Unconditional: original hdr's ds_clp ref was taken
	 * once at dispatch; needs exactly one release-cb put
	 * regardless of MDS-resend firing.
	 */
	nfs_put_client(w->ds_clp);
	hdr->completion_ops->completion(hdr);
	/* hdr is now freed; do not touch. */

	ffv2_stripe_ctx_put(ctx);
	pnfs_put_lseg(lseg);
	kfree(w);
}

static const struct rpc_call_ops ffv2_chunk_write_call_ops = {
	.rpc_call_prepare	= ffv2_chunk_write_prepare,
	.rpc_call_done		= ffv2_chunk_write_call_done,
	.rpc_release		= ffv2_chunk_write_release,
};

/*
 * Extracted per-mirror dispatch helper. The write path calls it once
 * the FINALIZE + COMMIT tail is available.
 *
 * Preconditions: caller has already established `ctx` for
 * `mirror_idx` -- the ctx ref belongs to the caller and is
 * INHERITED by the wrapper on success.  On failure the caller
 * retains ownership per the dispatch-failure pattern in
 * ffv2_write_pagelist_chunked.
 */
static enum pnfs_try_status
ffv2_chunk_write_dispatch_one_mirror(struct nfs_pgio_header *hdr,
				     struct ffv2_stripe_ctx *ctx,
				     u32 mirror_idx, int sync)
{
	struct pnfs_layout_segment *lseg = hdr->lseg;
	struct nfs4_ffv2_layout_segment *fls = FFV2_LSEG(lseg);
	struct nfs4_ffv2_mirror *mirror = fls->mirror_array[0];
	struct nfs4_ffv2_stripe *stripe;
	struct nfs4_ffv2_data_server *ds_slot;
	struct nfs4_ffv2_file_info *fi;
	struct nfs4_deviceid_node *devnode = NULL;
	struct nfs4_ffv2_layout_ds *layout_ds;
	struct nfs4_pnfs_ds *ds;
	struct nfs_server *mds_srv = NFS_SERVER(hdr->inode);
	struct rpc_clnt *ds_clnt;
	struct ffv2_chunk_write_dispatch *w = NULL;
	struct rpc_message msg;
	struct rpc_task_setup task_setup;
	struct rpc_task *task;
	size_t csum_len;
	int rc;
	u32 v, mv;

	(void)sync;	/* CHUNK_WRITE is always FILE_SYNC4. */

	/* Step 1: verify mirror_idx in range. */
	if (mirror->stripes_cnt == 0)
		return ffv2_write_fallback_to_mds(hdr);
	stripe = &mirror->stripes[0];
	if (mirror_idx >= stripe->data_servers_cnt)
		return ffv2_write_fallback_to_mds(hdr);
	ds_slot = &stripe->data_servers[mirror_idx];
	if (ds_slot->versions_cnt == 0)
		return ffv2_write_fallback_to_mds(hdr);
	fi = &ds_slot->versions[0];

	/* Step 2-4: acquire devnode (synchronous, released before
	 * return) + verify v4.2 + connect ds_clp.
	 */
	devnode = nfs4_find_get_deviceid(mds_srv, &ds_slot->devid,
					 hdr->cred, nfs_io_gfp_mask());
	if (!devnode)
		return ffv2_write_fallback_to_mds(hdr);
	layout_ds = FFV2_LAYOUT_DS_FROM_NODE(devnode);
	ds = layout_ds->ds;
	if (!ds || layout_ds->ds_versions_cnt == 0)
		goto out_put_devnode;
	v  = layout_ds->ds_versions[0].version;
	mv = layout_ds->ds_versions[0].minor_version;
	/*
	 * Draft :1706-1724: non-PASSTHROUGH mirrors REQUIRE v4.2.
	 * Accept v4.2+ (NFSv4 minor versions are additive so any v4.2+
	 * DS carries the CHUNK op set) to keep symmetry with
	 * ffv2_chunk_read_fetch_dispatch's `mv >= 2` gate: a strict
	 * `mv != 2` would let a hypothetical v4.3 DS fetch OK via
	 * CHUNK_READ but fail the paired CHUNK_WRITE and drop to MDS.
	 */
	if (v != 4 || mv < 2)
		goto out_put_devnode;

	rc = nfs4_pnfs_ds_connect(mds_srv, ds, devnode, NFS_DEF_TCP_TIMEO,
				  0, v, mv);
	if (rc || !ds->ds_clp)
		goto out_put_devnode;
	ds_clnt = ds->ds_clp->cl_rpcclient;

	/* Step 5: allocate the wrapper.  It must exist before any
	 * reference below is taken, because the wrapper is where those
	 * references are recorded and where the unwind path reads them
	 * back from.
	 */
	w = kzalloc(sizeof(*w), nfs_io_gfp_mask());
	if (!w)
		goto out_put_devnode;

	/* Step 6: ds_clp ref, held per shard.  Dropped by the
	 * release-cb via nfs_put_client(w->ds_clp).  Single ref
	 * taken, single ref put, one pair per shard.
	 */
	refcount_inc(&ds->ds_clp->cl_count);
	w->ds_clp = ds->ds_clp;

	/* Step 7: lseg ref; the release-cb balances it. */
	pnfs_get_lseg(lseg);

	/* Step 8: no fresh ctx ref -- the caller's ref is INHERITED
	 * by this dispatch on success.
	 *
	 * Wrapper is now owned by the release-cb once rpc_run_task
	 * succeeds; back-pointers first so the release-cb sees a
	 * fully populated wrapper.
	 */
	w->ctx  = ctx;
	w->lseg = lseg;
	w->hdr  = hdr;

	/* Step 9: shard-page payload. */
	w->wire.args.pages       = ctx->shard_pages[mirror_idx];
	w->wire.args.pgbase      = 0;
	w->wire.args.payload_len = ctx->shard_len;

	/* Step 10: checksum via the page-array variant.  If the layout
	 * advertises an algorithm we don't wire (or NONE), fall back
	 * to MDS -- the MDS treats absent cwa_checksums as MAY-compute
	 * per draft :9033-9039, but the client posture here is
	 * always-supply for defence in depth.
	 */
	rc = ffv2_checksum_compute_pages(mirror->checksum_algorithm,
					 w->wire.args.pages,
					 w->wire.args.pgbase,
					 w->wire.args.payload_len,
					 w->wire.args.checksum_bytes,
					 &csum_len);
	if (rc)
		goto out_undo_refs;
	w->wire.args.checksum_algo = mirror->checksum_algorithm;
	w->wire.args.checksum_len  = csum_len;

	/* Step 11: build the chunk owner identifying this write. */
	ffv2_build_chunk_owner(fls, mirror, &w->wire.args.owner);

	/* Step 12: DS-side stateid from the layout's per-mirror slot. */
	w->wire.args.stateid = fi->stateid;

	/* Step 13-16: fixed postures + offset conversion. */
	w->wire.args.stable       = NFS_FILE_SYNC;
	w->wire.args.offset       = div64_u64(
		ffv2_ds_offset(mirror, ctx->stripe_off),
		mirror->striping_unit_size);
	w->wire.args.chunk_size   = mirror->striping_unit_size;
	w->wire.args.payload_id   = 0;
	w->wire.args.flags        = 0;

	/*
	 * Consume the per-shard captured guard populated by the
	 * CHUNK_READ done-cb after CRC verification.  When a valid
	 * capture is available (contained-partial RMW path), send
	 * cwg_check=TRUE with the captured (gen_id, client_id) pair
	 * so the DS's CAS rejects with NFS4ERR_DELAY if a concurrent
	 * writer bumped the generation between our fetch and this
	 * write.  Otherwise (parity mirrors, full-stripe writes, or
	 * when the guard slot is still uncaptured), fall back to
	 * cwg_check=FALSE -- currently gated by ONLY_ONE_WRITER
	 * upstream so that path stays draft-conforming.
	 *
	 * Load-safety.  This helper runs POST-encode_lock-unlock, so
	 * the read is not under the mutex; the happens-before chain
	 * that makes the writer-side capture visible here is:
	 *
	 *   1. The CHUNK_READ .rpc_call_done on rpciod writes .valid +
	 *      .guard.
	 *   2. Writer's .rpc_release -> ffv2_rmw_fetch_done_one ->
	 *      complete(&ctx->fetch_done) -- release semantics.
	 *   3. The winner (task holding encode_lock in the RMW branch
	 *      of ffv2_write_pagelist_chunked) returns from
	 *      wait_for_completion_timeout on ctx->fetch_done --
	 *      acquire pairs with (2).
	 *   4. Winner completes encode + READY + mutex_unlock --
	 *      release semantics.
	 *   5. Winner (after the unlock in step 4) continues within
	 *      the same ffv2_write_pagelist_chunked invocation and
	 *      calls this function -- the read happens-after step 3
	 *      on the same task.
	 *   6. Siblings acquire encode_lock (paired with 4's release),
	 *      then unlock and reach this function -- writes visible
	 *      transitively via the mutex chain.
	 *
	 * A future multi-writer / parity-guard extension that shares
	 * captured_guard across threads NOT paired by this fetch
	 * completion would need to revisit this synchronization.
	 */
	/*
	 * Always ship cwg_check=TRUE.  The two shard categories that
	 * lack a captured guard -- full-stripe / fresh writes to EMPTY
	 * chunks (data or parity) and parity mirrors before a pre-
	 * write CHUNK_READ populates their guard slot -- send the
	 * {0,0} sentinel.
	 *
	 * The DS's CAS short-circuits on !prev (empty chunk), so a
	 * first-write with any guard proceeds without version
	 * comparison.  A non-empty chunk with a mismatching sentinel
	 * gets NFS4ERR_DELAY; a follow-up commit classifies that and
	 * retries with a fresh CHUNK_READ.  draft sec-write_chunk_guard4
	 * permits this: check=TRUE is the draft-conforming envelope
	 * regardless of guard contents (the DS decides accept vs delay
	 * based on prev + guard).
	 *
	 * With this uniform-encode in place, the ONLY_ONE_WRITER
	 * dispatch gate at the top of ffv2_write_pagelist_chunked is
	 * dropped by a follow-up commit.
	 */
	w->wire.args.guard.check = true;
	if (ctx->captured_guard[mirror_idx].valid) {
		w->wire.args.guard.guard = ctx->captured_guard[mirror_idx].guard;
	} else {
		w->wire.args.guard.guard.cg_gen_id = 0;
		w->wire.args.guard.guard.cg_client_id = 0;
	}

	/* Copy the DS filehandle into the wrapper (bounded, owned). */
	memcpy(&w->wire.fh, &fi->fh, sizeof(w->wire.fh));

	/*
	 * Initialize seq_res.sr_slot_ops before dispatch.
	 * nfs4_setup_sequence in .rpc_call_prepare allocates a slot but
	 * does NOT populate sr_slot_ops; nfs4_sequence_done later
	 * dereferences sr_slot_ops unconditionally and page-faults if
	 * it is NULL (offset 0 of struct nfs4_sequence_res).  The
	 * CHUNK_READ path calls nfs4_init_sequence for the same
	 * reason; do the same here.
	 */
	nfs4_init_sequence(w->ds_clp, &w->wire.seq_args,
			   &w->wire.res.seq_res,
			   0, 0);

	/* Step 17: commit-bucket hint mirroring the FFv1 pattern. */
	hdr->ds_commit_idx = mirror_idx;

	/* Step 18-19: build rpc_message + rpc_task_setup + run. */
	memset(&msg, 0, sizeof(msg));
	msg.rpc_argp    = &w->wire;
	msg.rpc_resp    = &w->wire.res;
	msg.rpc_cred    = hdr->cred;
	msg.rpc_proc    = &ffv2_chunk_write_procinfo;

	memset(&task_setup, 0, sizeof(task_setup));
	task_setup.rpc_client   = ds_clnt;
	task_setup.task         = &w->task;
	task_setup.rpc_message  = &msg;
	task_setup.callback_ops = &ffv2_chunk_write_call_ops;
	task_setup.callback_data = w;
	task_setup.workqueue    = nfsiod_workqueue;
	task_setup.flags        = RPC_TASK_ASYNC | RPC_TASK_SOFTCONN |
				  RPC_TASK_SOFT;

	task = rpc_run_task(&task_setup);
	if (IS_ERR(task)) {
		/* Defensive: rpc_new_task only allocates when
		 * task_setup.task is NULL, and we always pass &w->task,
		 * so rpc_run_task cannot currently return ERR_PTR.  Kept
		 * against upstream shape drift.
		 */
		goto out_undo_refs;
	}
	rpc_put_task(task);

	/* Devnode ref was synchronous; drop before returning. */
	nfs4_put_deviceid_node(devnode);
	return PNFS_ATTEMPTED;

out_undo_refs:
	/* Undo in reverse of steps 5-8.  ctx ref NOT dropped here:
	 * the caller retains ownership on dispatch failure.
	 */
	pnfs_put_lseg(lseg);
	nfs_put_client(w->ds_clp);
	kfree(w);
out_put_devnode:
	nfs4_put_deviceid_node(devnode);
	return ffv2_write_fallback_to_mds(hdr);
}

static void ffv2_stripe_ctx_free(struct ffv2_stripe_ctx *ctx)
{
	u32 i, j;

	if (!ctx)
		return;
	if (ctx->shard_pages) {
		for (i = 0; i < ctx->k + ctx->m; i++) {
			if (!ctx->shard_pages[i])
				continue;
			for (j = 0; j < ctx->pages_per_shard; j++)
				if (ctx->shard_pages[i][j])
					__free_page(ctx->shard_pages[i][j]);
			kfree(ctx->shard_pages[i]);
		}
		kfree(ctx->shard_pages);
	}
	kfree(ctx->captured_guard);
	kfree(ctx);
}

void ffv2_stripe_ctx_put(struct ffv2_stripe_ctx *ctx)
{
	struct nfs4_ffv2_layout_segment *fls;

	if (!ctx || !refcount_dec_and_test(&ctx->refcnt))
		return;
	fls = ctx->fls;
	if (fls) {
		spin_lock(&fls->fls_ctx_lock);
		list_del(&ctx->list);
		spin_unlock(&fls->fls_ctx_lock);
		wake_up(&fls->fls_ctx_wq);
	}
	ffv2_stripe_ctx_free(ctx);
}

/*
 * Drop the batch-anchor ref of every ctx still on the lseg's ctx
 * list.  Called from ffv2_free_layout_segment as an F13 backstop:
 * a mirror hdr whose alloc failed in pnfs_generic_pg_writepages
 * leaves its slot in arrivals never satisfied, so the anchor ref
 * would otherwise pin the ctx (and its shard pages) until module
 * unload.  Straggler dispatched WRITEs / fetch RPCs hold their own
 * refs and complete the free.  Safe to call after all lseg
 * references have drained (the caller is on the free_lseg path).
 */
void ffv2_stripe_ctx_list_drain(struct nfs4_ffv2_layout_segment *fls)
{
	for (;;) {
		struct ffv2_stripe_ctx *ctx;

		spin_lock(&fls->fls_ctx_lock);
		ctx = list_first_entry_or_null(&fls->fls_ctx_list,
					       struct ffv2_stripe_ctx,
					       list);
		if (!ctx || !refcount_inc_not_zero(&ctx->refcnt)) {
			spin_unlock(&fls->fls_ctx_lock);
			return;
		}
		spin_unlock(&fls->fls_ctx_lock);
		/*
		 * Drop the anchor ref this loop borrowed (best-effort
		 * cleanup for ctxes stuck at arrivals < k+m) plus the
		 * inspection ref we just took.  Anchors already
		 * released by their (k+m)-th arrival make the anchor
		 * put a no-op harmless in that it just decrements a
		 * refcount that already accounts for outstanding
		 * dispatched hdrs.
		 */
		ffv2_stripe_ctx_put(ctx);
		ffv2_stripe_ctx_put(ctx);
	}
}

/*
 * Per-pgio-descriptor identifier used as a sibling-mirror key.
 * hdr->io_completion is set for buffered writeback; hdr->dreq for
 * O_DIRECT.  Both are shared across mirrors of the same pgio but
 * differ between distinct writers.  Callers use whichever is
 * non-NULL; if both are NULL (rare kernel-internal write helpers)
 * we fall through to a NULL key -- safe because i_rwsem serialises
 * such writers at inode granularity, so only one is ever in flight
 * against this lseg at a time.
 */
static void *ffv2_writer_key(const struct nfs_pgio_header *hdr)
{
	if (hdr->io_completion)
		return (void *)hdr->io_completion;
	return (void *)hdr->dreq;
}

/*
 * Look up an in-flight stripe context matching (writer_key,
 * stripe_off) on `fls`; if none exists, install `alloc`.  On
 * success returns with the refcount already incremented for the
 * caller (so the caller does not need refcount_inc).
 *
 * Keying on the per-pgio writer_key as well as stripe_off ensures
 * sibling mirrors of the SAME writer share a ctx while a DIFFERENT
 * writer to the same stripe gets its own ctx.  Sharing across
 * writers would silently overwrite the second writer's user data
 * with the first's, since data pages are copied only on the alloc
 * path.
 *
 * `alloc` is the caller-preallocated candidate.  The caller
 * allocates upfront (before taking the lock) so
 * ffv2_stripe_ctx_alloc's page-alloc loop stays out of the
 * spinlock's critical section.
 */
/*
 * Wait-condition helper for the gate.  Returns true when the
 * outer for(;;) should re-scan: either no ctx with our stripe_off
 * is on the list, or the first one we see is joinable (same
 * writer_key, our mirror bit clear, ref still non-zero).  Returns
 * false while a conflicting ctx is still listed, keeping the
 * caller asleep on fls_ctx_wq.
 *
 * Crucially this re-scans the list under fls_ctx_lock each wake
 * rather than dereferencing a cached pointer captured before the
 * sleep -- the pre-wait 'conflict' may have been list_del'd and
 * freed by the release path that woke us.
 */
static bool
ffv2_stripe_gate_ready(struct nfs4_ffv2_layout_segment *fls,
		       u64 stripe_off, void *writer_key,
		       u32 mirror_idx)
{
	struct ffv2_stripe_ctx *ctx;
	bool ready = true;

	spin_lock(&fls->fls_ctx_lock);
	list_for_each_entry(ctx, &fls->fls_ctx_list, list) {
		if (ctx->stripe_off != stripe_off)
			continue;
		/*
		 * A same-stripe ctx is still listed.  We can make
		 * progress iff we could join it: same writer, our
		 * mirror slot still open, and it has not raced to
		 * zero (a zero-refcount ctx is mid-teardown, its
		 * list_del + wake is imminent).
		 */
		ready = ctx->writer_key == writer_key &&
			!test_bit(mirror_idx, ctx->mirror_seen) &&
			refcount_read(&ctx->refcnt) > 0;
		break;
	}
	spin_unlock(&fls->fls_ctx_lock);
	return ready;
}

/*
 * Gated find-or-add.  Returns the admitted ctx (with refcount
 * incremented on the caller's behalf) and *is_new set:
 *   *is_new = true  -> caller is the winner: `alloc` was installed;
 *                      still needs to fill shard buffers, encode.
 *                      ctx starts with refcount = 2 (batch anchor +
 *                      this mirror's dispatch ref).
 *   *is_new = false -> caller joins existing ctx; refcount was
 *                      inc'd (via refcount_inc_not_zero).
 *
 * On conflict (same stripe_off but different writer_key, or same
 * writer_key with mirror bit already set) drops the spinlock and
 * waits on fls->fls_ctx_wq for the conflicting ctx to leave the
 * list, then retries.  Returns NULL on gate timeout (caller falls
 * back to MDS).
 *
 * The mirror_idx bit gets set atomically with admission so a
 * concurrent second-batch arrival with the same writer_key detects
 * the collision immediately.
 */
static struct ffv2_stripe_ctx *
ffv2_stripe_ctx_find_or_add(struct nfs4_ffv2_layout_segment *fls,
			    void *writer_key, u64 stripe_off,
			    u32 mirror_idx,
			    struct ffv2_stripe_ctx *alloc,
			    bool *is_new)
{
	const unsigned long timeout = msecs_to_jiffies(30 * 1000);

	for (;;) {
		struct ffv2_stripe_ctx *ctx;
		bool same_writer, saw_conflict = false;

		spin_lock(&fls->fls_ctx_lock);
		list_for_each_entry(ctx, &fls->fls_ctx_list, list) {
			if (ctx->stripe_off != stripe_off)
				continue;
			same_writer = ctx->writer_key == writer_key;
			if (same_writer &&
			    !test_bit(mirror_idx, ctx->mirror_seen) &&
			    refcount_inc_not_zero(&ctx->refcnt)) {
				bool drop_anchor;

				__set_bit(mirror_idx, ctx->mirror_seen);
				ctx->arrivals++;
				drop_anchor = ctx->arrivals ==
					      ctx->k + ctx->m;
				spin_unlock(&fls->fls_ctx_lock);
				if (drop_anchor)
					ffv2_stripe_ctx_put(ctx);
				*is_new = false;
				return ctx;
			}
			/*
			 * Conflict: different writer, or same writer's
			 * second batch (mirror bit already set), or
			 * refcount raced to zero (a release is about to
			 * list_del + wake).  Sleep on fls_ctx_wq; the
			 * wait helper re-scans the list on each wake
			 * rather than dereferencing this pointer.
			 */
			saw_conflict = true;
			break;
		}
		if (!saw_conflict) {
			/* No match, no conflict -> install `alloc`. */
			alloc->writer_key = writer_key;
			alloc->stripe_off = stripe_off;
			alloc->state = FFV2_CTX_ASSEMBLING;
			bitmap_zero(alloc->mirror_seen,
				    NFS4_FFV2_MAX_DS_PER_STRIPE);
			__set_bit(mirror_idx, alloc->mirror_seen);
			alloc->arrivals = 1;
			list_add(&alloc->list, &fls->fls_ctx_list);
			spin_unlock(&fls->fls_ctx_lock);
			*is_new = true;
			return alloc;
		}
		spin_unlock(&fls->fls_ctx_lock);

		if (!wait_event_timeout(fls->fls_ctx_wq,
					ffv2_stripe_gate_ready(fls, stripe_off,
							       writer_key,
							       mirror_idx),
					timeout))
			return NULL;	/* gate timeout -> MDS */
		/* Loop to re-scan.  Another writer may have installed a
		 * new same-stripe ctx while we waited; the retry treats
		 * it exactly like the first pass.
		 */
	}
}

static struct ffv2_stripe_ctx *
ffv2_stripe_ctx_alloc(struct nfs4_ffv2_layout_segment *fls,
		      u32 k, u32 m, u32 shard_len, gfp_t gfp)
{
	struct ffv2_stripe_ctx *ctx;
	u32 i, j, pages_per_shard;

	pages_per_shard = DIV_ROUND_UP(shard_len, PAGE_SIZE);
	if (!pages_per_shard)
		return ERR_PTR(-EINVAL);

	ctx = kzalloc(sizeof(*ctx), gfp);
	if (!ctx)
		return ERR_PTR(-ENOMEM);
	/*
	 * Refcount is set by the caller after find_or_add resolves the
	 * winner: the alloc-winner gets 1, then each subsequent-mirror
	 * lookup inc's via refcount_inc_not_zero.
	 */
	ctx->k = k;
	ctx->m = m;
	ctx->shard_len = shard_len;
	ctx->pages_per_shard = pages_per_shard;
	ctx->fls = fls;
	mutex_init(&ctx->encode_lock);
	init_completion(&ctx->fetch_done);
	atomic_set(&ctx->fetch_pending, 0);
	ctx->fetch_status = 0;
	/*
	 * Per-shard captured guard slots.  kcalloc zeros .valid to
	 * false for every slot -- correct initial state (no guards
	 * captured yet; paired writes ship cwg_check=FALSE until a
	 * CHUNK_READ succeeds AND CRC-verifies).  Sized [k+m] to
	 * match ffv2_chunk_write_dispatch_one_mirror's mirror_idx
	 * range (parity mirrors always stay .valid=false).
	 */
	ctx->captured_guard = kcalloc(k + m, sizeof(*ctx->captured_guard),
				      gfp);
	if (!ctx->captured_guard) {
		/*
		 * Route through ffv2_stripe_ctx_free (rather than a raw
		 * kfree(ctx)) for consistency with the failure paths
		 * below.  Free is safe here: shard_pages is still NULL
		 * and captured_guard is NULL, so the free body reduces
		 * to kfree(ctx) -- but a future ctx field added between
		 * kzalloc and this failure point would be missed by the
		 * raw kfree.
		 */
		ffv2_stripe_ctx_free(ctx);
		return ERR_PTR(-ENOMEM);
	}

	ctx->shard_pages = kcalloc(k + m, sizeof(*ctx->shard_pages), gfp);
	if (!ctx->shard_pages)
		goto out_free;
	for (i = 0; i < k + m; i++) {
		ctx->shard_pages[i] = kcalloc(pages_per_shard,
					      sizeof(**ctx->shard_pages), gfp);
		if (!ctx->shard_pages[i])
			goto out_free;
		for (j = 0; j < pages_per_shard; j++) {
			ctx->shard_pages[i][j] = alloc_page(gfp);
			if (!ctx->shard_pages[i][j])
				goto out_free;
		}
	}
	return ctx;

out_free:
	ffv2_stripe_ctx_free(ctx);
	return ERR_PTR(-ENOMEM);
}

/*
 * Zero every byte of every shard buffer in the ctx.  Used before a
 * partial-stripe write to establish deterministic content for the
 * bytes the user did not supply (safe only when the untouched
 * region is entirely beyond current EOF -- see the append-past-EOF
 * path in ffv2_write_pagelist_chunked).
 */
static void ffv2_zero_shards(struct ffv2_stripe_ctx *ctx)
{
	u32 i, j;

	for (i = 0; i < ctx->k + ctx->m; i++) {
		for (j = 0; j < ctx->pages_per_shard; j++) {
			void *p = kmap_local_page(ctx->shard_pages[i][j]);

			memset(p, 0, PAGE_SIZE);
			kunmap_local(p);
		}
	}
}

/*
 * Copy `count` bytes from the user's data pages (in hdr->args) into
 * the ctx's per-shard page arrays, starting at byte
 * `dst_off_in_stripe` within the flattened k*shard_len stripe view.
 * dst_off_in_stripe + count MUST fit within k*shard_len.  For a
 * full-stripe write the caller passes (0, k*shard_len).
 */
static void ffv2_copy_user_to_shards_at(struct ffv2_stripe_ctx *ctx,
					struct nfs_pgio_header *hdr,
					u32 dst_off_in_stripe, u32 count)
{
	u32 shard, off_in_shard;
	u32 pos = 0;
	u32 page_idx = 0;
	u32 page_off = hdr->args.pgbase;
	struct page **user_pages = hdr->args.pages;

	shard = dst_off_in_stripe / ctx->shard_len;
	off_in_shard = dst_off_in_stripe % ctx->shard_len;
	while (pos < count) {
		u32 in_page = PAGE_SIZE - page_off;
		u32 in_shard = ctx->shard_len - off_in_shard;
		struct page *dst_page;
		u32 dst_page_idx = off_in_shard >> PAGE_SHIFT;
		u32 dst_off = off_in_shard & (PAGE_SIZE - 1);
		u32 in_dst_page = PAGE_SIZE - dst_off;
		u32 chunk = min3(in_page, in_shard, count - pos);
		void *src, *dst;

		/*
		 * Also clamp to destination-page room.  Source and shard
		 * page boundaries diverge whenever pgbase != 0 (O_DIRECT)
		 * or shard_len is not a multiple of PAGE_SIZE (MDS may
		 * pick any striping_unit_size >= 64), so a chunk that
		 * fits the source page can still overrun the shard's
		 * per-page allocation.
		 */
		chunk = min_t(u32, chunk, in_dst_page);

		if (WARN_ON(!user_pages || !user_pages[page_idx]))
			return;
		dst_page = ctx->shard_pages[shard][dst_page_idx];

		src = kmap_local_page(user_pages[page_idx]);
		dst = kmap_local_page(dst_page);
		memcpy(dst + dst_off, src + page_off, chunk);
		kunmap_local(dst);
		kunmap_local(src);

		pos += chunk;
		off_in_shard += chunk;
		page_off += chunk;
		if (page_off == PAGE_SIZE) {
			page_off = 0;
			page_idx++;
		}
		if (off_in_shard == ctx->shard_len) {
			off_in_shard = 0;
			shard++;
		}
	}
}

/*
 * Encode: walk the shard pages k+m at a time, k data + m parity,
 * page-by-page.  For each page position: kmap all k+m pages, call
 * the encoder on the byte buffers, kunmap.
 *
 * A real implementation should encode a whole shard at once (or
 * larger blocks) rather than page-by-page; page-by-page is chosen
 * here so kmap window stays small and the code is straightforward
 * to review.  Bulk encoding is a follow-up.
 */
static int ffv2_encode_locked(struct ffv2_stripe_ctx *ctx,
			      const struct ffv2_encoder_ops *enc)
{
	const u8 **data;
	u8 **parity;
	u32 pg, i;
	int rc = 0;

	data   = kcalloc(ctx->k, sizeof(*data), GFP_NOFS);
	parity = kcalloc(ctx->m, sizeof(*parity), GFP_NOFS);
	if (!data || !parity) {
		rc = -ENOMEM;
		goto out;
	}

	for (pg = 0; pg < ctx->pages_per_shard; pg++) {
		u32 nbytes = min_t(u32, PAGE_SIZE,
				   ctx->shard_len - pg * PAGE_SIZE);

		for (i = 0; i < ctx->k; i++)
			data[i] = kmap_local_page(ctx->shard_pages[i][pg]);
		for (i = 0; i < ctx->m; i++)
			parity[i] = kmap_local_page(
				ctx->shard_pages[ctx->k + i][pg]);

		rc = enc->encode(ctx->k, ctx->m, nbytes, data, parity);

		for (i = ctx->m; i-- > 0; )
			kunmap_local(parity[i]);
		for (i = ctx->k; i-- > 0; )
			kunmap_local((void *)data[i]);

		if (rc)
			break;
	}

out:
	kfree(parity);
	kfree(data);
	return rc;
}

/*
 * The earlier plain-WRITE call_ops (ffv2_write_prepare_v4/_v3,
 * _call_done, _count_stats, _done_cb, _release) and their two
 * rpc_call_ops tables have been removed.  The chunk-encoded write
 * path now uses ffv2_chunk_write_call_ops (defined above) via the
 * extracted ffv2_chunk_write_dispatch_one_mirror helper.  Plain
 * WRITE to DSes had no chunk-store lifecycle envelope and would
 * silently accept a per-chunk failure as success.
 */

/* ---------- RMW fetch engine ------------------------------------ */

/*
 * One per shard fetch.  Carried as rpc_task_setup.callback_data so
 * per-fetch state does not piggyback on nfs_pgio_header fields.
 * The wrapper outlives the RPC only until its release fires; we
 * free it there after nfs_pgio_header_free(hdr) and the
 * single-point decrement helper.
 */
struct ffv2_rmw_fetch {
	struct ffv2_stripe_ctx	*ctx;		/* holds one ctx ref */
	struct pnfs_layout_segment *lseg;	/* holds one lseg ref --
						 * pins ctx->fls / shard
						 * pages against a racing
						 * free_layout_segment when
						 * the winner has abandoned
						 * on gate timeout.
						 */
	struct nfs_pgio_header	*hdr;
	u32			shard_idx;
	u32			expected;	/* bytes DS is expected
						 * to hold at (stripe_off +
						 * shard_idx*unit), computed
						 * from ctx->rmw_isize.
						 */
	struct nfs_client	*ds_clp;	/* holds one cl_count ref */
};

/*
 * Fetch bookkeeping added to the ctx for the FETCHING phase.  The
 * winner initializes these before dispatching; every fetch's
 * ffv2_rmw_fetch_done_one() call decrements pending and, on the
 * last, completes.
 *
 * These live on the ctx (not the wrapper) because sibling mirrors
 * observe the outcome via the ctx state (FETCHING -> READY/FAILED)
 * and the winner is the sole waiter.
 */
static void ffv2_rmw_fetch_done_one(struct ffv2_stripe_ctx *ctx,
				    int status)
{
	if (status < 0)
		cmpxchg(&ctx->fetch_status, 0, status);
	if (atomic_dec_and_test(&ctx->fetch_pending))
		complete(&ctx->fetch_done);
}

static void ffv2_rmw_fetch_prepare_v4(struct rpc_task *task, void *data)
{
	struct ffv2_rmw_fetch *f = data;
	struct nfs_pgio_header *hdr = f->hdr;

	if (nfs4_setup_sequence(hdr->ds_clp,
				&hdr->args.seq_args,
				&hdr->res.seq_res,
				task))
		return;
	rpc_call_start(task);
}

static void ffv2_rmw_fetch_prepare_v3(struct rpc_task *task, void *data)
{
	rpc_call_start(task);
}

static void ffv2_rmw_fetch_call_done_v4(struct rpc_task *task, void *data)
{
	struct ffv2_rmw_fetch *f = data;
	struct nfs_pgio_header *hdr = f->hdr;

	/*
	 * Return the session slot UNCONDITIONALLY first: safe when no
	 * slot was ever acquired (sr_slot short-circuits).  Missing
	 * this leaks slots on rpc_exit paths and eventually wedges
	 * every I/O to the DS on slot_tbl_waitq.
	 */
	nfs4_sequence_done(task, &hdr->res.seq_res);

	if (task->tk_status < 0)
		return;
	/*
	 * v4 READ decoder sets tk_status = res->count on success
	 * (nfs4xdr.c: nfs4_xdr_dec_read).  Positive count with a
	 * shortfall against what the DS is supposed to hold means
	 * DS is short of authoritative size -- stale attr cache or
	 * DS damage; either way, encoding zeros over those bytes
	 * would silently corrupt.  Fail the whole RMW.
	 */
	if (hdr->res.count < f->expected) {
		task->tk_status = -EIO;
		return;
	}
	/* res->count >= expected: good.  Bytes in [count, shard_len)
	 * remain the pre-zeroed content, sound because the DS holds
	 * nothing there (either res->eof set or count == shard_len).
	 */
}

static void ffv2_rmw_fetch_call_done_v3(struct rpc_task *task, void *data)
{
	struct ffv2_rmw_fetch *f = data;
	struct nfs_pgio_header *hdr = f->hdr;

	if (task->tk_status < 0)
		return;
	if (hdr->res.count < f->expected) {
		task->tk_status = -EIO;
		return;
	}
}

static void ffv2_rmw_fetch_release(void *data)
{
	struct ffv2_rmw_fetch *f = data;
	struct nfs_pgio_header *hdr = f->hdr;
	struct nfs_client *ds_clp = f->ds_clp;
	struct ffv2_stripe_ctx *ctx = f->ctx;
	struct pnfs_layout_segment *lseg = f->lseg;
	int status = hdr->task.tk_status;

	/*
	 * Free the hdr FIRST (it owns nothing beyond this point) so
	 * the wrapper's ctx and lseg refs -- our last holds on the
	 * shard pages against straggler DMA -- are dropped as the
	 * tail action.  lseg goes AFTER the ctx put: ctx->fls lives
	 * inside the lseg, so a still-listed straggler ctx must not
	 * survive its lseg's free.
	 */
	nfs_pgio_header_free(hdr);
	if (ds_clp)
		nfs_put_client(ds_clp);
	ffv2_rmw_fetch_done_one(ctx, status);
	ffv2_stripe_ctx_put(ctx);
	pnfs_put_lseg(lseg);
	kfree(f);
}

static const struct rpc_call_ops ffv2_rmw_fetch_call_ops_v4 = {
	.rpc_call_prepare	= ffv2_rmw_fetch_prepare_v4,
	.rpc_call_done		= ffv2_rmw_fetch_call_done_v4,
	.rpc_release		= ffv2_rmw_fetch_release,
};

static const struct rpc_call_ops ffv2_rmw_fetch_call_ops_v3 = {
	.rpc_call_prepare	= ffv2_rmw_fetch_prepare_v3,
	.rpc_call_done		= ffv2_rmw_fetch_call_done_v3,
	.rpc_release		= ffv2_rmw_fetch_release,
};

/*
 * Build a READ rpc_message from hdr->args/hdr->res and run the RPC
 * async.  Replaces nfs_initiate_pgio() for the fetch path because
 * that helper hardcodes callback_data = hdr; we need it to be the
 * wrapper.  The rest of nfs_initiate_pgio's read-side setup
 * (rpc_ops->read_setup -> READ proc + seq_args/seq_res init) is
 * done inline here.
 */
static int ffv2_rmw_fetch_initiate(struct ffv2_rmw_fetch *f, u32 version)
{
	struct nfs_pgio_header *hdr = f->hdr;
	struct rpc_message msg = {
		.rpc_argp	= &hdr->args,
		.rpc_resp	= &hdr->res,
		.rpc_cred	= hdr->cred,
	};
	struct rpc_task_setup task_setup = {
		.rpc_client	= f->ds_clp->cl_rpcclient,
		.task		= &hdr->task,
		.rpc_message	= &msg,
		.callback_ops	= version == 3 ? &ffv2_rmw_fetch_call_ops_v3
					       : &ffv2_rmw_fetch_call_ops_v4,
		.callback_data	= f,
		.workqueue	= nfsiod_workqueue,
		.flags		= RPC_TASK_ASYNC | RPC_TASK_SOFTCONN |
				  RPC_TASK_SOFT,
	};
	struct rpc_task *task;

	f->ds_clp->rpc_ops->read_setup(hdr, &msg);
	task = rpc_run_task(&task_setup);
	if (IS_ERR(task))
		return PTR_ERR(task);
	rpc_put_task(task);
	return 0;
}

/*
 * Dispatch one shard's fetch, taking the ctx ref + ds_clp ref that
 * the release will drop.  Returns 0 on successful dispatch (RPC
 * async in flight, release will call fetch_done_one) or negative
 * errno on failure to dispatch (caller must call fetch_done_one
 * itself to keep the pending counter balanced).
 */
static int ffv2_rmw_fetch_one(struct ffv2_stripe_ctx *ctx,
			      struct nfs_pgio_header *tmpl,
			      struct nfs4_ffv2_mirror *mirror, u32 shard_idx)
{
	struct nfs4_ffv2_stripe *stripe;
	struct nfs4_ffv2_data_server *ds_slot;
	struct nfs4_ffv2_file_info *fi;
	struct nfs4_deviceid_node *devnode;
	struct nfs4_ffv2_layout_ds *layout_ds;
	struct nfs4_pnfs_ds *ds;
	struct nfs_server *mds_srv = NFS_SERVER(tmpl->inode);
	struct ffv2_rmw_fetch *f;
	struct nfs_pgio_header *hdr;
	u64 shard_file_off;
	u32 version;
	int rc;

	if (mirror->stripes_cnt == 0)
		return -EINVAL;
	stripe = &mirror->stripes[0];
	if (shard_idx >= stripe->data_servers_cnt)
		return -EINVAL;
	ds_slot = &stripe->data_servers[shard_idx];
	if (ds_slot->versions_cnt == 0)
		return -EINVAL;
	fi = &ds_slot->versions[0];

	devnode = nfs4_find_get_deviceid(mds_srv, &ds_slot->devid,
					 tmpl->cred, nfs_io_gfp_mask());
	if (!devnode)
		return -EIO;
	layout_ds = FFV2_LAYOUT_DS_FROM_NODE(devnode);
	ds = layout_ds->ds;
	if (!ds || layout_ds->ds_versions_cnt == 0) {
		nfs4_put_deviceid_node(devnode);
		return -EPROTONOSUPPORT;
	}
	version = layout_ds->ds_versions[0].version;
	if (version != 3 && version != 4) {
		nfs4_put_deviceid_node(devnode);
		return -EPROTONOSUPPORT;
	}
	rc = nfs4_pnfs_ds_connect(mds_srv, ds, devnode,
				  NFS_DEF_TCP_TIMEO, 0,
				  version,
				  layout_ds->ds_versions[0].minor_version);
	if (rc || !ds->ds_clp) {
		nfs4_put_deviceid_node(devnode);
		return rc ?: -EIO;
	}

	/*
	 * v4.2+ shards delegate to ffv2_chunk_read_fetch_dispatch,
	 * which runs CHUNK_READ (a v4.2 op) through the private
	 * call_ops (CRC verify + guard capture + DELAY retry + NOENT
	 * + shortfall gates).  NFSv4 minor versions are additive so
	 * v4.3+ DSes would also carry the op if they exist.  V3
	 * shards and v4.0/4.1 shards continue below on the plain-
	 * nfs4-read path.
	 *
	 * The delegate call redoes ds_slot / devnode / ds_connect
	 * lookup internally.  These are idempotent (find_get hits the
	 * cache; ds_connect early-outs when already connected) so the
	 * double-lookup is a one-time-per-shard cost.  A future
	 * consolidation could pass the already-resolved devnode / ds
	 * via an extended dispatch signature.
	 */
	if (version == 4 &&
	    layout_ds->ds_versions[0].minor_version >= 2) {
		nfs4_put_deviceid_node(devnode);
		return ffv2_chunk_read_fetch_dispatch(ctx, tmpl, mirror,
						      shard_idx, 1);
	}

	f = kzalloc(sizeof(*f), GFP_NOFS);
	/*
	 * nfs_pgio_header_alloc() -> nfs_readhdr_alloc() is hard-coded
	 * GFP_KERNEL; this path runs in a writeback / O_DIRECT NOFS
	 * context (the write hdr's own alloc used nfs_io_gfp_mask()).
	 * A recursion into the filesystem here can deadlock reclaim on
	 * the dirty pages this write is trying to drain.
	 */
	{
		unsigned int noflags = memalloc_nofs_save();

		hdr = nfs_pgio_header_alloc(&nfs_rw_read_ops);
		memalloc_nofs_restore(noflags);
	}
	if (!f || !hdr) {
		kfree(f);
		if (hdr)
			nfs_pgio_header_free(hdr);
		nfs4_put_deviceid_node(devnode);
		return -ENOMEM;
	}

	/*
	 * Per RMW design memo section 3.9: set exactly the fields the
	 * fetch's own path reads; leave hdr->release, completion_ops,
	 * mds_ops, io_completion, dreq, lseg untouched -- routing this
	 * hdr into the generic completion machinery would be wrong.
	 */
	hdr->inode = tmpl->inode;
	hdr->cred = tmpl->cred;
	hdr->args.fh = &fi->fh;
	hdr->args.stateid = fi->stateid;
	hdr->args.pages = ctx->shard_pages[shard_idx];
	hdr->args.pgbase = 0;
	hdr->args.count = ctx->shard_len;
	shard_file_off = ctx->stripe_off +
			 (u64)shard_idx * mirror->striping_unit_size;
	hdr->args.offset = ffv2_ds_offset(mirror, ctx->stripe_off);
	hdr->io_start = shard_file_off;
	hdr->good_bytes = ctx->shard_len;
	hdr->res.fattr = &hdr->fattr;
	nfs_fattr_init(&hdr->fattr);
	hdr->res.count = 0;
	hdr->res.eof = 0;
	hdr->pgio_mirror_idx = shard_idx;

	refcount_inc(&ds->ds_clp->cl_count);
	hdr->ds_clp = ds->ds_clp;
	refcount_inc(&ctx->refcnt);

	f->ctx = ctx;
	f->lseg = pnfs_get_lseg(tmpl->lseg);
	f->hdr = hdr;
	f->shard_idx = shard_idx;
	f->expected = clamp_t(u64,
		ctx->rmw_isize > shard_file_off ?
			ctx->rmw_isize - shard_file_off : 0,
		0, ctx->shard_len);
	f->ds_clp = ds->ds_clp;

	rc = ffv2_rmw_fetch_initiate(f, version);
	nfs4_put_deviceid_node(devnode);
	if (rc) {
		/* Release will not fire.  Undo the refs we took, free
		 * scratch, and let the caller run fetch_done_one for
		 * this shard's slot in the pending counter.
		 */
		nfs_put_client(ds->ds_clp);
		refcount_dec(&ctx->refcnt);
		pnfs_put_lseg(f->lseg);
		nfs_pgio_header_free(hdr);
		kfree(f);
	}
	return rc;
}

/*
 * Sync fetch entry point.  Under FETCHING state (transition made
 * by the caller under encode_lock), initialize the fetch counters,
 * dispatch all k shard fetches, and block until the completion
 * fires.  Returns 0 iff every shard completed successfully with
 * res->count >= expected.
 */
/*
 * Contained-partial RMW live entry point.  Guard plumbing is in
 * place (ffv2_chunk_write_dispatch_one_mirror consumes
 * ctx->captured_guard[mirror_idx]).  ffv2_rmw_fetch_one now
 * discriminates on DS version and delegates v4 shards to
 * ffv2_chunk_read_fetch_dispatch (CHUNK_READ); v3 shards stay on
 * the plain-nfs4-read path.
 *
 * The caller (ffv2_write_pagelist_chunked's contained-partial
 * branch) holds ctx->encode_lock across the fetch: the winner takes
 * encode_lock, transitions ASSEMBLING -> FETCHING, calls this, and
 * on return overlays user bytes + encodes + transitions to READY
 * (or sticky FAILED before unlock on any error).  Siblings block on
 * mutex_lock(encode_lock) naturally.
 *
 * Production reachability remains on the safe fallback path until
 * the FINALIZE / COMMIT correctness tail is available.
 */
static int ffv2_rmw_fetch_stripe(struct ffv2_stripe_ctx *ctx,
		      struct nfs_pgio_header *tmpl,
		      struct nfs4_ffv2_mirror *mirror)
{
	const unsigned long timeout = msecs_to_jiffies(60 * 1000);
	u32 dispatched = 0, undispatched = 0;
	u32 i;
	int rc;

	atomic_set(&ctx->fetch_pending, ctx->k);
	ctx->fetch_status = 0;
	reinit_completion(&ctx->fetch_done);
	ctx->rmw_isize = i_size_read(tmpl->inode);
	/*
	 * Clear captured_guard[i].valid alongside the fetch-counter
	 * re-arm.  A prior-cycle guard would otherwise sit stale in
	 * the slot and be read by the paired CHUNK_WRITE.  Clear all
	 * k+m for uniformity; parity slots stay .valid=false anyway.
	 */
	for (i = 0; i < ctx->k + ctx->m; i++)
		ctx->captured_guard[i].valid = false;

	for (i = 0; i < ctx->k; i++) {
		rc = ffv2_rmw_fetch_one(ctx, tmpl, mirror, i);
		if (!rc) {
			dispatched++;
		} else {
			cmpxchg(&ctx->fetch_status, 0, rc);
			undispatched++;
		}
	}
	/*
	 * Account undispatched slots against pending via the SAME
	 * single-point helper the RPC release uses.  Every shard
	 * gets exactly one decrement; the wait always completes.
	 */
	for (i = 0; i < undispatched; i++)
		ffv2_rmw_fetch_done_one(ctx, -EIO);

	if (dispatched > 0 &&
	    !wait_for_completion_timeout(&ctx->fetch_done, timeout)) {
		cmpxchg(&ctx->fetch_status, 0, -ETIMEDOUT);
		/* Straggler RPCs still hold ctx refs and shard pages
		 * outlive their DMA; last straggler's release runs
		 * done_one -> complete on the now-abandoned completion
		 * (harmless).
		 */
	}
	return ctx->fetch_status;
}

/* ---------- end RMW fetch engine -------------------------------- */

/* ---------- CHUNK_READ dispatch scaffold ------------------------
 *
 * No live caller yet.  A later commit wires
 * ffv2_chunk_read_fetch_dispatch() as the v4 fetch RPC for the
 * contained-partial RMW branch of ffv2_write_pagelist_chunked once
 * the FFV2_CTX_FETCHING state machine and guard consumer land
 * together.
 *
 * Design: parallel wrapper to the existing RMW fetch engine (which
 * stays for v3 fallback and legacy paths).  The CHUNK_READ reply
 * shape and CRC-verify / guard-capture policy differ enough from
 * plain NFSv4 READ that overloading the shared call_ops with a
 * runtime discriminator would be error-prone.  ffv2_rmw_fetch_one
 * discriminates on version and delegates v4 shards to
 * ffv2_chunk_read_fetch_dispatch; v3 shards stay on the existing
 * plain-nfs4-read path.
 */

struct ffv2_chunk_read_fetch {
	struct ffv2_stripe_ctx	*ctx;		/* holds one ctx ref */
	struct pnfs_layout_segment *lseg;	/* holds one lseg ref */
	struct nfs_client	*ds_clp;	/* holds one cl_count ref */
	u32			shard_idx;
	u32			expected;	/* bytes DS is expected to
						 * hold at this shard's
						 * (stripe_off + shard_idx *
						 * unit); used by the
						 * shortfall check.
						 */
	/*
	 * cred is BORROWED from the caller's tmpl->cred at dispatch
	 * time.  SunRPC takes its own cred ref inside
	 * rpc_task_set_rpc_message and releases it at task teardown;
	 * the async tail rides that ref.  No get_cred at dispatch; no
	 * put_cred in release.
	 */
	const struct cred	*cred;
	/*
	 * NFS4ERR_DELAY retry counter.  Bumped in .rpc_call_done
	 * before rpc_delay + rpc_restart_call_prepare; capped at
	 * FFV2_CHUNK_READ_MAX_DELAY_ATTEMPTS.
	 */
	int			retry_attempts;
	/*
	 * Composite task-data.  args / fh / seq_args / seq_res / res
	 * all live here; the CHUNK_READ procinfo encoder + decoder
	 * consume it via rpc_message.rpc_argp.
	 */
	struct ffv2_chunk_read_data data;
	/*
	 * Embedded rpc_task, matching the nfs_pgio_header hdr->task
	 * pattern.  The RPC core snapshots tk_flags before invoking
	 * .rpc_release and a caller-supplied task never carries
	 * RPC_TASK_DYNAMIC, so kfree(wrapper) inside .rpc_release is
	 * safe.
	 */
	struct rpc_task		task;
};

static void ffv2_chunk_read_dispatch_prepare_v4(struct rpc_task *task,
						void *data)
{
	struct ffv2_chunk_read_fetch *f = data;

	if (nfs4_setup_sequence(f->ds_clp, &f->data.seq_args,
				&f->data.res.seq_res, task))
		return;
	rpc_call_start(task);
}

/*
 * NFS4ERR_DELAY retry parameters.  Linear 100 ms per attempt,
 * capped at 1 s (unreachable at 5 attempts; kept as headroom for a
 * future attempt-count raise).  Total budget: 100+200+300+400+500 =
 * 1.5 s across 5 attempts, comfortably inside the RMW fetch
 * engine's 60 s wait_for_completion_timeout.
 *
 * Uses rpc_restart_call_prepare (NOT rpc_restart_call) so
 * .rpc_call_prepare re-runs on every restart to re-acquire a
 * session slot -- plain rpc_restart_call would re-encode the slot
 * nfs4_sequence_done just freed.
 */
#define FFV2_CHUNK_READ_DELAY_BASE_MS		100
#define FFV2_CHUNK_READ_DELAY_CAP_MS		1000
#define FFV2_CHUNK_READ_MAX_DELAY_ATTEMPTS	5

/*
 * CRC verify + guard capture for one CHUNK_READ reply.  Called
 * only when task->tk_status == 0 AND nchunks == 1 AND
 * effective_len is within bounds.
 *
 * FAIL CLOSED: any algorithm mismatch, unsupported algorithm, or
 * compute failure returns a negative errno; the guard is NOT
 * captured on any failure path.  Skipping verification on an
 * algorithm mismatch would let a DS-controlled algo tag over
 * unverified bytes capture a guard from garbage.
 *
 * Wire-integrity ONLY: a successful return here does NOT certify
 * against DS bit rot when the server recomputes the checksum on
 * read; that is a server-side concern.  The client can only
 * fail-closed on wire flips, which is what this check does.
 *
 * Returns 0 on verify success + guard captured, negative errno
 * on any failure (with .valid untouched -- caller relies on
 * kzalloc'd/reset false state).
 */
static int ffv2_chunk_read_verify_and_capture(struct ffv2_chunk_read_fetch *f)
{
	struct nfs4_ffv2_mirror *mirror;
	struct ffv2_read_chunk4 *chunk = &f->data.res.chunks[0];
	u8 computed[FFV2_CHECKSUM_MAX_LEN];
	size_t computed_len;
	int rc;

	/*
	 * Layout mirror lookup: shard_idx maps into the layout via
	 * fls->mirror_array[0]->stripes[0].data_servers[shard_idx].
	 * The current posture uses a single mirror index (fls_ctx keys
	 * per-writer, so we're always mirror 0 for this ctx).  We only
	 * need the mirror's checksum_algorithm for the gate; the actual
	 * DS lookup already happened at dispatch time.
	 */
	mirror = f->ctx->fls->mirror_array[0];

	/*
	 * Fail-closed gate 1: layout-declared algorithm.  Only CRC32 is
	 * wired here.  Layouts advertising anything else fall back to
	 * MDS at dispatch time, but check defensively in case a layout
	 * slipped past the dispatch gate.
	 */
	if (mirror->checksum_algorithm != FFV2_CHECKSUM_ALG_CRC32)
		return -EBADMSG;

	/*
	 * Fail-closed gate 2: wire-declared algorithm must match.
	 * DS-controlled input; a mismatch is either transitional (a
	 * future server adding CRC32C) or corrupt / attacker-supplied.
	 * WARN-and-continue is NOT safe here; fail-closed is the
	 * correct client posture regardless of whether the transition
	 * is legitimate.
	 */
	if (chunk->checksum.algorithm != FFV2_CHECKSUM_ALG_CRC32) {
		WARN_ONCE(1,
			  "ffv2 CHUNK_READ: layout CRC32 vs wire algo %u\n",
			  chunk->checksum.algorithm);
		return -EBADMSG;
	}

	/*
	 * Compute CRC over the spliced payload.
	 * ffv2_checksum_compute_pages applies zlib CRC-32/ISO-HDLC
	 * conditioning + big-endian pack.  chunk->chunk_len is the
	 * wire-authoritative payload byte count (already bounded >=
	 * effective_len by the decoder and the shortfall check).
	 */
	rc = ffv2_checksum_compute_pages(FFV2_CHECKSUM_ALG_CRC32,
					 f->data.args.pages,
					 f->data.args.pgbase,
					 chunk->chunk_len,
					 computed, &computed_len);
	if (rc)
		return rc == -EOPNOTSUPP ? -EBADMSG : rc;

	/*
	 * Wire cs_value is 4 bytes big-endian by decoder invariant.
	 * memcmp -- NOT constant-time; this is an integrity check,
	 * not a MAC.
	 */
	if (computed_len != 4 || chunk->checksum.value_len != 4 ||
	    memcmp(computed, chunk->checksum.value, 4) != 0)
		return -EBADMSG;

	/*
	 * Verify success -> capture guard.
	 * ffv2_chunk_write_dispatch_one_mirror reads
	 * ctx->captured_guard[mirror_idx].valid and stamps
	 * cwg_check=TRUE only when true.  Winner-side visibility to
	 * the paired write comes from the encode_lock release/acquire
	 * pair.
	 *
	 * shard_idx maps 1:1 to mirror_idx for data shards (mirror 0
	 * with k data + m parity; shard_idx < k ==> mirror_idx ==
	 * shard_idx).  Parity mirrors are not populated by fetch
	 * (they have no CHUNK_READ to capture from); their slots stay
	 * .valid=false.
	 */
	f->ctx->captured_guard[f->shard_idx].guard = chunk->owner.co_guard;
	f->ctx->captured_guard[f->shard_idx].valid = true;
	return 0;
}

/*
 * NFS4ERR_DELAY retry: bump attempt counter, schedule via
 * rpc_delay + rpc_restart_call_prepare.  Returns true if retry
 * scheduled (caller returns from done immediately); false if
 * cap exhausted (caller lets tk_status stay as -NFS4ERR_DELAY
 * and release drops refs).
 *
 * MUST use rpc_restart_call_prepare (NOT rpc_restart_call): the
 * done above already called nfs4_sequence_done which freed the
 * slot.  rpc_restart_call restarts at call_start and skips
 * .rpc_call_prepare, so the retry would encode a freed /
 * possibly-re-issued slot -> SEQ_MISORDERED or slot-table
 * corruption on every DELAY.  The _prepare variant restarts at
 * rpc_prepare_task, which re-invokes .rpc_call_prepare and
 * re-acquires a slot via nfs4_setup_sequence.
 */
static bool ffv2_chunk_read_delay_retry(struct rpc_task *task,
					struct ffv2_chunk_read_fetch *f)
{
	unsigned long delay_ms;

	f->retry_attempts++;
	if (f->retry_attempts > FFV2_CHUNK_READ_MAX_DELAY_ATTEMPTS)
		return false;
	delay_ms = min_t(unsigned long,
			 f->retry_attempts * FFV2_CHUNK_READ_DELAY_BASE_MS,
			 FFV2_CHUNK_READ_DELAY_CAP_MS);
	rpc_delay(task, msecs_to_jiffies(delay_ms));
	rpc_restart_call_prepare(task);
	return true;
}

static void ffv2_chunk_read_dispatch_call_done_v4(struct rpc_task *task,
						  void *data)
{
	struct ffv2_chunk_read_fetch *f = data;
	struct ffv2_read_chunk4 *chunk;
	int rc;

	/*
	 * Return the session slot UNCONDITIONALLY first: safe when no
	 * slot was ever acquired (sr_slot short-circuits).  Missing
	 * this leaks slots per rpc_exit paths and eventually wedges
	 * every I/O to the DS on slot_tbl_waitq.
	 */
	nfs4_sequence_done(task, &f->data.res.seq_res);

	if (task->tk_status < 0) {
		/*
		 * -NFS4ERR_DELAY: retry via rpc_delay +
		 * rpc_restart_call_prepare.  The retry runs on rpciod's
		 * timer path; the winner-side thread is still blocked in
		 * wait_for_completion_timeout, which covers the full
		 * retry sequence within one 60 s bound.
		 */
		if (task->tk_status == -NFS4ERR_DELAY &&
		    ffv2_chunk_read_delay_retry(task, f))
			return;
		/*
		 * -NFS4ERR_NOENT: RMW-specific -- no prior chunk in this
		 * range.  No-op zero-fill: admission's ffv2_zero_shards
		 * already zeroed the shard page vector under fetch-then-
		 * overlay resequencing, so set tk_status = 0 and let
		 * overlay + encode proceed with zeros.  Safe under the
		 * ffv2_only_one_writer(lseg) gate (no concurrent writer
		 * can have written the range between this NOENT and the
		 * paired CHUNK_WRITE).
		 */
		if (task->tk_status == -NFS4ERR_NOENT) {
			task->tk_status = 0;
			return;
		}
		/*
		 * Every other negative: leave tk_status; release drops
		 * refs; the RMW engine's cmpxchg records the failure onto
		 * ctx->fetch_status; ffv2_rmw_fetch_stripe returns that
		 * status and the caller transitions ctx to
		 * FFV2_CTX_FAILED and falls back to MDS.
		 */
		return;
	}

	/*
	 * task->tk_status == 0.
	 *
	 * MUST check nchunks == 0 BEFORE any read of chunks[0].  On a
	 * nchunks == 0 reply the chunks[0] slot is zero-init from the
	 * wrapper kzalloc; reading its algorithm would take the
	 * ffv2_chunk_read_verify_and_capture gate-1 branch (0 !=
	 * CRC32) and return -EBADMSG -- accidentally correct here but
	 * semantically wrong (reading uninitialized data).
	 *
	 * NFS4_OK + nchunks == 0 is the DS's transient-OOM truncation
	 * path with a separately-computed crr_eof; do NOT trust
	 * res.eof as a clean-EOF signal.  Fetch failure -> MDS
	 * fallback via the RMW engine.
	 */
	if (f->data.res.nchunks == 0) {
		task->tk_status = -EIO;
		return;
	}

	chunk = &f->data.res.chunks[0];

	/*
	 * Shortfall check: DS holds fewer bytes than the authoritative
	 * size says it must.  A shortfall means stale attr cache or DS
	 * damage, and encoding zeros over those bytes would silently
	 * corrupt.  Fail the whole fetch -> MDS fallback.
	 */
	if (chunk->effective_len < f->expected) {
		task->tk_status = -EIO;
		return;
	}

	/*
	 * CRC verify + guard capture.  On failure, tk_status =
	 * -EBADMSG and .valid stays false (kzalloc + fetch-stripe
	 * re-arm both clear it); the RMW engine records -EBADMSG on
	 * fetch_status and treats it as a fetch failure -> retry on a
	 * different mirror OR MDS fallback via the existing channel.
	 * No new retry channel is introduced here.
	 */
	rc = ffv2_chunk_read_verify_and_capture(f);
	if (rc)
		task->tk_status = rc;
}

static void ffv2_chunk_read_dispatch_release(void *data)
{
	struct ffv2_chunk_read_fetch *f = data;
	struct ffv2_stripe_ctx *ctx = f->ctx;
	struct pnfs_layout_segment *lseg = f->lseg;
	struct nfs_client *ds_clp = f->ds_clp;
	int status = f->task.tk_status;

	/*
	 * Release ordering:
	 *   1. read tk_status from embedded task FIRST (before any
	 *      drop that could free the wrapper).
	 *   2. drop DS client ref before touching ctx / lseg (same
	 *      order the RMW fetch engine uses).
	 *   3. decrement the RMW engine's fetch_pending via the
	 *      single-point helper; this is the only fetch site that
	 *      calls ffv2_rmw_fetch_done_one -- the entry-gate
	 *      short-exit does NOT (the caller owns the counter on
	 *      dispatch-failure paths).
	 *   4. ctx put BEFORE lseg put (ctx->fls lives inside the
	 *      lseg; a still-listed straggler ctx must not survive
	 *      its lseg's free).
	 *   5. kfree wrapper last.  No put_cred (borrow pattern).
	 */
	if (ds_clp)
		nfs_put_client(ds_clp);
	ffv2_rmw_fetch_done_one(ctx, status);
	ffv2_stripe_ctx_put(ctx);
	pnfs_put_lseg(lseg);
	kfree(f);
}

static const struct rpc_call_ops ffv2_chunk_read_dispatch_call_ops_v4 = {
	.rpc_call_prepare	= ffv2_chunk_read_dispatch_prepare_v4,
	.rpc_call_done		= ffv2_chunk_read_dispatch_call_done_v4,
	.rpc_release		= ffv2_chunk_read_dispatch_release,
};

/*
 * Public entry point: dispatch one shard's CHUNK_READ, taking the
 * ctx / lseg / ds_clp refs that the release will drop.  Returns 0
 * on successful dispatch (RPC async in flight, release will call
 * fetch_done_one) or a negative errno on failure to dispatch (the
 * caller must call fetch_done_one itself to keep the pending counter
 * balanced).
 *
 * count MUST be 1; count == 0 returns -EINVAL without touching
 * fetch_pending (the caller owns the counter on early-exit dispatch
 * failures).  This guard belongs at the dispatch entry because the
 * .p_encode void signature cannot surface -EINVAL from within the
 * encoder itself.
 *
 * Non-static: prototype in flexfilesv2_xdr_chunk.h so the RMW fetch
 * engine can call it once the flip site is wired.  NOT
 * EXPORT_SYMBOL_GPL -- ffv2-module-internal consumers only.
 */
int ffv2_chunk_read_fetch_dispatch(struct ffv2_stripe_ctx *ctx,
				   struct nfs_pgio_header *tmpl,
				   struct nfs4_ffv2_mirror *mirror,
				   u32 shard_idx, u32 count)
{
	struct nfs4_ffv2_stripe *stripe;
	struct nfs4_ffv2_data_server *ds_slot;
	struct nfs4_ffv2_file_info *fi;
	struct nfs4_deviceid_node *devnode;
	struct nfs4_ffv2_layout_ds *layout_ds;
	struct nfs4_pnfs_ds *ds;
	struct nfs_server *mds_srv = NFS_SERVER(tmpl->inode);
	struct ffv2_chunk_read_fetch *f;
	struct rpc_message msg;
	struct rpc_task_setup task_setup;
	struct rpc_task *task;
	u64 shard_file_off, chunk_index;
	u32 version;
	int rc;

	/*
	 * Entry gate: cra_count == 0 -> -EINVAL WITHOUT touching
	 * fetch_pending.  The RMW fetch engine's undispatched loop
	 * owns the counter on dispatch failures; a dispatch-entry
	 * decrement would double-decrement (silent corruption).
	 */
	if (WARN_ON_ONCE(count == 0))
		return -EINVAL;

	if (mirror->stripes_cnt == 0)
		return -EINVAL;
	stripe = &mirror->stripes[0];
	if (shard_idx >= stripe->data_servers_cnt)
		return -EINVAL;
	ds_slot = &stripe->data_servers[shard_idx];
	if (ds_slot->versions_cnt == 0)
		return -EINVAL;
	fi = &ds_slot->versions[0];

	devnode = nfs4_find_get_deviceid(mds_srv, &ds_slot->devid,
					 tmpl->cred, nfs_io_gfp_mask());
	if (!devnode)
		return -EIO;
	layout_ds = FFV2_LAYOUT_DS_FROM_NODE(devnode);
	ds = layout_ds->ds;
	if (!ds || layout_ds->ds_versions_cnt == 0) {
		nfs4_put_deviceid_node(devnode);
		return -EPROTONOSUPPORT;
	}
	version = layout_ds->ds_versions[0].version;
	/*
	 * CHUNK_READ is a v4.2 operation (the encoder hard-codes
	 * minorversion=2 in the compound header).  Enforce version ==
	 * 4 AND minor_version >= 2 before delegating -- draft
	 * :1706-1724 requires v4.2 on non-PASSTHROUGH mirrors, and
	 * NFSv4 minor versions are additive so any v4.2+ DS supports
	 * the ops we need.  V3 mirrors and v4.0/4.1 DSes take the
	 * plain-nfs4-read fallback path via -EPROTONOSUPPORT.
	 */
	if (version != 4 ||
	    layout_ds->ds_versions[0].minor_version < 2) {
		nfs4_put_deviceid_node(devnode);
		return -EPROTONOSUPPORT;
	}
	rc = nfs4_pnfs_ds_connect(mds_srv, ds, devnode,
				  NFS_DEF_TCP_TIMEO, 0, version,
				  layout_ds->ds_versions[0].minor_version);
	if (rc || !ds->ds_clp) {
		nfs4_put_deviceid_node(devnode);
		return rc ?: -EIO;
	}

	/*
	 * Wrapper alloc: nfs_io_gfp_mask() matches the stripe-ctx
	 * allocation shape.  memalloc_nofs_save/restore protects
	 * this path in writeback / O_DIRECT NOFS context, where an
	 * allocator reclaim recursion into the fs could deadlock on
	 * the dirty pages this write is trying to drain.
	 */
	{
		unsigned int noflags = memalloc_nofs_save();

		f = kzalloc(sizeof(*f), nfs_io_gfp_mask());
		memalloc_nofs_restore(noflags);
	}
	if (!f) {
		nfs4_put_deviceid_node(devnode);
		return -ENOMEM;
	}

	/* Populate ffv2_chunk_read_data. */
	f->data.args.stateid = fi->stateid;
	/*
	 * cra_offset is a CHUNK INDEX (not bytes).  ffv2_ds_offset
	 * returns the DS-side byte offset for stripe_off under this
	 * mirror's striping geometry; divide by striping_unit_size to
	 * get the chunk index the DS expects.  Under DENSE striping
	 * the same chunk index applies to every shard's DS (each shard
	 * has its own DS filehandle, but the chunk index within that
	 * DS's file is stripe_index).
	 */
	shard_file_off = ctx->stripe_off +
			 (u64)shard_idx * mirror->striping_unit_size;
	chunk_index = ffv2_ds_offset(mirror, ctx->stripe_off);
	if (mirror->striping_unit_size != 0)
		chunk_index /= mirror->striping_unit_size;
	f->data.args.offset = chunk_index;
	f->data.args.count = count;			/* always 1 */
	f->data.args.pages = ctx->shard_pages[shard_idx];
	f->data.args.pgbase = 0;
	f->data.args.pglen = ctx->shard_len;
	/*
	 * Copy DS filehandle into the wrapper's fh slot (the caller's
	 * fi may outlive the RPC because the lseg ref pins the layout,
	 * but a local copy is cheaper than reasoning about that on
	 * every field access).
	 */
	memcpy(&f->data.fh, &fi->fh, sizeof(f->data.fh));
	nfs4_init_sequence(ds->ds_clp, &f->data.seq_args,
			   &f->data.res.seq_res,
			   0, 0);

	/*
	 * Wrapper fields: refs first (they own their targets from
	 * this point), then borrowed cred, then expected byte count.
	 */
	refcount_inc(&ds->ds_clp->cl_count);
	refcount_inc(&ctx->refcnt);
	f->ctx = ctx;
	f->lseg = pnfs_get_lseg(tmpl->lseg);
	f->ds_clp = ds->ds_clp;
	f->shard_idx = shard_idx;
	f->cred = tmpl->cred;
	f->expected = clamp_t(u64,
		ctx->rmw_isize > shard_file_off ?
			ctx->rmw_isize - shard_file_off : 0,
		0, ctx->shard_len);

	/*
	 * Build rpc_task_setup inline so the ops struct is referenced
	 * from this compilation unit even with no live caller yet
	 * (-Wunused-function under W=1 would fire on the static
	 * call_ops struct otherwise).  RPC_TASK_ASYNC + SOFTCONN +
	 * SOFT matches the existing RMW fetch initiate path.
	 */
	msg = (struct rpc_message){
		.rpc_proc	= &ffv2_chunk_read_procinfo,
		.rpc_argp	= &f->data,
		.rpc_resp	= &f->data.res,
		.rpc_cred	= f->cred,
	};
	task_setup = (struct rpc_task_setup){
		.rpc_client	= f->ds_clp->cl_rpcclient,
		.task		= &f->task,
		.rpc_message	= &msg,
		.callback_ops	= &ffv2_chunk_read_dispatch_call_ops_v4,
		.callback_data	= f,
		.workqueue	= nfsiod_workqueue,
		.flags		= RPC_TASK_ASYNC | RPC_TASK_SOFTCONN |
				  RPC_TASK_SOFT,
	};

	task = rpc_run_task(&task_setup);
	nfs4_put_deviceid_node(devnode);
	if (IS_ERR(task)) {
		/*
		 * Release will NOT fire.  Undo the refs we took, free the
		 * wrapper, and let the caller run fetch_done_one for this
		 * shard's slot in the pending counter.  Raw refcount_dec
		 * on ctx (not ffv2_stripe_ctx_put) because the caller
		 * still holds its own ctx ref, so this dec cannot be the
		 * last.
		 */
		nfs_put_client(ds->ds_clp);
		refcount_dec(&ctx->refcnt);
		pnfs_put_lseg(f->lseg);
		kfree(f);
		return PTR_ERR(task);
	}
	rpc_put_task(task);
	return 0;
}

/* ---------- end CHUNK_READ dispatch scaffold -------------------- */

/*
 * Chunk-encoded write dispatch.  Called once per mirror index by
 * pnfs_do_write; pageio processes mirrors sequentially so mirror 0
 * arrives first, allocates + populates + encodes the stripe context,
 * and publishes it on the lseg for mirrors 1..k+m-1 to consume.
 *
 * Refcount discipline: the ctx starts at 1 (mirror 0's ref); each
 * subsequent mirror inc's before its dispatch.  Each successful
 * dispatch has its ref dropped by ffv2_write_release() at RPC
 * completion.  A dispatch failure drops the ref inline before
 * returning PNFS_NOT_ATTEMPTED.
 */
enum pnfs_try_status
ffv2_write_pagelist_chunked(struct nfs_pgio_header *hdr, int sync)
{
	struct pnfs_layout_segment *lseg = hdr->lseg;
	struct nfs4_ffv2_layout_segment *fls = FFV2_LSEG(lseg);
	struct nfs4_ffv2_mirror *mirror = fls->mirror_array[0];
	struct ffv2_stripe_ctx *ctx;
	const struct ffv2_encoder_ops *enc;
	u32 k = mirror->protection_data;
	u32 m = mirror->protection_parity;
	u32 mirror_idx = hdr->pgio_mirror_idx;

	enc = ffv2_find_encoder(mirror->coding_type);
	if (!enc || !enc->encode)
		return PNFS_NOT_ATTEMPTED;

	/*
	 * Chunked DS-direct is defined only for DENSE striping: SPARSE
	 * has no natural file-offset home for parity shards, and NONE
	 * is unspecified.  Anything else falls back to MDS.
	 */
	if (mirror->striping != FFV2_STRIPING_DENSE)
		return ffv2_write_fallback_to_mds(hdr);

	/*
	 * Guard validation is performed by the data server.  The
	 * CHUNK_WRITE encoder ships cwg_check=TRUE uniformly (captured
	 * guard when valid, {0,0} sentinel otherwise), which is the
	 * draft-conforming envelope regardless of writer count; the DS
	 * decides accept vs NFS4ERR_DELAY from its own guard state.
	 * Empty-chunk first-writes accept immediately (the DS's CAS
	 * short-circuits on !prev); non-empty mismatches will be
	 * retried via RMW-refresh once the classify + retry loop is
	 * in place.
	 */

	{
		u64 stripe_bytes = (u64)k * mirror->striping_unit_size;
		u64 stripe_off, off_in_stripe;
		bool full_stripe, safe_partial, contained_partial;
		struct ffv2_stripe_ctx *cand, *found;
		int rc_enc = 0;

		stripe_off = hdr->args.offset - (hdr->args.offset % stripe_bytes);
		off_in_stripe = hdr->args.offset - stripe_off;
		full_stripe = (off_in_stripe == 0 &&
			       hdr->args.count == stripe_bytes);
		/*
		 * Partial-stripe safe-append: the user write is fully
		 * contained within a single stripe, AND the stripe starts
		 * at or past current EOF so the un-user-supplied bytes are
		 * definitively beyond the file and reading them would
		 * return short.  Zero-filling those bytes then encoding is
		 * indistinguishable from what a read after this write
		 * would observe.
		 */
		safe_partial = !full_stripe &&
			       off_in_stripe + hdr->args.count <= stripe_bytes &&
			       i_size_read(hdr->inode) <= stripe_off;
		/*
		 * Contained-partial RMW: user write fully contained
		 * within a single stripe (off_in_stripe + count <=
		 * stripe_bytes), and overlaps existing data (i_size >
		 * stripe_off).  Requires fetch-then-overlay via
		 * ffv2_rmw_fetch_stripe; the paired CHUNK_WRITEs ship
		 * cwg_check=TRUE with the CRC-verified captured guards
		 * so the DS's CAS catches concurrent-writer races.
		 *
		 * Stripe-spanning writes (off_in_stripe + count >
		 * stripe_bytes) KEEP the MDS fallback -- the ctx
		 * represents ONE stripe (ctx->stripe_off, k shards), and
		 * admitting a spanning write would confuse the single-
		 * stripe fetch engine.
		 */
		contained_partial = !full_stripe && !safe_partial &&
				    off_in_stripe + hdr->args.count <=
				    stripe_bytes;
		if (!full_stripe && !safe_partial && !contained_partial)
			return ffv2_write_fallback_to_mds(hdr);

		/*
		 * Preallocate (page-alloc loop is heavy, keep it out of
		 * the spinlock); admit under lock via find_or_add.
		 * refcount = 2 on entry to find_or_add: 1 for the batch
		 * anchor (dropped by the (k+m)-th arrival), 1 for THIS
		 * mirror's dispatch ref (returned to the caller).
		 * Sibling admissions get a single ref each.
		 */
		cand = ffv2_stripe_ctx_alloc(fls, k, m,
					     mirror->striping_unit_size,
					     nfs_io_gfp_mask());
		if (IS_ERR(cand))
			return ffv2_write_fallback_to_mds(hdr);
		refcount_set(&cand->refcnt, 2);

		{
			bool is_new = false;

			found = ffv2_stripe_ctx_find_or_add(
				fls, ffv2_writer_key(hdr), stripe_off,
				mirror_idx, cand, &is_new);
			if (!found) {
				ffv2_stripe_ctx_free(cand);
				return ffv2_write_fallback_to_mds(hdr);
			}
			if (!is_new) {
				ffv2_stripe_ctx_free(cand);
				ctx = found;
			} else {
				ctx = cand;
				/*
				 * Admission-time zero + optional user copy.
				 * For full-stripe / safe-append: user bytes
				 * go straight into the shards.  For
				 * contained-partial RMW: DEFER
				 * ffv2_copy_user_to_shards_at until AFTER
				 * the fetch -- the fetch DMAs full shard_len
				 * into the same pages and an admission-time
				 * user copy would be clobbered by the
				 * predecessor DS data.  ffv2_zero_shards
				 * stays for both paths so bytes beyond
				 * `expected` remain pre-zeroed (NOENT is a
				 * no-op memset because the shard is already
				 * zero).
				 */
				ffv2_zero_shards(ctx);
				if (!contained_partial)
					ffv2_copy_user_to_shards_at(ctx, hdr,
						(u32)off_in_stripe,
						hdr->args.count);
			}
		}

		/*
		 * Serialize encode / state transition under encode_lock:
		 * HELD across the synchronous fetch for contained-
		 * partial RMW batches.  Siblings blocking on mutex_lock
		 * see READY (winner succeeded) or FAILED (winner failed)
		 * naturally on acquire; they never observe FETCHING at
		 * the encode gate because the winner holds the lock
		 * across the entire transition.
		 *
		 * FAILED is sticky: any observer puts its dispatch ref
		 * and returns NOT_ATTEMPTED, so all mirrors of this
		 * batch fall to MDS.
		 */
		mutex_lock(&ctx->encode_lock);
		/*
		 * Encode-gate predicate.  FETCHING is a TRANSIENT state
		 * that only exists while the winner holds this same
		 * mutex, so siblings that acquire the lock ALWAYS observe
		 * READY or FAILED here -- never FETCHING.  A sibling
		 * observing state != ASSEMBLING (either READY skip-encode
		 * or FAILED fallback) skips the encode work below
		 * entirely.  Retain a WARN-guarded defensive check that
		 * the transient never leaks past the mutex; that would
		 * indicate a spec violation.
		 */
		WARN_ON_ONCE(ctx->state == FFV2_CTX_FETCHING);
		if (ctx->state == FFV2_CTX_ASSEMBLING) {
			if (contained_partial) {
				/*
				 * Transition ASSEMBLING -> FETCHING, run
				 * the synchronous fetch while HOLDING
				 * encode_lock (bounded by the fetch
				 * engine's 60 s wait_for_completion_timeout).
				 * RPC callbacks do NOT acquire encode_lock,
				 * so no lock-cycle through the fetch
				 * release path.  On success: overlay user
				 * bytes onto fetched shards, encode,
				 * transition to READY.  On any failure:
				 * sticky FAILED before unlock.
				 */
				int rc_fetch;

				ctx->state = FFV2_CTX_FETCHING;
				rc_fetch = ffv2_rmw_fetch_stripe(ctx, hdr,
								 mirror);
				if (rc_fetch) {
					ctx->state = FFV2_CTX_FAILED;
					rc_enc = rc_fetch;
				} else {
					/*
					 * Fetch-then-overlay: user bytes
					 * overlay predecessor from DS.
					 * The winner uses ITS OWN hdr's
					 * off_in_stripe + count -- same
					 * across all mirrors of the batch
					 * (pgio-coalesced), so equivalent
					 * to the is_new mirror's copy for
					 * full-stripe/safe-append.
					 */
					ffv2_copy_user_to_shards_at(ctx, hdr,
						(u32)off_in_stripe,
						hdr->args.count);
					rc_enc = enc->encode
						? ffv2_encode_locked(ctx, enc)
						: -EOPNOTSUPP;
					if (rc_enc) {
						ctx->state = FFV2_CTX_FAILED;
					} else {
						ctx->encoded = true;
						ctx->state = FFV2_CTX_READY;
					}
				}
			} else {
				/*
				 * Full-stripe / safe-append: no fetch;
				 * user bytes already in shards from
				 * admission-time copy.  Encode directly.
				 */
				rc_enc = enc->encode
					? ffv2_encode_locked(ctx, enc)
					: -EOPNOTSUPP;
				if (rc_enc) {
					ctx->state = FFV2_CTX_FAILED;
				} else {
					ctx->encoded = true;
					ctx->state = FFV2_CTX_READY;
				}
			}
		}
		if (ctx->state == FFV2_CTX_FAILED)
			rc_enc = rc_enc ? rc_enc : -EIO;
		mutex_unlock(&ctx->encode_lock);
		if (rc_enc) {
			ffv2_stripe_ctx_put(ctx);
			return ffv2_write_fallback_to_mds(hdr);
		}
	}
	if (mirror_idx >= ctx->k + ctx->m) {
		ffv2_stripe_ctx_put(ctx);
		return ffv2_write_fallback_to_mds(hdr);
	}

	/*
	 * From here on the ctx ref belongs to this dispatch.  Hand
	 * off to the CHUNK_WRITE helper, which resolves ds_slot /
	 * devnode / ds_clp itself, allocates the wrapper, populates
	 * args, and runs the private RPC via
	 * ffv2_chunk_write_procinfo.  On PNFS_ATTEMPTED the wrapper's
	 * release-cb owns all subsequent teardown (including the
	 * inherited ctx ref).  On PNFS_NOT_ATTEMPTED the helper has
	 * unwound its own local refs (devnode, lseg, ds_clp) and left
	 * ctx to us; drop inline below.
	 *
	 * At this commit the temporary gate above short-circuits
	 * before we reach here, so this call is unreachable from the
	 * write path in production.  Unit tests reach the helper via
	 * its extracted-callable form directly.  Patch 5 flips the
	 * flag and makes this the live wire dispatch.
	 */
	{
		enum pnfs_try_status rc_disp;

		rc_disp = ffv2_chunk_write_dispatch_one_mirror(
			hdr, ctx, mirror_idx, sync);
		if (rc_disp == PNFS_ATTEMPTED)
			return rc_disp;
	}

	/*
	 * Sibling dispatch-time failure after some other mirror
	 * already dispatched: the DS state can be torn until the
	 * fallback path takes over.  Always mark the layout for
	 * return here (DS-layer failures invalidate layout state
	 * independent of MDS-fallback eligibility); then let the
	 * helper decide PNFS_NOT_ATTEMPTED vs PNFS_TRY_AGAIN based
	 * on the no-MDS-fallback policy.  Both actions are
	 * idempotent when the helper also fires mark-for-return.
	 */
	if (hdr->lseg)
		pnfs_error_mark_layout_for_return(hdr->inode, hdr->lseg);
	ffv2_stripe_ctx_put(ctx);
	return ffv2_write_fallback_to_mds(hdr);
}
