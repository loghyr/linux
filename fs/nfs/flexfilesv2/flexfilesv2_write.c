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

/* ffv2_stripe_ctx_put is defined further down; forward-declare for
 * the CHUNK_WRITE dispatch below, which references it in the
 * release-cb ref-drop sequence and the dispatch-failure undo path.
 */
static void ffv2_stripe_ctx_put(struct ffv2_stripe_ctx *ctx);

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
 * ctx / lseg refs.  hdr->ds_clp is dropped by the release-cb reading
 * hdr->ds_clp directly BEFORE the completion chain frees hdr
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
	/* ds_clp lives on hdr->ds_clp; released via nfs_put_client
	 * in the release-cb BEFORE the completion chain frees hdr.
	 */
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
	struct nfs_pgio_header *hdr = w->hdr;

	nfs4_setup_sequence(hdr->ds_clp, &w->wire.seq_args,
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
 *   5. nfs_put_client(hdr->ds_clp) BEFORE the completion chain --
 *      matches pnfs_generic_rw_release order in fs/nfs/pnfs_nfs.c.
 *   6. hdr->completion_ops->completion(hdr) -- frees hdr; MUST NOT
 *      reference hdr after this.
 *   7. ffv2_stripe_ctx_put(ctx) then pnfs_put_lseg(lseg) --
 *      ctx-before-lseg because ctx->fls back-references lseg.
 *   8. kfree(wrapper) -- LAST.
 */
static void ffv2_chunk_write_release(void *data)
{
	struct ffv2_chunk_write_dispatch *w = data;
	struct nfs_pgio_header *hdr = w->hdr;
	struct ffv2_stripe_ctx *ctx = w->ctx;
	struct pnfs_layout_segment *lseg = w->lseg;

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

	/* Put ds_clp BEFORE the completion chain frees hdr.
	 * pnfs_generic_rw_release at pnfs_nfs.c:24-30 has the same
	 * order.  Unconditional: original hdr's ds_clp ref was taken
	 * once at dispatch; needs exactly one release-cb put
	 * regardless of MDS-resend firing.
	 */
	nfs_put_client(hdr->ds_clp);
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
static enum pnfs_try_status __maybe_unused
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
	/* Draft :1706-1724: non-PASSTHROUGH mirrors REQUIRE v4.2. */
	if (v != 4 || mv != 2)
		goto out_put_devnode;

	rc = nfs4_pnfs_ds_connect(mds_srv, ds, devnode, NFS_DEF_TCP_TIMEO,
				  0, v, mv);
	if (rc || !ds->ds_clp)
		goto out_put_devnode;
	ds_clnt = ds->ds_clp->cl_rpcclient;

	/* Step 5: ds_clp ref + set hdr->ds_clp.  Dropped by
	 * release-cb via nfs_put_client(hdr->ds_clp) BEFORE the
	 * completion chain.  Single ref taken, single ref put.
	 */
	refcount_inc(&ds->ds_clp->cl_count);
	hdr->ds_clp = ds->ds_clp;

	/* Step 6: lseg ref; the release-cb balances it. */
	pnfs_get_lseg(lseg);

	/* Step 7: no fresh ctx ref -- the caller's ref is INHERITED
	 * by this dispatch on success.
	 */

	/* Step 8: allocate wrapper. */
	w = kzalloc(sizeof(*w), nfs_io_gfp_mask());
	if (!w)
		goto out_undo_refs;

	/* Wrapper is now owned by the release-cb once rpc_run_task
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
		goto out_free_wrapper;
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
	w->wire.args.guard.check  = false;

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
	nfs4_init_sequence(hdr->ds_clp, &w->wire.seq_args,
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
	task_setup.task         = &hdr->task;
	task_setup.rpc_message  = &msg;
	task_setup.callback_ops = &ffv2_chunk_write_call_ops;
	task_setup.callback_data = w;
	task_setup.workqueue    = nfsiod_workqueue;
	task_setup.flags        = RPC_TASK_ASYNC | RPC_TASK_SOFTCONN |
				  RPC_TASK_SOFT;

	task = rpc_run_task(&task_setup);
	if (IS_ERR(task)) {
		/* Defensive: rpc_new_task only allocates when
		 * task_setup.task is NULL, and we always pass &hdr->task,
		 * so rpc_run_task cannot currently return ERR_PTR.  Kept
		 * against upstream shape drift.
		 */
		goto out_free_wrapper;
	}
	rpc_put_task(task);

	/* Devnode ref was synchronous; drop before returning. */
	nfs4_put_deviceid_node(devnode);
	return PNFS_ATTEMPTED;

out_free_wrapper:
	kfree(w);
out_undo_refs:
	/* Undo in reverse of steps 5-8.  ctx ref NOT dropped here:
	 * the caller retains ownership on dispatch failure.
	 */
	pnfs_put_lseg(lseg);
	nfs_put_client(hdr->ds_clp);
	hdr->ds_clp = NULL;
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
	kfree(ctx);
}

static void ffv2_stripe_ctx_put(struct ffv2_stripe_ctx *ctx)
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
 * Per-mirror-N write RPC glue.  Symmetric with the read path
 * (ffv2_read_prepare_v4 etc.), with an added release-time drop of
 * the shared stripe-ctx reference.
 */
static void ffv2_write_prepare_v4(struct rpc_task *task, void *data)
{
	struct nfs_pgio_header *hdr = data;

	if (nfs4_setup_sequence(hdr->ds_clp,
				&hdr->args.seq_args,
				&hdr->res.seq_res,
				task))
		return;
	rpc_call_start(task);
}

static void ffv2_write_call_done(struct rpc_task *task, void *data)
{
	struct nfs_pgio_header *hdr = data;

	if (test_bit(NFS_IOHDR_REDO, &hdr->flags) &&
	    task->tk_status == 0) {
		nfs4_sequence_done(task, &hdr->res.seq_res);
		return;
	}
	hdr->mds_ops->rpc_call_done(task, hdr);
}

static void ffv2_write_count_stats(struct rpc_task *task, void *data)
{
	struct nfs_pgio_header *hdr = data;

	rpc_count_iostats_metrics(task,
	    &NFS_CLIENT(hdr->inode)->cl_metrics[NFSPROC4_CLNT_WRITE]);
}

/*
 * DS-side write completion hook.  On DS-side transport failure set
 * NFS_IOHDR_RESEND_MDS so ffv2_write_release() reissues the write
 * against the MDS via pnfs_write_done_resend_to_mds().  Returning
 * task->tk_status (a negative errno) makes nfs_pgio_result() skip
 * nfs_set_pgio_error(), which is what we want: the resend will drive
 * the pages to completion, we do not want the failed DS attempt to
 * flip the pages to a "completed with error" state that
 * nfs_write_completion() might interpret as done.
 *
 * Per-DS-ioerr tracking for LAYOUTRETURN is a follow-up.
 */
static int ffv2_write_done_cb(struct rpc_task *task,
			      struct nfs_pgio_header *hdr)
{
	if (task->tk_status < 0) {
		if (!test_and_set_bit(NFS_IOHDR_RESEND_MDS, &hdr->flags))
			pnfs_error_mark_layout_for_return(hdr->inode,
							  hdr->lseg);
		return task->tk_status;
	}
	return 0;
}

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
 * Contained-partial RMW is off pending guard plumbing: the entry
 * function short-circuits before reaching this fetch path.  The
 * machinery is retained for the follow-up commit that lands guard
 * support and for unit tests that reach the helper directly.
 */
static int __maybe_unused
ffv2_rmw_fetch_stripe(struct ffv2_stripe_ctx *ctx,
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

static void ffv2_write_release(void *data)
{
	struct nfs_pgio_header *hdr = data;
	struct pnfs_layout_segment *lseg = hdr->lseg;
	struct nfs4_ffv2_layout_segment *fls = lseg ? FFV2_LSEG(lseg) : NULL;

	if (fls && fls->mirror_array_cnt > 0 && fls->mirror_array[0]) {
		struct nfs4_ffv2_mirror *mirror = fls->mirror_array[0];
		u64 stripe_bytes = (u64)mirror->protection_data *
				   mirror->striping_unit_size;
		struct ffv2_stripe_ctx *ctx;
		u64 stripe_off;
		void *writer_key = ffv2_writer_key(hdr);

		/*
		 * Derive the stripe-aligned key from hdr->mds_offset by
		 * rounding down; mds_offset itself keeps its
		 * file-absolute, pre-conversion meaning for
		 * layoutcommit / RESEND_MDS bookkeeping.  Unaligned
		 * safe-append / RMW batches would otherwise miss the
		 * ctx and leak the shard-page arrays until lseg
		 * teardown.
		 */
		if (stripe_bytes)
			stripe_off = div64_u64(hdr->mds_offset, stripe_bytes) *
				     stripe_bytes;
		else
			stripe_off = hdr->mds_offset;

		spin_lock(&fls->fls_ctx_lock);
		list_for_each_entry(ctx, &fls->fls_ctx_list, list) {
			if (ctx->writer_key != writer_key ||
			    ctx->stripe_off != stripe_off)
				continue;
			spin_unlock(&fls->fls_ctx_lock);
			ffv2_stripe_ctx_put(ctx);
			goto done;
		}
		spin_unlock(&fls->fls_ctx_lock);
	}
done:
	/*
	 * If ffv2_write_done_cb marked this hdr for MDS resend on a DS
	 * error, actually drive that resend now.  Without this hook the
	 * RESEND_MDS bit would be set but never consumed, and
	 * nfs_write_completion would mark the pages as committed --
	 * silent data loss.  Matches ff_layout_write_release.
	 */
	if (test_bit(NFS_IOHDR_RESEND_MDS, &hdr->flags) &&
	    !test_and_set_bit(NFS_IOHDR_REDO, &hdr->flags))
		hdr->task.tk_status = pnfs_write_done_resend_to_mds(hdr);
	pnfs_generic_rw_release(data);
}

static const struct rpc_call_ops ffv2_write_call_ops_v4 = {
	.rpc_call_prepare	= ffv2_write_prepare_v4,
	.rpc_call_done		= ffv2_write_call_done,
	.rpc_count_stats	= ffv2_write_count_stats,
	.rpc_release		= ffv2_write_release,
};

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
static bool ffv2_chunk_write_dispatch_enabled;

enum pnfs_try_status
ffv2_write_pagelist_chunked(struct nfs_pgio_header *hdr, int sync)
{
	struct pnfs_layout_segment *lseg = hdr->lseg;
	struct nfs4_ffv2_layout_segment *fls = FFV2_LSEG(lseg);
	struct nfs4_ffv2_mirror *mirror = fls->mirror_array[0];
	struct ffv2_stripe_ctx *ctx;
	struct nfs4_ffv2_stripe *stripe;
	struct nfs4_ffv2_data_server *ds_slot;
	struct nfs4_ffv2_file_info *fi;
	struct nfs4_deviceid_node *devnode;
	struct nfs4_ffv2_layout_ds *layout_ds;
	struct nfs4_pnfs_ds *ds;
	struct nfs_server *mds_srv = NFS_SERVER(hdr->inode);
	struct rpc_clnt *ds_clnt;
	const struct ffv2_encoder_ops *enc;
	u32 k = mirror->protection_data;
	u32 m = mirror->protection_parity;
	u32 mirror_idx = hdr->pgio_mirror_idx;
	int rc;

	enc = ffv2_find_encoder(mirror->coding_type);
	if (!enc || !enc->encode)
		return PNFS_NOT_ATTEMPTED;

	/* The FINALIZE + COMMIT tail is added before this path is enabled. */
	if (!READ_ONCE(ffv2_chunk_write_dispatch_enabled))
		return ffv2_write_fallback_to_mds(hdr);

	/*
	 * Chunked DS-direct is defined only for DENSE striping: SPARSE
	 * has no natural file-offset home for parity shards, and NONE
	 * is unspecified.  Anything else falls back to MDS.
	 */
	if (mirror->striping != FFV2_STRIPING_DENSE)
		return ffv2_write_fallback_to_mds(hdr);

	/*
	 * Chunked dispatch is currently limited to exclusive-writer
	 * layouts.  Draft :2220-2227 requires cwa_guard.check=TRUE on
	 * every CHUNK_WRITE unless FFV2_FLAGS_ONLY_ONE_WRITER is set;
	 * the guard plumbing that would let this client send a real
	 * guard on non-exclusive layouts is not yet in place, so
	 * decline every layout that permits concurrent writers rather
	 * than sending a draft-non-conforming cwa_guard.check=FALSE.
	 */
	if (!ffv2_only_one_writer(lseg))
		return ffv2_write_fallback_to_mds(hdr);

	{
		u64 stripe_bytes = (u64)k * mirror->striping_unit_size;
		u64 stripe_off, off_in_stripe;
		bool full_stripe, safe_partial;
		struct ffv2_stripe_ctx *cand, *found;

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
		 * would observe.  Reads of an existing stripe we would
		 * overwrite need RMW (fetch, modify, encode); that is
		 * deferred and falls back to MDS below.
		 */
		safe_partial = !full_stripe &&
			       off_in_stripe + hdr->args.count <= stripe_bytes &&
			       i_size_read(hdr->inode) <= stripe_off;
		/*
		 * Contained-partial RMW is off pending guard plumbing.
		 * A contained-partial write that overlaps existing data
		 * needs guard-based CAS to safely detect a concurrent
		 * winner between fetch and CHUNK_WRITE; without that,
		 * a write-hole would be silently accepted.  Full-stripe
		 * and safe-append (contained + at/past EOF) still
		 * qualify -- neither needs a predecessor read.
		 */
		if (!full_stripe && !safe_partial)
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
				ffv2_zero_shards(ctx);
				ffv2_copy_user_to_shards_at(ctx, hdr,
							    (u32)off_in_stripe,
							    hdr->args.count);
			}
		}
	}

	{
		/*
		 * Serialize encode/state transition under encode_lock.
		 * First mirror in encodes and flips to READY; siblings
		 * see READY and skip.  FAILED is sticky: any observer
		 * puts its dispatch ref and returns NOT_ATTEMPTED so
		 * all mirrors of this batch fall to MDS (I8, F5, F8).
		 */
		int rc_enc = 0;

		mutex_lock(&ctx->encode_lock);
		if (ctx->state == FFV2_CTX_ASSEMBLING ||
		    ctx->state == FFV2_CTX_FETCHING) {
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

	/* From here on the ctx ref belongs to this dispatch. */
	if (mirror->stripes_cnt == 0)
		goto out_put_ctx;
	stripe = &mirror->stripes[0];
	if (mirror_idx >= stripe->data_servers_cnt)
		goto out_put_ctx;
	ds_slot = &stripe->data_servers[mirror_idx];
	if (ds_slot->versions_cnt == 0)
		goto out_put_ctx;
	fi = &ds_slot->versions[0];

	devnode = nfs4_find_get_deviceid(mds_srv, &ds_slot->devid,
					 hdr->cred, nfs_io_gfp_mask());
	if (!devnode)
		goto out_put_ctx;
	layout_ds = FFV2_LAYOUT_DS_FROM_NODE(devnode);
	ds = layout_ds->ds;
	if (!ds || layout_ds->ds_versions_cnt == 0 ||
	    layout_ds->ds_versions[0].version != 4) {
		nfs4_put_deviceid_node(devnode);
		goto out_put_ctx;
	}

	rc = nfs4_pnfs_ds_connect(mds_srv, ds, devnode,
				  NFS_DEF_TCP_TIMEO, 0,
				  layout_ds->ds_versions[0].version,
				  layout_ds->ds_versions[0].minor_version);
	if (rc || !ds->ds_clp) {
		nfs4_put_deviceid_node(devnode);
		goto out_put_ctx;
	}
	ds_clnt = ds->ds_clp->cl_rpcclient;

	refcount_inc(&ds->ds_clp->cl_count);
	hdr->ds_clp = ds->ds_clp;
	hdr->args.fh = &fi->fh;
	hdr->args.stateid = fi->stateid;
	hdr->mds_offset = hdr->args.offset;
	hdr->pgio_done_cb = ffv2_write_done_cb;

	/*
	 * Override user pages with this mirror's shard pages.  The DS
	 * offset is derived from the stripe-aligned ctx->stripe_off,
	 * not from the (possibly unaligned) hdr->args.offset -- the
	 * latter is what ffv2_ds_offset was originally called with and
	 * that shifts DS placement for any off_in_stripe != 0 batch.
	 */
	hdr->args.pages  = ctx->shard_pages[mirror_idx];
	hdr->args.pgbase = 0;
	hdr->args.count  = ctx->shard_len;
	hdr->args.offset = ffv2_ds_offset(mirror, ctx->stripe_off);

	nfs_initiate_pgio(ds_clnt, hdr, hdr->cred,
			  ds->ds_clp->rpc_ops, &ffv2_write_call_ops_v4,
			  sync, RPC_TASK_SOFTCONN, NULL);
	nfs4_put_deviceid_node(devnode);
	return PNFS_ATTEMPTED;

out_put_ctx:
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
