// SPDX-License-Identifier: GPL-2.0
/*
 * Chunk-encoded write path for the NFSv4 Flexfile Version 2 layout
 * driver.  When the lseg's coding_type has parity (RS_VANDERMONDE,
 * MOJETTE, XOR_PARITY, LINUX_MD_RAID, ...), a single user write
 * batch expands to k+m parallel DS writes: k data-shard slices of
 * the stripe, m parity-shard buffers produced by the encoder.
 *
 * One header covers a whole stripe and issues all k+m writes from
 * it.  ffv2_write_pagelist_chunked():
 *   1. Claims the stripe, so no other writer can touch it until
 *      every shard has finalized and committed.
 *   2. Assembles the stripe context and encodes under encode_lock.
 *   3. Dispatches k+m CHUNK_WRITEs, each pointed at its own shard's
 *      page array rather than at the user pages.
 *   4. Completes the header once the whole two-phase chain lands.
 *
 * The pageio mirror fanout is deliberately not used for this:
 * mirrors describe replication, and a k+m stripe is k+m *different*
 * payloads derived from one encode.  See
 * ffv2_pg_get_mirror_count_write in flexfilesv2.c.
 *
 * Serialization is per stripe, not per lseg: two writers touching
 * different stripes of the same file proceed in parallel, and only a
 * writer that wants a stripe another already holds waits for it.
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
 * dispatch helper.
 */

/*
 * One shard of a stripe write: the CHUNK_WRITE wire composite plus
 * the RPC state and the back-pointer its callbacks need.  The inner
 * ffv2_chunk_write_data (wire args + wire res + SEQUENCE) is passed
 * as rpc_message.rpc_argp so the wire encoder / decoder is unchanged;
 * this struct is passed as callback_data.  The wrapping is required
 * because the on-wire data struct (in flexfilesv2_xdr_chunk.h) has no
 * back-pointer fields.
 */
struct ffv2_stripe_write;

struct ffv2_chunk_write_dispatch {
	struct ffv2_chunk_write_data	wire;
	struct ffv2_stripe_write	*sw;	/* parent; never NULL */
	/*
	 * Per-shard RPC state.  NOT hdr->task / hdr->ds_clp: a stripe
	 * dispatches k+m shards to k+m distinct data servers from one
	 * header, and neither the header's embedded rpc_task nor its
	 * single ds_clp can be shared across them.  Mirrors the
	 * CHUNK_READ fetch wrapper, which is already per-shard.
	 *
	 * ds_clp holds a reference owned by the parent and released
	 * when the parent is freed.
	 */
	struct rpc_task			task;
	struct nfs_client		*ds_clp;
	struct ffv2_chunk_wb_ctx	*wb;
	/*
	 * Index of this shard within the stripe, and the same index
	 * into ctx->captured_guard[].  Carried explicitly rather than
	 * derived from (w - sw->disp) so the guard-refresh path can
	 * name its slot without pointer arithmetic.
	 */
	u32				mirror_idx;
	/*
	 * NFS4ERR_DELAY guard-refresh counter.  Bumped each time the
	 * data server rejects this shard's guard and we re-read it;
	 * capped at FFV2_CHUNK_WRITE_MAX_GUARD_REFRESH.
	 */
	u32				guard_refreshes;
	bool				landed;
};

/*
 * Parking queue for a CHUNK_WRITE awaiting its guard refresh.  The
 * write task sleeps here between rpc_restart_call_prepare() and the
 * refreshing CHUNK_READ's release, so the restart cannot re-encode
 * before the new guard has landed.  Module-global rather than
 * per-stripe: an rpc_wait_queue is not free to set up and tear down,
 * and the queue only ever holds tasks that are individually woken by
 * name.
 */
static struct rpc_wait_queue ffv2_guard_refresh_wq;

void ffv2_guard_refresh_init(void)
{
	rpc_init_wait_queue(&ffv2_guard_refresh_wq, "ffv2_guard_refresh");
}

void ffv2_guard_refresh_exit(void)
{
	rpc_destroy_wait_queue(&ffv2_guard_refresh_wq);
}

/*
 * One per pgio header: the stripe write, and the owner of everything
 * the shards share.  The shards are embedded, so a shard callback can
 * always reach the parent, and the parent cannot be freed while any
 * callback can still name it.
 *
 * Completion runs in two phases, because a CHUNK_FINALIZE and a
 * CHUNK_COMMIT each address exactly one chunk on one data server:
 *
 *      k+m CHUNK_WRITEs
 *        -> writes_pending reaches 0
 *        -> on success, fan out k+m FINALIZE -> COMMIT chains
 *        -> chains_pending reaches 0
 *        -> stamp the header and complete it
 *
 * Letting each shard trigger the existing chain instead would
 * finalize one chunk and leave the rest PENDING for the server to
 * reclaim, which is silent data loss.  A failure anywhere in phase
 * one skips phase two entirely: the stripe is not durable, so
 * finalizing any part of it is wrong.
 *
 * References.  Every reference is taken by, and released by, a named
 * party; the last one out frees the struct along with the ctx, lseg
 * and per-shard data server references it owns:
 *
 *   take                              drop
 *   ----                              ----
 *   allocation, held by the           the dispatching thread, before
 *   dispatching thread                it returns
 *   each launched shard               that shard's rpc_release
 *   each launched writeback chain     that chain's terminal callback
 *
 * Neither completion tail releases anything.  The table above is the
 * whole story, and a tail that also dropped would double-drop
 * against it as soon as a tail can run on a thread that still holds
 * a reference of its own -- which is every tail, since a tail only
 * ever runs from inside a callback that is holding one.
 *
 * At this commit the mirror machinery still hands the layout driver
 * one shard per header, so nr_shards is 1 and both barriers fire on
 * the single shard.  The flip to k+m shards per header changes the
 * initializers and the dispatch loop, not this shape.
 */
struct ffv2_stripe_write {
	struct nfs_pgio_header		*hdr;	/* borrowed */
	struct pnfs_layout_segment	*lseg;	/* referenced */
	struct ffv2_stripe_ctx		*ctx;	/* referenced */

	refcount_t			sw_ref;
	atomic_t			writes_pending;
	atomic_t			chains_pending;
	int				status;	/* first error wins */
	/*
	 * Set by any shard whose failure the layout permits retrying
	 * through the metadata server.  Not NFS_IOHDR_RESEND_MDS: that
	 * flag lives on the header, but the decision is made per shard,
	 * so with k+m shards in flight one shard's clear would erase
	 * another's set and the tail would read whichever raced last.
	 */
	atomic_t			resend_mds;
	struct list_head		pending_chunks;
	spinlock_t		pending_lock;

	u32				nr_shards;
	struct ffv2_chunk_write_dispatch disp[];
};

static void ffv2_stripe_write_complete(struct ffv2_stripe_write *sw);
static void ffv2_stripe_write_put(struct ffv2_stripe_write *sw);

static void ffv2_pending_stripe_put(void *owner)
{
	ffv2_stripe_write_put(owner);
}

bool ffv2_stripe_verifiers_complete(struct ffv2_stripe_write *sw)
{
	struct ffv2_pending_chunk *pending;
	u32 count = 0;

	list_for_each_entry(pending, &sw->pending_chunks, stripe_list) {
		if (pending->state != FFV2_PENDING_LIFECYCLE_DONE ||
		    (pending->shard_idx == 0 && list_empty(&pending->requests)) ||
		    !ffv2_pending_chunk_verifiers_complete(pending))
			return false;
		count++;
	}
	return count == sw->nr_shards;
}
EXPORT_SYMBOL_GPL(ffv2_stripe_verifiers_complete);

static struct ffv2_commit_aggregate *
ffv2_stripe_claim_pending(struct ffv2_stripe_write *sw)
{
	struct ffv2_pending_chunk *pending;
	struct ffv2_commit_aggregate *agg;
	struct ffv2_commit_chunk *chunk;
	unsigned int count = 0, i;

	agg = kzalloc(sizeof(*agg), GFP_NOFS);
	if (!agg)
		return NULL;
	INIT_LIST_HEAD(&agg->list);
	refcount_set(&agg->ref, 1);
	INIT_LIST_HEAD(&agg->chunks);
	if (sw->nr_shards == 0)
		goto fail_alloc;
	for (i = 0; i < sw->nr_shards; i++) {
		chunk = kzalloc(sizeof(*chunk), GFP_NOFS);
		if (!chunk)
			goto fail_alloc;
		INIT_LIST_HEAD(&chunk->list);
		list_add_tail(&chunk->list, &agg->chunks);
	}
	spin_lock(&sw->pending_lock);
	if (atomic_read(&sw->chains_pending) != 0 || sw->status ||
	    !ffv2_stripe_verifiers_complete(sw))
		goto fail_unlock;
	list_for_each_entry(pending, &sw->pending_chunks, stripe_list) {
		pending->state = FFV2_PENDING_COMMITTING;
		count++;
	}
	if (count != sw->nr_shards)
		goto fail_states;
	agg->stripe_ref = !list_empty(&sw->pending_chunks) ?
		list_first_entry(&sw->pending_chunks,
			struct ffv2_pending_chunk, stripe_list)->stripe_ref : NULL;
	agg->stripe_put = !list_empty(&sw->pending_chunks) ?
		list_first_entry(&sw->pending_chunks,
			struct ffv2_pending_chunk, stripe_list)->stripe_put : NULL;
	agg->stripe_owner = !list_empty(&sw->pending_chunks) ?
		list_first_entry(&sw->pending_chunks,
			struct ffv2_pending_chunk, stripe_list)->stripe_owner : NULL;
	if (agg->stripe_ref)
		refcount_inc(agg->stripe_ref);
	agg->lseg = pnfs_get_lseg(sw->lseg);
	agg->inode = sw->hdr->inode;
	chunk = list_first_entry(&agg->chunks, struct ffv2_commit_chunk, list);
	list_for_each_entry(pending, &sw->pending_chunks, stripe_list) {
		chunk->pending = pending;
		chunk = list_next_entry(chunk, list);
	}
	agg->count = count;
	spin_unlock(&sw->pending_lock);
	return agg;

fail_states:
	list_for_each_entry(pending, &sw->pending_chunks, stripe_list)
		if (pending->state == FFV2_PENDING_COMMITTING)
			pending->state = FFV2_PENDING_LIFECYCLE_DONE;
fail_unlock:
	spin_unlock(&sw->pending_lock);
	goto fail_alloc;
fail_alloc:
	{
		struct ffv2_commit_chunk *chunk, *tmp;
		list_for_each_entry_safe(chunk, tmp, &agg->chunks, list) {
			list_del(&chunk->list);
			kfree(chunk);
		}
	}
	kfree(agg);
	return NULL;
}

struct nfs_commit_data *ffv2_stripe_commitdata_alloc(
					struct ffv2_stripe_write *sw)
{
	struct ffv2_commit_aggregate *agg;
	struct nfs_commit_data *data;

	agg = ffv2_stripe_claim_pending(sw);
	if (!agg)
		return NULL;
	data = ffv2_commit_aggregate_commitdata_alloc(agg);
	if (data)
		return data;
	ffv2_commit_aggregate_free(agg);
	return NULL;
}
EXPORT_SYMBOL_GPL(ffv2_stripe_commitdata_alloc);

struct nfs_commit_data *ffv2_commit_lseg_pending(
					struct pnfs_layout_segment *lseg)
{
	struct ffv2_pending_chunk *pending, *candidate = NULL;
	struct ffv2_stripe_write *sw;

	if (!lseg)
		return NULL;
	spin_lock(&FFV2_LSEG(lseg)->fls_pending_lock);
	list_for_each_entry(pending, &FFV2_LSEG(lseg)->fls_pending_list, list) {
		if (pending->state == FFV2_PENDING_LIFECYCLE_DONE) {
			candidate = pending;
			break;
		}
	}
	if (!candidate) {
		spin_unlock(&FFV2_LSEG(lseg)->fls_pending_lock);
		return NULL;
	}
	sw = candidate->sw;
	refcount_inc(&sw->sw_ref);
	spin_unlock(&FFV2_LSEG(lseg)->fls_pending_lock);
	{
		struct nfs_commit_data *data = ffv2_stripe_commitdata_alloc(sw);
		ffv2_stripe_write_put(sw);
		return data;
	}
}
EXPORT_SYMBOL_GPL(ffv2_commit_lseg_pending);

struct nfs_commit_data *ffv2_commit_inode_pending(struct inode *inode)
{
	struct pnfs_layout_hdr *lo = NFS_I(inode)->layout;
	struct pnfs_layout_segment *lseg, *candidate = NULL;
	struct nfs_commit_data *data;

	if (!lo)
		return NULL;
	spin_lock(&inode->i_lock);
	list_for_each_entry(lseg, &lo->plh_segs, pls_list) {
		if (!list_empty(&FFV2_LSEG(lseg)->fls_pending_list)) {
			candidate = pnfs_get_lseg(lseg);
			break;
		}
	}
	spin_unlock(&inode->i_lock);
	if (!candidate)
		return NULL;
	data = ffv2_commit_lseg_pending(candidate);
	pnfs_put_lseg(candidate);
	return data;
}
EXPORT_SYMBOL_GPL(ffv2_commit_inode_pending);

static bool ffv2_chunk_write_guard_refresh(struct rpc_task *task,
					   struct ffv2_chunk_write_dispatch *w);

/*
 * Record a shard's or a chain's failure.  First error wins: a later
 * failure tells us nothing the first one did not, and the first is
 * the one with a plausible causal story.
 */
static void ffv2_stripe_write_set_status(struct ffv2_stripe_write *sw,
					 int status)
{
	if (status)
		cmpxchg(&sw->status, 0, status);
}

static void ffv2_stripe_write_free(struct ffv2_stripe_write *sw)
{
	u32 i;

	spin_lock(&sw->pending_lock);
	WARN_ON_ONCE(!list_empty(&sw->pending_chunks));
	spin_unlock(&sw->pending_lock);

	for (i = 0; i < sw->nr_shards; i++)
		if (sw->disp[i].ds_clp)
			nfs_put_client(sw->disp[i].ds_clp);

	/*
	 * ctx before lseg: ctx->fls back-references the lseg.  ctx is
	 * NULL when the dispatch failed before it took ownership, in
	 * which case the caller still holds that reference.
	 */
	if (sw->ctx)
		ffv2_stripe_ctx_put(sw->ctx);
	pnfs_put_lseg(sw->lseg);
	kfree(sw);
}

static void ffv2_stripe_write_put(struct ffv2_stripe_write *sw)
{
	if (refcount_dec_and_test(&sw->sw_ref))
		ffv2_stripe_write_free(sw);
}

/*
 * Retire n writeback chains that were never launched, by counting
 * them as completed.  Without this the phase-two barrier never
 * reaches zero, the header is never completed, and the write hangs
 * for the life of the mount.
 *
 * atomic_sub_and_test rather than a loop of atomic_dec_and_test: the
 * chains already in flight may drain concurrently, so a loop could
 * carry the counter past zero and leave it negative.
 */
static void ffv2_stripe_write_chains_retire(struct ffv2_stripe_write *sw,
					    u32 n)
{
	if (n && atomic_sub_and_test(n, &sw->chains_pending))
		ffv2_stripe_write_complete(sw);
}

/*
 * .rpc_call_prepare: allocate a session slot.  nfs4_setup_sequence
 * calls rpc_call_start internally when a slot is granted; on wait it
 * reschedules on slot_tbl_waitq without further action.  Callers
 * MUST NOT invoke rpc_call_start themselves in either case.
 */
static void ffv2_chunk_write_prepare(struct rpc_task *task, void *data)
{
	struct ffv2_chunk_write_dispatch *w = data;
	struct ffv2_captured_guard *slot =
		&w->sw->ctx->captured_guard[w->mirror_idx];

	/*
	 * Take the guard from its slot on every pass, not just the
	 * first.  On the initial dispatch this reproduces what the
	 * dispatch helper already encoded; after a refresh it picks up
	 * the value the data server just gave us, which is the whole
	 * point of restarting through .rpc_call_prepare rather than
	 * re-encoding by hand.  cwg_check stays TRUE either way, and a
	 * slot with nothing in it sends the {0,0} sentinel that an
	 * empty chunk accepts.
	 */
	w->wire.args.guard.check = true;
	if (slot->valid) {
		w->wire.args.guard.guard = slot->guard;
	} else {
		w->wire.args.guard.guard.cg_gen_id = 0;
	}
	w->wire.args.guard.guard.cg_client_id =
		ffv2_cg_client_id(w->sw->ctx->fls->mirror_array[0]);

	nfs4_setup_sequence(w->ds_clp, &w->wire.seq_args, &w->wire.res.seq_res,
			    task);
}

/*
 * .rpc_call_done: return the session slot first, and stop if the
 * sequence layer restarted the call (3a decoder guarantees
 * sr_status populated per every exit path; missing the slot
 * return leaks slots on rpc_exit and wedges the session).  Then
 * re-decide the failure disposition based on this attempt's
 * outcome: clear the stale bit, apply per-chunk validation on
 * success, or jump to the failure tail.
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
 *   - Ask for a metadata-server resend ONLY when the layout permits
 *     that proxy, and return: the resend owns the outcome from there.
 *     The request is recorded on the stripe rather than the header,
 *     because it is decided per shard.
 *   - With FFV2_FLAGS_NO_IO_THRU_MDS set the draft (:2198-2203)
 *     forbids the resend, so the write terminates here.  Normalize
 *     an unmapped NFS4ERR_* status to an errno so the completion
 *     tail has something it can report to userspace.  The tail's
 *     guarded pnfs_write_done_resend_to_mds never fires on this
 *     path.
 */
static void ffv2_chunk_write_call_done(struct rpc_task *task, void *data)
{
	struct ffv2_chunk_write_dispatch *w = data;
	struct nfs_pgio_header *hdr = w->sw->hdr;
	struct ffv2_chunk_write_res *res = &w->wire.res;

	/*
	 * Return the session slot, and honour the verdict: a zero return
	 * means nfs41_sequence_process already restarted the task with
	 * tk_status cleared, so the res fields below describe a reply
	 * that was never decoded.  Safe when no slot was ever acquired --
	 * nfs4_sequence_done short-circuits to 1 on a NULL sr_slot
	 * (nfs4proc.c:1053).  Skipping it leaks a slot on rpc_exit paths
	 * and eventually wedges the data server's session.
	 */
	if (!nfs4_sequence_done(task, &w->wire.res.seq_res))
		return;

	if (task->tk_status == 0) {
		if (res->nblocks != 1) {
			task->tk_status = -EPROTO;
			goto fail;
		}
		if (res->block_status[0] == FFV2_NFS4ERR_CHUNK_GUARDED &&
		    ffv2_chunk_write_guard_refresh(task, w))
			return;
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
		w->landed = true;
		/* Happy path: retained res fields (block_activated[0],
		 * owners[0], writeverf) will be consumed by the patch-5
		 * FINALIZE tail.
		 */
		return;
	}
fail:
	pnfs_error_mark_layout_for_return(hdr->inode, hdr->lseg);
	if (!ffv2_no_fallback_to_mds(hdr->lseg)) {
		atomic_set(&w->sw->resend_mds, 1);
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
	 * Reporting the failure on the header is the completion tail's
	 * job, not this callback's: the header covers the whole stripe
	 * and only the tail knows whether any shard failed.  The
	 * release callback folds this status into the stripe write, and
	 * the tail turns it into nfs_set_pgio_error() -- which is what
	 * nfs_write_completion() actually reads, tk_status alone being
	 * ignored on this path.
	 */
}

/*
 * Start one shard's FINALIZE -> COMMIT chain (see
 * flexfilesv2_lifecycle.c).  The wb_ctx borrows hdr / ds_clp / lseg
 * from the stripe write and pins it with a reference that the
 * chain's terminal callback drops; it owns none of them itself.
 *
 * Returns 0 once the chain is running, or an errno if it never
 * started, in which case the wb_ctx has already been freed.
 */
static int ffv2_chunk_write_prepare_wb(struct ffv2_chunk_write_dispatch *w,
					       struct ffv2_chunk_wb_ctx **out)
{
	struct ffv2_stripe_write *sw = w->sw;
	struct ffv2_chunk_wb_ctx *wb;

	wb = kzalloc_obj(*wb, GFP_NOFS);
	if (!wb)
		return -ENOMEM;
	wb->pending = kzalloc(sizeof(*wb->pending), GFP_NOFS);
	if (!wb->pending) {
		kfree(wb);
		return -ENOMEM;
	}

	wb->sw = sw;
	wb->hdr = sw->hdr;
	wb->pending->ds_clp = w->ds_clp;
	refcount_inc(&wb->pending->ds_clp->cl_count);
	INIT_LIST_HEAD(&wb->pending->list);
	INIT_LIST_HEAD(&wb->pending->stripe_list);
	INIT_LIST_HEAD(&wb->pending->requests);
	wb->pending->sw = sw;
	wb->pending->stripe_ref = &sw->sw_ref;
	wb->pending->stripe_put = ffv2_pending_stripe_put;
	wb->pending->stripe_owner = sw;
	wb->pending->state = FFV2_PENDING_IMMEDIATE;
	wb->pending->stripe_lock = &sw->pending_lock;
	wb->pending->hdr = sw->hdr;
	wb->pending->lseg = pnfs_get_lseg(sw->lseg);
	wb->pending->cred = get_cred(sw->hdr->cred);
	wb->pending->fh = w->wire.fh;
	wb->pending->stateid = w->wire.args.stateid;
	wb->pending->offset = w->wire.args.offset;
	wb->pending->count = 1;
	wb->pending->shard_idx = w->mirror_idx;
	wb->pending->owner = w->wire.res.owners[0];
	memcpy(&wb->pending->writeverf, &w->wire.res.writeverf,
	       sizeof(wb->pending->writeverf));
	if (w->mirror_idx == 0) {
		struct nfs_page *req;

		list_for_each_entry(req, &sw->hdr->pages, wb_list) {
			struct ffv2_pending_req *p = kzalloc(sizeof(*p), GFP_NOFS);

			if (!p) {
				ffv2_pending_chunk_free(wb->pending);
				kfree(wb);
				return -ENOMEM;
			}
			kref_get(&req->wb_kref);
			p->req = req;
			p->inode = nfs_page_to_inode(req);
			p->context = get_nfs_open_context(
				req->wb_lock_context->open_context);
			list_add_tail(&p->list, &wb->pending->requests);
		}
	}
	spin_lock(&FFV2_LSEG(sw->lseg)->fls_pending_lock);
	list_add_tail(&wb->pending->list,
		      &FFV2_LSEG(sw->lseg)->fls_pending_list);
	spin_lock(&sw->pending_lock);
	list_add_tail(&wb->pending->stripe_list, &sw->pending_chunks);
	spin_unlock(&sw->pending_lock);
	set_bit(FFV2_PENDING_QUEUED, &wb->pending->flags);
	spin_unlock(&FFV2_LSEG(sw->lseg)->fls_pending_lock);

	/*
	 * Taken before the chain can run, dropped by its terminal
	 * callback.  The caller still holds a reference of its own, so
	 * the undo below cannot be the last one.
	 */
	refcount_inc(&sw->sw_ref);
	w->wb = wb;
	*out = wb;
	return 0;
}

static void ffv2_chunk_write_discard_wb(struct ffv2_chunk_wb_ctx *wb)
{
	struct ffv2_stripe_write *sw = wb->sw;
	u32 i;

	for (i = 0; i < sw->nr_shards; i++)
		if (sw->disp[i].wb == wb)
			sw->disp[i].wb = NULL;
	ffv2_pending_chunk_free(wb->pending);
	refcount_dec(&sw->sw_ref);
	kfree(wb);
}

static int ffv2_chunk_write_drain_wb(struct ffv2_chunk_wb_ctx *wb)
{
	int rc;

	ffv2_pending_chunk_retain(wb->pending);
	rc = ffv2_chunk_wb_start(wb);
	if (rc) {
		ffv2_pending_chunk_abort(wb->pending);
		ffv2_chunk_write_discard_wb(wb);
		return rc;
	}
	return 0;
}

static void ffv2_chunk_write_rollback_done(void *arg, int status,
					   const nfs4_verifier *writeverf)
{
	struct ffv2_stripe_write *sw = arg;

	if (status)
		atomic_set(&sw->resend_mds, 0);
	ffv2_stripe_write_chain_done(sw, status);
}

static void ffv2_stripe_write_rollback(struct ffv2_stripe_write *sw)
{
	u32 i;

	for (i = 0; i < sw->nr_shards; i++) {
		struct ffv2_chunk_write_dispatch *w = &sw->disp[i];
		struct ffv2_chunk_lifecycle_ctx ctx = {
			.ds_clp = w->ds_clp,
			.lseg = sw->lseg,
			.complete_arg = sw,
			.complete = ffv2_chunk_write_rollback_done,
		};
		int rc;

		if (!w->landed) {
			ffv2_stripe_write_chains_retire(sw, 1);
			continue;
		}
		refcount_inc(&sw->sw_ref);
		rc = ffv2_chunk_rollback_dispatch_one_mirror(&ctx, sw->hdr->cred,
			&w->wire.fh, &w->wire.args.stateid,
			w->wire.args.offset, 1, &w->wire.res.owners[0], 1);
		if (rc) {
			atomic_set(&sw->resend_mds, 0);
			ffv2_stripe_write_chain_done(sw, rc);
		}
	}
}

/*
 * Phase-one barrier tail: every CHUNK_WRITE has completed.  On
 * success, fan out one FINALIZE -> COMMIT chain per shard; the
 * phase-two tail runs when the last of them completes.
 *
 * Runs from the last shard's rpc_release, which still holds that
 * shard's reference for the duration.  A dispatch that launches no
 * shard at all never gets here: it leaves the header untouched for
 * ffv2_write_fallback_to_mds(), and writes_pending stays where it
 * started.
 */
static void ffv2_stripe_write_phase1(struct ffv2_stripe_write *sw)
{
	u32 i;

	/*
	 * A failed stripe is not durable, so finalizing any shard of it
	 * is wrong.  Roll back every shard that accepted its CHUNK_WRITE
	 * before completing the header or resending through the MDS.
	 */
	if (sw->status || atomic_read(&sw->resend_mds)) {
		ffv2_stripe_write_rollback(sw);
		return;
	}

	for (i = 0; i < sw->nr_shards; i++) {
		int rc = ffv2_chunk_write_prepare_wb(&sw->disp[i],
							&sw->disp[i].wb);

		if (rc) {
			/*
			 * The wire write landed but this chunk will never
			 * be finalized, so the server will reclaim it: the
			 * write must not report "n bytes durable" or a
			 * later read of the same offset returns a hole.
			 * Mark the layout for return so a retry gets fresh
			 * state, then count the chains that never launched
			 * as completed -- otherwise the phase-two barrier
			 * never fires and the header never completes.
			 */
			ffv2_stripe_write_set_status(sw, rc);
			pnfs_error_mark_layout_for_return(sw->hdr->inode,
							  sw->lseg);
			while (i--)
				ffv2_chunk_write_discard_wb(sw->disp[i].wb);
			ffv2_stripe_write_chains_retire(sw, sw->nr_shards);
			return;
		}
	}

	for (i = 0; i < sw->nr_shards; i++) {
		int rc = ffv2_chunk_write_drain_wb(sw->disp[i].wb);

		if (rc) {
			u32 failed = i;
			u32 j;

			ffv2_stripe_write_set_status(sw, rc);
			pnfs_error_mark_layout_for_return(sw->hdr->inode, sw->lseg);
			for (j = failed + 1; j < sw->nr_shards; j++)
				ffv2_chunk_write_discard_wb(sw->disp[j].wb);
			ffv2_stripe_write_chains_retire(sw,
							sw->nr_shards - failed);
			return;
		}
	}

}

/*
 * Phase-two barrier tail: the stripe is finished, one way or the
 * other.  The only place the header is stamped and completed.
 *
 * Releases nothing: every reference belongs to the party that took
 * it, and this tail can run on a thread that still holds one.
 */
static void ffv2_stripe_write_complete(struct ffv2_stripe_write *sw)
{
	struct nfs_pgio_header *hdr = sw->hdr;

	if (atomic_read(&sw->resend_mds) &&
	    !test_and_set_bit(NFS_IOHDR_REDO, &hdr->flags)) {
		hdr->task.tk_status = pnfs_write_done_resend_to_mds(hdr);
	} else if (sw->status) {
		/*
		 * nfs_write_completion() reads NFS_IOHDR_ERROR,
		 * hdr->error and hdr->good_bytes, none of which
		 * tk_status sets -- and this path bypasses
		 * pnfs_ld_write_done(), so nothing else will set them
		 * either.  Without this call a failed write takes the
		 * success branch: pages queued for COMMIT against an
		 * unpopulated writeverf, and for O_DIRECT the bytes
		 * reported to userspace as written.
		 */
		nfs_set_pgio_error(hdr, sw->status, hdr->args.offset);
		if (hdr->task.tk_status == 0)
			hdr->task.tk_status = sw->status;
	} else {
		/*
		 * The stripe chain has completed at every data server.  Report
		 * the logical write length; parity and padding are not user data.
		 */
		hdr->res.count = hdr->args.count;
		hdr->verf.committed = NFS_FILE_SYNC;
		memcpy(&hdr->verf.verifier, &sw->disp[0].wire.res.writeverf,
		       sizeof(hdr->verf.verifier));

		/*
		 * Report the logical end of write to the metadata server.
		 * It cannot derive it: a k+m stripe leaves each data
		 * server holding a fraction of the bytes, so the size it
		 * reflects back from them is short by that factor.  Take
		 * the extent from args, which is file-relative and covers
		 * the whole stripe; res.count is one shard's payload.
		 * FFv1 sets layoutcommit from its write-done path for the
		 * same reason.
		 */
		pnfs_set_layoutcommit(hdr->inode, hdr->lseg,
				      hdr->mds_offset + (loff_t)hdr->args.count);
	}

	hdr->completion_ops->completion(hdr);
	/* hdr is now freed; do not touch. */
}

/*
 * Terminal callback of one shard's FINALIZE -> COMMIT chain, called
 * from flexfilesv2_lifecycle.c.
 */
void ffv2_stripe_write_chain_done(struct ffv2_stripe_write *sw, int status)
{
	ffv2_stripe_write_set_status(sw, status);
	ffv2_stripe_write_chains_retire(sw, 1);
	ffv2_stripe_write_put(sw);
}

/*
 * .rpc_release: fold this shard's outcome into the stripe write and
 * drop the shard's reference.  Nothing here touches the header
 * beyond the per-shard byte credit -- the header belongs to the
 * completion tails, which run once for the whole stripe.
 */
static void ffv2_chunk_write_release(void *data)
{
	struct ffv2_chunk_write_dispatch *w = data;
	struct ffv2_stripe_write *sw = w->sw;

	/*
	 * The RPC ran on w->task, not on hdr->task, so this is the only
	 * place this shard's status is visible.
	 */
	ffv2_stripe_write_set_status(sw, w->task.tk_status);

	/*
	 * Credit the bytes this data server accepted.  The normal
	 * write-done chain does this via nfs_writeback_done; the
	 * private CHUNK path bypasses that chain, so mountstats would
	 * otherwise under-report every successful CHUNK_WRITE.  Per
	 * shard, because that is what each server actually wrote.
	 */
	if (w->task.tk_status == 0)
		nfs_add_stats(sw->hdr->inode, NFSIOS_SERVERWRITTENBYTES,
			      w->wire.args.payload_len);

	if (atomic_dec_and_test(&sw->writes_pending))
		ffv2_stripe_write_phase1(sw);

	ffv2_stripe_write_put(sw);
}

static const struct rpc_call_ops ffv2_chunk_write_call_ops = {
	.rpc_call_prepare	= ffv2_chunk_write_prepare,
	.rpc_call_done		= ffv2_chunk_write_call_done,
	.rpc_release		= ffv2_chunk_write_release,
};

/*
 * Launch shard `idx` of the stripe write.  Resolves that shard's data
 * server, fills in its wire arguments from the already-encoded stripe,
 * and runs the CHUNK_WRITE.
 *
 * Returns 0 with the RPC in flight and a reference on sw taken for it,
 * or an errno with nothing launched and no reference taken -- in which
 * case the caller owns the accounting for this shard, because a
 * release callback that would have done it will never run.
 */
static int ffv2_shard_launch(struct ffv2_stripe_write *sw, u32 idx)
{
	struct nfs_pgio_header *hdr = sw->hdr;
	struct ffv2_stripe_ctx *ctx = sw->ctx;
	struct pnfs_layout_segment *lseg = sw->lseg;
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
	struct ffv2_chunk_write_dispatch *w = &sw->disp[idx];
	struct rpc_message msg;
	struct rpc_task_setup task_setup;
	struct rpc_task *task;
	size_t csum_len;
	int rc = 0;	/* the early exits below jump past every assignment */
	u32 v, mv;
	u32 mirror_idx = idx;

	/* Step 1: verify the shard index has a data server. */
	if (mirror->stripes_cnt == 0)
		return -EINVAL;
	stripe = &mirror->stripes[0];
	if (mirror_idx >= stripe->data_servers_cnt)
		return -EINVAL;
	ds_slot = &stripe->data_servers[mirror_idx];
	if (ds_slot->versions_cnt == 0)
		return -EINVAL;
	fi = &ds_slot->versions[0];

	/* Step 2-4: acquire devnode (synchronous, released before
	 * return) + verify v4.2 + connect ds_clp.
	 */
	devnode = nfs4_find_get_deviceid(mds_srv, &ds_slot->devid,
					 hdr->cred, nfs_io_gfp_mask());
	if (!devnode)
		return -EIO;
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

	/* Step 5: ds_clp ref, one per shard, released when the stripe
	 * write is freed.  Recorded before anything can fail so the
	 * unwind below has a single shape.
	 */
	refcount_inc(&ds->ds_clp->cl_count);
	w->ds_clp = ds->ds_clp;

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
	 * capture is available -- every shard of a contained-partial
	 * read-modify-write, data and parity alike -- the captured
	 * (gen_id, client_id) pair travels with this write so the data
	 * server's compare-and-swap rejects with NFS4ERR_DELAY if a
	 * concurrent writer bumped the generation in between.  Shards
	 * with no capture send the sentinel; see the encode note below.
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
	 * Always ship cwg_check=TRUE.  Shards that lack a captured
	 * guard -- full-stripe and safe-append writes, which never
	 * fetch, plus any shard whose fetch was declined or failed
	 * verification -- send the {0,0} sentinel.  Contained-partial
	 * read-modify-write fetches all k+m shards, so both data and
	 * parity carry a real guard on that path.
	 *
	 * The DS's CAS short-circuits on !prev (empty chunk), so a
	 * first-write with any guard proceeds without version
	 * comparison.  A non-empty chunk with a mismatching sentinel
	 * gets NFS4ERR_DELAY, which ffv2_chunk_write_call_done answers
	 * by re-reading the guard and restarting this write.  draft
	 * sec-write_chunk_guard4 permits this: check=TRUE is the
	 * draft-conforming envelope regardless of guard contents (the
	 * DS decides accept vs delay based on prev + guard).
	 *
	 * The guard value itself is stamped by ffv2_chunk_write_prepare
	 * rather than here, so a write restarted through
	 * .rpc_call_prepare picks up a refreshed guard without this
	 * helper running again.  Record which slot this shard owns;
	 * prepare reads it on every pass.
	 */
	w->mirror_idx = mirror_idx;

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
	nfs4_init_sequence(w->ds_clp, &w->wire.seq_args, &w->wire.res.seq_res,
			   0, 0);

	/* Step 18-19: build rpc_message + rpc_task_setup + run. */
	memset(&msg, 0, sizeof(msg));
	/*
	 * argp and resp must land on the structs whose first member is
	 * the SEQUENCE args / res -- nfs41_assign_slot casts them
	 * directly when it hands a freed slot to a parked task.  Same
	 * pairing as .rpc_argp = &hdr->args / .rpc_resp = &hdr->res on
	 * the plain-NFSv4.1 path.
	 */
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

	/*
	 * The shard's own reference, taken before the RPC can run
	 * because the release callback may fire the moment rpc_run_task
	 * hands the task to the workqueue.
	 */
	refcount_inc(&sw->sw_ref);

	task = rpc_run_task(&task_setup);
	if (IS_ERR(task)) {
		/* Defensive: rpc_new_task only allocates when
		 * task_setup.task is NULL, and we always pass &w->task,
		 * so rpc_run_task cannot currently return ERR_PTR.  Kept
		 * against upstream shape drift.
		 */
		refcount_dec(&sw->sw_ref);
		rc = PTR_ERR(task);
		goto out_undo_refs;
	}
	rpc_put_task(task);

	/* Devnode ref was synchronous; drop before returning. */
	nfs4_put_deviceid_node(devnode);
	return 0;

out_undo_refs:
	/*
	 * Nothing launched for this shard.  Drop the data server
	 * reference here rather than leaving it to the free path: the
	 * caller may still launch later shards, so the stripe write
	 * lives on and this slot must not keep a reference to a server
	 * it never talked to.
	 */
	nfs_put_client(w->ds_clp);
	w->ds_clp = NULL;
out_put_devnode:
	nfs4_put_deviceid_node(devnode);
	return rc ? rc : -EIO;
}

/*
 * Retire n shards that were never launched, by counting them as
 * completed.  The mirror of ffv2_stripe_write_chains_retire, and
 * needed for the same reason: a launch that stops part way through
 * leaves writes_pending short of zero, so the phase-one barrier never
 * fires, the header is never completed, and the write hangs for the
 * life of the mount.
 */
static void ffv2_stripe_write_writes_retire(struct ffv2_stripe_write *sw,
					    u32 n)
{
	if (n && atomic_sub_and_test(n, &sw->writes_pending))
		ffv2_stripe_write_phase1(sw);
}

/*
 * Dispatch one whole stripe: allocate the stripe write and launch its
 * k+m CHUNK_WRITEs from this single header.
 *
 * On PNFS_ATTEMPTED the header belongs to the completion tails and the
 * caller must not touch it -- including when no shard actually
 * launched.  That is deliberate: a launch failure is a failure of this
 * write, not a reason to hand the request back for re-dispatch.
 * Returning PNFS_TRY_AGAIN here would re-enter this path with the same
 * layout and the same failing data server, which is the retry cycle
 * the stripe rework exists to remove.  The un-launched shards are
 * counted as completed-with-error instead, so the barriers fire and
 * the tail reports the error on the header exactly once.
 *
 * The only path that does not take the header is the allocation
 * failure below, which happens before anything is in flight; the
 * caller unwinds it like any other pre-dispatch failure.
 */
static enum pnfs_try_status
ffv2_stripe_write_dispatch(struct nfs_pgio_header *hdr,
			   struct ffv2_stripe_ctx *ctx, int sync)
{
	struct pnfs_layout_segment *lseg = hdr->lseg;
	struct ffv2_stripe_write *sw;
	u32 nr = ctx->k + ctx->m;
	u32 i;

	(void)sync;	/* CHUNK_WRITE is always FILE_SYNC4. */

	sw = kzalloc(struct_size(sw, disp, nr), nfs_io_gfp_mask());
	if (!sw)
		return PNFS_NOT_ATTEMPTED;

	sw->nr_shards = nr;
	sw->hdr = hdr;
	sw->lseg = lseg;
	sw->ctx = ctx;			/* the caller's ref, inherited */
	refcount_set(&sw->sw_ref, 1);	/* this thread's, dropped below */
	atomic_set(&sw->writes_pending, nr);
	atomic_set(&sw->chains_pending, nr);
	INIT_LIST_HEAD(&sw->pending_chunks);
	spin_lock_init(&sw->pending_lock);
	pnfs_get_lseg(lseg);
	for (i = 0; i < nr; i++)
		sw->disp[i].sw = sw;

	/*
	 * Commit-bucket hint.  Flexfiles v2 registers no pNFS commit
	 * operations, so nothing consumes it; a stripe has no single
	 * bucket to name in any case.
	 */
	hdr->ds_commit_idx = 0;

	for (i = 0; i < nr; i++) {
		int rc = ffv2_shard_launch(sw, i);

		if (rc) {
			ffv2_stripe_write_set_status(sw, rc);
			pnfs_error_mark_layout_for_return(hdr->inode, lseg);
			ffv2_stripe_write_writes_retire(sw, nr - i);
			break;
		}
	}

	ffv2_stripe_write_put(sw);	/* this thread's reference */
	return PNFS_ATTEMPTED;
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

/*
 * Releasing the last reference unlinks the context, which is what
 * releases the stripe: ownership lasts exactly as long as the context
 * is on the list.  Every path that claims a stripe therefore unclaims
 * it simply by dropping its reference, on success and on every error.
 *
 * wake_up_all, not wake_up: waiters are queued on one wait queue per
 * layout segment but are each waiting for a different stripe, so
 * waking only one could rouse a waiter for an unrelated stripe and
 * leave the one that could now proceed asleep.
 */
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
		wake_up_all(&fls->fls_ctx_wq);
	}
	ffv2_stripe_ctx_free(ctx);
}

/*
 * Stop accepting stripe claims on this segment, and wake every waiter
 * so nobody sleeps on a stripe whose owner completes after the recall.
 * In-flight work is untouched: it holds its own references and its
 * completion tails do not care that the layout is going away.
 */
void ffv2_claim_close(struct nfs4_ffv2_layout_segment *fls)
{
	spin_lock(&fls->fls_ctx_lock);
	fls->fls_claim_closed = true;
	spin_unlock(&fls->fls_ctx_lock);
	wake_up_all(&fls->fls_ctx_wq);
}

/*
 * Claim the stripe at `stripe_off` by installing `cand` on the layout
 * segment's list.  A stripe has at most one owner.
 *
 * This replaces the old sibling rendezvous, which had to count k+m
 * arrivals because the shards of one stripe came from k+m separate
 * callers.  One caller now brings the whole stripe, so a second caller
 * for the same stripe is not a sibling to wait for -- it is a
 * conflicting writer to serialise against.  That is a mutex over a
 * stripe rather than a barrier across mirrors, and it cannot livelock
 * the way an arrival count could, because completion no longer depends
 * on anyone else turning up.
 *
 * Returns cand on success, or NULL with *closed false if the stripe is
 * already owned, true if the segment no longer accepts claims.
 */
static struct ffv2_stripe_ctx *
ffv2_stripe_claim(struct nfs4_ffv2_layout_segment *fls, u64 stripe_off,
		  struct ffv2_stripe_ctx *cand, bool *closed)
{
	struct ffv2_stripe_ctx *ctx;

	spin_lock(&fls->fls_ctx_lock);
	if (fls->fls_claim_closed) {
		spin_unlock(&fls->fls_ctx_lock);
		*closed = true;
		return NULL;
	}
	list_for_each_entry(ctx, &fls->fls_ctx_list, list) {
		if (ctx->stripe_off == stripe_off) {
			spin_unlock(&fls->fls_ctx_lock);
			return NULL;
		}
	}
	cand->stripe_off = stripe_off;
	/*
	 * Explicit, not inherited from the kzalloc.  If FFV2_CTX_*
	 * were ever reordered so ASSEMBLING stopped being zero, the
	 * encode gate below would be skipped, rc_enc would stay 0, and
	 * k+m unencoded shards would ship -- all-zero parity that the
	 * data server accepts and that only fails at reconstruction.
	 */
	cand->state = FFV2_CTX_ASSEMBLING;
	list_add(&cand->list, &fls->fls_ctx_list);
	spin_unlock(&fls->fls_ctx_lock);
	return cand;
}

/*
 * Wait predicate: stop waiting once the stripe is free, or once the
 * segment stops accepting claims at all.  Re-scans under the lock and
 * never holds a pointer to another writer's context across the lock
 * drop -- the context it saw may be unlinked and freed the instant the
 * lock is released.
 */
static bool ffv2_stripe_wait_done(struct nfs4_ffv2_layout_segment *fls,
				  u64 stripe_off)
{
	struct ffv2_stripe_ctx *ctx;
	bool done = true;

	spin_lock(&fls->fls_ctx_lock);
	if (!fls->fls_claim_closed) {
		list_for_each_entry(ctx, &fls->fls_ctx_list, list) {
			if (ctx->stripe_off == stripe_off) {
				done = false;
				break;
			}
		}
	}
	spin_unlock(&fls->fls_ctx_lock);
	return done;
}

/*
 * Called from ffv2_free_layout_segment.  Nothing should be linked
 * here: a stripe context is owned by the stripe write that claimed
 * it, and that write holds a reference on this layout segment, so the
 * segment cannot reach its free path while any context is still on
 * the list.
 *
 * Anything left is a leaked claim.  Warn rather than free it -- the
 * owner may still hold a pointer, and dropping a reference it did not
 * take would free the context underneath a live writer.  (This used
 * to drop two references per context, releasing the batch anchor that
 * the k+m arrival rendezvous relied on; with one header owning the
 * whole stripe there is no anchor to release.)
 */
void ffv2_stripe_ctx_list_drain(struct nfs4_ffv2_layout_segment *fls)
{
	WARN_ON_ONCE(!list_empty(&fls->fls_ctx_list));
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
	 * captured yet; paired writes ship the {0,0} sentinel until a
	 * CHUNK_READ succeeds AND CRC-verifies).  Sized [k+m] to
	 * match ffv2_chunk_write_dispatch_one_mirror's mirror_idx
	 * range; every slot in that range is a fetch target.
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
	 * Return the session slot first, and stop if the sequence layer
	 * restarted the call: it clears tk_status, and the shortfall
	 * check below would then read hdr->res.count from a reply that
	 * was never decoded and fail the RMW with -EIO.  Safe when no
	 * slot was ever acquired (sr_slot short-circuits).  Missing the
	 * slot return leaks slots on rpc_exit paths and eventually
	 * wedges every I/O to the DS on slot_tbl_waitq.
	 */
	if (!nfs4_sequence_done(task, &hdr->res.seq_res))
		return;

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
 * ffv2_rmw_fetch_one() returns this in place of 0 when it declines to
 * issue an RPC for a shard at all.  Distinct from both other returns:
 * 0 means an RPC is in flight and its release will decrement the
 * pending counter, a negative errno means dispatch failed and the
 * fetch as a whole fails, and this means the caller must decrement
 * the counter itself WITHOUT recording an error.
 */
#define FFV2_RMW_FETCH_SKIPPED		1

/*
 * Dispatch one shard's fetch, taking the ctx ref + ds_clp ref that
 * the release will drop.  Returns 0 on successful dispatch (RPC
 * async in flight, release will call fetch_done_one),
 * FFV2_RMW_FETCH_SKIPPED when no RPC was issued by choice, or a
 * negative errno on failure to dispatch (in the latter two cases the
 * caller must call fetch_done_one itself to keep the pending counter
 * balanced).
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
						      shard_idx, 1, NULL);
	}

	/*
	 * A parity shard reaching here has nothing worth fetching.  The
	 * only reason to read a parity chunk is to capture its guard,
	 * and only CHUNK_READ carries one; the plain-NFSv4-READ path
	 * below would spend a round trip on bytes ffv2_encode_locked
	 * overwrites, then measure them against an `expected` derived
	 * from a file offset no parity byte lives at.  Decline instead,
	 * and let the paired CHUNK_WRITE ship the {0,0} sentinel just as
	 * it did before parity fetched at all.
	 */
	if (shard_idx >= ctx->k) {
		nfs4_put_deviceid_node(devnode);
		return FFV2_RMW_FETCH_SKIPPED;
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

	/* Initialize only fields consumed by the private fetch completion. */
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
 * dispatch a fetch for each of the k+m shards, and block until the
 * completion fires.  Returns 0 iff every shard either completed
 * successfully with res->count >= expected or was deliberately
 * skipped.
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
 * The FINALIZE / COMMIT correctness tail is active for this path.
 */
static int ffv2_rmw_fetch_stripe(struct ffv2_stripe_ctx *ctx,
		      struct nfs_pgio_header *tmpl,
		      struct nfs4_ffv2_mirror *mirror)
{
	const unsigned long timeout = msecs_to_jiffies(60 * 1000);
	u32 dispatched = 0, undispatched = 0, skipped = 0;
	u32 nshards = ctx->k + ctx->m;
	u32 i;
	int rc;

	atomic_set(&ctx->fetch_pending, nshards);
	ctx->fetch_status = 0;
	reinit_completion(&ctx->fetch_done);
	ctx->rmw_isize = i_size_read(tmpl->inode);
	/*
	 * Clear captured_guard[i].valid alongside the fetch-counter
	 * re-arm.  A prior-cycle guard would otherwise sit stale in
	 * the slot and be read by the paired CHUNK_WRITE.
	 */
	for (i = 0; i < nshards; i++)
		ctx->captured_guard[i].valid = false;

	/*
	 * Fetch every shard, parity included.  Parity chunks carry a
	 * guard exactly as data chunks do, and their paired CHUNK_WRITE
	 * needs it: shipping the {0,0} sentinel against a non-empty
	 * parity chunk fails the data server's CAS and comes back
	 * NFS4ERR_DELAY.  The fetched parity bytes themselves are
	 * discarded -- ffv2_encode_locked recomputes every parity shard
	 * from the k data shards after the overlay -- so this reads for
	 * the guard alone.
	 *
	 * A failed parity fetch fails the whole read-modify-write and
	 * drops the batch to the metadata server, exactly as a data
	 * shard's failure does.  That is deliberate rather than
	 * best-effort: until the paired write can retry an
	 * NFS4ERR_DELAY, carrying on with the sentinel would trade a
	 * clean fallback for a rejected parity write with nowhere to
	 * go.  Worth revisiting once that retry exists, since a parity
	 * guard is only needed for the data server to accept the
	 * write -- concurrent-writer detection already rests on the
	 * data shards, which no writer can update without updating
	 * parity too.
	 */
	for (i = 0; i < nshards; i++) {
		rc = ffv2_rmw_fetch_one(ctx, tmpl, mirror, i);
		if (!rc) {
			dispatched++;
		} else if (rc == FFV2_RMW_FETCH_SKIPPED) {
			skipped++;
		} else {
			cmpxchg(&ctx->fetch_status, 0, rc);
			undispatched++;
		}
	}
	/*
	 * Account undispatched and skipped slots against pending via
	 * the SAME single-point helper the RPC release uses.  Every
	 * shard gets exactly one decrement; the wait always completes.
	 * Skipped slots pass status 0: a shard we chose not to fetch is
	 * not a fetch failure, and recording one would fail the whole
	 * read-modify-write and drop the batch to the metadata server.
	 */
	for (i = 0; i < undispatched; i++)
		ffv2_rmw_fetch_done_one(ctx, -EIO);
	for (i = 0; i < skipped; i++)
		ffv2_rmw_fetch_done_one(ctx, 0);

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
	 * Guard-refresh mode.  NULL for the read-modify-write engine.
	 * Non-NULL names the CHUNK_WRITE parked on
	 * ffv2_guard_refresh_wq waiting for this read's guard, and
	 * switches the release from decrementing fetch_pending (not
	 * armed on this path) to waking that write.
	 */
	struct ffv2_chunk_write_dispatch *refresh_for;
	/*
	 * Payload landing pages for a guard refresh, owned here and
	 * freed by the release.  A refresh CANNOT read into
	 * ctx->shard_pages[shard_idx]: those hold the encoded bytes
	 * the parked CHUNK_WRITE is still sending, and overwriting
	 * them with predecessor data would corrupt the write this
	 * refresh exists to complete.  The bytes that land here are
	 * discarded; only the guard is wanted.  CHUNK_HEADER_READ
	 * would make the whole allocation unnecessary.
	 */
	struct page		**scratch;
	u32			scratch_pages;
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
	 * shard_idx maps 1:1 to mirror_idx across the whole k+m range
	 * (a single mirror holding k data shards then m parity shards),
	 * so this indexes the paired CHUNK_WRITE's slot directly.
	 * Parity shards reach here too: they are fetched for their
	 * guard alone, and capture on the same CRC-verified terms.
	 */
	f->ctx->captured_guard[f->shard_idx].guard = chunk->guard;
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
	 * Return the session slot first, and stop if the sequence layer
	 * restarted the call -- it clears tk_status, and everything
	 * below reads a reply that was never decoded.  Safe when no slot
	 * was ever acquired (sr_slot short-circuits).  Missing the slot
	 * return leaks slots per rpc_exit paths and eventually wedges
	 * every I/O to the DS on slot_tbl_waitq.
	 */
	if (!nfs4_sequence_done(task, &f->data.res.seq_res))
		return;

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
	if (chunk->status != NFS4_OK && chunk->status != NFS4ERR_NOENT) {
		task->tk_status =
			chunk->status == FFV2_NFS4ERR_PAYLOAD_NOT_ATOMIC ?
			-EBADMSG : -EIO;
		return;
	}

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

/*
 * Re-read one shard's chunk guard and restart its CHUNK_WRITE with it.
 *
 * Returns true when the retry is under way and the caller must return
 * immediately: the task has been restarted and parked, so the failure
 * path below it must not run.  Returns false when the attempt budget
 * is spent, leaving tk_status alone so the caller fails the shard as
 * it always did.
 *
 * The task is restarted BEFORE it is parked.  rpc_restart_call_prepare
 * sets the next action to re-run .rpc_call_prepare, which is what
 * re-encodes the guard; rpc_sleep_on then holds the task there until
 * the refresh completes.  Ordering matters -- parking without
 * restarting would resume a task whose next action is still to
 * complete, and restarting without parking would race the re-encode
 * against the refresh.
 *
 * Because the task restarts rather than completes, its .rpc_release
 * does not run, so writes_pending is untouched and the stripe's
 * phase-one barrier still sees exactly one pending write per shard.
 */
static bool ffv2_chunk_write_guard_refresh(struct rpc_task *task,
					   struct ffv2_chunk_write_dispatch *w)
{
	struct ffv2_stripe_write *sw = w->sw;
	struct ffv2_stripe_ctx *ctx = sw->ctx;
	struct nfs4_ffv2_mirror *mirror;
	int rc;

	if (w->guard_refreshes >= FFV2_CHUNK_WRITE_MAX_GUARD_REFRESH)
		return false;
	w->guard_refreshes++;

	if (WARN_ON_ONCE(!ctx->fls || !ctx->fls->mirror_array))
		return false;
	mirror = ctx->fls->mirror_array[0];

	/*
	 * Drop the rejected guard before asking for a new one.  If the
	 * refresh fails to capture, the retry must fall back to the
	 * sentinel rather than resend the value the server just told us
	 * was wrong.
	 */
	ctx->captured_guard[w->mirror_idx].valid = false;

	/* Keep the parked write wrapper alive until the refresh releases. */
	refcount_inc(&sw->sw_ref);
	rpc_restart_call_prepare(task);
	rpc_sleep_on(&ffv2_guard_refresh_wq, task, NULL);

	rc = ffv2_chunk_read_fetch_dispatch(ctx, sw->hdr, mirror,
					    w->mirror_idx, 1, w);
	if (rc) {
		/*
		 * Nothing was dispatched, so no release will fire and
		 * nothing else can wake this task.  Wake it here; the
		 * retry proceeds with the sentinel and either succeeds
		 * against a now-empty chunk or spends another attempt.
		 */
		rpc_wake_up_queued_task(&ffv2_guard_refresh_wq, task);
		ffv2_stripe_write_put(sw);
	}
	return true;
}

/*
 * Scratch payload pages for a guard refresh.  See the `scratch`
 * comment on struct ffv2_chunk_read_fetch for why the shard pages
 * cannot be used.  Returns 0 with f->scratch populated, or -ENOMEM
 * with nothing allocated.
 */
static int ffv2_chunk_read_alloc_scratch(struct ffv2_chunk_read_fetch *f,
					 u32 npages)
{
	u32 i;

	f->scratch = kcalloc(npages, sizeof(*f->scratch), nfs_io_gfp_mask());
	if (!f->scratch)
		return -ENOMEM;
	for (i = 0; i < npages; i++) {
		f->scratch[i] = alloc_page(nfs_io_gfp_mask());
		if (!f->scratch[i]) {
			while (i-- > 0)
				__free_page(f->scratch[i]);
			kfree(f->scratch);
			f->scratch = NULL;
			return -ENOMEM;
		}
	}
	f->scratch_pages = npages;
	return 0;
}

static void ffv2_chunk_read_free_scratch(struct ffv2_chunk_read_fetch *f)
{
	u32 i;

	if (!f->scratch)
		return;
	for (i = 0; i < f->scratch_pages; i++)
		__free_page(f->scratch[i]);
	kfree(f->scratch);
	f->scratch = NULL;
	f->scratch_pages = 0;
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
	if (f->refresh_for) {
		struct ffv2_stripe_write *sw = f->refresh_for->sw;

		/*
		 * Guard refresh: wake the parked CHUNK_WRITE instead of
		 * touching fetch_pending, which belongs to the RMW engine
		 * and is not armed here.  The wake is unconditional --
		 * every refresh outcome must produce exactly one, or the
		 * write sleeps until the stripe's 60 s bound.  A refresh
		 * that captured nothing leaves the slot invalid, and the
		 * retry re-sends the sentinel: correct if the chunk has
		 * since become empty, and otherwise spends one more of a
		 * bounded number of attempts.
		 */
		ffv2_chunk_read_free_scratch(f);
		rpc_wake_up_queued_task(&ffv2_guard_refresh_wq,
					&f->refresh_for->task);
		ffv2_stripe_write_put(sw);
	} else {
		ffv2_rmw_fetch_done_one(ctx, status);
	}
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
				   u32 shard_idx, u32 count,
				   struct ffv2_chunk_write_dispatch *refresh_for)
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
		chunk_index = div64_u64(chunk_index,
					mirror->striping_unit_size);
	f->data.args.offset = chunk_index;
	f->data.args.count = count;			/* always 1 */
	/*
	 * A guard refresh lands in its own pages: ctx->shard_pages[]
	 * still holds the encoded bytes the parked CHUNK_WRITE is
	 * sending, and this reply would overwrite them.
	 */
	if (refresh_for) {
		rc = ffv2_chunk_read_alloc_scratch(f, ctx->pages_per_shard);
		if (rc) {
			kfree(f);
			nfs4_put_deviceid_node(devnode);
			return rc;
		}
		f->refresh_for = refresh_for;
		f->data.args.pages = f->scratch;
	} else {
		f->data.args.pages = ctx->shard_pages[shard_idx];
	}
	f->data.args.pgbase = 0;
	f->data.args.pglen = ctx->shard_len;
	/*
	 * Copy DS filehandle into the wrapper's fh slot (the caller's
	 * fi may outlive the RPC because the lseg ref pins the layout,
	 * but a local copy is cheaper than reasoning about that on
	 * every field access).
	 */
	memcpy(&f->data.fh, &fi->fh, sizeof(f->data.fh));
	nfs4_init_sequence(ds->ds_clp, &f->data.seq_args, &f->data.res.seq_res,
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
	/*
	 * How many bytes the data server must hold for this shard.  The
	 * i_size-derived expectation only means something for a data
	 * shard, whose bytes occupy [shard_file_off, +shard_len) of the
	 * file.  A parity shard has no file offset at all -- the
	 * shard_file_off computed above lands in the NEXT stripe's data
	 * -- so comparing its length against i_size would gate on an
	 * unrelated region.  Expect nothing from parity and let the CRC
	 * check below carry the integrity guarantee on its own.
	 */
	if (shard_idx < ctx->k)
		f->expected = clamp_t(u64,
			ctx->rmw_isize > shard_file_off ?
				ctx->rmw_isize - shard_file_off : 0,
			0, ctx->shard_len);
	else
		f->expected = 0;

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
		ffv2_chunk_read_free_scratch(f);
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
	int rc_fail = -EIO;
	u32 k = mirror->protection_data;
	u32 m = mirror->protection_parity;

	/*
	 * No encoder for this layout's encoding family.  Route through
	 * the fallback helper rather than returning PNFS_NOT_ATTEMPTED
	 * directly: pnfs_do_write turns a bare PNFS_NOT_ATTEMPTED into
	 * pnfs_write_through_mds(), and when the layout carries
	 * FFV2_FLAGS_NO_IO_THRU_MDS the client MUST NOT proxy I/O
	 * through the metadata server.  The helper honours that flag,
	 * marking the layout for return and asking for a fresh one
	 * instead.
	 *
	 * Reachable today for MIRRORED and MOJETTE_NON_SYSTEMATIC,
	 * neither of which this client has an encoder for.
	 */
	enc = ffv2_find_encoder(mirror->coding_type);
	if (!enc || !enc->encode)
		return ffv2_write_fallback_to_mds(hdr);

	/*
	 * Chunked DS-direct is defined only for DENSE striping: SPARSE
	 * has no natural file-offset home for parity shards, and NONE
	 * is unspecified.  Anything else falls back to MDS.
	 */
	if (mirror->striping != FFV2_STRIPING_DENSE)
		return ffv2_write_fallback_to_mds(hdr);

	/*
	 * Always send a checked guard.  A valid captured guard supplies the
	 * compare value; an uncaptured shard uses the zero sentinel.  The
	 * data server decides whether the compare succeeds or must be retried.
	 */

	{
		u64 stripe_bytes = (u64)k * mirror->striping_unit_size;
		u64 stripe_off, off_in_stripe;
		bool full_stripe, safe_partial, contained_partial;
		struct ffv2_stripe_ctx *cand, *found;
		int rc_enc = 0;

		div64_u64_rem(hdr->args.offset, stripe_bytes, &off_in_stripe);
		stripe_off = hdr->args.offset - off_in_stripe;
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
		 * Preallocate outside the lock (the page-alloc loop is
		 * heavy), then claim the stripe.  A single reference: this
		 * header owns the stripe for as long as it holds it, and
		 * dropping the last reference is what releases it.
		 */
		cand = ffv2_stripe_ctx_alloc(fls, k, m,
					     mirror->striping_unit_size,
					     nfs_io_gfp_mask());
		if (IS_ERR(cand))
			return ffv2_write_fallback_to_mds(hdr);
		refcount_set(&cand->refcnt, 1);

		/*
		 * Wait for a conflicting writer rather than failing.  No
		 * timeout, and that is load-bearing: an owner always
		 * reaches its completion in bounded time, because every
		 * shard carries RPC_TASK_SOFT and the read-modify-write
		 * fetch is capped, so a waiter cannot wait forever.  Having
		 * no deadline is what removes the PNFS_TRY_AGAIN re-entry
		 * that made this path cycle.  If a future change introduces
		 * an owner path that is not bounded, this argument breaks
		 * and the timeout has to come back.
		 *
		 * Killable rather than uninterruptible: a data server
		 * connect runs synchronously inside the claimed window and
		 * follows hard-mount semantics, so a waiter can legitimately
		 * be here longer than the hung-task detector's patience.
		 */
		for (;;) {
			bool closed = false;

			found = ffv2_stripe_claim(fls, stripe_off, cand,
						  &closed);
			if (found)
				break;
			if (closed) {
				/*
				 * The segment is being recalled.  Nothing is
				 * claimed and nothing launched, so hand the
				 * header back for a fresh layout rather than
				 * writing against one the server is taking
				 * away.
				 */
				ffv2_stripe_ctx_free(cand);
				return ffv2_write_fallback_to_mds(hdr);
			}
			if (wait_event_killable(fls->fls_ctx_wq,
						ffv2_stripe_wait_done(fls,
								stripe_off))) {
				/*
				 * Killed while waiting.  Nothing was claimed
				 * and nothing launched, so -- as on the
				 * out_fail_claimed path -- completing the
				 * header here is ours to do; no release
				 * callback exists to do it for us.
				 */
				ffv2_stripe_ctx_free(cand);
				nfs_set_pgio_error(hdr, -ERESTARTSYS,
						   hdr->args.offset);
				hdr->completion_ops->completion(hdr);
				/* hdr is now freed; do not touch. */
				return PNFS_ATTEMPTED;
			}
		}
		ctx = cand;

		/*
		 * Zero the shards, and for everything except a
		 * read-modify-write copy the user bytes in now.  The RMW
		 * copy is deferred until after the fetch, which DMAs a full
		 * shard into these same pages and would otherwise overwrite
		 * it with predecessor data.  The zeroing applies either way,
		 * so bytes past `expected` stay pre-zeroed.
		 */
		ffv2_zero_shards(ctx);
		if (!contained_partial)
			ffv2_copy_user_to_shards_at(ctx, hdr,
						    (u32)off_in_stripe,
						    hdr->args.count);

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
			rc_fail = rc_enc;
			goto out_fail_claimed;
		}
	}

	/*
	 * From here on the stripe context belongs to the dispatch, which
	 * launches all k+m shards from this one header.  On
	 * PNFS_ATTEMPTED the header belongs to the completion tails and
	 * must not be touched again.
	 */
	if (ffv2_stripe_write_dispatch(hdr, ctx, sync) == PNFS_ATTEMPTED)
		return PNFS_ATTEMPTED;
	rc_fail = -ENOMEM;	/* the only non-ATTEMPTED return it has */

out_fail_claimed:
	/*
	 * Failed while holding the stripe, before anything was in
	 * flight.  Release it -- dropping the last reference unlinks the
	 * context and wakes any conflicting writer -- and report the
	 * error on the header.
	 *
	 * PNFS_ATTEMPTED, not NOT_ATTEMPTED and not TRY_AGAIN.  The write
	 * was attempted and it failed.  Either of the other two hands the
	 * request back for re-dispatch against the same layout, which is
	 * the cycle this path exists to avoid -- and under
	 * FFV2_FLAGS_NO_IO_THRU_MDS the metadata server route is
	 * forbidden anyway, so there is nowhere else for it to go.
	 *
	 * PNFS_ATTEMPTED also means pnfs_do_write() does nothing further:
	 * completing the header is ours.  No RPC was launched here, so no
	 * release callback will ever run and neither barrier tail fires;
	 * without the explicit completion below the requests stay under
	 * writeback and the write hangs in folio_wait_writeback for the
	 * life of the mount -- the very failure this rework removes.
	 * Unclaim first: once the header is completed it may be freed,
	 * and a waiter woken by the unclaim must not see a half-torn-down
	 * owner.
	 */
	pnfs_error_mark_layout_for_return(hdr->inode, lseg);
	ffv2_stripe_ctx_put(ctx);
	nfs_set_pgio_error(hdr, rc_fail, hdr->args.offset);
	hdr->completion_ops->completion(hdr);
	/* hdr is now freed; do not touch. */
	return PNFS_ATTEMPTED;
}
