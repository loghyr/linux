// SPDX-License-Identifier: GPL-2.0
/*
 * CHUNK_FINALIZE and CHUNK_COMMIT dispatch machinery for the pNFS
 * Flexfile Version 2 layout driver.
 *
 * This file adds the async rpc_call_ops (prepare / done / release
 * triplet) and per-mirror dispatch entry points that the writeback
 * chain hooks into the post-CHUNK_WRITE lifecycle sequence.
 *
 * The dispatch shape is deliberately narrower than the CHUNK_WRITE
 * dispatch machinery in flexfilesv2_write.c: FINALIZE and COMMIT
 * are pure lifecycle ops -- no bulk payload on either the send or
 * receive side, no pgio_header-driven completion chain to preserve,
 * no RESEND_MDS branch (the writeback path has already committed to
 * the DS by the time FINALIZE fires).  The dispatch here ships one
 * op per mirror and reports success/failure back to the caller via
 * a single completion callback.
 *
 * The FINALIZE -> COMMIT sequencing (issue COMMIT only after
 * FINALIZE succeeds on the mirror; compare writeverfs to detect a
 * DS reboot between the two ops) is the concern of the writeback
 * chain in a later commit; this file just gives that chain the
 * primitives it needs.
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 */

#include <linux/module.h>
#include <linux/nfs4.h>
#include <linux/nfs_common.h>
#include <linux/nfs_fs.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/sunrpc/sched.h>

#include "../internal.h"
#include "../iostat.h"
#include "../nfs4_fs.h"
#include "../pnfs.h"
#include "flexfilesv2.h"
#include "flexfilesv2_xdr_chunk.h"

/* Forward declarations for the wb-chain callbacks. */
static void
ffv2_chunk_wb_finalize_done(void *arg, int status,
			    const nfs4_verifier *wv);
static void
ffv2_chunk_wb_commit_done(void *arg, int status,
			  const nfs4_verifier *wv);
static void ffv2_chunk_wb_finish(struct ffv2_chunk_wb_ctx *wb, int status);
static void ffv2_deferred_drain_clear_groups(
		struct ffv2_deferred_drain *drain);

bool ffv2_deferred_pending_matches_drain(
		const struct ffv2_deferred_drain *drain,
		const struct ffv2_pending_chunk *pending)
{
	if (!drain || !drain->data || !pending)
		return false;
	return pending->lseg == drain->lseg &&
		pending->dreq == drain->data->dreq &&
		pending->commit_bucket == drain->data->ds_commit_index &&
		READ_ONCE(pending->state) == FFV2_PENDING_DEFERRED;
}
EXPORT_SYMBOL_GPL(ffv2_deferred_pending_matches_drain);

static bool
ffv2_pending_drain_identity(const struct ffv2_deferred_drain *drain,
			    const struct ffv2_pending_chunk *pending)
{
	if (!drain || !drain->data || !pending)
		return false;
	return pending->lseg == drain->lseg &&
		pending->dreq == drain->data->dreq;
}

/*
 * The generic commit list selects pages by the data-shard bucket.  A
 * deferred stripe's sibling shards belong to other DS buckets, but remain
 * part of the same cohort and must be claimed with the selected data pages.
 */
static bool
ffv2_deferred_cohort_pending_matches_drain(
		const struct ffv2_deferred_drain *drain,
		const struct ffv2_pending_chunk *pending)
{
	return ffv2_pending_drain_identity(drain, pending) &&
		READ_ONCE(pending->state) == FFV2_PENDING_DEFERRED;
}

bool ffv2_deferred_finalize_verifier_matches(
		struct ffv2_pending_chunk * const *pending, unsigned int count,
		const nfs4_verifier *writeverf)
{
	unsigned int i;

	if (!count || !writeverf)
		return false;
	for (i = 0; i < count; i++)
		if (memcmp(writeverf, &pending[i]->writeverf,
			   sizeof(*writeverf)))
			return false;
	return true;
}
EXPORT_SYMBOL_GPL(ffv2_deferred_finalize_verifier_matches);

bool ffv2_deferred_commit_verifier_matches(
		struct ffv2_pending_chunk * const *pending, unsigned int count,
		const nfs4_verifier *writeverf)
{
	unsigned int i;

	if (!count || !writeverf)
		return false;
	for (i = 0; i < count; i++)
		if (memcmp(writeverf, &pending[i]->finalize_writeverf,
			   sizeof(*writeverf)))
			return false;
	return true;
}
EXPORT_SYMBOL_GPL(ffv2_deferred_commit_verifier_matches);

/* ------------------------------------------------------------------ */
/* CHUNK_FINALIZE dispatch                                            */
/* ------------------------------------------------------------------ */

/*
 * Dispatch wrapper: wire args/res + the caller's completion
 * context.  The caller's ffv2_chunk_lifecycle_ctx is COPIED
 * into the wrapper at dispatch time (small struct; avoids the
 * caller having to keep the ctx alive across async
 * completion).  The complete callback + complete_arg are
 * invoked from the release-cb exactly once.
 */
struct ffv2_chunk_finalize_dispatch {
	struct ffv2_chunk_finalize_data	wire;
	struct ffv2_chunk_lifecycle_ctx	ctx;
	/*
	 * NFS4ERR_DELAY backoff counter, bumped by
	 * ffv2_chunk_lifecycle_delay_retry before each rpc_delay +
	 * rpc_restart_call_prepare; capped at
	 * FFV2_CHUNK_LIFECYCLE_MAX_DELAY_ATTEMPTS.
	 */
	u32				retry_attempts;
	/*
	 * Own the rpc_task rather than letting rpc_new_task allocate
	 * one.  See ffv2_chunk_finalize_dispatch_one_mirror for why
	 * that allocation cannot be allowed to fail here.
	 */
	struct rpc_task			task;
	/*
	 * Snapshot of task->tk_status captured at the tail of
	 * call_done, so release-cb can propagate the exact errno
	 * (transport failure, per-chunk NFS4ERR_*, etc.) without
	 * re-deriving from wire fields.  rpc_release's signature
	 * gives no rpc_task pointer, so we save the status here
	 * while it's still accessible.
	 */
	int				rpc_status;
};

/*
 * Fold a reply's status array into one errno.
 *
 * The array is ONE STATUS PER OWNER, not per chunk.  cfa_offset +
 * cfa_count give the chunk RANGE; cfa_chunks<> lists which owners to
 * transition within it, and the data server returns one status per
 * entry of that list (it loops over cfa_chunks_len calling
 * chunk_store_transition with the whole range each time).  So the
 * expected length is the owner count -- currently 1, hard-coded by
 * the encoder -- and does NOT grow when the range is batched.
 *
 * A length that does not match describes a different operation than
 * the one we issued; treat it as an op-shape violation rather than
 * guessing at it.
 *
 * First failure wins.  A later one adds nothing the first did not,
 * and the first is the one with a plausible causal story (the same
 * rule ffv2_stripe_write_set_status applies across shards).
 */
static int ffv2_chunk_lifecycle_fold_status(u32 nstatus, const u32 *status,
					    u32 expected)
{
	u32 i;

	if (nstatus != expected)
		return -EPROTO;
	for (i = 0; i < nstatus; i++)
		if (status[i] != NFS4_OK)
			return nfs4_stat_to_errno(status[i]);
	return 0;
}

/*
 * NFS4ERR_DELAY on a lifecycle op: back off and resend the same
 * request.  Unlike CHUNK_WRITE there is no guard to refresh -- neither
 * FINALIZE nor COMMIT carries one -- so a delay here is the data
 * server asking us to come back, not a compare-and-swap rejection.
 *
 * Returns true when the retry is scheduled and the caller must return
 * at once, false when the attempt budget is spent and the caller
 * should record the delay as this shard's outcome.
 *
 * MUST use rpc_restart_call_prepare, not rpc_restart_call: the caller
 * has already run nfs4_sequence_done and freed the session slot, so
 * only the _prepare variant re-runs .rpc_call_prepare and acquires a
 * fresh one.  Restarting at call_start would encode a freed slot and
 * corrupt the slot table.  Same reasoning as
 * ffv2_chunk_read_delay_retry.
 *
 * Because the task restarts rather than completes, its .rpc_release
 * does not fire, so the writeback chain's accounting is untouched and
 * the completion callback still runs exactly once.
 */
static bool ffv2_chunk_lifecycle_delay_retry(struct rpc_task *task,
					     u32 *attempts)
{
	unsigned long delay_ms;

	if (++*attempts > FFV2_CHUNK_LIFECYCLE_MAX_DELAY_ATTEMPTS)
		return false;
	delay_ms = min_t(unsigned long,
			 *attempts * FFV2_CHUNK_LIFECYCLE_DELAY_BASE_MS,
			 FFV2_CHUNK_LIFECYCLE_DELAY_CAP_MS);
	rpc_delay(task, msecs_to_jiffies(delay_ms));
	rpc_restart_call_prepare(task);
	return true;
}

/*
 * .rpc_call_prepare: allocate a session slot on the DS's
 * session.  Same pattern as ffv2_chunk_write_prepare in
 * flexfilesv2_write.c and ffv2_chunk_read prepare-cb.
 * nfs4_setup_sequence internally calls rpc_call_start when a
 * slot is granted; on wait it reschedules on slot_tbl_waitq.
 * The caller MUST NOT invoke rpc_call_start itself.
 */
static void ffv2_chunk_finalize_prepare(struct rpc_task *task, void *data)
{
	struct ffv2_chunk_finalize_dispatch *d = data;

	nfs4_setup_sequence(d->ctx.ds_clp, &d->wire.seq_args,
			    &d->wire.res.seq_res, task);
}

/*
 * .rpc_call_done: return the session slot first, and stop if the
 * sequence layer restarted the call (the CHUNK_FINALIZE decoder
 * guarantees sr_status is populated on every exit path via the
 * sr_status = 1 sentinel; missing the slot return leaks slots on
 * rpc_exit and wedges the session).  Then classify the outcome so
 * the release-cb sees a coherent task->tk_status:
 *
 *   - task->tk_status != 0: RPC-time failure, transport /
 *     session / etc.  Propagate as-is.
 *   - the reply's statuses, folded by
 *     ffv2_chunk_lifecycle_fold_status: one entry per OWNER we
 *     listed, not per chunk in the range.  A length that does not
 *     match is an op-shape violation (-EPROTO); otherwise the first
 *     non-NFS4_OK entry wins as its mapped errno.
 *   - happy path: task->tk_status left at 0, writeverf held
 *     in res->writeverf for the release-cb to forward.
 */
static void ffv2_chunk_finalize_call_done(struct rpc_task *task, void *data)
{
	struct ffv2_chunk_finalize_dispatch *d = data;
	struct ffv2_chunk_finalize_res *res = &d->wire.res;

	/*
	 * Stop if the sequence layer restarted the call: it clears
	 * tk_status, so the shape check below would read an undecoded
	 * reply, see nstatus == 0 and snapshot -EPROTO as this shard's
	 * outcome.
	 */
	if (!nfs4_sequence_done(task, &d->wire.res.seq_res))
		return;

	if (task->tk_status == -NFS4ERR_DELAY &&
	    ffv2_chunk_lifecycle_delay_retry(task, &d->retry_attempts))
		return;

	if (task->tk_status == 0)
		task->tk_status = ffv2_chunk_lifecycle_fold_status(
			res->nstatus, res->status, d->wire.args.nowners);

	/* Snapshot for the release-cb, which has no rpc_task
	 * access.  Preserves transport-level errnos
	 * (-ETIMEDOUT, -ECONNREFUSED, -EIO) that a wire-field
	 * re-derivation would collapse to -EREMOTEIO or -EPROTO.
	 */
	d->rpc_status = task->tk_status;
}

/*
 * .rpc_release: invoke the caller's completion callback (once)
 * with the final status and, on success, a pointer to the
 * DS's writeverf.  The writeverf pointer is valid ONLY until
 * this function returns -- the caller MUST copy the bytes if
 * it needs them (e.g., to compare against the sibling COMMIT's
 * writeverf later).
 *
 * The dispatch does NOT release the ds_clp reference: the
 * caller retains ownership of ds_clp for the lifetime of the
 * dispatch (matches ffv2_chunk_lifecycle_ctx's documented
 * contract at flexfilesv2_xdr_chunk.h).
 */
static void ffv2_chunk_finalize_release(void *data)
{
	struct ffv2_chunk_finalize_dispatch *d = data;
	const nfs4_verifier *wv = NULL;

	/* rpc_status was snapshotted from task->tk_status at the
	 * tail of call_done -- covers the full classification
	 * (RPC-transport errno, per-chunk NFS4ERR_*, op-shape
	 * -EPROTO).  Only forward the writeverf on true success.
	 */
	if (d->rpc_status == 0)
		wv = &d->wire.res.writeverf;

	d->ctx.complete(d->ctx.complete_arg, d->rpc_status, wv);
	kfree(d);
}

static const struct rpc_call_ops ffv2_chunk_finalize_call_ops = {
	.rpc_call_prepare	= ffv2_chunk_finalize_prepare,
	.rpc_call_done		= ffv2_chunk_finalize_call_done,
	.rpc_release		= ffv2_chunk_finalize_release,
};

int ffv2_chunk_finalize_dispatch_one_mirror(
	struct ffv2_chunk_lifecycle_ctx *ctx,
	const struct cred *cred,
	const struct nfs_fh *fh,
	const nfs4_stateid *stateid,
	u64 offset, u32 count,
	const struct chunk_owner4 *owners, u32 nowners)
{
	struct ffv2_chunk_finalize_dispatch *d;
	struct rpc_message msg = {
		.rpc_proc = &ffv2_chunk_finalize_procinfo,
		.rpc_cred = cred,
	};
	struct rpc_task_setup task_setup = {
		.rpc_client	= NULL,	/* set from ds_clp below */
		.rpc_message	= &msg,
		.callback_ops	= &ffv2_chunk_finalize_call_ops,
		/*
		 * RPC_TASK_SOFT | RPC_TASK_SOFTCONN matches plain-NFSv4.1
		 * COMMIT (see nfs_initiate_commit).  SOFTCONN alone fails
		 * only on connection-establishment errors; on an
		 * established transport that then hangs, the RPC would
		 * retry indefinitely and the completion callback would
		 * never fire -- a ds_clp leak by construction, since the
		 * caller retains the ref pending the callback (see the
		 * ffv2_chunk_lifecycle_ctx header contract).  SOFT
		 * bounds the retry storm and lets the caller decide
		 * whether to reissue.
		 */
		.flags		= RPC_TASK_ASYNC | RPC_TASK_SOFTCONN |
				  RPC_TASK_SOFT,
	};
	struct rpc_task *task;

	if (WARN_ON_ONCE(!ctx || !ctx->ds_clp || !ctx->complete))
		return -EINVAL;
	/*
	 * count is the chunk RANGE, and it is not bounded by the
	 * reply arrays: those carry one status per OWNER, and the
	 * encoder sends a single owner.  A zero range is still
	 * meaningless, so reject only that.
	 */
	if (WARN_ON_ONCE(count == 0))
		return -EINVAL;
	/*
	 * nowners bounds the reply's status array, which IS sized
	 * FFV2_MAX_CHUNKS_PER_OP -- unlike the range above.
	 */
	if (WARN_ON_ONCE(nowners == 0 ||
			 nowners > FFV2_MAX_CHUNKS_PER_OP))
		return -EINVAL;

	d = kzalloc(sizeof(*d), GFP_NOFS);
	if (!d)
		return -ENOMEM;

	d->ctx = *ctx;
	d->wire.fh = *fh;
	d->wire.args.stateid = *stateid;
	d->wire.args.offset = offset;
	d->wire.args.count = count;
	d->wire.args.nowners = nowners;
	memcpy(d->wire.args.owners, owners,
	       nowners * sizeof(*owners));
	/* seq_res.sr_status sentinel: 1 == RPC-level error, matches
	 * nfs41_sequence_res_init at nfs4proc.c:1019-1024.  Set
	 * before task submission so a decoder that never runs
	 * still yields the right route in the release-cb.
	 */
	d->wire.res.seq_res.sr_status = 1;
	/*
	 * Initialize seq_res.sr_slot_ops from ctx->ds_clp->cl_mvops.
	 * Without this the call_done's nfs4_sequence_done would
	 * dereference a NULL sr_slot_ops (offset 0 of struct
	 * nfs4_sequence_res) and page-fault on offset +8.  Same
	 * defect and fix as ffv2_chunk_write_dispatch_one_mirror.
	 */
	nfs4_init_sequence(ctx->ds_clp, &d->wire.seq_args,
			   &d->wire.res.seq_res, 0, 0);

	/*
	 * argp and resp must land on the structs whose first member is
	 * the SEQUENCE args / res -- nfs41_assign_slot casts them
	 * directly when it hands a freed slot to a parked task.  Passing
	 * the dispatch wrapper for both, as this did, put neither at
	 * offset 0: the handoff scribbled the slot pointer over
	 * args.stateid and the task never saw the slot it was given.
	 */
	msg.rpc_argp = &d->wire;
	msg.rpc_resp = &d->wire.res;
	task_setup.rpc_client = ctx->ds_clp->cl_rpcclient;
	task_setup.callback_data = d;
	/*
	 * Supplying the task is what makes the IS_ERR arm below safe.
	 * With task_setup.task NULL, rpc_new_task() allocates one, and
	 * on allocation failure it runs rpc_release_calldata() -- our
	 * release callback -- before returning ERR_PTR.  The callback
	 * would then report success to the caller (rpc_status is still
	 * the kzalloc'd 0, because call_done never ran) with a zeroed
	 * writeverf, and free the wrapper that the arm below frees
	 * again.  An embedded task cannot fail to allocate, so the arm
	 * stays genuinely dead.
	 */
	task_setup.task = &d->task;

	task = rpc_run_task(&task_setup);
	if (IS_ERR(task)) {
		kfree(d);
		return PTR_ERR(task);
	}
	rpc_put_task(task);
	return 0;
}

/* ------------------------------------------------------------------ */
/* CHUNK_COMMIT dispatch                                              */
/* ------------------------------------------------------------------ */

struct ffv2_commit_batch_item {
	struct ffv2_commit_batch *batch;
	struct ffv2_pending_chunk *pending[FFV2_MAX_CHUNKS_PER_OP];
	struct chunk_owner4 owners[FFV2_MAX_CHUNKS_PER_OP];
	u64 offset;
	u32 count;
	u32 nowners;
};

struct ffv2_commit_batch {
	struct kref ref;
	struct ffv2_commit_aggregate *agg;
	atomic_t pending;
	int status;
	unsigned int count;
	struct ffv2_commit_batch_item items[];
};

static void ffv2_commit_batch_release(struct kref *ref)
{
	struct ffv2_commit_batch *batch =
		container_of(ref, struct ffv2_commit_batch, ref);
	kfree(batch);
}

static void ffv2_commit_batch_done(void *arg, int status,
					const nfs4_verifier *wv)
{
	struct ffv2_commit_batch_item *item = arg;
	unsigned int i;
	bool last;

	if (status)
		cmpxchg(&item->batch->status, 0, status);
	else if (!wv)
		cmpxchg(&item->batch->status, 0, -EPROTO);
	else {
		for (i = 0; i < item->nowners; i++) {
			struct ffv2_pending_chunk *pending = item->pending[i];

			if (memcmp(wv, &pending->finalize_writeverf,
				   sizeof(*wv))) {
				cmpxchg(&item->batch->status, 0, -EPROTO);
				continue;
			}
			memcpy(&pending->commit_writeverf, wv,
			       sizeof(pending->commit_writeverf));
			set_bit(FFV2_PENDING_HAVE_COMMIT_VERF,
				&pending->flags);
		}
	}
	last = atomic_dec_and_test(&item->batch->pending);
	if (last)
		item->batch->agg->dispatch_batch = NULL;
	if (last)
		refcount_dec(&item->batch->agg->ref);
	if (last && item->batch->agg->dispatch_done)
		item->batch->agg->dispatch_done(
			item->batch->agg->dispatch_done_owner,
			item->batch->status);
	kref_put(&item->batch->ref, ffv2_commit_batch_release);
}

static void ffv2_commit_batch_sync_done(struct ffv2_commit_batch_item *item,
						int status)
{
	bool last;

	cmpxchg(&item->batch->status, 0, status);
	last = atomic_dec_and_test(&item->batch->pending);
	if (last)
		refcount_dec(&item->batch->agg->ref);
	if (last && item->batch->agg->dispatch_done)
		item->batch->agg->dispatch_done(
			item->batch->agg->dispatch_done_owner,
			item->batch->status);
}

int ffv2_commit_aggregate_dispatch(struct ffv2_commit_aggregate *agg)
{
	struct ffv2_commit_chunk *chunk;
	struct ffv2_commit_batch *batch;
	unsigned int count = 0, i = 0, j;
	u64 end;

	if (!agg || list_empty(&agg->chunks))
		return -EINVAL;
	if (WARN_ON_ONCE(!agg->dispatch_done))
		return -EINVAL;
	list_for_each_entry(chunk, &agg->chunks, list)
		count++;
	list_for_each_entry(chunk, &agg->chunks, list) {
		struct ffv2_pending_chunk *pending = chunk->pending;

		if (!pending->count ||
		    check_add_overflow(pending->offset,
				       (u64)pending->count, &end))
			return -EOVERFLOW;
	}
	batch = kzalloc(struct_size(batch, items, count), GFP_NOFS);
	if (!batch)
		return -ENOMEM;
	kref_init(&batch->ref);
	batch->agg = agg;
	batch->count = count;
	atomic_set(&batch->pending, count);
	batch->status = 0;
	refcount_inc(&agg->ref);
	agg->dispatch_batch = batch;
	list_for_each_entry(chunk, &agg->chunks, list) {
		struct ffv2_pending_chunk *pending = chunk->pending;
		struct ffv2_commit_batch_item *item = NULL;

		end = pending->offset + pending->count;

		for (j = 0; j < i; j++) {
			struct ffv2_pending_chunk *first = batch->items[j].pending[0];
			u64 item_end = batch->items[j].offset +
				batch->items[j].count;
			u64 new_start = min(batch->items[j].offset,
					    pending->offset);
			u64 new_end = max(item_end, end);

			if (batch->items[j].nowners == FFV2_MAX_CHUNKS_PER_OP ||
			    first->ds_clp != pending->ds_clp ||
			    memcmp(&first->fh, &pending->fh, sizeof(first->fh)) ||
			    memcmp(&first->stateid, &pending->stateid,
				   sizeof(first->stateid)) ||
			    new_end - new_start > U32_MAX)
				continue;
			item = &batch->items[j];
			break;
		}
		if (!item)
			item = &batch->items[i++];
		if (!item->nowners) {
			item->batch = batch;
			item->offset = pending->offset;
			item->count = pending->count;
		} else {
			u64 item_end = item->offset + item->count;
			u64 new_start = min(item->offset, pending->offset);
			u64 new_end = max(item_end, end);

			item->offset = new_start;
			item->count = new_end - new_start;
		}
		item->pending[item->nowners] = pending;
		item->owners[item->nowners] = pending->owner;
		item->nowners++;
	}
	batch->count = i;
	atomic_set(&batch->pending, i);
	for (i = 0; i < batch->count; i++) {
		struct ffv2_commit_batch_item *item = &batch->items[i];
		struct ffv2_chunk_lifecycle_ctx ctx = {
			.ds_clp = item->pending[0]->ds_clp,
			.lseg = item->pending[0]->lseg,
			.complete_arg = item,
			.complete = ffv2_commit_batch_done,
		};

		kref_get(&batch->ref);
		if (ffv2_chunk_commit_dispatch_one_mirror(&ctx,
				item->pending[0]->cred, &item->pending[0]->fh,
				&item->pending[0]->stateid, item->offset,
				item->count, item->owners, item->nowners)) {
			ffv2_commit_batch_sync_done(item, -EIO);
			kref_put(&batch->ref, ffv2_commit_batch_release);
		}
	}
	kref_put(&batch->ref, ffv2_commit_batch_release);
	return 0;
}
EXPORT_SYMBOL_GPL(ffv2_commit_aggregate_dispatch);

void ffv2_commit_aggregate_complete(void *owner, int status)
{
	struct nfs_commit_data *data = owner;
	struct ffv2_commit_aggregate *agg = data->private;
	struct ffv2_commit_chunk *chunk;

	if (!status)
		list_for_each_entry(chunk, &agg->chunks, list)
			if (!ffv2_pending_chunk_verifiers_complete(chunk->pending)) {
				status = -EPROTO;
				break;
			}

	data->task.tk_status = status;
	ffv2_commit_release_pages(data);
}
EXPORT_SYMBOL_GPL(ffv2_commit_aggregate_complete);



/*
 * Wrapper + call-ops for CHUNK_COMMIT.  Structurally identical to
 * the FINALIZE dispatch above (same one-op-per-mirror, same
 * completion-callback shape, same single-owner-per-op interop
 * invariant).  Duplicated rather than aliased with FINALIZE for the
 * same reason the wire encoders / decoders are duplicated: future
 * asymmetry (COMMIT gaining a durability-hint arg, FINALIZE losing
 * writeverf, etc.) can diverge without a rename churn on shared
 * helpers.
 */
struct ffv2_chunk_commit_dispatch {
	struct ffv2_chunk_commit_data	wire;
	struct ffv2_chunk_lifecycle_ctx	ctx;
	u32				retry_attempts;	/* see FINALIZE wrapper */
	struct rpc_task			task;		/* see FINALIZE wrapper */
	int				rpc_status;	/* see FINALIZE wrapper */
};

static void ffv2_chunk_commit_prepare(struct rpc_task *task, void *data)
{
	struct ffv2_chunk_commit_dispatch *d = data;

	nfs4_setup_sequence(d->ctx.ds_clp, &d->wire.seq_args,
			    &d->wire.res.seq_res, task);
}

static void ffv2_chunk_commit_call_done(struct rpc_task *task, void *data)
{
	struct ffv2_chunk_commit_dispatch *d = data;
	struct ffv2_chunk_commit_res *res = &d->wire.res;

	/* Same restart bail-out as the FINALIZE call_done above. */
	if (!nfs4_sequence_done(task, &d->wire.res.seq_res))
		return;

	if (task->tk_status == -NFS4ERR_DELAY &&
	    ffv2_chunk_lifecycle_delay_retry(task, &d->retry_attempts))
		return;

	if (task->tk_status == 0)
		task->tk_status = ffv2_chunk_lifecycle_fold_status(
			res->nstatus, res->status, d->wire.args.nowners);
	d->rpc_status = task->tk_status;
}

static void ffv2_chunk_commit_release(void *data)
{
	struct ffv2_chunk_commit_dispatch *d = data;
	const nfs4_verifier *wv = NULL;

	if (d->rpc_status == 0)
		wv = &d->wire.res.writeverf;
	d->ctx.complete(d->ctx.complete_arg, d->rpc_status, wv);
	kfree(d);
}

static const struct rpc_call_ops ffv2_chunk_commit_call_ops = {
	.rpc_call_prepare	= ffv2_chunk_commit_prepare,
	.rpc_call_done		= ffv2_chunk_commit_call_done,
	.rpc_release		= ffv2_chunk_commit_release,
};

int ffv2_chunk_commit_dispatch_one_mirror(
	struct ffv2_chunk_lifecycle_ctx *ctx,
	const struct cred *cred,
	const struct nfs_fh *fh,
	const nfs4_stateid *stateid,
	u64 offset, u32 count,
	const struct chunk_owner4 *owners, u32 nowners)
{
	struct ffv2_chunk_commit_dispatch *d;
	struct rpc_message msg = {
		.rpc_proc = &ffv2_chunk_commit_procinfo,
		.rpc_cred = cred,
	};
	struct rpc_task_setup task_setup = {
		.rpc_client	= NULL,	/* set from ds_clp below */
		.rpc_message	= &msg,
		.callback_ops	= &ffv2_chunk_commit_call_ops,
		/*
		 * RPC_TASK_SOFT | RPC_TASK_SOFTCONN matches plain-NFSv4.1
		 * COMMIT (see nfs_initiate_commit).  SOFTCONN alone fails
		 * only on connection-establishment errors; on an
		 * established transport that then hangs, the RPC would
		 * retry indefinitely and the completion callback would
		 * never fire -- a ds_clp leak by construction, since the
		 * caller retains the ref pending the callback (see the
		 * ffv2_chunk_lifecycle_ctx header contract).  SOFT
		 * bounds the retry storm and lets the caller decide
		 * whether to reissue.
		 */
		.flags		= RPC_TASK_ASYNC | RPC_TASK_SOFTCONN |
				  RPC_TASK_SOFT,
	};
	struct rpc_task *task;

	if (WARN_ON_ONCE(!ctx || !ctx->ds_clp || !ctx->complete))
		return -EINVAL;
	/*
	 * count is the chunk RANGE, and it is not bounded by the
	 * reply arrays: those carry one status per OWNER, and the
	 * encoder sends a single owner.  A zero range is still
	 * meaningless, so reject only that.
	 */
	if (WARN_ON_ONCE(count == 0))
		return -EINVAL;
	/*
	 * nowners bounds the reply's status array, which IS sized
	 * FFV2_MAX_CHUNKS_PER_OP -- unlike the range above.
	 */
	if (WARN_ON_ONCE(nowners == 0 ||
			 nowners > FFV2_MAX_CHUNKS_PER_OP))
		return -EINVAL;

	d = kzalloc(sizeof(*d), GFP_NOFS);
	if (!d)
		return -ENOMEM;

	d->ctx = *ctx;
	d->wire.fh = *fh;
	d->wire.args.stateid = *stateid;
	d->wire.args.offset = offset;
	d->wire.args.count = count;
	d->wire.args.nowners = nowners;
	memcpy(d->wire.args.owners, owners,
	       nowners * sizeof(*owners));
	d->wire.res.seq_res.sr_status = 1;
	/*
	 * Initialize sr_slot_ops -- same defect and fix as the
	 * FINALIZE dispatch above.
	 */
	nfs4_init_sequence(ctx->ds_clp, &d->wire.seq_args,
			   &d->wire.res.seq_res, 0, 0);

	msg.rpc_argp = &d->wire;
	msg.rpc_resp = &d->wire.res;
	task_setup.rpc_client = ctx->ds_clp->cl_rpcclient;
	task_setup.callback_data = d;
	/* Embedded task, for the reason given in the FINALIZE dispatch. */
	task_setup.task = &d->task;

	task = rpc_run_task(&task_setup);
	if (IS_ERR(task)) {
		kfree(d);
		return PTR_ERR(task);
	}
	rpc_put_task(task);
	return 0;
}

struct ffv2_chunk_rollback_dispatch {
	struct ffv2_chunk_rollback_data	wire;
	struct ffv2_chunk_lifecycle_ctx	ctx;
	u32				retry_attempts;
	struct rpc_task			task;
	int				rpc_status;
};

static void ffv2_chunk_rollback_prepare(struct rpc_task *task, void *data)
{
	struct ffv2_chunk_rollback_dispatch *d = data;

	nfs4_setup_sequence(d->ctx.ds_clp, &d->wire.seq_args,
			    &d->wire.res.seq_res, task);
}

static void ffv2_chunk_rollback_call_done(struct rpc_task *task, void *data)
{
	struct ffv2_chunk_rollback_dispatch *d = data;
	struct ffv2_chunk_rollback_res *res = &d->wire.res;
	u32 i;

	if (!nfs4_sequence_done(task, &res->seq_res))
		return;
	if (task->tk_status == -NFS4ERR_DELAY &&
	    ffv2_chunk_lifecycle_delay_retry(task, &d->retry_attempts))
		return;
	if (!task->tk_status) {
		if (res->nstatus != d->wire.args.nowners) {
			task->tk_status = -EPROTO;
		} else {
			for (i = 0; i < res->nstatus; i++) {
				if (res->status[i] == NFS4_OK)
					continue;
				task->tk_status =
					nfs4_stat_to_errno(res->status[i]);
				break;
			}
		}
	}
	d->rpc_status = task->tk_status;
}

static void ffv2_chunk_rollback_release(void *data)
{
	struct ffv2_chunk_rollback_dispatch *d = data;
	const nfs4_verifier *writeverf = NULL;

	if (!d->rpc_status)
		writeverf = &d->wire.res.writeverf;
	d->ctx.complete(d->ctx.complete_arg, d->rpc_status, writeverf);
	kfree(d);
}

static const struct rpc_call_ops ffv2_chunk_rollback_call_ops = {
	.rpc_call_prepare	= ffv2_chunk_rollback_prepare,
	.rpc_call_done		= ffv2_chunk_rollback_call_done,
	.rpc_release		= ffv2_chunk_rollback_release,
};

int
ffv2_chunk_rollback_dispatch_one_mirror(struct ffv2_chunk_lifecycle_ctx *ctx,
					const struct cred *cred,
	const struct nfs_fh *fh,
	const nfs4_stateid *stateid,
	u64 offset, u32 count,
	const struct chunk_owner4 *owners, u32 nowners)
{
	struct ffv2_chunk_rollback_dispatch *d;
	struct rpc_message msg = {
		.rpc_proc = &ffv2_chunk_rollback_procinfo,
		.rpc_cred = cred,
	};
	struct rpc_task_setup task_setup = {
		.rpc_message	= &msg,
		.callback_ops	= &ffv2_chunk_rollback_call_ops,
		.flags		= RPC_TASK_ASYNC | RPC_TASK_SOFTCONN |
				  RPC_TASK_SOFT,
	};
	struct rpc_task *task;

	if (WARN_ON_ONCE(!ctx || !ctx->ds_clp || !ctx->complete ||
			 !count || !nowners ||
			 nowners > FFV2_MAX_CHUNKS_PER_OP))
		return -EINVAL;
	d = kzalloc_obj(*d, GFP_NOFS);
	if (!d)
		return -ENOMEM;
	d->ctx = *ctx;
	d->wire.fh = *fh;
	d->wire.args.stateid = *stateid;
	d->wire.args.offset = offset;
	d->wire.args.count = count;
	d->wire.args.nowners = nowners;
	memcpy(d->wire.args.owners, owners, nowners * sizeof(*owners));
	d->wire.res.seq_res.sr_status = 1;
	nfs4_init_sequence(ctx->ds_clp, &d->wire.seq_args,
			   &d->wire.res.seq_res, 0, 0);
	msg.rpc_argp = &d->wire;
	msg.rpc_resp = &d->wire.res;
	task_setup.rpc_client = ctx->ds_clp->cl_rpcclient;
	task_setup.callback_data = d;
	task_setup.task = &d->task;
	task = rpc_run_task(&task_setup);
	if (IS_ERR(task)) {
		kfree(d);
		return PTR_ERR(task);
	}
	rpc_put_task(task);
	return 0;
}

static void ffv2_deferred_drain_release(struct kref *ref)
{
	struct ffv2_deferred_drain *drain =
		container_of(ref, struct ffv2_deferred_drain, ref);

	kfree(drain);
}

void ffv2_deferred_drain_put(struct ffv2_deferred_drain *drain)
{
	kref_put(&drain->ref, ffv2_deferred_drain_release);
}

static void ffv2_deferred_pending_drop_requests(
		struct ffv2_pending_chunk *pending)
{
	struct ffv2_pending_req *request, *tmp;

	list_for_each_entry_safe(request, tmp, &pending->requests, list) {
		list_del(&request->list);
		put_nfs_open_context(request->context);
		nfs_release_request(request->req);
		kfree(request);
	}
}

static void
ffv2_deferred_cohort_release(struct ffv2_deferred_cohort *cohort)
{
	if (!cohort->stripe_ref || !cohort->stripe_put)
		return;
	cohort->stripe_put(cohort->stripe_owner);
	cohort->stripe_ref = NULL;
	cohort->stripe_put = NULL;
	cohort->stripe_owner = NULL;
}

static void ffv2_deferred_pending_finish(struct ffv2_pending_chunk *pending,
					 int status)
{
	struct ffv2_stripe_pending_view view;

	ffv2_stripe_pending_view(pending->sw, &view);
	spin_lock(view.pending_lock);
	ffv2_deferred_pending_drop_requests(pending);
	if (!status)
		pending->state = FFV2_PENDING_LIFECYCLE_DONE;
	spin_unlock(view.pending_lock);
	if (status)
		ffv2_pending_chunk_abort(pending);
	ffv2_pending_chunk_free(pending);
}

static void ffv2_deferred_drain_release_pages(
		struct ffv2_deferred_drain *drain)
{
	struct ffv2_deferred_cohort *cohort;
	struct nfs_page *req;
	struct nfs_direct_req *dreq = drain->data->dreq;
	int status = drain->status;

	list_for_each_entry(cohort, &drain->cohorts, list) {
		struct ffv2_stripe_pending_view view;
		struct ffv2_pending_chunk *pending;

		ffv2_stripe_pending_view(cohort->sw, &view);
		spin_lock(view.pending_lock);
		list_for_each_entry(pending, view.pending_chunks, stripe_list)
			ffv2_deferred_pending_drop_requests(pending);
		spin_unlock(view.pending_lock);
	}

	list_for_each_entry(cohort, &drain->cohorts, list) {
		struct ffv2_stripe_pending_view view;
		struct ffv2_pending_chunk *pending, *tmp;

		ffv2_stripe_pending_view(cohort->sw, &view);
		list_for_each_entry_safe(pending, tmp, view.pending_chunks,
					 stripe_list)
			ffv2_deferred_pending_finish(pending, status);
		ffv2_deferred_cohort_release(cohort);
	}

	if (dreq) {
		/*
		 * FFv2 validates each cohort's FINALIZE and COMMIT
		 * verifiers before reaching this point.  The generic direct
		 * completion takes one verifier for all pages, while a bucket
		 * drain may contain several cohorts, so do not hand a mixed
		 * list to that single-verifier check after a successful drain.
		 * On failure, leave the pages for its normal truncation path.
		 */
		if (!status) {
			while (!list_empty(&drain->data->pages)) {
				req = nfs_list_entry(drain->data->pages.next);
				nfs_list_remove_request(req);
				nfs_release_request(req);
				nfs_unlock_and_release_request(req);
			}
		}
		drain->data->task.tk_status = status;
		nfs_direct_commit_complete(drain->data);
		return;
	}

	while (!list_empty(&drain->data->pages)) {
		req = nfs_list_entry(drain->data->pages.next);
		nfs_list_remove_request(req);
		nfs_folio_clear_commit(req);
		if (status) {
			nfs_mark_request_dirty(req);
			set_bit(NFS_CONTEXT_WRITE_SYNC,
				&req->wb_lock_context->open_context->flags);
			atomic_long_inc(&NFS_I(drain->data->inode)->redirtied_pages);
		}
		nfs_inode_remove_request(req);
		nfs_unlock_and_release_request(req);
	}
}

static void ffv2_deferred_drain_finish(struct ffv2_deferred_drain *drain)
{
	if (atomic_cmpxchg(&drain->finished, 0, 1))
		return;
	if (drain->status)
		pnfs_error_mark_layout_for_return(drain->data->inode,
						  drain->data->lseg);
	ffv2_deferred_drain_release_pages(drain);
	if (!drain->data->dreq)
		nfs_commit_end(drain->mds_cinfo);
	if (drain->data->lseg) {
		pnfs_put_lseg(drain->data->lseg);
		drain->data->lseg = NULL;
	}
	nfs_commitdata_release(drain->data);
	drain->data = NULL;
	ffv2_deferred_drain_clear_groups(drain);
}

bool ffv2_deferred_group_complete(struct ffv2_deferred_drain *drain,
					  struct ffv2_deferred_group *group,
					  int status)
{
	if (group->finished)
		return false;
	group->finished = true;
	if (status)
		cmpxchg(&drain->status, 0, status);
	return atomic_dec_and_test(&drain->pending_ops) &&
		READ_ONCE(drain->launch_done);
}
EXPORT_SYMBOL_GPL(ffv2_deferred_group_complete);

static void ffv2_deferred_group_finish(struct ffv2_deferred_group *group,
					       int status)
{
	struct ffv2_deferred_drain *drain = group->drain;

	if (ffv2_deferred_group_complete(drain, group, status))
		ffv2_deferred_drain_finish(drain);
}

static void ffv2_deferred_group_commit_done(void *arg, int status,
					     const nfs4_verifier *writeverf)
{
	struct ffv2_deferred_group *group = arg;
	struct ffv2_deferred_drain *drain = group->drain;
	unsigned int i;

	if (!status && !writeverf)
		status = -EPROTO;
	if (!status) {
		if (!ffv2_deferred_commit_verifier_matches(group->pending,
							    group->nowners,
							    writeverf))
			status = -EPROTO;
		if (!status) {
			for (i = 0; i < group->nowners; i++) {
				struct ffv2_pending_chunk *pending =
					group->pending[i];

				memcpy(&pending->commit_writeverf, writeverf,
				       sizeof(pending->commit_writeverf));
				set_bit(FFV2_PENDING_HAVE_COMMIT_VERF,
					&pending->flags);
			}
		}
	}
	ffv2_deferred_group_finish(group, status);
	kref_put(&drain->ref, ffv2_deferred_drain_release);
}

static void ffv2_deferred_group_finalize_done(void *arg, int status,
						const nfs4_verifier *writeverf)
{
	struct ffv2_deferred_group *group = arg;
	struct ffv2_deferred_drain *drain = group->drain;
	struct ffv2_chunk_lifecycle_ctx ctx;
	unsigned int i;

	if (status || !writeverf) {
		ffv2_deferred_group_finish(group, status ?: -EPROTO);
		kref_put(&drain->ref, ffv2_deferred_drain_release);
		return;
	}
	if (!ffv2_deferred_finalize_verifier_matches(group->pending,
							 group->nowners, writeverf)) {
		ffv2_deferred_group_finish(group, -EPROTO);
		kref_put(&drain->ref, ffv2_deferred_drain_release);
		return;
	}
	for (i = 0; i < group->nowners; i++) {
		memcpy(&group->pending[i]->finalize_writeverf, writeverf,
		       sizeof(group->pending[i]->finalize_writeverf));
		set_bit(FFV2_PENDING_HAVE_FINALIZE_VERF,
			&group->pending[i]->flags);
	}
	ctx.ds_clp = group->pending[0]->ds_clp;
	ctx.lseg = group->pending[0]->lseg;
	ctx.complete_arg = group;
	ctx.complete = ffv2_deferred_group_commit_done;
	status = ffv2_chunk_commit_dispatch_one_mirror(&ctx,
			group->pending[0]->cred, &group->pending[0]->fh,
			&group->pending[0]->stateid, group->offset, group->count,
			group->owners, group->nowners);
	if (status)
		ffv2_deferred_group_commit_done(group, status, NULL);
}

/*
 * Launch the deferred drain.  A successful call consumes the caller's
 * drain reference; synchronous dispatch failures are folded into group
 * completion.  A nonzero return is pre-launch: the caller still owns
 * drain->data and the drain reference and must release both.
 */
int ffv2_deferred_drain_start(struct ffv2_deferred_drain *drain, int how)
{
	struct ffv2_deferred_group *group;
	unsigned int count = 0;

	(void)how;

	list_for_each_entry(group, &drain->groups, list)
		count++;
	if (WARN_ON_ONCE(!count)) {
		ffv2_deferred_drain_abort(drain);
		return -EAGAIN;
	}
	atomic_set(&drain->pending_ops, count);
	list_for_each_entry(group, &drain->groups, list) {
		struct ffv2_chunk_lifecycle_ctx ctx = {
			.ds_clp = group->pending[0]->ds_clp,
			.lseg = group->pending[0]->lseg,
			.complete_arg = group,
			.complete = ffv2_deferred_group_finalize_done,
		};
		int ret;

		kref_get(&drain->ref);
		ret = ffv2_chunk_finalize_dispatch_one_mirror(&ctx,
				group->pending[0]->cred, &group->pending[0]->fh,
				&group->pending[0]->stateid, group->offset,
				group->count, group->owners, group->nowners);
		if (ret) {
			ffv2_deferred_group_finish(group, ret);
			kref_put(&drain->ref, ffv2_deferred_drain_release);
		}
	}
	WRITE_ONCE(drain->launch_done, true);
	if (!atomic_read(&drain->pending_ops))
		ffv2_deferred_drain_finish(drain);
	kref_put(&drain->ref, ffv2_deferred_drain_release);
	return 0;
}
EXPORT_SYMBOL_GPL(ffv2_deferred_drain_start);

/* ------------------------------------------------------------------ */
/* Writeback chain: FINALIZE -> COMMIT after CHUNK_WRITE              */
/* ------------------------------------------------------------------ */

void ffv2_pending_chunk_free(struct ffv2_pending_chunk *pending)
{
	struct nfs4_ffv2_layout_segment *fls = FFV2_LSEG(pending->lseg);
	struct ffv2_pending_req *p, *tmp;
	bool release_stripe;

	spin_lock(pending->stripe_lock);
	if (WARN_ON_ONCE(READ_ONCE(pending->state) == FFV2_PENDING_RETAINED))
		goto out_unlock;
	release_stripe = pending->state != FFV2_PENDING_IMMEDIATE &&
		pending->stripe_put;
	spin_unlock(pending->stripe_lock);

	list_for_each_entry_safe(p, tmp, &pending->requests, list) {
		list_del(&p->list);
		put_nfs_open_context(p->context);
		nfs_release_request(p->req);
		kfree(p);
	}

	spin_lock(&fls->fls_pending_lock);
	if (test_and_clear_bit(FFV2_PENDING_QUEUED, &pending->flags)) {
		list_del_init(&pending->list);
	}
	spin_unlock(&fls->fls_pending_lock);
	wake_up_all(&fls->fls_ctx_wq);
	spin_lock(pending->stripe_lock);
	list_del_init(&pending->stripe_list);
	spin_unlock(pending->stripe_lock);
	put_cred(pending->cred);
	nfs_put_client(pending->ds_clp);
	if (pending->dreq)
		nfs_direct_req_put(pending->dreq);
	pnfs_put_lseg(pending->lseg);
	if (release_stripe)
		pending->stripe_put(pending->stripe_owner);
	kfree(pending);
	return;

out_unlock:
	spin_unlock(pending->stripe_lock);
}
EXPORT_SYMBOL_GPL(ffv2_pending_chunk_free);

void ffv2_pending_lseg_reclaim(struct nfs4_ffv2_layout_segment *fls)
{
	struct ffv2_pending_chunk *pending, *tmp;
	LIST_HEAD(reclaim);

	spin_lock(&fls->fls_pending_lock);
	list_for_each_entry_safe(pending, tmp, &fls->fls_pending_list, list) {
		bool committing;

		spin_lock(pending->stripe_lock);
		committing = pending->state == FFV2_PENDING_COMMITTING;
		spin_unlock(pending->stripe_lock);
		if (committing)
			continue;
		list_del_init(&pending->list);
		clear_bit(FFV2_PENDING_QUEUED, &pending->flags);
		list_add_tail(&pending->list, &reclaim);
	}
	spin_unlock(&fls->fls_pending_lock);

	list_for_each_entry_safe(pending, tmp, &reclaim, list) {
		list_del_init(&pending->list);
		ffv2_pending_chunk_abort(pending);
		ffv2_pending_chunk_free(pending);
	}

	wait_event(fls->fls_ctx_wq,
		   list_empty_careful(&fls->fls_pending_list));
}
EXPORT_SYMBOL_GPL(ffv2_pending_lseg_reclaim);

void ffv2_pending_chunk_retain(struct ffv2_pending_chunk *pending)
{
	if (WARN_ON_ONCE(!pending->stripe_lock))
		return;
	spin_lock(pending->stripe_lock);
	if (WARN_ON_ONCE(!pending->stripe_ref))
		goto out_unlock;
	if (WARN_ON_ONCE(pending->state != FFV2_PENDING_IMMEDIATE))
		goto out_unlock;
	refcount_inc(pending->stripe_ref);
	pending->state = FFV2_PENDING_RETAINED;
out_unlock:
	spin_unlock(pending->stripe_lock);
}
EXPORT_SYMBOL_GPL(ffv2_pending_chunk_retain);

void ffv2_pending_chunk_defer(struct ffv2_pending_chunk *pending)
{
	if (WARN_ON_ONCE(!pending->stripe_lock))
		return;
	spin_lock(pending->stripe_lock);
	if (WARN_ON_ONCE(pending->state != FFV2_PENDING_RETAINED))
		goto out_unlock;
	pending->state = FFV2_PENDING_DEFERRED;
out_unlock:
	spin_unlock(pending->stripe_lock);
}
EXPORT_SYMBOL_GPL(ffv2_pending_chunk_defer);

void ffv2_pending_chunk_lifecycle_done(struct ffv2_pending_chunk *pending)
{
	if (WARN_ON_ONCE(!pending->stripe_lock))
		return;
	spin_lock(pending->stripe_lock);
	if (WARN_ON_ONCE(pending->state != FFV2_PENDING_RETAINED))
		goto out_unlock;
	pending->state = FFV2_PENDING_LIFECYCLE_DONE;
out_unlock:
	spin_unlock(pending->stripe_lock);
}
EXPORT_SYMBOL_GPL(ffv2_pending_chunk_lifecycle_done);

void ffv2_pending_chunk_abort(struct ffv2_pending_chunk *pending)
{
	bool release_stripe = false;

	if (WARN_ON_ONCE(!pending->stripe_lock))
		return;
	spin_lock(pending->stripe_lock);
	if (pending->state == FFV2_PENDING_RETAINED ||
	    pending->state == FFV2_PENDING_DEFERRED ||
	    pending->state == FFV2_PENDING_COMMITTING) {
		pending->state = FFV2_PENDING_IMMEDIATE;
		release_stripe = true;
	}
	spin_unlock(pending->stripe_lock);
	if (release_stripe && pending->stripe_put)
		pending->stripe_put(pending->stripe_owner);
}
EXPORT_SYMBOL_GPL(ffv2_pending_chunk_abort);

bool ffv2_pending_chunk_verifiers_complete(struct ffv2_pending_chunk *pending)
{
	return test_bit(FFV2_PENDING_HAVE_FINALIZE_VERF, &pending->flags) &&
		test_bit(FFV2_PENDING_HAVE_COMMIT_VERF, &pending->flags) &&
		!memcmp(&pending->finalize_writeverf,
			&pending->commit_writeverf,
			sizeof(pending->finalize_writeverf));
}
EXPORT_SYMBOL_GPL(ffv2_pending_chunk_verifiers_complete);

/* Caller holds fls_pending_lock.  A request must have one owner. */
static unsigned int
ffv2_pending_request_lookup_locked(struct nfs4_ffv2_layout_segment *fls,
					   struct nfs_page *req,
					   struct ffv2_pending_chunk **found)
{
	struct ffv2_pending_chunk *pending;
	struct ffv2_pending_req *p;
	unsigned int count = 0;

	list_for_each_entry(pending, &fls->fls_pending_list, list) {
		if (pending->shard_idx != 0)
			continue;
		list_for_each_entry(p, &pending->requests, list) {
			if (p->req != req)
				continue;
			if (!count)
				*found = pending;
			count++;
		}
	}
	return count;
}

static struct ffv2_deferred_cohort *
ffv2_deferred_cohort_find(struct ffv2_deferred_drain *drain,
				   struct ffv2_stripe_write *sw)
{
	struct ffv2_deferred_cohort *cohort;

	list_for_each_entry(cohort, &drain->cohorts, list)
		if (cohort->sw == sw)
			return cohort;
	return NULL;
}

bool ffv2_deferred_group_matches_pending(
		const struct ffv2_deferred_group *group,
		const struct ffv2_pending_chunk *pending)
{
	const struct ffv2_pending_chunk *first;

	if (!group || !pending || !group->nowners || !group->pending[0])
		return false;
	first = group->pending[0];
	return first->ds_clp == pending->ds_clp &&
		!memcmp(&first->fh, &pending->fh, sizeof(first->fh)) &&
		!memcmp(&first->stateid, &pending->stateid,
			 sizeof(first->stateid));
}
EXPORT_SYMBOL_GPL(ffv2_deferred_group_matches_pending);

int ffv2_deferred_group_extend_range(
		struct ffv2_deferred_group *group,
		const struct ffv2_pending_chunk *pending)
{
	u64 pending_end, group_end, start, end;

	if (!group || !pending)
		return -EINVAL;
	if (check_add_overflow(pending->offset, (u64)pending->count,
				       &pending_end) ||
	    check_add_overflow(group->offset, (u64)group->count,
			       &group_end))
		return -EOVERFLOW;
	start = min(group->offset, pending->offset);
	end = max(group_end, pending_end);
	if (end <= start || end - start > U32_MAX)
		return -E2BIG;
	group->offset = start;
	group->count = end - start;
	return 0;
}
EXPORT_SYMBOL_GPL(ffv2_deferred_group_extend_range);

static int
ffv2_deferred_group_add(struct ffv2_deferred_drain *drain,
				struct ffv2_deferred_cohort *cohort,
				struct ffv2_pending_chunk *pending)
{
	struct ffv2_deferred_group *group;
	u64 end;
	int ret;

	list_for_each_entry(group, &drain->groups, list) {
		if (group->cohort != cohort ||
		    !ffv2_deferred_group_matches_pending(group, pending))
			continue;
		if (group->nowners == FFV2_MAX_CHUNKS_PER_OP)
			continue;
		ret = ffv2_deferred_group_extend_range(group, pending);
		if (ret == -E2BIG)
			continue;
		if (ret)
			return ret;
		group->pending[group->nowners] = pending;
		group->owners[group->nowners] = pending->owner;
		group->nowners++;
		return 0;
	}

	group = kzalloc_obj(*group, GFP_ATOMIC);
	if (!group)
		return -ENOMEM;
	group->drain = drain;
	group->cohort = cohort;
	if (check_add_overflow(pending->offset, (u64)pending->count, &end) ||
	    !pending->count || end - pending->offset > U32_MAX) {
		kfree(group);
		return -EOVERFLOW;
	}
	group->offset = pending->offset;
	group->count = pending->count;
	group->pending[0] = pending;
	group->owners[0] = pending->owner;
	group->nowners = 1;
	list_add_tail(&group->list, &drain->groups);
	return 0;
}

static void
ffv2_deferred_drain_clear_groups(struct ffv2_deferred_drain *drain)
{
	struct ffv2_deferred_group *group, *group_tmp;
	struct ffv2_deferred_cohort *cohort, *cohort_tmp;

	list_for_each_entry_safe(group, group_tmp, &drain->groups, list) {
		list_del(&group->list);
		kfree(group);
	}
	list_for_each_entry_safe(cohort, cohort_tmp, &drain->cohorts, list) {
		list_del(&cohort->list);
		ffv2_deferred_cohort_release(cohort);
		kfree(cohort);
	}
}

static void
ffv2_deferred_drain_remove_cohort(struct ffv2_deferred_drain *drain,
					struct ffv2_deferred_cohort *cohort)
{
	struct ffv2_deferred_group *group, *group_tmp;

	list_for_each_entry_safe(group, group_tmp, &drain->groups, list) {
		if (group->cohort != cohort)
			continue;
		list_del(&group->list);
		kfree(group);
	}
	list_del(&cohort->list);
	ffv2_deferred_cohort_release(cohort);
	kfree(cohort);
}

static void
ffv2_deferred_drain_restore_pages(struct ffv2_deferred_drain *drain)
{
	list_splice_tail_init(&drain->retry_pages, &drain->data->pages);
}

static void
ffv2_deferred_drain_unclaim_locked(struct ffv2_deferred_drain *drain,
				   struct nfs4_ffv2_layout_segment *fls)
{
	struct ffv2_deferred_cohort *cohort;

	lockdep_assert_held(&fls->fls_pending_lock);
	list_for_each_entry(cohort, &drain->cohorts, list) {
		struct ffv2_stripe_pending_view view;
		struct ffv2_pending_chunk *pending;

		if (!cohort->claimed)
			continue;
		ffv2_stripe_pending_view(cohort->sw, &view);
		spin_lock(view.pending_lock);
		list_for_each_entry(pending, view.pending_chunks, stripe_list)
			if (pending->state == FFV2_PENDING_COMMITTING &&
			    ffv2_pending_drain_identity(drain, pending))
				pending->state = FFV2_PENDING_DEFERRED;
		spin_unlock(view.pending_lock);
	}
}

static void ffv2_deferred_drain_unclaim(struct ffv2_deferred_drain *drain)
{
	struct nfs4_ffv2_layout_segment *fls;

	if (list_empty(&drain->cohorts))
		return;
	if (WARN_ON_ONCE(!drain->lseg))
		return;
	fls = FFV2_LSEG(drain->lseg);
	lockdep_assert_not_held(&fls->fls_pending_lock);
	spin_lock(&fls->fls_pending_lock);
	ffv2_deferred_drain_unclaim_locked(drain, fls);
	spin_unlock(&fls->fls_pending_lock);
}

void ffv2_deferred_drain_abort(struct ffv2_deferred_drain *drain)
{
	if (!drain || !drain->data)
		return;
	if (WARN_ON_ONCE(drain->launch_done))
		return;
	ffv2_deferred_drain_unclaim(drain);
	ffv2_deferred_drain_restore_pages(drain);
	ffv2_deferred_drain_clear_groups(drain);
}
EXPORT_SYMBOL_GPL(ffv2_deferred_drain_abort);

static int
ffv2_deferred_cohort_validate(struct ffv2_deferred_drain *drain,
				       struct ffv2_deferred_cohort *cohort,
				       struct nfs4_ffv2_layout_segment *fls)
{
	struct ffv2_pending_chunk *pending, *shard_zero = NULL;
	struct ffv2_stripe_pending_view view;
	unsigned int shards = 0, expected = 0, actual = 0;
	struct ffv2_pending_req *request;
	struct nfs_page *req;
	u32 seen = 0;

	ffv2_stripe_pending_view(cohort->sw, &view);
	spin_lock(view.pending_lock);
	if (view.nr_shards > FFV2_MAX_CHUNKS_PER_OP) {
		spin_unlock(view.pending_lock);
		return -E2BIG;
	}
	list_for_each_entry(pending, view.pending_chunks, stripe_list) {
		if (!ffv2_deferred_cohort_pending_matches_drain(drain, pending)) {
			spin_unlock(view.pending_lock);
			return -EAGAIN;
		}
		if (pending->shard_idx >= view.nr_shards ||
		    seen & BIT(pending->shard_idx)) {
			spin_unlock(view.pending_lock);
			return -EPROTO;
		}
		seen |= BIT(pending->shard_idx);
		if (pending->shard_idx == 0)
			shard_zero = pending;
		shards++;
	}
	if (!shard_zero || shards != view.nr_shards) {
		spin_unlock(view.pending_lock);
		return -EAGAIN;
	}

	list_for_each_entry(request, &shard_zero->requests, list)
		expected++;
	spin_unlock(view.pending_lock);
	list_for_each_entry(req, &drain->data->pages, wb_list) {
		struct ffv2_pending_chunk *owner = NULL;

		if (ffv2_pending_request_lookup_locked(fls, req, &owner) != 1)
			return -EPROTO;
		if (owner->sw == cohort->sw)
			actual++;
	}
	if (expected != actual)
		return -EAGAIN;
	return 0;
}

/*
 * Claim complete deferred cohorts from the list already detached by the
 * generic pNFS commit code.  The caller holds commit_mutex; this helper takes
 * the lseg and stripe locks only while matching and changing pending state.
 * Retry pages remain detached so the caller can drop commit_mutex before
 * nfs_retry_commit() re-enters the mark hook.
 */
int ffv2_deferred_drain_claim(struct ffv2_deferred_drain *drain,
				       struct nfs_commit_info *cinfo)
{
	struct nfs4_ffv2_layout_segment *fls = FFV2_LSEG(drain->lseg);
	struct ffv2_deferred_cohort *cohort, *cohort_tmp;
	struct nfs_page *req, *req_tmp;
	int ret = 0;

	lockdep_assert_held(&NFS_I(cinfo->inode)->commit_mutex);
	INIT_LIST_HEAD(&drain->cohorts);
	INIT_LIST_HEAD(&drain->groups);
	INIT_LIST_HEAD(&drain->retry_pages);
	spin_lock(&fls->fls_pending_lock);
	list_for_each_entry(req, &drain->data->pages, wb_list) {
		struct ffv2_pending_chunk *pending = NULL;
		struct ffv2_deferred_cohort *new_cohort;

		if (ffv2_pending_request_lookup_locked(fls, req, &pending) != 1 ||
		    !ffv2_deferred_pending_matches_drain(drain, pending)) {
			ret = -EPROTO;
			goto out_unlock;
		}
		new_cohort = ffv2_deferred_cohort_find(drain, pending->sw);
		if (new_cohort)
			continue;
		new_cohort = kzalloc_obj(*new_cohort, GFP_ATOMIC);
		if (!new_cohort) {
			ret = -ENOMEM;
			goto out_unlock;
		}
		new_cohort->sw = pending->sw;
		if (WARN_ON_ONCE(!pending->stripe_ref || !pending->stripe_put)) {
			kfree(new_cohort);
			ret = -EPROTO;
			goto out_unlock;
		}
		refcount_inc(pending->stripe_ref);
		new_cohort->stripe_ref = pending->stripe_ref;
		new_cohort->stripe_put = pending->stripe_put;
		new_cohort->stripe_owner = pending->stripe_owner;
		list_add_tail(&new_cohort->list, &drain->cohorts);
		{
			struct ffv2_stripe_pending_view view;

			ffv2_stripe_pending_view(pending->sw, &view);
			spin_lock(view.pending_lock);
			list_for_each_entry(pending, view.pending_chunks,
					stripe_list) {
				ret = ffv2_deferred_group_add(drain, new_cohort,
							      pending);
				if (ret)
					break;
			}
			spin_unlock(view.pending_lock);
		}
		if (ret)
			goto out_unlock;
	}

	list_for_each_entry_safe(cohort, cohort_tmp, &drain->cohorts, list) {
		ret = ffv2_deferred_cohort_validate(drain, cohort, fls);
		if (!ret) {
			cohort->complete = true;
			continue;
		}
		if (ret != -EAGAIN)
			goto out_unlock;
		list_for_each_entry_safe(req, req_tmp, &drain->data->pages,
					 wb_list) {
			struct ffv2_pending_chunk *pending = NULL;

			if (ffv2_pending_request_lookup_locked(fls, req,
							&pending) == 1 &&
				pending->sw == cohort->sw)
				list_move_tail(&req->wb_list, &drain->retry_pages);
		}
		ffv2_deferred_drain_remove_cohort(drain, cohort);
		ret = 0;
	}

	list_for_each_entry(cohort, &drain->cohorts, list) {
		struct ffv2_pending_chunk *pending;
		struct ffv2_stripe_pending_view view;

		if (!cohort->complete)
			continue;
		ffv2_stripe_pending_view(cohort->sw, &view);
		spin_lock(view.pending_lock);
		list_for_each_entry(pending, view.pending_chunks,
					stripe_list)
			pending->state = FFV2_PENDING_COMMITTING;
		spin_unlock(view.pending_lock);
		cohort->claimed = true;
	}
	if (list_empty(&drain->groups))
		ret = -EAGAIN;
out_unlock:
	if (ret)
		ffv2_deferred_drain_unclaim_locked(drain, fls);
	spin_unlock(&fls->fls_pending_lock);
	if (ret) {
		ffv2_deferred_drain_restore_pages(drain);
		ffv2_deferred_drain_clear_groups(drain);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(ffv2_deferred_drain_claim);

int ffv2_pending_chunk_lock_requests(struct ffv2_pending_chunk *pending)
{
	struct ffv2_pending_req *p, *tmp;
	int count = 0;

	if (WARN_ON_ONCE(READ_ONCE(pending->state) == FFV2_PENDING_RETAINED))
		return -EBUSY;
	list_for_each_entry_safe(p, tmp, &pending->requests, list) {
		if (!nfs_lock_request(p->req))
			goto rollback;
		p->locked = true;
		count++;
	}
	return count;
rollback:
	list_for_each_entry(p, &pending->requests, list) {
		if (p->locked) {
			nfs_unlock_request(p->req);
			p->locked = false;
		}
	}
	return -EBUSY;
}
EXPORT_SYMBOL_GPL(ffv2_pending_chunk_lock_requests);

int ffv2_pending_chunk_move_requests(struct ffv2_pending_chunk *pending,
					     struct list_head *dst)
{
	struct ffv2_pending_req *p, *tmp;
	int count = 0;

	if (WARN_ON_ONCE(READ_ONCE(pending->state) == FFV2_PENDING_RETAINED))
		return -EBUSY;
	list_for_each_entry_safe(p, tmp, &pending->requests, list) {
		/* The aggregate preflight locks every request before this pass. */
		WARN_ON_ONCE(!p->locked);
		list_del(&p->list);
		nfs_list_add_request(p->req, dst);
		put_nfs_open_context(p->context);
		kfree(p);
		count++;
	}
	return count;
}
EXPORT_SYMBOL_GPL(ffv2_pending_chunk_move_requests);

static int ffv2_pending_chunk_take_scanned(struct ffv2_pending_chunk *pending,
						 struct pnfs_layout_segment *lseg,
						 struct list_head *dst,
						 struct nfs_commit_info *cinfo)
{
	struct ffv2_pending_req *p, *tmp;
	int count = 0;

	list_for_each_entry_safe(p, tmp, &pending->requests, list) {
		if (!pnfs_generic_take_request_commit(lseg, p->req, dst,
						      cinfo))
			continue;
		list_del(&p->list);
		put_nfs_open_context(p->context);
		nfs_release_request(p->req);
		kfree(p);
		count++;
	}
	return count;
}

struct nfs_commit_data *ffv2_pending_commitdata_alloc(
					struct ffv2_pending_chunk *pending)
{
	struct ffv2_pending_req *first;
	struct nfs_commit_data *data;

	if (WARN_ON_ONCE(READ_ONCE(pending->state) !=
			 FFV2_PENDING_LIFECYCLE_DONE &&
			 READ_ONCE(pending->state) != FFV2_PENDING_COMMITTING))
		return NULL;
	first = list_first_entry_or_null(&pending->requests,
					struct ffv2_pending_req, list);
	if (!first)
		return NULL;
	data = nfs_commitdata_alloc();
	if (!data) {
		ffv2_pending_chunk_abort(pending);
		return NULL;
	}
	data->inode = first->inode;
	data->cred = get_cred(first->context->cred);
	data->context = get_nfs_open_context(first->context);
	data->args.fh = NFS_FH(data->inode);
	data->lseg = pnfs_get_lseg(pending->lseg);
	data->ds_clp = pending->ds_clp;
	refcount_inc(&data->ds_clp->cl_count);
	data->private = pending;
	if (ffv2_pending_chunk_move_requests(pending, &data->pages) <= 0) {
		ffv2_pending_commitdata_free(data);
		ffv2_pending_chunk_abort(pending);
		return NULL;
	}
	return data;
}
EXPORT_SYMBOL_GPL(ffv2_pending_commitdata_alloc);

void ffv2_pending_commitdata_free(struct nfs_commit_data *data)
{
	struct nfs_page *req, *tmp;

	list_for_each_entry_safe(req, tmp, &data->pages, wb_list) {
		list_del_init(&req->wb_list);
		nfs_release_request(req);
	}
	put_cred(data->cred);
	if (data->lseg)
		pnfs_put_lseg(data->lseg);
	if (data->ds_clp)
		nfs_put_client(data->ds_clp);
	nfs_commitdata_release(data);
}
EXPORT_SYMBOL_GPL(ffv2_pending_commitdata_free);

static void ffv2_commitdata_free(struct nfs_commit_data *data)
{
	put_cred(data->cred);
	if (data->lseg)
		pnfs_put_lseg(data->lseg);
	if (data->ds_clp)
		nfs_put_client(data->ds_clp);
	nfs_commitdata_release(data);
}

static void ffv2_commit_aggregate_rollback(struct ffv2_commit_aggregate *agg)
{
	struct ffv2_commit_chunk *chunk;

	list_for_each_entry(chunk, &agg->chunks, list) {
		spin_lock(chunk->pending->stripe_lock);
		if (chunk->pending->state == FFV2_PENDING_COMMITTING)
			chunk->pending->state = FFV2_PENDING_LIFECYCLE_DONE;
		spin_unlock(chunk->pending->stripe_lock);
	}
}

static void ffv2_commit_aggregate_retry(struct ffv2_commit_aggregate *agg,
					struct nfs_direct_req *dreq)
{
	struct ffv2_commit_chunk *chunk;
	struct ffv2_pending_req *p, *first;
	struct nfs_commit_info cinfo;
	LIST_HEAD(retry);

	first = list_first_entry(&list_first_entry(&agg->chunks,
					struct ffv2_commit_chunk, list)->pending->requests,
					struct ffv2_pending_req, list);
	nfs_init_cinfo(&cinfo, first->inode, dreq);
	mutex_lock(&NFS_I(cinfo.inode)->commit_mutex);
	list_for_each_entry(chunk, &agg->chunks, list)
		list_for_each_entry(p, &chunk->pending->requests, list)
			pnfs_generic_take_request_commit(chunk->pending->lseg,
							 p->req, &retry, &cinfo);
	mutex_unlock(&NFS_I(cinfo.inode)->commit_mutex);
	if (!list_empty(&retry))
		nfs_retry_commit(&retry,
			list_first_entry(&agg->chunks, struct ffv2_commit_chunk,
					 list)->pending->lseg,
			&cinfo, 0);
}

int ffv2_commit_aggregate_move_requests(struct ffv2_commit_aggregate *agg,
						struct list_head *dst,
						struct nfs_direct_req *dreq)
{
	struct ffv2_commit_chunk *chunk;
	struct ffv2_pending_req *first;
	struct ffv2_pending_req *p;
	struct nfs_commit_info cinfo;
	int total = 0;

	first = list_first_entry(&list_first_entry(&agg->chunks,
					struct ffv2_commit_chunk, list)->pending->requests,
					struct ffv2_pending_req, list);
	nfs_init_cinfo(&cinfo, first->inode, dreq);
	mutex_lock(&NFS_I(cinfo.inode)->commit_mutex);
	/* Never splice requests still owned by a written bucket. */
	list_for_each_entry(chunk, &agg->chunks, list) {
		list_for_each_entry(p, &chunk->pending->requests, list) {
			if (test_bit(PG_COMMIT_TO_DS, &p->req->wb_flags) ||
			    !pnfs_generic_request_commit_available(
					chunk->pending->lseg, p->req, &cinfo)) {
				ffv2_commit_aggregate_rollback(agg);
				mutex_unlock(&NFS_I(cinfo.inode)->commit_mutex);
				return -EAGAIN;
			}
		}
	}
	list_for_each_entry(chunk, &agg->chunks, list) {
		total += ffv2_pending_chunk_take_scanned(chunk->pending,
						 chunk->pending->lseg, dst, &cinfo);
	}
	mutex_unlock(&NFS_I(cinfo.inode)->commit_mutex);
	return total;
}
EXPORT_SYMBOL_GPL(ffv2_commit_aggregate_move_requests);

struct nfs_commit_data *ffv2_commit_aggregate_commitdata_alloc(
					struct ffv2_commit_aggregate *agg,
					struct nfs_direct_req *dreq)
{
	struct ffv2_commit_chunk *chunk;
	struct ffv2_pending_req *first;
	struct nfs_commit_data *data;

	chunk = list_first_entry_or_null(&agg->chunks,
					struct ffv2_commit_chunk, list);
	if (!chunk)
		return NULL;
	first = list_first_entry_or_null(&chunk->pending->requests,
					struct ffv2_pending_req, list);
	if (!first)
		return NULL;
	data = nfs_commitdata_alloc();
	if (!data) {
		ffv2_commit_aggregate_retry(agg, dreq);
		ffv2_commit_aggregate_rollback(agg);
		return NULL;
	}
	data->inode = first->inode;
	data->dreq = dreq;
	data->cred = get_cred(first->context->cred);
	data->context = get_nfs_open_context(first->context);
	data->args.fh = NFS_FH(data->inode);
	data->res.verf = &data->verf;
	data->verf.committed = NFS_FILE_SYNC;
	memcpy(&data->verf.verifier,
	       &chunk->pending->commit_writeverf,
	       sizeof(data->verf.verifier));
	data->lseg = pnfs_get_lseg(chunk->pending->lseg);
	data->ds_clp = chunk->pending->ds_clp;
	refcount_inc(&data->ds_clp->cl_count);
	data->private = agg;
	/* Direct I/O completion balances the request-local counter. */
	agg->mds_cinfo = dreq ? &dreq->mds_cinfo :
				 &NFS_I(data->inode)->commit_info;
	nfs_commit_begin(agg->mds_cinfo);
	if (ffv2_commit_aggregate_move_requests(agg, &data->pages, dreq) <= 0) {
		nfs_commit_end(agg->mds_cinfo);
		agg->mds_cinfo = NULL;
		data->private = NULL;
		ffv2_pending_commitdata_free(data);
		return NULL;
	}
	agg->data = data;
	return data;
}
EXPORT_SYMBOL_GPL(ffv2_commit_aggregate_commitdata_alloc);

void ffv2_commit_aggregate_free(struct ffv2_commit_aggregate *agg)
{
	struct ffv2_commit_chunk *chunk, *tmp;

	if (!refcount_dec_and_test(&agg->ref))
		return;

	list_for_each_entry_safe(chunk, tmp, &agg->chunks, list) {
		bool committing;

		list_del(&chunk->list);
		spin_lock(chunk->pending->stripe_lock);
		committing = chunk->pending->state == FFV2_PENDING_COMMITTING;
		spin_unlock(chunk->pending->stripe_lock);
		if (committing) {
			ffv2_pending_chunk_abort(chunk->pending);
			ffv2_pending_chunk_free(chunk->pending);
		}
		kfree(chunk);
	}
	if (agg->stripe_put)
		agg->stripe_put(agg->stripe_owner);
	if (agg->lseg)
		pnfs_put_lseg(agg->lseg);
	kfree(agg);
}
EXPORT_SYMBOL_GPL(ffv2_commit_aggregate_free);

void ffv2_commit_release_pages(struct nfs_commit_data *data)
{
	struct nfs_page *req;
	int status = data->task.tk_status;

	if (data->dreq) {
		nfs_direct_commit_complete(data);
		if (data->private) {
			ffv2_commit_aggregate_free(data->private);
			data->private = NULL;
		}
		ffv2_commitdata_free(data);
		return;
	}

	while (!list_empty(&data->pages)) {
		req = nfs_list_entry(data->pages.next);
		nfs_list_remove_request(req);
		nfs_folio_clear_commit(req);
		if (status < 0) {
			nfs_mapping_set_error(nfs_page_to_folio(req), status);
			nfs_inode_remove_request(req);
		} else {
			nfs_inode_remove_request(req);
		}
		nfs_unlock_and_release_request(req);
	}
	if (data->private)
		nfs_commit_end(((struct ffv2_commit_aggregate *)data->private)->mds_cinfo);
	if (data->private) {
		ffv2_commit_aggregate_free(data->private);
		data->private = NULL;
	}
	ffv2_commitdata_free(data);
}
EXPORT_SYMBOL_GPL(ffv2_commit_release_pages);

/*
 * Terminal callback of one shard's FINALIZE -> COMMIT chain, reached
 * on success and on every failure that aborts the chain.
 *
 * status is the chain's terminal status: 0 when both FINALIZE and
 * COMMIT returned NFS4_OK and their writeverfs matched, a mapped
 * errno otherwise.  It is reported to the stripe write rather than
 * to the header directly: a stripe is durable only once every shard
 * has been finalized, so the header is completed by the stripe's own
 * tail once the last chain has reported in.
 *
 * The wb_ctx borrows hdr / DS and layout state from the stripe write.
 * The pending record is removed before the stripe reference is dropped.
 */
static void ffv2_chunk_wb_finish(struct ffv2_chunk_wb_ctx *wb, int status)
{
	bool retained;

	spin_lock(wb->pending->stripe_lock);
	retained = wb->pending->state == FFV2_PENDING_RETAINED;
	spin_unlock(wb->pending->stripe_lock);
	if (status == 0 && retained) {
		/* Stable writes already completed their DS lifecycle. */
		if (wb->hdr->args.stable == NFS_UNSTABLE)
			ffv2_pending_chunk_lifecycle_done(wb->pending);
		else {
			/* Drop the retained stripe reference before freeing it. */
			ffv2_pending_chunk_abort(wb->pending);
			ffv2_pending_chunk_free(wb->pending);
		}
		ffv2_stripe_write_chain_done(wb->sw, status);
		kfree(wb);
		return;
	}
	if (status && retained)
		ffv2_pending_chunk_abort(wb->pending);
	ffv2_pending_chunk_free(wb->pending);
	ffv2_stripe_write_chain_done(wb->sw, status);
	kfree(wb);
}

struct ffv2_finalize_batch {
	struct ffv2_chunk_wb_ctx *wb[FFV2_MAX_CHUNKS_PER_OP];
	u32 count;
};

static void ffv2_finalize_batch_done(void *arg, int status,
					 const nfs4_verifier *wv)
{
	struct ffv2_finalize_batch *batch = arg;
	u32 i;

	if (status || !wv) {
		if (!status)
			status = -EPROTO;
		for (i = 0; i < batch->count; i++) {
			struct ffv2_chunk_wb_ctx *wb = batch->wb[i];

			pnfs_error_mark_layout_for_return(wb->hdr->inode,
						  wb->pending->lseg);
			ffv2_chunk_wb_finish(wb, status);
		}
		kfree(batch);
		return;
	}
	for (i = 0; i < batch->count; i++)
		if (memcmp(wv, &batch->wb[i]->pending->writeverf,
			   sizeof(*wv))) {
			for (i = 0; i < batch->count; i++) {
				struct ffv2_chunk_wb_ctx *wb = batch->wb[i];

				pnfs_error_mark_layout_for_return(wb->hdr->inode,
							  wb->pending->lseg);
				ffv2_chunk_wb_finish(wb, -EPROTO);
			}
			kfree(batch);
			return;
		}

	for (i = 0; i < batch->count; i++) {
		struct ffv2_chunk_wb_ctx *wb = batch->wb[i];
		struct ffv2_chunk_lifecycle_ctx commit_ctx = {
			.ds_clp = wb->pending->ds_clp,
			.lseg = wb->pending->lseg,
			.complete_arg = wb,
			.complete = ffv2_chunk_wb_commit_done,
		};
		int rc;

		memcpy(&wb->pending->finalize_writeverf, wv,
		       sizeof(wb->pending->finalize_writeverf));
		set_bit(FFV2_PENDING_HAVE_FINALIZE_VERF,
			&wb->pending->flags);
		memcpy(&wb->finalize_writeverf, wv,
		       sizeof(wb->finalize_writeverf));
		wb->have_finalize_writeverf = true;
		rc = ffv2_chunk_commit_dispatch_one_mirror(&commit_ctx,
				wb->pending->cred, &wb->pending->fh,
				&wb->pending->stateid, wb->pending->offset,
				wb->pending->count, &wb->pending->owner, 1);
		if (rc) {
			pnfs_error_mark_layout_for_return(wb->hdr->inode,
						  wb->pending->lseg);
			ffv2_chunk_wb_finish(wb, rc);
		}
	}
	kfree(batch);
}

int ffv2_chunk_wb_start_batch(struct ffv2_chunk_wb_ctx **wbs, u32 count)
{
	struct ffv2_chunk_wb_ctx *first;
	struct ffv2_finalize_batch *batch;
	struct ffv2_chunk_lifecycle_ctx ctx;
	struct chunk_owner4 owners[FFV2_MAX_CHUNKS_PER_OP];
	u64 offset, end;
	u32 i;

	if (!count || count > FFV2_MAX_CHUNKS_PER_OP)
		return -EINVAL;
	first = wbs[0];
	batch = kzalloc(sizeof(*batch), GFP_NOFS);
	if (!batch)
		return -ENOMEM;
	batch->count = count;
	for (i = 0; i < count; i++) {
		struct ffv2_pending_chunk *pending = wbs[i]->pending;

		if (pending->ds_clp != first->pending->ds_clp ||
		    memcmp(&pending->fh, &first->pending->fh,
			   sizeof(pending->fh)) ||
		    memcmp(&pending->stateid, &first->pending->stateid,
			   sizeof(pending->stateid))) {
			kfree(batch);
			return -EXDEV;
		}
		batch->wb[i] = wbs[i];
		owners[i] = pending->owner;
	}
	if (check_add_overflow(first->pending->offset,
			       (u64)first->pending->count, &end)) {
		kfree(batch);
		return -EOVERFLOW;
	}
	offset = first->pending->offset;
	for (i = 1; i < count; i++) {
		struct ffv2_pending_chunk *pending = wbs[i]->pending;
		u64 pending_end;

		if (check_add_overflow(pending->offset,
				       (u64)pending->count, &pending_end)) {
			kfree(batch);
			return -EOVERFLOW;
		}

		if (pending->offset < offset)
			offset = pending->offset;
		if (pending_end > end)
			end = pending_end;
	}
	if (end <= offset || end - offset > U32_MAX) {
		kfree(batch);
		return -E2BIG;
	}
	ctx.ds_clp = first->pending->ds_clp;
	ctx.lseg = first->pending->lseg;
	ctx.complete_arg = batch;
	ctx.complete = ffv2_finalize_batch_done;
	if (ffv2_chunk_finalize_dispatch_one_mirror(&ctx,
			first->pending->cred, &first->pending->fh,
			&first->pending->stateid, offset, end - offset,
			owners, count)) {
		kfree(batch);
		return -EIO;
	}
	return 0;
}

/*
 * FINALIZE completion callback.  Fires from the FINALIZE
 * dispatch's release-cb exactly once.  On success, captures
 * the writeverf and chains to COMMIT.  On failure, marks the
 * lseg for return (any DS-observed lifecycle failure
 * invalidates the current pNFS state, same rationale as
 * ffv2_chunk_write_call_done at flexfilesv2_write.c:180-190)
 * and completes hdr with the propagated errno.
 *
 * On COMMIT dispatch failure (kzalloc / rpc_run_task IS_ERR),
 * complete_hdr fires directly with the dispatch errno --
 * commit_done will NOT fire in that case.
 */
static void ffv2_chunk_wb_finalize_done(void *arg, int status,
					const nfs4_verifier *wv)
{
	struct ffv2_chunk_wb_ctx *wb = arg;
	struct ffv2_chunk_lifecycle_ctx commit_ctx;
	int rc;

	if (status) {
		pnfs_error_mark_layout_for_return(wb->hdr->inode,
					  wb->pending->lseg);
		ffv2_chunk_wb_finish(wb, status);
		return;
	}

	if (WARN_ON_ONCE(!wv)) {
		/* Contract violation: dispatch reported success but
		 * omitted the writeverf.  Fail closed.
		 */
		ffv2_chunk_wb_finish(wb, -EPROTO);
		return;
	}

	/* A data-server reboot between CHUNK_WRITE and FINALIZE
	 * invalidates the write verifier captured with the pending owner. */
	if (memcmp(wv, &wb->pending->writeverf,
		   sizeof(wb->pending->writeverf)) != 0) {
		pnfs_error_mark_layout_for_return(wb->hdr->inode,
					  wb->pending->lseg);
		ffv2_chunk_wb_finish(wb, -EPROTO);
		return;
	}

	memcpy(&wb->pending->finalize_writeverf, wv,
	       sizeof(wb->pending->finalize_writeverf));
	set_bit(FFV2_PENDING_HAVE_FINALIZE_VERF, &wb->pending->flags);
	wb->have_finalize_writeverf = true;
	memcpy(&wb->finalize_writeverf, wv, sizeof(wb->finalize_writeverf));

	commit_ctx.ds_clp = wb->pending->ds_clp;
	commit_ctx.lseg = wb->pending->lseg;
	commit_ctx.complete_arg = wb;
	commit_ctx.complete = ffv2_chunk_wb_commit_done;

	rc = ffv2_chunk_commit_dispatch_one_mirror(&commit_ctx,
			wb->pending->cred, &wb->pending->fh, &wb->pending->stateid,
			wb->pending->offset, wb->pending->count,
			&wb->pending->owner, 1);
	if (rc) {
		pnfs_error_mark_layout_for_return(wb->hdr->inode,
					  wb->pending->lseg);
		ffv2_chunk_wb_finish(wb, rc);
	}
	/* Otherwise commit_done fires eventually; do not touch wb. */
}

/*
 * COMMIT completion callback.  Fires from the COMMIT
 * dispatch's release-cb exactly once.  Compares the COMMIT
 * writeverf against the one FINALIZE returned.  A mismatch means the
 * data server rebooted between the two operations, so FINALIZE's
 * durability guarantee is no longer valid.
 */
static void ffv2_chunk_wb_commit_done(void *arg, int status,
				      const nfs4_verifier *wv)
{
	struct ffv2_chunk_wb_ctx *wb = arg;

	if (status) {
		pnfs_error_mark_layout_for_return(wb->hdr->inode,
					  wb->pending->lseg);
		ffv2_chunk_wb_finish(wb, status);
		return;
	}

	if (WARN_ON_ONCE(!wv) || !wb->have_finalize_writeverf ||
		    !test_bit(FFV2_PENDING_HAVE_FINALIZE_VERF,
			       &wb->pending->flags)) {
		ffv2_chunk_wb_finish(wb, -EPROTO);
		return;
	}
	memcpy(&wb->pending->commit_writeverf, wv,
	       sizeof(wb->pending->commit_writeverf));
	set_bit(FFV2_PENDING_HAVE_COMMIT_VERF, &wb->pending->flags);

	if (memcmp(wv, &wb->finalize_writeverf,
		   sizeof(wb->finalize_writeverf)) != 0) {
		/* A reboot invalidates the layout's data-server state. */
		pnfs_error_mark_layout_for_return(wb->hdr->inode,
					  wb->pending->lseg);
		ffv2_chunk_wb_finish(wb, -EPROTO);
		return;
	}

	if (WARN_ON_ONCE(!test_bit(FFV2_PENDING_HAVE_COMMIT_VERF,
				   &wb->pending->flags)) ||
		    memcmp(&wb->pending->commit_writeverf, wv,
			   sizeof(wb->pending->commit_writeverf)) != 0) {
		ffv2_chunk_wb_finish(wb, -EPROTO);
		return;
	}

	ffv2_chunk_wb_finish(wb, 0);
}

/*
 * Transfer the layout stateid, chunk index, and server-recorded owner
 * from CHUNK_WRITE to the FINALIZE/COMMIT state machine.  Each write
 * currently carries one owner, so the lifecycle request has one entry.
 */
int ffv2_chunk_wb_start(struct ffv2_chunk_wb_ctx *wb)
{
	struct ffv2_chunk_lifecycle_ctx finalize_ctx;

	if (WARN_ON_ONCE(!wb || !wb->hdr || !wb->pending ||
			 !wb->pending->ds_clp))
		return -EINVAL;

	/*
	 * pending.count is the chunk RANGE to transition, bounded only by
	 * being non-empty: the reply arrays carry one status per owner,
	 * and this client sends one owner, so a wider range does not
	 * widen the reply.  Checked here as well as at the dispatch
	 * entry points so a bad hand-off trips at the transition site
	 * rather than at the encoder.
	 *
	 * Callers still pass 1 today; the chain fires once per chunk.
	 * Batching the range is the point of this plumbing and lands
	 * with the commit-phase accumulator.
	 */
	if (WARN_ON_ONCE(wb->pending->count == 0))
		return -EINVAL;

	/* Layout stateid must be present -- CHUNK_WRITE couldn't
	 * have reached hand-off without one (fi->stateid was the
	 * cwa_stateid the DS's trust table validated).  A zero
	 * stateid here would mean the hand-off populated wb from
	 * an anonymous / uninitialised source.  Trip the assert
	 * before wire time to keep the diagnostic close to the
	 * source of the drift.
	 */
	if (WARN_ON_ONCE(wb->pending->stateid.type ==
			 NFS4_SPECIAL_STATEID_TYPE))
		return -EINVAL;

	/* Cred must be present for the RPC layer (msg.rpc_cred);
	 * missing here would fall through to whatever
	 * rpc_new_task's cred fallback picks, silently violating
	 * the "same credentials as CHUNK_WRITE used" contract that
	 * lets the DS attribute the FINALIZE / COMMIT to the same
	 * client.  Fail closed.
	 */
	if (WARN_ON_ONCE(!wb->pending->cred))
		return -EINVAL;

	finalize_ctx.ds_clp = wb->pending->ds_clp;
	finalize_ctx.lseg = wb->pending->lseg;
	finalize_ctx.complete_arg = wb;
	finalize_ctx.complete = ffv2_chunk_wb_finalize_done;

	return ffv2_chunk_finalize_dispatch_one_mirror(&finalize_ctx,
			wb->pending->cred, &wb->pending->fh,
			&wb->pending->stateid, wb->pending->offset,
			wb->pending->count, &wb->pending->owner, 1);
}
