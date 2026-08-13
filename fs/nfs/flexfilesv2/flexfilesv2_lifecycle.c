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

/* ------------------------------------------------------------------ */
/* Writeback chain: FINALIZE -> COMMIT after CHUNK_WRITE              */
/* ------------------------------------------------------------------ */

void ffv2_pending_chunk_free(struct ffv2_pending_chunk *pending)
{
	struct nfs4_ffv2_layout_segment *fls = FFV2_LSEG(pending->lseg);
	struct ffv2_pending_req *p, *tmp;

	if (WARN_ON_ONCE(pending->state == FFV2_PENDING_RETAINED))
		return;
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
	spin_lock(pending->stripe_lock);
	list_del_init(&pending->stripe_list);
	spin_unlock(pending->stripe_lock);
	put_cred(pending->cred);
	nfs_put_client(pending->ds_clp);
	pnfs_put_lseg(pending->lseg);
	if (pending->state != FFV2_PENDING_IMMEDIATE && pending->stripe_put)
		pending->stripe_put(pending->stripe_owner);
	kfree(pending);
}
EXPORT_SYMBOL_GPL(ffv2_pending_chunk_free);

void ffv2_pending_chunk_retain(struct ffv2_pending_chunk *pending)
{
	if (WARN_ON_ONCE(!pending->stripe_ref))
		return;
	if (WARN_ON_ONCE(pending->state != FFV2_PENDING_IMMEDIATE))
		return;
	refcount_inc(pending->stripe_ref);
	pending->state = FFV2_PENDING_RETAINED;
}
EXPORT_SYMBOL_GPL(ffv2_pending_chunk_retain);

void ffv2_pending_chunk_lifecycle_done(struct ffv2_pending_chunk *pending)
{
	if (WARN_ON_ONCE(pending->state != FFV2_PENDING_RETAINED))
		return;
	pending->state = FFV2_PENDING_LIFECYCLE_DONE;
}
EXPORT_SYMBOL_GPL(ffv2_pending_chunk_lifecycle_done);

void ffv2_pending_chunk_abort(struct ffv2_pending_chunk *pending)
{
	if (pending->state == FFV2_PENDING_RETAINED ||
	    pending->state == FFV2_PENDING_COMMITTING) {
		pending->state = FFV2_PENDING_IMMEDIATE;
		if (pending->stripe_put)
			pending->stripe_put(pending->stripe_owner);
	}
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

int ffv2_pending_chunk_lock_requests(struct ffv2_pending_chunk *pending)
{
	struct ffv2_pending_req *p, *tmp;
	int count = 0;

	if (WARN_ON_ONCE(pending->state == FFV2_PENDING_RETAINED))
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

	if (WARN_ON_ONCE(pending->state == FFV2_PENDING_RETAINED))
		return -EBUSY;
	list_for_each_entry_safe(p, tmp, &pending->requests, list) {
		if (WARN_ON_ONCE(!p->locked))
			return -EBUSY;
		list_del(&p->list);
		nfs_list_add_request(p->req, dst);
		put_nfs_open_context(p->context);
		kfree(p);
		count++;
	}
	return count;
}
EXPORT_SYMBOL_GPL(ffv2_pending_chunk_move_requests);

struct nfs_commit_data *ffv2_pending_commitdata_alloc(
					struct ffv2_pending_chunk *pending)
{
	struct ffv2_pending_req *first;
	struct nfs_commit_data *data;

	if (WARN_ON_ONCE(pending->state != FFV2_PENDING_LIFECYCLE_DONE &&
			pending->state != FFV2_PENDING_COMMITTING))
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

int ffv2_commit_aggregate_move_requests(struct ffv2_commit_aggregate *agg,
						struct list_head *dst)
{
	struct ffv2_commit_chunk *chunk;
	struct ffv2_pending_req *first, *p;
	struct nfs_commit_info cinfo;
	int total = 0, moved;

	list_for_each_entry(chunk, &agg->chunks, list) {
		moved = ffv2_pending_chunk_lock_requests(chunk->pending);
		if (moved < 0) {
			struct ffv2_commit_chunk *rollback;
			struct ffv2_pending_req *p;
			list_for_each_entry(rollback, &agg->chunks, list)
				list_for_each_entry(p, &rollback->pending->requests,
						    list)
					if (p->locked) {
						nfs_unlock_request(p->req);
						p->locked = false;
					}
			return moved;
		}
	}
	first = list_first_entry(&list_first_entry(&agg->chunks,
					struct ffv2_commit_chunk, list)->pending->requests,
					struct ffv2_pending_req, list);
	nfs_init_cinfo(&cinfo, first->inode, NULL);
	cinfo.ds = &FFV2_LAYOUT_FROM_HDR(
		list_first_entry(&agg->chunks, struct ffv2_commit_chunk,
					 list)->pending->lseg->pls_layout)->commit_info;
	mutex_lock(&NFS_I(cinfo.inode)->commit_mutex);
	list_for_each_entry(chunk, &agg->chunks, list)
		list_for_each_entry(p, &chunk->pending->requests, list)
			pnfs_generic_clear_request_commit(p->req, &cinfo);
	list_for_each_entry(chunk, &agg->chunks, list) {
		moved = ffv2_pending_chunk_move_requests(chunk->pending, dst);
		if (moved < 0) {
			mutex_unlock(&NFS_I(cinfo.inode)->commit_mutex);
			return moved;
		}
		total += moved;
	}
	mutex_unlock(&NFS_I(cinfo.inode)->commit_mutex);
	return total;
}
EXPORT_SYMBOL_GPL(ffv2_commit_aggregate_move_requests);

struct nfs_commit_data *ffv2_commit_aggregate_commitdata_alloc(
					struct ffv2_commit_aggregate *agg)
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
	if (!data)
		return NULL;
	data->inode = first->inode;
	data->cred = get_cred(first->context->cred);
	data->context = get_nfs_open_context(first->context);
	data->args.fh = NFS_FH(data->inode);
	data->lseg = pnfs_get_lseg(chunk->pending->lseg);
	data->ds_clp = chunk->pending->ds_clp;
	refcount_inc(&data->ds_clp->cl_count);
	data->private = agg;
	agg->mds_cinfo = &NFS_I(data->inode)->commit_info;
	nfs_commit_begin(agg->mds_cinfo);
	if (ffv2_commit_aggregate_move_requests(agg, &data->pages) <= 0) {
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

	list_for_each_entry_safe(chunk, tmp, &agg->chunks, list) {
		list_del(&chunk->list);
		if (chunk->pending->state == FFV2_PENDING_COMMITTING) {
			ffv2_pending_chunk_abort(chunk->pending);
			ffv2_pending_chunk_free(chunk->pending);
		}
		kfree(chunk);
	}
	if (agg->stripe_put)
		agg->stripe_put(agg->stripe_owner);
	kfree(agg);
}
EXPORT_SYMBOL_GPL(ffv2_commit_aggregate_free);

void ffv2_commit_release_pages(struct nfs_commit_data *data)
{
	struct nfs_page *req;
	int status = data->task.tk_status;

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
	if (status == 0 && wb->pending->state == FFV2_PENDING_RETAINED) {
		ffv2_pending_chunk_lifecycle_done(wb->pending);
		ffv2_stripe_write_chain_done(wb->sw, status);
		kfree(wb);
		return;
	}
	if (status && wb->pending->state == FFV2_PENDING_RETAINED)
		ffv2_pending_chunk_abort(wb->pending);
	ffv2_pending_chunk_free(wb->pending);
	ffv2_stripe_write_chain_done(wb->sw, status);
	kfree(wb);
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
