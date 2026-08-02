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
#include "../nfs4_fs.h"
#include "../pnfs.h"
#include "flexfilesv2.h"
#include "flexfilesv2_xdr_chunk.h"

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
 * .rpc_call_done: return the session slot unconditionally
 * first (the CHUNK_FINALIZE decoder guarantees sr_status is
 * populated on every exit path via the sr_status = 1 sentinel;
 * missing this leaks slots on rpc_exit and wedges the
 * session).  Then classify the outcome so the release-cb sees
 * a coherent task->tk_status:
 *
 *   - task->tk_status != 0: RPC-time failure, transport /
 *     session / etc.  Propagate as-is.
 *   - res->nstatus != 1: op-shape violation (single-owner
 *     dispatch expects a length-1 status<> array); -EPROTO.
 *   - res->status[0] != NFS4_OK: per-chunk failure; propagate
 *     the mapped errno (nfs4_stat_to_errno returns negative
 *     already).
 *   - happy path: task->tk_status left at 0, writeverf held
 *     in res->writeverf for the release-cb to forward.
 */
static void ffv2_chunk_finalize_call_done(struct rpc_task *task, void *data)
{
	struct ffv2_chunk_finalize_dispatch *d = data;
	struct ffv2_chunk_finalize_res *res = &d->wire.res;

	nfs4_sequence_done(task, &d->wire.res.seq_res);

	if (task->tk_status == 0) {
		if (res->nstatus != 1)
			task->tk_status = -EPROTO;
		else if (res->status[0] != NFS4_OK)
			task->tk_status = nfs4_stat_to_errno(res->status[0]);
	}

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
	const struct chunk_owner4 *owner)
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
	if (WARN_ON_ONCE(count != 1))
		return -EINVAL;

	d = kzalloc(sizeof(*d), GFP_NOFS);
	if (!d)
		return -ENOMEM;

	d->ctx = *ctx;
	d->wire.fh = *fh;
	d->wire.args.stateid = *stateid;
	d->wire.args.offset = offset;
	d->wire.args.count = count;
	d->wire.args.owner = *owner;
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

	msg.rpc_argp = &d->wire;
	msg.rpc_resp = &d->wire.res;
	task_setup.rpc_client = ctx->ds_clp->cl_rpcclient;
	task_setup.callback_data = d;

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

	nfs4_sequence_done(task, &d->wire.res.seq_res);

	if (task->tk_status == 0) {
		if (res->nstatus != 1)
			task->tk_status = -EPROTO;
		else if (res->status[0] != NFS4_OK)
			task->tk_status = nfs4_stat_to_errno(res->status[0]);
	}
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
	const struct chunk_owner4 *owner)
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
	if (WARN_ON_ONCE(count != 1))
		return -EINVAL;

	d = kzalloc(sizeof(*d), GFP_NOFS);
	if (!d)
		return -ENOMEM;

	d->ctx = *ctx;
	d->wire.fh = *fh;
	d->wire.args.stateid = *stateid;
	d->wire.args.offset = offset;
	d->wire.args.count = count;
	d->wire.args.owner = *owner;
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

	task = rpc_run_task(&task_setup);
	if (IS_ERR(task)) {
		kfree(d);
		return PTR_ERR(task);
	}
	rpc_put_task(task);
	return 0;
}
