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
static void ffv2_chunk_wb_complete_hdr(struct ffv2_chunk_wb_ctx *wb,
				       int status);

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

/* ------------------------------------------------------------------ */
/* Writeback chain: FINALIZE -> COMMIT after CHUNK_WRITE              */
/* ------------------------------------------------------------------ */

/*
 * Final cleanup after the FINALIZE -> COMMIT chain terminates
 * (successfully or with an error).  Runs the deferred hdr
 * completion + ds_clp / lseg / ctx release that
 * ffv2_chunk_write_release skipped when it transferred
 * ownership to the wb_ctx.
 *
 * status is the wb-chain's terminal status: 0 on success
 * (both FINALIZE and COMMIT returned NFS4_OK AND writeverfs
 * matched), a mapped errno otherwise.  Stamped onto
 * hdr->task.tk_status so the write completion chain reports
 * the error to userspace rather than silent success on a
 * FINALIZE / COMMIT failure.
 *
 * Ordering: nfs_put_client BEFORE hdr completion (matches
 * pnfs_generic_rw_release at pnfs_nfs.c:24-30).  ctx_put
 * BEFORE lseg_put (matches ffv2_chunk_write_release ordering:
 * ctx->fls back-references lseg).  kfree(wb) LAST.
 */
static void ffv2_chunk_wb_complete_hdr(struct ffv2_chunk_wb_ctx *wb,
				       int status)
{
	struct nfs_pgio_header *hdr = wb->hdr;

	if (status) {
		/*
		 * The chunked write path bypasses pnfs_ld_write_done
		 * (and therefore nfs_pgio_result), so stamping
		 * hdr->task.tk_status alone is NOT consumed by the
		 * nfs_write_completion loop at write.c:923 -- it
		 * reads NFS_IOHDR_ERROR + hdr->error + hdr->good_bytes,
		 * which are set only by nfs_set_pgio_error.  Without
		 * this call, a FINALIZE / COMMIT failure returns
		 * write() as "n bytes durable" even though the DS
		 * chunk is orphaned -- silent data loss.
		 *
		 * pos = hdr->args.offset: the byte offset of THIS
		 * pgio-header (matches nfs_pgio_result's call at
		 * pagelist.c:862).  nfs_set_pgio_error clamps
		 * good_bytes to zero for the failing header and
		 * sets NFS_IOHDR_ERROR + hdr->error so the
		 * completion loop marks pages with the failure via
		 * nfs_mapping_set_error.  Also keep the tk_status
		 * write for observability (traces, WARN triggers).
		 */
		nfs_set_pgio_error(hdr, status, hdr->args.offset);
		if (hdr->task.tk_status == 0)
			hdr->task.tk_status = status;
	}

	nfs_put_client(wb->ds_clp);
	hdr->completion_ops->completion(hdr);
	/* hdr is now freed; do not touch. */

	ffv2_stripe_ctx_put(wb->ctx);
	pnfs_put_lseg(wb->lseg);
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
		pnfs_error_mark_layout_for_return(wb->hdr->inode, wb->lseg);
		ffv2_chunk_wb_complete_hdr(wb, status);
		return;
	}

	if (WARN_ON_ONCE(!wv)) {
		/* Contract violation: dispatch reported success but
		 * omitted the writeverf.  Fail closed.
		 */
		ffv2_chunk_wb_complete_hdr(wb, -EPROTO);
		return;
	}

	memcpy(&wb->finalize_writeverf, wv, sizeof(wb->finalize_writeverf));
	wb->have_finalize_writeverf = true;

	commit_ctx.ds_clp = wb->ds_clp;
	commit_ctx.lseg = wb->lseg;
	commit_ctx.complete_arg = wb;
	commit_ctx.complete = ffv2_chunk_wb_commit_done;

	rc = ffv2_chunk_commit_dispatch_one_mirror(&commit_ctx,
			wb->cred, &wb->fh, &wb->stateid,
			wb->offset, wb->count, &wb->owner);
	if (rc) {
		pnfs_error_mark_layout_for_return(wb->hdr->inode, wb->lseg);
		ffv2_chunk_wb_complete_hdr(wb, rc);
	}
	/* Otherwise commit_done fires eventually; do not touch wb. */
}

/*
 * COMMIT completion callback.  Fires from the COMMIT
 * dispatch's release-cb exactly once.  Compares the COMMIT
 * writeverf against the one FINALIZE returned; a mismatch
 * means the DS rebooted between the two ops and FINALIZE's
 * durability guarantee is no longer valid.  Treated as -EPROTO for
 * now; a follow-up commit will map this to a proper retry hook.
 */
static void ffv2_chunk_wb_commit_done(void *arg, int status,
				      const nfs4_verifier *wv)
{
	struct ffv2_chunk_wb_ctx *wb = arg;

	if (status) {
		pnfs_error_mark_layout_for_return(wb->hdr->inode, wb->lseg);
		ffv2_chunk_wb_complete_hdr(wb, status);
		return;
	}

	if (WARN_ON_ONCE(!wv) || !wb->have_finalize_writeverf) {
		ffv2_chunk_wb_complete_hdr(wb, -EPROTO);
		return;
	}

	if (memcmp(wv, &wb->finalize_writeverf,
		   sizeof(wb->finalize_writeverf)) != 0) {
		/* DS reboot between FINALIZE and COMMIT: mark the
		 * layout for return so LAYOUTGET-fresh picks up a
		 * clean state.  A follow-up commit will replace this
		 * -EPROTO with a proper retry hook.
		 */
		pnfs_error_mark_layout_for_return(wb->hdr->inode, wb->lseg);
		ffv2_chunk_wb_complete_hdr(wb, -EPROTO);
		return;
	}

	ffv2_chunk_wb_complete_hdr(wb, 0);
}

/*
 * ffv2_chunk_wb_start -- guard/stateid consumer sync between the
 * CHUNK_WRITE hand-off and the FINALIZE / COMMIT dispatch.
 *
 * The wb_ctx passed here must be populated by the CHUNK_WRITE
 * release-cb hand-off (ffv2_chunk_write_release_hand_off_wb in
 * flexfilesv2_write.c) from the CHUNK_WRITE dispatch's wire fields.
 * The consumer chain is:
 *
 *   CHUNK_WRITE dispatch (flexfilesv2_write.c):
 *     w->wire.args.stateid  = fi->stateid           (layout stateid)
 *     w->wire.args.offset   = chunk_index
 *     w->wire.args.owner    = client-picked chunk_owner4
 *   CHUNK_WRITE completion:
 *     w->wire.res.owners[0] = DS-recorded chunk_owner4 (guard-
 *                             consumer source, same shape as
 *                             w->wire.args.owner on a successful
 *                             write per the single-owner-per-op
 *                             contract)
 *
 *   hand-off wb_ctx:
 *     wb->stateid           = w->wire.args.stateid (layout stateid)
 *     wb->offset            = w->wire.args.offset  (same chunk index)
 *     wb->owner             = w->wire.res.owners[0] (DS-recorded)
 *     wb->count             = 1                   (single-owner invariant)
 *
 *   FINALIZE / COMMIT dispatch (this file):
 *     cfa_stateid / cca_stateid = wb->stateid (same layout stateid
 *                                              the DS's trust table
 *                                              accepted for
 *                                              CHUNK_WRITE)
 *     cfa_chunks[0] / cca_chunks[0] = wb->owner (identifies which
 *                                                PENDING chunk to
 *                                                transition)
 *
 * Every WARN_ON_ONCE here is defence-in-depth against an accidental
 * drift in the hand-off (e.g., a caller populating wb_ctx from a
 * non-CHUNK_WRITE source).  The CHUNK_WRITE call_done already
 * rejects the res.nblocks != 1 shape that would leave res.owners[0]
 * undefined; these asserts catch it if the code shape ever regresses.
 */
int ffv2_chunk_wb_start(struct ffv2_chunk_wb_ctx *wb)
{
	struct ffv2_chunk_lifecycle_ctx finalize_ctx;

	if (WARN_ON_ONCE(!wb || !wb->hdr || !wb->ds_clp))
		return -EINVAL;

	/* Single-owner invariant: matches the encoders'
	 * WARN_ON_ONCE(count != 1) and the CHUNK_WRITE res.nblocks ==
	 * 1 check.  Assert here so any future hand-off that thinks it
	 * can batch trips the warning at the transition site rather
	 * than at the encoder.
	 */
	if (WARN_ON_ONCE(wb->count != 1))
		return -EINVAL;

	/* Layout stateid must be present -- CHUNK_WRITE couldn't
	 * have reached hand-off without one (fi->stateid was the
	 * cwa_stateid the DS's trust table validated).  A zero
	 * stateid here would mean the hand-off populated wb from
	 * an anonymous / uninitialised source.  Trip the assert
	 * before wire time to keep the diagnostic close to the
	 * source of the drift.
	 */
	if (WARN_ON_ONCE(wb->stateid.type == NFS4_SPECIAL_STATEID_TYPE))
		return -EINVAL;

	/* Cred must be present for the RPC layer (msg.rpc_cred);
	 * missing here would fall through to whatever
	 * rpc_new_task's cred fallback picks, silently violating
	 * the "same credentials as CHUNK_WRITE used" contract that
	 * lets the DS attribute the FINALIZE / COMMIT to the same
	 * client.  Fail closed.
	 */
	if (WARN_ON_ONCE(!wb->cred))
		return -EINVAL;

	finalize_ctx.ds_clp = wb->ds_clp;
	finalize_ctx.lseg = wb->lseg;
	finalize_ctx.complete_arg = wb;
	finalize_ctx.complete = ffv2_chunk_wb_finalize_done;

	return ffv2_chunk_finalize_dispatch_one_mirror(&finalize_ctx,
			wb->cred, &wb->fh, &wb->stateid,
			wb->offset, wb->count, &wb->owner);
}
