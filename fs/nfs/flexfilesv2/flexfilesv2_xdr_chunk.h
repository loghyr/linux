/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Private header for the CHUNK_WRITE and CHUNK_READ wire scaffolds.
 * Isolated from flexfilesv2.h so that unrelated ffv2 files
 * (encoders, xor, mojette, ...) don't drag in the nfs_xdr.h +
 * SUNRPC include cascade.  Only files that speak CHUNK_WRITE /
 * CHUNK_READ on the wire (this file's .c and the dispatch paths)
 * include this.
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 */

#ifndef FS_NFS_NFS4FLEXFILES_V2_XDR_CHUNK_H
#define FS_NFS_NFS4FLEXFILES_V2_XDR_CHUNK_H

#include <linux/nfs4.h>
#include <linux/nfs_xdr.h>
#include <linux/sunrpc/clnt.h>

#include "flexfilesv2.h"

/*
 * In-memory form of write_chunk_guard4 (the CAS union on
 * CHUNK_WRITE4args).  When check == true, the encoder emits
 * cwg_check = TRUE + the guard value; when false the union
 * collapses to a bool-only 4 bytes on the wire.
 *
 * The captured guard on RMW writes comes from the RMW fetch path's
 * retained read_chunk4.cr_owner.co_guard.  A later commit wires the
 * plumbing that populates this on the RMW write path.
 */
struct ffv2_write_chunk_guard4 {
	bool			check;
	struct chunk_guard4	guard;
};

/*
 * CHUNK_WRITE4args in-memory form.
 *
 * cwa_offset is a CHUNK INDEX (not bytes) -- draft sec-CHUNK_WRITE
 * explicitly; the DS multiplies by chunk_size for placement.
 *
 * cwa_chunk_size is the file's NOMINAL STRIDE (not the payload byte
 * count); the DS latches it on the file's first write.  Shard
 * payload bytes live in the pages attached to the rpc_rqst via
 * xdr_write_pages, with payload_len as the wire length (may be <
 * chunk_size for the file's tail chunk).
 */
struct ffv2_chunk_write_args {
	nfs4_stateid			stateid;
	u64				offset;		/* chunk index */
	u32				stable;		/* stable_how4 */
	struct chunk_owner4		owner;
	u32				payload_id;	/* always 0 for now */
	u32				flags;		/* always 0 for now */
	struct ffv2_write_chunk_guard4	guard;
	u32				chunk_size;	/* nominal stride */
	u32				checksum_algo;
	u8				checksum_bytes[FFV2_CHECKSUM_MAX_LEN];
	size_t				checksum_len;
	struct page			**pages;
	u32				pgbase;
	u32				payload_len;	/* bytes on the wire */
};

/*
 * CHUNK_WRITE4resok in-memory form.  Reply-array bounds are
 * FFV2_MAX_CHUNKS_PER_OP to cap malformed-reply allocations;
 * nblocks reports the actual N the DS returned.
 *
 * seq_res MUST stay the first member.  nfs41_assign_slot
 * (fs/nfs/nfs4session.c) hands a freed slot to a parked task by
 * casting rpc_resp straight to struct nfs4_sequence_res, exactly as
 * struct nfs_pgio_res does for the plain-NFSv4.1 path.  Move it and
 * the handoff writes the slot pointer over the reply body instead,
 * the task never sees the slot it was given, and the slot is lost
 * from the table for good.
 */
struct ffv2_chunk_write_res {
	struct nfs4_sequence_res	seq_res;	/* MUST be first */
	u32				count;
	u32				committed;
	nfs4_verifier			writeverf;
	u32				nblocks;
	u32				block_status[FFV2_MAX_CHUNKS_PER_OP];
	bool				block_activated[FFV2_MAX_CHUNKS_PER_OP];
	struct chunk_owner4		owners[FFV2_MAX_CHUNKS_PER_OP];
};

/*
 * Composite task-data struct passed as rpc_message.rpc_argp on the
 * CHUNK_WRITE task.  Holds the op args, the SEQUENCE args (populated
 * by nfs4_setup_sequence in the call_ops .rpc_call_prepare hook of
 * the dispatch site), the PUTFH filehandle, and reply body storage.
 *
 * seq_res is populated by the decoder BEFORE any CHUNK_WRITE op
 * status is consulted, so any error reply still yields a well-formed
 * seq_res that nfs41_sequence_process can use to dispatch its
 * recovery arms (session-recover on -NFS4ERR_BADSESSION, retry-new-
 * seq on -NFS4ERR_DELAY, etc.).  Missing that ordering leaks slots
 * per rpc_exit path and eventually wedges every DS I/O on
 * slot_tbl_waitq.
 *
 * NFS4ERR_DELAY maps to -NFS4ERR_DELAY (not -EAGAIN).  The DELAY
 * code is in neither nfs4_errtbl_common nor nfs4_errtbl and falls
 * through common.c's default (`return -stat`).  The dispatch's
 * retry state machine must match -NFS4ERR_DELAY, not -EAGAIN.
 */
struct ffv2_chunk_write_data {
	/*
	 * seq_args MUST stay the first member, for the argp half of
	 * the same nfs41_assign_slot cast described above
	 * ffv2_chunk_write_res.  rpc_resp points at .res, not here.
	 */
	struct nfs4_sequence_args	seq_args;
	struct ffv2_chunk_write_args	args;
	struct nfs_fh			fh;
	struct ffv2_chunk_write_res	res;
};

extern const struct rpc_procinfo ffv2_chunk_write_procinfo;

/*
 * CHUNK_READ4args in-memory form.
 *
 * offset is a CHUNK INDEX (u64), NOT bytes -- same units as
 * cwa_offset on the WRITE side, per draft sec-CHUNK_READ.  count is
 * a chunk count (u32), NOT bytes; the initial posture always sends 1
 * (the encoder rejects 0).
 *
 * pages/pgbase/pglen point at the caller-supplied reply page vector;
 * the encoder wires them into rpc_prepare_reply_pages before COMPOUND
 * emit so the transport lays out the receive buffer with a
 * head/pages split at the fixed prefix, and the decoder splices
 * cr_chunk<> bytes onto pages via xdr_read_pages (no memcpy on the
 * payload path).
 */
struct ffv2_chunk_read_args {
	nfs4_stateid	stateid;
	u64		offset;		/* chunk INDEX, not bytes */
	u32		count;		/* chunk COUNT; always 1 for now */
	struct page	**pages;	/* caller's reply-page vector */
	u32		pgbase;
	u32		pglen;		/* bytes of room in pages */
};

/*
 * checksum4 in-memory form.  cs_value bytes are stored verbatim from
 * the wire (already big-endian); the dispatch layer byte-compares
 * against the same big-endian shape produced by ffv2_checksum_compute.
 * No client-side algorithm interpretation in the decoder;
 * algorithm/value_len are stored as-is and cross-checked against the
 * layout by the caller.
 */
struct ffv2_checksum4 {
	u32		algorithm;
	u32		value_len;	/* bytes populated in value[] */
	u8		value[FFV2_CHECKSUM_MAX_LEN];
};

/* One crr_chunks<> element. */
struct ffv2_read_chunk4 {
	struct ffv2_checksum4	checksum;
	u32			effective_len;	/* bytes valid in payload */
	struct chunk_owner4	owner;		/* guard-capture source */
	struct chunk_guard4	guard;		/* per-chunk CAS state */
	u32			payload_id;	/* always 0 for now */
	u32			locked;		/* chunk_state_flags4 */
	u32			status;		/* nfsstat4 */
	u32			chunk_len;	/* cr_chunk<> wire length */
};

/*
 * CHUNK_READ4resok in-memory form.  chunks[] cap is
 * FFV2_MAX_CHUNKS_PER_OP for defensive allocation sizing; the
 * decoder currently enforces nchunks in {0, 1}.  nchunks == 0 is the
 * DS's transient-OOM truncation path with a separately-computed
 * crr_eof that the caller MUST treat as retry/fallback, not a clean
 * EOF.
 */
struct ffv2_chunk_read_res {
	/* MUST be first -- see ffv2_chunk_write_res. */
	struct nfs4_sequence_res seq_res;
	bool			eof;
	u32			nchunks;
	struct ffv2_read_chunk4	chunks[FFV2_MAX_CHUNKS_PER_OP];
};

/*
 * Composite task-data struct passed as rpc_message.rpc_argp on the
 * CHUNK_READ task.  Same shape rationale as ffv2_chunk_write_data:
 * seq_res is populated by the decoder BEFORE any CHUNK_READ op
 * status is consulted, so any error reply still yields a well-formed
 * seq_res that nfs41_sequence_process can use to dispatch its
 * recovery arms.  NFS4ERR_DELAY maps to -NFS4ERR_DELAY (not
 * -EAGAIN); the dispatch layer must match on -NFS4ERR_DELAY for its
 * retry loop.
 */
struct ffv2_chunk_read_data {
	/* MUST be first -- see ffv2_chunk_write_data. */
	struct nfs4_sequence_args	seq_args;
	struct ffv2_chunk_read_args	args;
	struct nfs_fh			fh;
	struct ffv2_chunk_read_res	res;
};

extern const struct rpc_procinfo ffv2_chunk_read_procinfo;

/*
 * NFS4ERR_DELAY retry parameters, shared by every CHUNK_READ caller.
 * Linear 100 ms per attempt, capped at 1 s (unreachable at 5 attempts;
 * kept as headroom for a future attempt-count raise).  Total budget:
 * 100+200+300+400+500 = 1.5 s across 5 attempts, comfortably inside
 * the RMW fetch engine's 60 s wait_for_completion_timeout.
 *
 * Retries MUST go through rpc_restart_call_prepare (NOT
 * rpc_restart_call): the done callback has already run
 * nfs4_sequence_done, which freed the slot.  rpc_restart_call
 * restarts at call_start and skips .rpc_call_prepare, so the retry
 * would re-encode a freed and possibly re-issued slot --
 * SEQ_MISORDERED or slot-table corruption on every DELAY.  The
 * _prepare variant restarts at rpc_prepare_task, which re-invokes
 * .rpc_call_prepare and re-acquires a slot via nfs4_setup_sequence.
 */
#define FFV2_CHUNK_READ_DELAY_BASE_MS		100
#define FFV2_CHUNK_READ_DELAY_CAP_MS		1000
#define FFV2_CHUNK_READ_MAX_DELAY_ATTEMPTS	5

/*
 * CHUNK_READ dispatch entry.  Called once per data shard by the
 * contained-partial RMW branch of ffv2_write_pagelist_chunked once
 * that branch is enabled.
 *
 * count MUST be 1; count == 0 returns -EINVAL WITHOUT touching
 * ctx->fetch_pending (the caller owns the RMW fetch counter on
 * dispatch failures).  Returns 0 on successful async dispatch (the
 * release path calls ffv2_rmw_fetch_done_one) or a negative errno on
 * failure to dispatch (the caller must call ffv2_rmw_fetch_done_one
 * itself).
 *
 * Non-static within the ffv2 module -- NOT EXPORT_SYMBOL_GPL.  No
 * out-of-module consumer exists.
 */
struct ffv2_stripe_ctx;
struct nfs_pgio_header;
struct nfs4_ffv2_mirror;
int ffv2_chunk_read_fetch_dispatch(struct ffv2_stripe_ctx *ctx,
				   struct nfs_pgio_header *tmpl,
				   struct nfs4_ffv2_mirror *mirror,
				   u32 shard_idx, u32 count);

/*
 * CHUNK_FINALIZE4args in-memory form.
 *
 * stateid is the layout stateid (draft authorization contract).
 * The DS's chunk_lifecycle_check_stateid() bypasses the trust-table
 * check on the anonymous stateid; the dispatch layer passes the
 * file's layout stateid captured at LAYOUTGET time.
 *
 * offset is a CHUNK INDEX (u64), NOT bytes -- same units as
 * cwa_offset / cra_offset on the WRITE / READ sides.  count is a
 * chunk count (u32).  The current single-owner-per-op shape sends
 * nchunks == 1; nchunks > 1 is a future batching slice.
 *
 * The owner triple names WHICH prior CHUNK_WRITE this FINALIZE
 * refers to.
 */
struct ffv2_chunk_finalize_args {
	nfs4_stateid		stateid;
	u64			offset;		/* chunk INDEX, not bytes */
	u32			count;		/* chunk COUNT, always 1 */
	struct chunk_owner4	owner;
};

/*
 * CHUNK_FINALIZE4resok in-memory form.  writeverf lets the client
 * detect a DS reboot between FINALIZE and COMMIT (matches
 * CHUNK_WRITE4resok::writeverf semantics).  Per-chunk status is
 * a bounded array capped at FFV2_MAX_CHUNKS_PER_OP for defensive
 * allocation sizing; nstatus reports the actual N the DS returned
 * (expected 1 for single-owner requests).
 */
struct ffv2_chunk_finalize_res {
	/* MUST be first -- see ffv2_chunk_write_res. */
	struct nfs4_sequence_res seq_res;
	nfs4_verifier		writeverf;
	u32			nstatus;
	u32			status[FFV2_MAX_CHUNKS_PER_OP];
};

/*
 * Composite task-data struct passed as rpc_message.rpc_argp on the
 * CHUNK_FINALIZE task.  Same shape rationale as
 * ffv2_chunk_write_data / ffv2_chunk_read_data: seq_res is populated
 * by the decoder BEFORE any CHUNK_FINALIZE op status is consulted,
 * so any error reply still yields a well-formed seq_res that
 * nfs41_sequence_process can use for its recovery arms.
 * NFS4ERR_DELAY maps to -NFS4ERR_DELAY (not -EAGAIN); the dispatch
 * layer must match on -NFS4ERR_DELAY for its retry-with-backoff
 * loop.
 */
struct ffv2_chunk_finalize_data {
	/* MUST be first -- see ffv2_chunk_write_data. */
	struct nfs4_sequence_args	seq_args;
	struct ffv2_chunk_finalize_args	args;
	struct nfs_fh			fh;
	struct ffv2_chunk_finalize_res	res;
};

extern const struct rpc_procinfo ffv2_chunk_finalize_procinfo;

/*
 * CHUNK_COMMIT4args in-memory form.  Shape mirrors
 * CHUNK_FINALIZE4args verbatim; the only wire differences are the
 * op number (78 vs 80) and the field-prefix convention (cca_ vs
 * cfa_).  Same single-owner-per-op interop shape as FINALIZE.
 *
 * Called after CHUNK_FINALIZE by the dispatch layer to transition
 * FINALIZED -> COMMITTED on the DS with a durability barrier
 * (matches the plain-WRITE + COMMIT pairing on the NFSv4.1 side,
 * adapted to the CHUNK op family).
 */
struct ffv2_chunk_commit_args {
	nfs4_stateid		stateid;
	u64			offset;		/* chunk INDEX, not bytes */
	u32			count;		/* chunk COUNT, always 1 */
	struct chunk_owner4	owner;
};

/*
 * CHUNK_COMMIT4resok in-memory form.  Wire shape mirrors
 * CHUNK_FINALIZE4resok exactly.  The writeverf pair (returned by
 * both FINALIZE and COMMIT) lets the client detect a DS reboot
 * between the two ops; the dispatch layer compares the two
 * verifiers and treats a mismatch as a lost-durability signal that
 * MUST invalidate the FINALIZE and retry.
 */
struct ffv2_chunk_commit_res {
	/* MUST be first -- see ffv2_chunk_write_res. */
	struct nfs4_sequence_res seq_res;
	nfs4_verifier		writeverf;
	u32			nstatus;
	u32			status[FFV2_MAX_CHUNKS_PER_OP];
};

/*
 * Composite task-data struct passed as rpc_message.rpc_argp on the
 * CHUNK_COMMIT task.  Same rationale as ffv2_chunk_finalize_data:
 * seq_res is populated BEFORE any CHUNK_COMMIT op status is
 * consulted, NFS4ERR_DELAY maps to -NFS4ERR_DELAY (not -EAGAIN),
 * and the dispatch layer must match on -NFS4ERR_DELAY for its retry
 * loop.
 */
struct ffv2_chunk_commit_data {
	/* MUST be first -- see ffv2_chunk_write_data. */
	struct nfs4_sequence_args	seq_args;
	struct ffv2_chunk_commit_args	args;
	struct nfs_fh			fh;
	struct ffv2_chunk_commit_res	res;
};

extern const struct rpc_procinfo ffv2_chunk_commit_procinfo;

struct ffv2_chunk_rollback_args {
	nfs4_stateid		stateid;
	u64			offset;
	u32			count;
	u32			nowners;
	struct chunk_owner4	owners[FFV2_MAX_CHUNKS_PER_OP];
};

struct ffv2_chunk_rollback_res {
	struct nfs4_sequence_res seq_res;
	nfs4_verifier		writeverf;
	u32			nstatus;
	u32			status[FFV2_MAX_CHUNKS_PER_OP];
};

struct ffv2_chunk_rollback_data {
	struct nfs4_sequence_args seq_args;
	struct ffv2_chunk_rollback_args args;
	struct nfs_fh		fh;
	struct ffv2_chunk_rollback_res res;
};

extern const struct rpc_procinfo ffv2_chunk_rollback_procinfo;

/*
 * Lifecycle-op dispatch entry points.  Called by the
 * FINALIZE-then-COMMIT sequencing after a successful CHUNK_WRITE
 * reaches the release-cb hook.
 *
 * The caller supplies a ffv2_chunk_lifecycle_ctx with a
 * completion callback that fires exactly once from the
 * dispatch's release-cb, on either success (task->tk_status ==
 * 0 and the DS returned NFS4_OK) or failure (any error path).
 * The callback receives the mapped errno (0 for success) and,
 * on success only, the DS's writeverf; on failure writeverf is
 * NULL and the caller MUST NOT dereference it.
 *
 * Ownership: the caller retains the nfs_client reference on
 * ds_clp for the lifetime of the dispatch (dispatch does NOT
 * take an additional ref).  The caller MUST NOT free ds_clp
 * until the completion callback has fired.  This matches the
 * ffv2_chunk_write_dispatch pattern in flexfilesv2_write.c
 * where hdr->ds_clp lives on the pgio_header.
 */
struct nfs_client;
struct pnfs_layout_segment;

struct ffv2_chunk_lifecycle_ctx {
	struct nfs_client		*ds_clp;
	/*
	 * lseg is carried through to the completion callback: FINALIZE
	 * / COMMIT error paths need to mark the layout for return via
	 * pnfs_error_mark_layout_for_return (matches the
	 * ffv2_chunk_write_call_done pattern in flexfilesv2_write.c).
	 * The dispatch itself does not read lseg; it is a caller-set
	 * forward that the completion callback is free to consume.
	 */
	struct pnfs_layout_segment	*lseg;
	/* Completion callback: fires exactly once from release-cb.
	 * status == 0 on success; writeverf non-NULL on success
	 * ONLY (points into a wrapper-owned buffer valid only
	 * until the callback returns; caller must copy if it
	 * needs to compare across FINALIZE vs COMMIT).
	 */
	void				*complete_arg;
	void				(*complete)(void *arg, int status,
					   const nfs4_verifier *writeverf);
};

/*
 * ffv2_chunk_finalize_dispatch_one_mirror -- dispatch a
 * CHUNK_FINALIZE against a single DS mirror.  Non-blocking:
 * returns 0 on successful async dispatch (completion callback
 * will fire) or negative errno on failure to dispatch (caller
 * must NOT wait for the completion callback -- it will not
 * fire in that case).
 *
 * Non-static within the ffv2 module -- NOT EXPORT_SYMBOL_GPL.
 * No out-of-module consumer exists or is planned.
 */
int ffv2_chunk_finalize_dispatch_one_mirror(
	struct ffv2_chunk_lifecycle_ctx *ctx,
	const struct cred *cred,
	const struct nfs_fh *fh,
	const nfs4_stateid *stateid,
	u64 offset, u32 count,
	const struct chunk_owner4 *owner);

/*
 * ffv2_chunk_commit_dispatch_one_mirror -- dispatch a
 * CHUNK_COMMIT against a single DS mirror.  Semantics mirror
 * FINALIZE.  Same callback ownership rules.
 */
int ffv2_chunk_commit_dispatch_one_mirror(
	struct ffv2_chunk_lifecycle_ctx *ctx,
	const struct cred *cred,
	const struct nfs_fh *fh,
	const nfs4_stateid *stateid,
	u64 offset, u32 count,
	const struct chunk_owner4 *owner);

int
ffv2_chunk_rollback_dispatch_one_mirror(struct ffv2_chunk_lifecycle_ctx *ctx,
					const struct cred *cred,
	const struct nfs_fh *fh,
	const nfs4_stateid *stateid,
	u64 offset, u32 count,
	const struct chunk_owner4 *owners, u32 nowners);

/*
 * Post-CHUNK_WRITE writeback context.  Chains FINALIZE -> COMMIT for
 * one shard of a stripe write, started from the phase-one completion
 * tail in flexfilesv2_write.c once every CHUNK_WRITE of the stripe
 * has succeeded.
 *
 * Ownership discipline: the wb_ctx owns nothing but itself.  hdr,
 * ds_clp and lseg are all borrowed from the parent stripe write,
 * which the chain pins with a reference taken at hand-off.
 * The terminal callback reports the chain's status back via
 * ffv2_stripe_write_chain_done() -- which drops that reference and,
 * when it is the last chain to finish, completes the header -- and
 * then frees the wb_ctx.  A single chain therefore never completes
 * the header itself: a stripe is durable only once every shard has
 * been finalized.
 *
 * The writeverf captured on FINALIZE is compared against the
 * writeverf returned by COMMIT.  A mismatch means the data server
 * rebooted between the two ops -- treated as a lost-durability
 * signal reported as an error status for the stripe.
 */
struct nfs_pgio_header;
struct ffv2_stripe_write;

void ffv2_stripe_write_chain_done(struct ffv2_stripe_write *sw, int status);

struct ffv2_chunk_wb_ctx {
	/* Populated by the caller (the phase-one completion tail).
	 * Every pointer here is borrowed from sw.
	 */
	struct ffv2_stripe_write	*sw;
	struct nfs_pgio_header		*hdr;
	struct nfs_client		*ds_clp;
	struct pnfs_layout_segment	*lseg;
	const struct cred		*cred;
	struct nfs_fh			fh;
	nfs4_stateid			stateid;
	u64				offset;
	u32				count;
	struct chunk_owner4		owner;
	/* Populated by the FINALIZE completion callback:          */
	nfs4_verifier			finalize_writeverf;
	bool				have_finalize_writeverf;
};

/*
 * ffv2_chunk_wb_start -- kick off the FINALIZE -> COMMIT chain
 * for one shard.  On success (return 0), the chain is running and
 * the wb_ctx is owned by the callbacks -- caller must NOT touch it
 * or free it.  On failure, the wb_ctx is untouched; the caller
 * retains ownership and MUST free it.
 *
 * The chain's terminal status (0 on success, -EPROTO on writeverf
 * mismatch, the propagated errno on FINALIZE / COMMIT failure)
 * reaches the stripe write via ffv2_stripe_write_chain_done().
 */
int ffv2_chunk_wb_start(struct ffv2_chunk_wb_ctx *wb);

#endif /* FS_NFS_NFS4FLEXFILES_V2_XDR_CHUNK_H */
