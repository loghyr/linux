/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Private header for the CHUNK_WRITE wire scaffold.  Isolated from
 * flexfilesv2.h so that unrelated ffv2 files (encoders, xor,
 * mojette, ...) don't drag in the nfs_xdr.h + SUNRPC include
 * cascade.  Only files that speak CHUNK_WRITE on the wire (this
 * file's .c and the dispatch path) include this.
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
 */
struct ffv2_chunk_write_res {
	struct nfs4_sequence_res	seq_res;
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
	struct nfs4_sequence_args	seq_args;
	struct ffv2_chunk_write_args	args;
	struct nfs_fh			fh;
	struct ffv2_chunk_write_res	res;
};

extern const struct rpc_procinfo ffv2_chunk_write_procinfo;

#endif /* FS_NFS_NFS4FLEXFILES_V2_XDR_CHUNK_H */
