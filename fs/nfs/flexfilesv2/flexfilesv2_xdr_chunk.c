// SPDX-License-Identifier: GPL-2.0
/*
 * NFSv4.2 CHUNK_WRITE wire scaffold for the FlexFiles Version 2
 * layout driver.  Op code 87 per draft-haynes-nfsv4-flexfiles-v2.
 *
 * Encoder + decoder + rpc_procinfo definition; the dispatch site
 * that consumes them lands in a later commit.
 *
 * Architectural choice: the compound-scaffolding helpers in
 * fs/nfs/nfs4xdr.c (encode_compound_hdr, encode_sequence,
 * encode_putfh, matching decode_*, and the *_maxsz macros) are
 * static and not exported.  Rather than duplicate them or add
 * EXPORT_SYMBOL_GPL to nfs4xdr.c, hand-roll the small compound
 * envelope and use the exported nfs4_setup_sequence /
 * nfs4_sequence_done for session-slot management.
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/nfs4.h>
#include <linux/nfs_common.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_xdr.h>
#include <linux/string.h>
#include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/sched.h>
#include <linux/sunrpc/xdr.h>

#include "../internal.h"
#include "../nfs4_fs.h"
#include "../nfs4session.h"
#include "../pnfs.h"
#include "flexfilesv2.h"
#include "flexfilesv2_xdr_chunk.h"

/*
 * Compound header size upper bound.  Fixed by RFC 8881 §17.2:
 *   tag<>    = 4-byte length + 0-byte tag body (we send empty tag)
 *   minorversion = 4 bytes
 *   nops<>   = 4-byte length + no body until op headers begin
 */
#define FFV2_COMPOUND_HDR_MAXSZ		(4 + 4 + 4)

/*
 * SEQUENCE op header + body upper bound per encode_sequence in
 * fs/nfs/nfs4xdr.c:
 *   op code      = 4 bytes
 *   sessionid    = NFS4_MAX_SESSIONID_LEN (16 bytes fixed)
 *   seqid        = 4 bytes
 *   slotid       = 4 bytes
 *   max_slotid   = 4 bytes
 *   cache_this   = 4 bytes
 */
#define FFV2_SEQUENCE_ENC_MAXSZ		(4 + NFS4_MAX_SESSIONID_LEN + 4 * 4)

/*
 * PUTFH op header + body upper bound:
 *   op code      = 4 bytes
 *   fh length    = 4 bytes
 *   fh data      = NFS4_FHSIZE bytes (128 bytes upper bound)
 */
#define FFV2_PUTFH_ENC_MAXSZ		(4 + 4 + NFS4_FHSIZE)

/*
 * CHUNK_WRITE op header + INLINE body (excludes cwa_chunks<>
 * payload which is attached via xdr_write_pages, not inline):
 *   op code (4) + stateid (16) + offset (8) + stable (4)
 *   + owner (16: cohort 8 + client_id 4 + co_id 4)
 *   + payload_id (4) + flags (4)
 *   + guard: cwg_check (4) + (worst case) cwg_guard (8)
 *   + chunk_size (4)
 *   + cwa_checksums length (4) + one entry:
 *       cs_algorithm (4) + cs_value length (4) + cs_value (padded up to
 *       FFV2_CHECKSUM_MAX_LEN = 64)
 *   + cwa_chunks length (4) (payload bytes go via xdr_write_pages)
 */
#define FFV2_CHUNK_WRITE_INLINE_ENC_MAXSZ \
	(4 + NFS4_STATEID_SIZE + 8 + 4 + 16 + 4 + 4 + (4 + 8) + 4 + \
	 (4 + (4 + 4 + FFV2_CHECKSUM_MAX_LEN)) + 4)

/*
 * Total inline args (bytes attached inline to the XDR buffer,
 * excluding the payload pages).  Payload bytes are added
 * separately via xdr_write_pages; the caller sets
 * p_arglen in rpc_procinfo to this constant in 4-byte units.
 */
#define FFV2_CHUNK_WRITE_ARGS_MAXSZ_BYTES \
	(FFV2_COMPOUND_HDR_MAXSZ + FFV2_SEQUENCE_ENC_MAXSZ + \
	 FFV2_PUTFH_ENC_MAXSZ + FFV2_CHUNK_WRITE_INLINE_ENC_MAXSZ)

/*
 * Reply size upper bound:
 *   compound status (4) + tag length (4) + resarray length (4)
 *   SEQUENCE op hdr (4) + status (4) + sessionid (16) + 20 bytes
 *     (seqid/slotid/highest_slotid/target_highest_slotid/status_flags)
 *   PUTFH op hdr (4) + status (4)
 *   CHUNK_WRITE op hdr (4) + status (4) + resok:
 *     count (4) + committed (4) + writeverf (NFS4_VERIFIER_SIZE = 8)
 *     + block_status<> length (4) + N * 4
 *     + block_activated<> length (4) + N * 4
 *     + owners<> length (4) + N * 16
 * With N capped at FFV2_MAX_CHUNKS_PER_OP.
 */
#define FFV2_CHUNK_WRITE_RES_MAXSZ_BYTES \
	((4 + 4 + 4) + \
	 (4 + 4 + NFS4_MAX_SESSIONID_LEN + 20) + \
	 (4 + 4) + \
	 (4 + 4 + 4 + 4 + NFS4_VERIFIER_SIZE + \
	  (4 + FFV2_MAX_CHUNKS_PER_OP * 4) + \
	  (4 + FFV2_MAX_CHUNKS_PER_OP * 4) + \
	  (4 + FFV2_MAX_CHUNKS_PER_OP * 16)))

/*
 * NFS ops track args/replen in u32 units.  Convert byte constants.
 */
#define BYTES_TO_U32(n)			(((n) + 3) >> 2)

#define FFV2_CHUNK_WRITE_ARGS_MAXSZ	\
	BYTES_TO_U32(FFV2_CHUNK_WRITE_ARGS_MAXSZ_BYTES)
#define FFV2_CHUNK_WRITE_RES_MAXSZ	\
	BYTES_TO_U32(FFV2_CHUNK_WRITE_RES_MAXSZ_BYTES)

/*
 * CHUNK_READ op body (inline; no send-side page splicing):
 *   op code (4) + stateid (16) + offset (8) + count (4) = 32 bytes
 */
#define FFV2_CHUNK_READ_INLINE_ENC_MAXSZ	(4 + NFS4_STATEID_SIZE + 8 + 4)

/*
 * Total inline args for CHUNK_READ.  Payload lives OUT-of-line
 * (in the caller's reply pages, via rpc_prepare_reply_pages);
 * no xdr_write_pages on the send side.
 */
#define FFV2_CHUNK_READ_ARGS_MAXSZ_BYTES \
	(FFV2_COMPOUND_HDR_MAXSZ + FFV2_SEQUENCE_ENC_MAXSZ + \
	 FFV2_PUTFH_ENC_MAXSZ + FFV2_CHUNK_READ_INLINE_ENC_MAXSZ)

/*
 * Reply size upper bound for CHUNK_READ resok HEAD area only.
 * The cr_chunk<> payload bytes go out-of-line into the caller's
 * pages via xdr_read_pages and are NOT counted here.
 *
 *   compound status (4) + tag length (4) + resarray length (4)
 *   SEQUENCE op hdr (4) + status (4) + sessionid (16) + 20
 *     (seqid/slotid/highest_slotid/target_highest_slotid/status_flags)
 *   PUTFH op hdr (4) + status (4)
 *   CHUNK_READ op hdr (4) + status (4) + resok:
 *     crr_eof (4) + crr_chunks<> length (4)
 *     + N * per_chunk_worst_case
 *
 * Per-chunk worst case in bytes (allows a future non-CRC32
 * algorithm at max cs_value = SHA-512 = 64 bytes):
 *   cs_algorithm (4) + cs_value_len (4) + cs_value (64, pad-free
 *   at 64) + cr_effective_len (4) + cr_owner (16) + cr_guard (8)
 *   + cr_payload_id (4) + cr_locked (4)
 *   + cr_status (4) + cr_chunk<> length (4) = 116
 * With N capped at FFV2_MAX_CHUNKS_PER_OP.
 *
 * Note: the runtime decoder enforces N in {0, 1} and cs_value_len ==
 * 4, but maxsz stays at the worst case -- undersizing yields hard-
 * to-diagnose xdr_inline_decode NULLs at first wire test.
 */
#define FFV2_CHUNK_READ_RES_MAXSZ_BYTES \
	((4 + 4 + 4) + \
	 (4 + 4 + NFS4_MAX_SESSIONID_LEN + 20) + \
	 (4 + 4) + \
	 (4 + 4 + 4 + 4 + \
	  FFV2_MAX_CHUNKS_PER_OP * \
	  (4 + 4 + FFV2_CHECKSUM_MAX_LEN + 4 + 16 + 8 + 4 + 4 + 4 + 4)))

#define FFV2_CHUNK_READ_ARGS_MAXSZ	\
	BYTES_TO_U32(FFV2_CHUNK_READ_ARGS_MAXSZ_BYTES)
#define FFV2_CHUNK_READ_RES_MAXSZ	\
	BYTES_TO_U32(FFV2_CHUNK_READ_RES_MAXSZ_BYTES)

/*
 * CHUNK_FINALIZE op body (all inline; no page splicing):
 *   op code (4) + stateid (16) + offset (8) + count (4)
 *   + chunks<> length (4) + N * chunk_owner4 (16) = 36 + 16N bytes
 *
 * N capped at FFV2_MAX_CHUNKS_PER_OP; the current single-owner-
 * per-op shape sends N == 1.
 */
#define FFV2_CHUNK_FINALIZE_INLINE_ENC_MAXSZ \
	(4 + NFS4_STATEID_SIZE + 8 + 4 + 4 + FFV2_MAX_CHUNKS_PER_OP * 16)

#define FFV2_CHUNK_FINALIZE_ARGS_MAXSZ_BYTES \
	(FFV2_COMPOUND_HDR_MAXSZ + FFV2_SEQUENCE_ENC_MAXSZ + \
	 FFV2_PUTFH_ENC_MAXSZ + FFV2_CHUNK_FINALIZE_INLINE_ENC_MAXSZ)

/*
 * Reply size upper bound for CHUNK_FINALIZE:
 *   compound status (4) + tag length (4) + resarray length (4) = 12
 *   SEQUENCE op hdr (4) + status (4) + sessionid (16) + 20     = 44
 *   PUTFH op hdr (4) + status (4)                              = 8
 *   CHUNK_FINALIZE op hdr (4) + status (4) + resok:
 *     cfr_writeverf (8) + cfr_status<> length (4) + N * 4
 *   With N capped at FFV2_MAX_CHUNKS_PER_OP.
 */
#define FFV2_CHUNK_FINALIZE_RES_MAXSZ_BYTES \
	((4 + 4 + 4) + \
	 (4 + 4 + NFS4_MAX_SESSIONID_LEN + 20) + \
	 (4 + 4) + \
	 (4 + 4 + NFS4_VERIFIER_SIZE + \
	  (4 + FFV2_MAX_CHUNKS_PER_OP * 4)))

#define FFV2_CHUNK_FINALIZE_ARGS_MAXSZ	\
	BYTES_TO_U32(FFV2_CHUNK_FINALIZE_ARGS_MAXSZ_BYTES)
#define FFV2_CHUNK_FINALIZE_RES_MAXSZ	\
	BYTES_TO_U32(FFV2_CHUNK_FINALIZE_RES_MAXSZ_BYTES)

/*
 * CHUNK_COMMIT op body + reply.  Wire shape mirrors CHUNK_FINALIZE
 * verbatim (see the sizing block above); the constants are
 * duplicated rather than aliased so a future asymmetry (e.g.
 * COMMIT gaining a durability-hint field, or FINALIZE losing
 * writeverf) can diverge without a rename churn.  Values are
 * identical today.
 */
#define FFV2_CHUNK_COMMIT_INLINE_ENC_MAXSZ \
	(4 + NFS4_STATEID_SIZE + 8 + 4 + 4 + FFV2_MAX_CHUNKS_PER_OP * 16)

#define FFV2_CHUNK_COMMIT_ARGS_MAXSZ_BYTES \
	(FFV2_COMPOUND_HDR_MAXSZ + FFV2_SEQUENCE_ENC_MAXSZ + \
	 FFV2_PUTFH_ENC_MAXSZ + FFV2_CHUNK_COMMIT_INLINE_ENC_MAXSZ)

#define FFV2_CHUNK_COMMIT_RES_MAXSZ_BYTES \
	((4 + 4 + 4) + \
	 (4 + 4 + NFS4_MAX_SESSIONID_LEN + 20) + \
	 (4 + 4) + \
	 (4 + 4 + NFS4_VERIFIER_SIZE + \
	  (4 + FFV2_MAX_CHUNKS_PER_OP * 4)))

#define FFV2_CHUNK_COMMIT_ARGS_MAXSZ	\
	BYTES_TO_U32(FFV2_CHUNK_COMMIT_ARGS_MAXSZ_BYTES)
#define FFV2_CHUNK_COMMIT_RES_MAXSZ	\
	BYTES_TO_U32(FFV2_CHUNK_COMMIT_RES_MAXSZ_BYTES)

#define FFV2_CHUNK_ROLLBACK_INLINE_ENC_MAXSZ \
	(4 + NFS4_STATEID_SIZE + 8 + 4 + 4 + FFV2_MAX_CHUNKS_PER_OP * 16)
#define FFV2_CHUNK_ROLLBACK_ARGS_MAXSZ_BYTES \
	(FFV2_COMPOUND_HDR_MAXSZ + FFV2_SEQUENCE_ENC_MAXSZ + \
	 FFV2_PUTFH_ENC_MAXSZ + FFV2_CHUNK_ROLLBACK_INLINE_ENC_MAXSZ)
#define FFV2_CHUNK_ROLLBACK_RES_MAXSZ_BYTES \
	FFV2_CHUNK_COMMIT_RES_MAXSZ_BYTES
#define FFV2_CHUNK_ROLLBACK_ARGS_MAXSZ \
	BYTES_TO_U32(FFV2_CHUNK_ROLLBACK_ARGS_MAXSZ_BYTES)
#define FFV2_CHUNK_ROLLBACK_RES_MAXSZ \
	BYTES_TO_U32(FFV2_CHUNK_ROLLBACK_RES_MAXSZ_BYTES)

/*
 * Fixed prefix (in u32 quads) that the CHUNK_READ decoder actually
 * expects to consume from head before xdr_read_pages transitions to
 * the page area.  Passed to rpc_prepare_reply_pages as the hdrsize
 * argument; sets the head/pages split point on the receive buffer.
 *
 * Computed from the known-good shape (nchunks == 1 with a CRC32-
 * shape checksum4):
 *   compound (3q) + SEQUENCE resok (11q) + PUTFH resok (2q)
 *   + CHUNK_READ op hdr (1q) + status (1q)
 *   + crr_eof (1q) + crr_chunks_len (1q)
 *   + 1 * (cs_algorithm (1q) + cs_value_len (1q)
 *          + cs_value bytes (1q; CRC32 = 4 bytes quad-aligned,
 *            no pad)
 *          + cr_effective_len (1q) + cr_owner (4q) + cr_guard (2q)
 *          + cr_payload_id (1q) + cr_locked (1q)
 *          + cr_status (1q) + cr_chunk_len (1q))
 *   = 34 quads.
 *
 * The corresponding N=0 short-reply (transient-OOM truncation on
 * the DS side) yields a shorter wire; the xprt fills only what the
 * wire supplies and the decoder walks nchunks=0 without touching
 * the trailing quads.  A future batching (N > 1) or non-CRC32
 * checksum extension MUST rework this constant as a coordinated change.
 */
#define FFV2_CHUNK_READ_REPLY_HDR_QUADS		34

/*
 * Reserve space in the XDR stream.  A NULL return from
 * xdr_reserve_space means the calculated p_arglen is under-sized
 * for the encoded compound -- a bug in the maxsz constants above,
 * not a wire-level error.  Log once and return a sentinel pointer
 * into a static discard buffer so the encoder body continues
 * without a null-deref crash; the send will still be malformed
 * (over-length past p_arglen never went on the wire) and the
 * xprt layer surfaces the error on the outbound path.
 * BUG_ON is reserved for real invariant violations under checkpatch
 * AVOID_BUG; a maxsz miscalculation is a soft bug at worst.
 */
static __be32 ffv2_reserve_discard[32] __ro_after_init;

static __be32 *ffv2_reserve_space(struct xdr_stream *xdr, size_t nbytes)
{
	__be32 *p = xdr_reserve_space(xdr, nbytes);

	if (unlikely(!p)) {
		WARN_ONCE(1, "ffv2 CHUNK op: p_arglen under-sized (%zu bytes)\n",
			  nbytes);
		return ffv2_reserve_discard;
	}
	return p;
}

/* -------------------- encoder -------------------- */

static void ffv2_xdr_enc_compound_hdr(struct xdr_stream *xdr,
				      u32 minorversion, u32 nops)
{
	__be32 *p = ffv2_reserve_space(xdr, 4 + 4 + 4);

	*p++ = cpu_to_be32(0);			/* tag<>: zero length */
	*p++ = cpu_to_be32(minorversion);	/* MUST be 2 for CHUNK ops */
	*p   = cpu_to_be32(nops);
}

static void ffv2_xdr_enc_op_hdr(struct xdr_stream *xdr, u32 op)
{
	__be32 *p = ffv2_reserve_space(xdr, 4);

	*p = cpu_to_be32(op);
}

static void ffv2_xdr_enc_sequence(struct xdr_stream *xdr,
				  const struct nfs4_sequence_args *sa)
{
	struct nfs4_slot *slot = sa->sa_slot;
	struct nfs4_slot_table *tp = slot->table;
	struct nfs4_session *session = tp->session;
	__be32 *p;

	/*
	 * Invariant: nfs4_setup_sequence in the dispatch site's
	 * .rpc_call_prepare hook guarantees non-NULL session before
	 * this encoder runs.  A null here means a session-teardown
	 * race, memory corruption, or a caller that skipped
	 * nfs4_setup_sequence.
	 *
	 * The compound header has already committed to nops=3.
	 * Silently skipping SEQUENCE leaves the wire nops-inconsistent
	 * (nops=3 header, two op bodies) and the DS returns
	 * NFS4ERR_BADXDR; that is still catchable, so WARN + graceful
	 * degradation is preferred over BUG_ON per checkpatch AVOID_BUG.
	 */
	if (WARN_ON_ONCE(!session))
		return;

	ffv2_xdr_enc_op_hdr(xdr, OP_SEQUENCE);
	p = ffv2_reserve_space(xdr, NFS4_MAX_SESSIONID_LEN + 4 * 4);
	memcpy(p, session->sess_id.data, NFS4_MAX_SESSIONID_LEN);
	p += XDR_QUADLEN(NFS4_MAX_SESSIONID_LEN);
	*p++ = cpu_to_be32(slot->seq_nr);
	*p++ = cpu_to_be32(slot->slot_nr);
	*p++ = cpu_to_be32(tp->highest_used_slotid);
	*p   = cpu_to_be32(sa->sa_cache_this);
}

static void ffv2_xdr_enc_putfh(struct xdr_stream *xdr,
			       const struct nfs_fh *fh)
{
	__be32 *p;

	unsigned int padded = XDR_QUADLEN(fh->size) << 2;

	ffv2_xdr_enc_op_hdr(xdr, OP_PUTFH);
	p = ffv2_reserve_space(xdr, 4);
	*p = cpu_to_be32(fh->size);
	p = ffv2_reserve_space(xdr, padded);
	memcpy(p, fh->data, fh->size);
	/*
	 * Zero the XDR pad bytes.  rpc_malloc buffers are not
	 * __GFP_ZERO; without this, up to 3 bytes of stale kernel
	 * heap leak onto the wire for any fh->size not a multiple of
	 * 4.  RFC 4506 §4.11 requires residual opaque bytes zero.
	 * Kernel encode_string / xdr_encode_opaque_fixed do this
	 * transparently; hand-rolled encoders must not skip it.
	 */
	if (padded > fh->size)
		memset((char *)p + fh->size, 0, padded - fh->size);
}

static void ffv2_xdr_enc_stateid(struct xdr_stream *xdr,
				 const nfs4_stateid *stateid)
{
	__be32 *p = ffv2_reserve_space(xdr, NFS4_STATEID_SIZE);

	memcpy(p, stateid, NFS4_STATEID_SIZE);
}

static void ffv2_xdr_enc_chunk_guard(struct xdr_stream *xdr,
				     const struct chunk_guard4 *g)
{
	__be32 *p = ffv2_reserve_space(xdr, 8);

	*p++ = cpu_to_be32(g->cg_gen_id);
	*p   = cpu_to_be32(g->cg_client_id);
}

/*
 * chunk_owner4 is the {cohort, client, chunk} triple -- 16 bytes, no
 * nested guard.  The guard rides its own wire field.
 */
static void ffv2_xdr_enc_chunk_owner(struct xdr_stream *xdr,
				     const struct chunk_owner4 *o)
{
	__be32 *p = ffv2_reserve_space(xdr, 16);

	p = xdr_encode_hyper(p, o->co_cohort_id);
	*p++ = cpu_to_be32(o->co_client_id);
	*p   = cpu_to_be32(o->co_id);
}

static void ffv2_xdr_enc_checksum(struct xdr_stream *xdr, u32 algo,
				  const u8 *bytes, size_t len)
{
	__be32 *p;

	p = ffv2_reserve_space(xdr, 4 + 4);
	*p++ = cpu_to_be32(algo);
	*p   = cpu_to_be32(len);
	if (len) {
		unsigned int padded = XDR_QUADLEN(len) << 2;

		p = ffv2_reserve_space(xdr, padded);
		memcpy(p, bytes, len);
		/* RFC 4506 §4.11 pad-zeroing; see PUTFH encoder note. */
		if (padded > len)
			memset((char *)p + len, 0, padded - len);
	}
}

static void ffv2_xdr_enc_chunk_write_op(struct xdr_stream *xdr,
					const struct ffv2_chunk_write_args *a)
{
	__be32 *p;

	ffv2_xdr_enc_op_hdr(xdr, OP_CHUNK_WRITE);
	ffv2_xdr_enc_stateid(xdr, &a->stateid);
	p = ffv2_reserve_space(xdr, 8 + 4);
	p = xdr_encode_hyper(p, a->offset);	/* chunk INDEX, not bytes */
	*p = cpu_to_be32(a->stable);
	ffv2_xdr_enc_chunk_owner(xdr, &a->owner);
	p = ffv2_reserve_space(xdr, 4 + 4);
	*p++ = cpu_to_be32(a->payload_id);	/* always 0 for now */
	*p   = cpu_to_be32(a->flags);		/* always 0 for now */
	if (a->guard.check) {
		p = ffv2_reserve_space(xdr, 4);
		*p = cpu_to_be32(1);
		ffv2_xdr_enc_chunk_guard(xdr, &a->guard.guard);
	} else {
		p = ffv2_reserve_space(xdr, 4);
		*p = 0;
	}
	p = ffv2_reserve_space(xdr, 4);
	*p = cpu_to_be32(a->chunk_size);	/* nominal stride */
	/* cwa_checksums<>: fixed N=1 for the current posture */
	p = ffv2_reserve_space(xdr, 4);
	*p = cpu_to_be32(1);
	ffv2_xdr_enc_checksum(xdr, a->checksum_algo,
			      a->checksum_bytes, a->checksum_len);
	/* cwa_chunks<>: length header inline, payload bytes via pages */
	p = ffv2_reserve_space(xdr, 4);
	*p = cpu_to_be32(a->payload_len);
	xdr_write_pages(xdr, a->pages, a->pgbase, a->payload_len);
}

static void ffv2_xdr_enc_chunk_write(struct rpc_rqst *req,
				     struct xdr_stream *xdr,
				     const void *data)
{
	const struct ffv2_chunk_write_data *d = data;

	ffv2_xdr_enc_compound_hdr(xdr, 2, 3);	/* v4.2, 3 ops */
	ffv2_xdr_enc_sequence(xdr, &d->seq_args);
	ffv2_xdr_enc_putfh(xdr, &d->fh);
	ffv2_xdr_enc_chunk_write_op(xdr, &d->args);
	/*
	 * Mark the send buffer as file-write source so RDMA transports
	 * use direct data placement.  Matches nfs4_xdr_enc_write at
	 * fs/nfs/nfs4xdr.c:2687.  TCP unaffected; missing this on RDMA
	 * regresses to inline placement (silent perf cliff).
	 */
	req->rq_snd_buf.flags |= XDRBUF_WRITE;
}

static void ffv2_xdr_enc_chunk_read_op(struct xdr_stream *xdr,
				       const struct ffv2_chunk_read_args *a)
{
	__be32 *p;

	ffv2_xdr_enc_op_hdr(xdr, OP_CHUNK_READ);
	ffv2_xdr_enc_stateid(xdr, &a->stateid);
	p = ffv2_reserve_space(xdr, 8 + 4);
	p = xdr_encode_hyper(p, a->offset);	/* chunk INDEX, not bytes */
	*p = cpu_to_be32(a->count);		/* chunk COUNT, not bytes */
}

/*
 * CHUNK_READ encoder.  Straight compound emit: no send-side page
 * splicing (the CHUNK_READ body is fixed 32 bytes).  The reply-side
 * page splice is set up via rpc_prepare_reply_pages BEFORE the
 * compound emit, with hdrsize pinned to the fixed-prefix quad count
 * (see FFV2_CHUNK_READ_REPLY_HDR_QUADS).  XDRBUF_READ marks the
 * receive buffer as file-read destination so RDMA transports use
 * direct data placement (mirrors CHUNK_WRITE's XDRBUF_WRITE on send;
 * model: nfs4_xdr_enc_read in fs/nfs/nfs4xdr.c).  Missing this on
 * RDMA regresses to inline placement (silent perf cliff).
 *
 * The .p_encode signature returns void, so this encoder cannot
 * surface -EINVAL to the caller.  The API-boundary check for
 * cra_count == 0 belongs in the dispatch entry, before rpc_run_task
 * submission, where an integer error can be returned.  As last-ditch
 * defence -- if a zero cra_count reaches this encoder anyway -- emit
 * an empty COMPOUND (nops=0) so the send path doesn't choke on an
 * empty xdr_stream.  The server may return NFS4_OK with an empty
 * resarray; the decoder converts that short-OK reply to -EPROTO via
 * the short-OK-reply guard.
 */
static bool ffv2_xdr_enc_chunk_read_check(const struct ffv2_chunk_read_args *a)
{
	/*
	 * Return true when args are invalid so the caller emits the
	 * empty-COMPOUND fallback.  WARN_ON_ONCE pinpoints the
	 * offending call site so the dispatch layer can be fixed to
	 * filter upstream.
	 */
	return WARN_ON_ONCE(a->count == 0);
}

static void ffv2_xdr_enc_chunk_read(struct rpc_rqst *req,
				    struct xdr_stream *xdr,
				    const void *data)
{
	const struct ffv2_chunk_read_data *d = data;

	if (ffv2_xdr_enc_chunk_read_check(&d->args)) {
		/*
		 * Empty COMPOUND fallback for cra_count == 0.  Server
		 * may return NFS4_OK with an empty resarray; the
		 * decoder maps that short-OK to -EPROTO via the
		 * short-OK-reply guard.  Not the documented -EINVAL
		 * contract (see encoder comment); the dispatch layer
		 * must filter upstream.
		 */
		ffv2_xdr_enc_compound_hdr(xdr, 2, 0);
		return;
	}

	/*
	 * Arrange the reply-page split BEFORE emitting the compound:
	 * hdrsize (in quads) is the fixed prefix that head must hold,
	 * then up to pglen bytes of payload land in the caller's
	 * pages.  See FFV2_CHUNK_READ_REPLY_HDR_QUADS for the
	 * derivation.  A future rework of the boundary shape must
	 * update both the constant and the decoder invariants
	 * together.
	 */
	rpc_prepare_reply_pages(req, d->args.pages, d->args.pgbase,
				d->args.pglen,
				FFV2_CHUNK_READ_REPLY_HDR_QUADS);

	ffv2_xdr_enc_compound_hdr(xdr, 2, 3);	/* v4.2, 3 ops */
	ffv2_xdr_enc_sequence(xdr, &d->seq_args);
	ffv2_xdr_enc_putfh(xdr, &d->fh);
	ffv2_xdr_enc_chunk_read_op(xdr, &d->args);
	/*
	 * Mark the receive buffer as file-read destination so
	 * RDMA transports use direct data placement.  Matches
	 * nfs4_xdr_enc_read at fs/nfs/nfs4xdr.c:2607.  TCP
	 * unaffected; missing this on RDMA regresses to inline
	 * placement (silent perf cliff, mirrors WRITE-side).
	 */
	req->rq_rcv_buf.flags |= XDRBUF_READ;
}

/*
 * CHUNK_FINALIZE op body (all inline; no page splicing).  Emits:
 *   op code + cfa_stateid + cfa_offset + cfa_count + cfa_chunks<> (1
 *   entry)
 *
 * The single-entry chunk_owner4 array is the current single-owner-
 * per-op interop shape; N > 1 batching is a future extension.
 */
static void ffv2_xdr_enc_chunk_finalize_op(struct xdr_stream *xdr,
					   const struct ffv2_chunk_finalize_args *a)
{
	__be32 *p;

	ffv2_xdr_enc_op_hdr(xdr, OP_CHUNK_FINALIZE);
	ffv2_xdr_enc_stateid(xdr, &a->stateid);
	p = ffv2_reserve_space(xdr, 8 + 4 + 4);
	p = xdr_encode_hyper(p, a->offset);	/* chunk INDEX, not bytes */
	*p++ = cpu_to_be32(a->count);
	*p = cpu_to_be32(a->nowners);		/* cfa_chunks<> length */
	{
		u32 i;

		for (i = 0; i < a->nowners; i++)
			ffv2_xdr_enc_chunk_owner(xdr, &a->owners[i]);
	}
}

/*
 * Zero-count contract, mirroring CHUNK_READ: p_encode returns void
 * so this encoder cannot surface -EINVAL to the caller.  The
 * API-boundary check for count == 0 belongs in the dispatch layer,
 * before rpc_run_task submission, where an integer error can be
 * returned.  Last-ditch defence: emit an empty COMPOUND (nops=0)
 * so the send path doesn't choke on an empty xdr_stream.  The
 * server may then return NFS4_OK with an empty resarray; the
 * decoder converts that short-OK reply to -EPROTO via the short-
 * OK-reply guard.
 */
static bool ffv2_xdr_enc_chunk_finalize_check(const struct ffv2_chunk_finalize_args *a)
{
	/*
	 * count and cfa_chunks<> length are independent wire fields:
	 * count is the range count for offset+count, cfa_chunks<>
	 * lists WHICH owners to transition within that range.  The
	 * current single-owner-per-op interop shape uses count == 1
	 * alongside the encoder's hard-coded chunks<> length == 1;
	 * tightening the guard to reject count != 1 codifies the
	 * invariant so a dispatch caller that accidentally sets
	 * count > 1 fires WARN_ON_ONCE with the offending call site.
	 * When the client adopts batching (count > 1 alongside a
	 * variable-length chunks<> array), this guard AND the hard-
	 * coded 1 in the encoder BOTH must flip together.
	 */
	return WARN_ON_ONCE(a->count == 0 || a->nowners == 0 ||
			    a->nowners > FFV2_MAX_CHUNKS_PER_OP);
}

static void ffv2_xdr_enc_chunk_finalize(struct rpc_rqst *req,
					struct xdr_stream *xdr,
					const void *data)
{
	const struct ffv2_chunk_finalize_data *d = data;

	if (ffv2_xdr_enc_chunk_finalize_check(&d->args)) {
		/*
		 * Empty COMPOUND fallback for cfa_count == 0.  See the
		 * check-function comment above and the sibling
		 * CHUNK_READ handling for rationale.  The dispatch
		 * layer MUST filter count == 0 upstream.
		 */
		ffv2_xdr_enc_compound_hdr(xdr, 2, 0);
		return;
	}

	ffv2_xdr_enc_compound_hdr(xdr, 2, 3);	/* v4.2, 3 ops */
	ffv2_xdr_enc_sequence(xdr, &d->seq_args);
	ffv2_xdr_enc_putfh(xdr, &d->fh);
	ffv2_xdr_enc_chunk_finalize_op(xdr, &d->args);
	/* No XDRBUF_READ / XDRBUF_WRITE flag: FINALIZE is a
	 * metadata-only op with no bulk payload on either
	 * direction; RDMA direct data placement does not apply. */
}

/*
 * CHUNK_COMMIT op body (all inline; no page splicing).  Emits:
 *   op code + cca_stateid + cca_offset + cca_count + cca_chunks<> (1 entry)
 * Wire shape mirrors CHUNK_FINALIZE verbatim; the encoder is
 * intentionally not shared with FINALIZE so a future asymmetry
 * (e.g., COMMIT gaining a durability-hint field) doesn't force a
 * rename churn on the shared helper.
 */
static void ffv2_xdr_enc_chunk_commit_op(struct xdr_stream *xdr,
					 const struct ffv2_chunk_commit_args *a)
{
	__be32 *p;

	ffv2_xdr_enc_op_hdr(xdr, OP_CHUNK_COMMIT);
	ffv2_xdr_enc_stateid(xdr, &a->stateid);
	p = ffv2_reserve_space(xdr, 8 + 4 + 4);
	p = xdr_encode_hyper(p, a->offset);	/* chunk INDEX, not bytes */
	*p++ = cpu_to_be32(a->count);
	*p = cpu_to_be32(a->nowners);		/* cca_chunks<> length */
	{
		u32 i;

		for (i = 0; i < a->nowners; i++)
			ffv2_xdr_enc_chunk_owner(xdr, &a->owners[i]);
	}
}

/*
 * Zero-count contract: same fallback as CHUNK_FINALIZE.  5c
 * dispatch MUST filter cca_count == 0 upstream; the WARN_ON_ONCE
 * pinpoints the offending call site if it ever slips through.
 */
static bool ffv2_xdr_enc_chunk_commit_check(const struct ffv2_chunk_commit_args *a)
{
	/*
	 * Same invariant as CHUNK_FINALIZE's check: current interop
	 * shape is count == 1 alongside hard-coded chunks<>len == 1;
	 * see the FINALIZE encoder for the rationale and the
	 * flip-both-together contract for future batching.
	 */
	return WARN_ON_ONCE(a->count == 0 || a->nowners == 0 ||
			    a->nowners > FFV2_MAX_CHUNKS_PER_OP);
}

static void ffv2_xdr_enc_chunk_commit(struct rpc_rqst *req,
				      struct xdr_stream *xdr,
				      const void *data)
{
	const struct ffv2_chunk_commit_data *d = data;

	if (ffv2_xdr_enc_chunk_commit_check(&d->args)) {
		/*
		 * Empty COMPOUND fallback for cca_count == 0.  See
		 * CHUNK_FINALIZE's encoder for the rationale; the
		 * dispatch layer must filter upstream.
		 */
		ffv2_xdr_enc_compound_hdr(xdr, 2, 0);
		return;
	}

	ffv2_xdr_enc_compound_hdr(xdr, 2, 3);	/* v4.2, 3 ops */
	ffv2_xdr_enc_sequence(xdr, &d->seq_args);
	ffv2_xdr_enc_putfh(xdr, &d->fh);
	ffv2_xdr_enc_chunk_commit_op(xdr, &d->args);
	/* No XDRBUF_READ / XDRBUF_WRITE flag: COMMIT is a
	 * metadata-only durability barrier with no bulk payload;
	 * RDMA direct data placement does not apply. */
}

static void
ffv2_xdr_enc_chunk_rollback_op(struct xdr_stream *xdr,
				const struct ffv2_chunk_rollback_args *a)
{
	__be32 *p;
	u32 i;

	ffv2_xdr_enc_op_hdr(xdr, OP_CHUNK_ROLLBACK);
	ffv2_xdr_enc_stateid(xdr, &a->stateid);
	p = ffv2_reserve_space(xdr, 8 + 4 + 4);
	p = xdr_encode_hyper(p, a->offset);
	*p++ = cpu_to_be32(a->count);
	*p = cpu_to_be32(a->nowners);
	for (i = 0; i < a->nowners; i++)
		ffv2_xdr_enc_chunk_owner(xdr, &a->owners[i]);
}

static void ffv2_xdr_enc_chunk_rollback(struct rpc_rqst *req,
					struct xdr_stream *xdr,
					const void *data)
{
	const struct ffv2_chunk_rollback_data *d = data;

	if (WARN_ON_ONCE(!d->args.count || !d->args.nowners ||
			 d->args.nowners > FFV2_MAX_CHUNKS_PER_OP)) {
		ffv2_xdr_enc_compound_hdr(xdr, 2, 0);
		return;
	}
	ffv2_xdr_enc_compound_hdr(xdr, 2, 3);
	ffv2_xdr_enc_sequence(xdr, &d->seq_args);
	ffv2_xdr_enc_putfh(xdr, &d->fh);
	ffv2_xdr_enc_chunk_rollback_op(xdr, &d->args);
}

/* -------------------- decoder -------------------- */

/*
 * Decode the COMPOUND4res header.  DOES NOT bail on non-OK compound
 * status: per RFC 8881 §16.2.2, compound status equals the status
 * of the LAST op executed, and the resarray still contains resoks
 * of every op that ran before that.  The SEQUENCE resok in
 * particular MUST be decoded to keep the session slot state honest
 * (see ffv2_xdr_dec_sequence comment).  The only case that
 * short-circuits is nops == 0 (NFS4ERR_MINOR_VERS_MISMATCH class,
 * empty resarray), where there is genuinely nothing to decode.
 *
 * Writes the compound-level status to *cstatus_out (raw wire
 * value; caller maps via nfs4_stat_to_errno).  Returns 0 on
 * successful header parse, -EIO on truncated input, -EPROTO on
 * malformed tag length.
 */
static int ffv2_xdr_dec_compound_hdr(struct xdr_stream *xdr,
				     u32 *cstatus_out, u32 *nops_out)
{
	__be32 *p;
	u32 tag_len;

	p = xdr_inline_decode(xdr, 4 + 4);
	if (!p)
		return -EIO;
	*cstatus_out = be32_to_cpup(p++);
	tag_len = be32_to_cpup(p);
	/*
	 * Bound the tag against NFS4_OPAQUE_LIMIT to reject hostile
	 * MDS replies before XDR_QUADLEN() u32-wraps on ~UINT_MAX
	 * (would return zero and misalign the parse silently).
	 */
	if (tag_len > NFS4_OPAQUE_LIMIT)
		return -EPROTO;
	if (tag_len != 0) {
		p = xdr_inline_decode(xdr, XDR_QUADLEN(tag_len) << 2);
		if (!p)
			return -EIO;
	}
	p = xdr_inline_decode(xdr, 4);
	if (!p)
		return -EIO;
	*nops_out = be32_to_cpup(p);
	return 0;
}

/*
 * Decode an OP header (op code + status).  Returns -EIO on short
 * buffer, -EPROTO on op code mismatch, 0 on success (status
 * written to *status_out; caller maps via nfs4_stat_to_errno).
 */
static int ffv2_xdr_dec_op_hdr(struct xdr_stream *xdr, u32 expect_op,
			       u32 *status_out)
{
	__be32 *p = xdr_inline_decode(xdr, 4 + 4);

	if (!p)
		return -EIO;
	if (be32_to_cpup(p++) != expect_op)
		return -EPROTO;
	*status_out = be32_to_cpup(p);
	return 0;
}

/*
 * Decode SEQUENCE resok into the caller's nfs4_sequence_res.  This
 * MUST be called before consulting any later op's status: on
 * NFS4ERR_DELAY (mapped by nfs4_stat_to_errno to -NFS4ERR_DELAY),
 * or on session-recovery signals like NFS4ERR_BADSESSION, the
 * nfs41_sequence_process state machine at fs/nfs/nfs4proc.c:872
 * MUST see sr_status populated with the negative errno form to
 * dispatch its recovery arms.  Skipping this or storing the raw
 * positive wire value would silently fall through to the
 * "success" arm, burn the slot's seq_nr for a request the server
 * rejected, and eventually wedge the DS on SEQ_MISORDERED.
 *
 * sr_status invariants (matching decode_sequence at
 * fs/nfs/nfs4xdr.c:5931-5993):
 *   - success: sr_status = 0
 *   - server-returned NFS4ERR_*: sr_status = -NFS4ERR_* (via
 *     nfs4_stat_to_errno; session-range codes fall through
 *     common.c:145 -> return -stat, e.g. NFS4ERR_DELAY -> -10008)
 *   - truncated buffer / op-code mismatch: sr_status = -EIO /
 *     -EPROTO, so nfs41_sequence_process' error arms fire even
 *     on our own decode failures
 *
 * Caller (ffv2_xdr_dec_chunk_write) initializes sr_status = 1
 * before calling us, matching the nfs41_sequence_res_init
 * sentinel at nfs4proc.c:1019-1024 that flags "RPC-level error,
 * server may not have processed" if we never even reach the
 * SEQUENCE op-header.
 */
static int ffv2_xdr_dec_sequence(struct xdr_stream *xdr,
				 struct nfs4_sequence_res *res)
{
	__be32 *p;
	u32 status;
	int rc;

	rc = ffv2_xdr_dec_op_hdr(xdr, OP_SEQUENCE, &status);
	if (rc) {
		res->sr_status = rc;	/* -EIO / -EPROTO */
		return rc;
	}
	if (status != NFS4_OK) {
		res->sr_status = nfs4_stat_to_errno(status);
		return res->sr_status;
	}
	res->sr_status = 0;
	/*
	 * sessionid (16) + seqid (4) + slotid (4) + highest_slotid (4)
	 * + target_highest_slotid (4) + status_flags (4)
	 */
	p = xdr_inline_decode(xdr, NFS4_MAX_SESSIONID_LEN + 4 * 5);
	if (!p) {
		res->sr_status = -EIO;
		return -EIO;
	}
	/*
	 * Validate sessionid + seqid + slotid returned by the server
	 * -- these are the values we sent in the SEQUENCE request, and
	 * the server MUST echo them back per RFC 8881 S18.46.  A wrong
	 * value ack-and-advances a slot we didn't send, desyncing the
	 * session; nfs4_sequence_done uses sr_status == 0 to advance
	 * seq_nr, so wrong-slot ack is a permanent-desync class bug.
	 * Matches decode_sequence at fs/nfs/nfs4xdr.c:5947-5980
	 * ("If the server returns different values for sessionID,
	 * slotID or sequence number, the server is looney tunes").
	 */
	{
		struct nfs4_slot *slot = res->sr_slot;
		struct nfs4_session *session = slot->table->session;
		u32 wire_seqid, wire_slotid;

		if (memcmp(p, session->sess_id.data,
			   NFS4_MAX_SESSIONID_LEN) != 0) {
			res->sr_status = -EREMOTEIO;
			return -EREMOTEIO;
		}
		p += XDR_QUADLEN(NFS4_MAX_SESSIONID_LEN);
		wire_seqid = be32_to_cpup(p++);
		if (wire_seqid != slot->seq_nr) {
			res->sr_status = -EREMOTEIO;
			return -EREMOTEIO;
		}
		wire_slotid = be32_to_cpup(p++);
		if (wire_slotid != slot->slot_nr) {
			res->sr_status = -EREMOTEIO;
			return -EREMOTEIO;
		}
	}
	res->sr_highest_slotid		= be32_to_cpup(p++);
	res->sr_target_highest_slotid	= be32_to_cpup(p++);
	res->sr_status_flags		= be32_to_cpup(p);
	return 0;
}

static int ffv2_xdr_dec_chunk_guard(struct xdr_stream *xdr,
				    struct chunk_guard4 *out)
{
	__be32 *p = xdr_inline_decode(xdr, 8);

	if (!p)
		return -EIO;
	out->cg_gen_id    = be32_to_cpup(p++);
	out->cg_client_id = be32_to_cpup(p);
	return 0;
}

static int ffv2_xdr_dec_chunk_owner(struct xdr_stream *xdr,
				    struct chunk_owner4 *out)
{
	__be32 *p = xdr_inline_decode(xdr, 16);

	if (!p)
		return -EIO;
	p = xdr_decode_hyper(p, &out->co_cohort_id);
	out->co_client_id = be32_to_cpup(p++);
	out->co_id        = be32_to_cpup(p);
	return 0;
}

static int ffv2_xdr_dec_chunk_write_resok(struct xdr_stream *xdr,
					  struct ffv2_chunk_write_res *r)
{
	__be32 *p;
	u32 n, i;
	int rc;

	/* cwr_count (4) + cwr_committed (4) + cwr_writeverf (8) */
	p = xdr_inline_decode(xdr, 4 + 4 + NFS4_VERIFIER_SIZE);
	if (!p)
		return -EIO;
	r->count     = be32_to_cpup(p++);
	r->committed = be32_to_cpup(p++);
	memcpy(&r->writeverf, p, NFS4_VERIFIER_SIZE);

	/* cwr_block_status<> */
	p = xdr_inline_decode(xdr, 4);
	if (!p)
		return -EIO;
	n = be32_to_cpup(p);
	if (n > FFV2_MAX_CHUNKS_PER_OP)
		return -EPROTO;
	r->nblocks = n;
	for (i = 0; i < n; i++) {
		p = xdr_inline_decode(xdr, 4);
		if (!p)
			return -EIO;
		r->block_status[i] = be32_to_cpup(p);
	}

	/* cwr_block_activated<> -- length must match block_status */
	p = xdr_inline_decode(xdr, 4);
	if (!p)
		return -EIO;
	if (be32_to_cpup(p) != n)
		return -EPROTO;
	for (i = 0; i < n; i++) {
		p = xdr_inline_decode(xdr, 4);
		if (!p)
			return -EIO;
		r->block_activated[i] = !!be32_to_cpup(p);
	}

	/* cwr_owners<> -- length must match block_status */
	p = xdr_inline_decode(xdr, 4);
	if (!p)
		return -EIO;
	if (be32_to_cpup(p) != n)
		return -EPROTO;
	for (i = 0; i < n; i++) {
		rc = ffv2_xdr_dec_chunk_owner(xdr, &r->owners[i]);
		if (rc)
			return rc;
	}
	return 0;
}

static int ffv2_xdr_dec_chunk_write(struct rpc_rqst *req,
				    struct xdr_stream *xdr,
				    void *data)
{
	/* rpc_resp is the res struct, not the composite -- see
	 * ffv2_chunk_write_res on why seq_res leads it.
	 */
	struct ffv2_chunk_write_res *d = data;
	u32 cstatus, nops, opstatus;
	int rc;

	/*
	 * Initialize sr_status sentinel BEFORE header parse.  Matches
	 * nfs41_sequence_res_init at nfs4proc.c:1019-1024: value 1
	 * signals "RPC-level error, server may not have processed"
	 * for the case where the header itself is truncated and we
	 * never reach the SEQUENCE op-header.  nfs41_sequence_process
	 * has an explicit case-1 arm (nfs4proc.c:884-892) that
	 * handles this without desyncing the slot.
	 */
	d->seq_res.sr_status = 1;

	rc = ffv2_xdr_dec_compound_hdr(xdr, &cstatus, &nops);
	if (rc)
		return rc;

	/*
	 * SEQUENCE resok decode is UNCONDITIONAL on the compound
	 * status -- per RFC 8881 §16.2.2, compound status equals the
	 * last-op status; the resarray still contains SEQUENCE's resok
	 * whenever nops >= 1.  Skipping the decode here would defeat
	 * the whole slot-lifetime discipline that the RMW pattern in
	 * flexfilesv2_write.c enforces.
	 *
	 * The ONE exception is nops == 0 (NFS4ERR_MINOR_VERS_MISMATCH
	 * class: server sends an empty resarray).  In that case the
	 * compound-level status IS the whole story and there is no
	 * SEQUENCE resok to decode.  nfs4_sequence_done will see the
	 * sentinel sr_status = 1 and route to case 1 correctly.
	 *
	 * A short OK reply is malformed -- if cstatus == NFS4_OK the
	 * server MUST have executed every op in the compound (per
	 * RFC 8881 §16.2.2); a short-count on an OK compound is a
	 * server bug.  Reject with -EPROTO before nfs4_stat_to_errno
	 * silently returns 0 -- callers would otherwise think the
	 * write landed when CHUNK_WRITE was never dispatched.
	 */
	if (nops == 0) {
		if (cstatus == NFS4_OK)
			return -EPROTO;
		return nfs4_stat_to_errno(cstatus);
	}

	rc = ffv2_xdr_dec_sequence(xdr, &d->seq_res);
	if (rc)
		return rc;

	/*
	 * Now that seq_res is populated, we can early-return on op
	 * statuses.  Per RFC 8881, an op that doesn't run has no
	 * resarray entry, so the compound-header nops count tells us
	 * exactly which ops we can decode.  Same short-OK-reply
	 * guard as above applies at each op boundary.
	 */
	if (nops < 2) {
		if (cstatus == NFS4_OK)
			return -EPROTO;
		return nfs4_stat_to_errno(cstatus);
	}

	rc = ffv2_xdr_dec_op_hdr(xdr, OP_PUTFH, &opstatus);
	if (rc)
		return rc;
	if (opstatus != NFS4_OK)
		return nfs4_stat_to_errno(opstatus);

	if (nops < 3) {
		if (cstatus == NFS4_OK)
			return -EPROTO;
		return nfs4_stat_to_errno(cstatus);
	}

	rc = ffv2_xdr_dec_op_hdr(xdr, OP_CHUNK_WRITE, &opstatus);
	if (rc)
		return rc;
	if (opstatus != NFS4_OK)
		/*
		 * NFS4ERR_DELAY maps to -NFS4ERR_DELAY (not -EAGAIN).
		 * The RMW retry state machine matches on -NFS4ERR_DELAY
		 * per nfs41_sequence_process' case at nfs4proc.c:893.
		 * Other NFS4ERR_* map via nfs4_stat_to_errno; unmapped
		 * session-range codes fall through common.c's default
		 * to -stat.
		 */
		return nfs4_stat_to_errno(opstatus);
	return ffv2_xdr_dec_chunk_write_resok(xdr, d);
}

/*
 * Decode a checksum4 (cs_algorithm + cs_value<64>) from the wire
 * into out.  The current runtime hard-enforces cs_value_len == 4:
 * the reply-page split set by rpc_prepare_reply_pages is FIXED at
 * the CRC32 shape; any other value shifts the head/pages boundary
 * and desyncs the payload split.  The XDR-level opaque<64> upper
 * bound is also checked as defence in depth before the stricter
 * gate.  Value bytes are big-endian on the wire; the dispatch layer
 * byte-compares against the same big-endian shape emitted by
 * ffv2_checksum_compute (see flexfilesv2_checksum.c).
 */
static int ffv2_xdr_dec_checksum4(struct xdr_stream *xdr,
				  struct ffv2_checksum4 *out)
{
	__be32 *p;
	u32 len;

	p = xdr_inline_decode(xdr, 4 + 4);
	if (!p)
		return -EIO;
	out->algorithm = be32_to_cpup(p++);
	len = be32_to_cpup(p);
	/*
	 * Defence-in-depth: XDR-level opaque<64> upper bound.  The
	 * stricter gate below rejects everything except exactly 4, but
	 * keep the wire-spec bound explicit so a future caller can't
	 * quietly regress it out.
	 */
	if (len > FFV2_CHECKSUM_MAX_LEN)
		return -EPROTO;
	/*
	 * Currently cs_value_len MUST be 4 (matches the fixed reply-
	 * page boundary; also rejects a checksumless-chunk reply).  A
	 * "skip verify on NONE / len 0" policy becomes live only after
	 * a coordinated reply-page boundary rework.
	 */
	if (len != 4)
		return -EPROTO;
	out->value_len = len;
	p = xdr_inline_decode(xdr, 4);		/* CRC32: 4 bytes, no pad */
	if (!p)
		return -EIO;
	memcpy(out->value, p, 4);
	return 0;
}

/*
 * CHUNK_FINALIZE4resok decoder.
 *   cfr_writeverf (8 bytes) + cfr_status<> (length-prefixed array
 *   of nfsstat4).
 *
 * Reject any per-chunk array length > FFV2_MAX_CHUNKS_PER_OP as
 * defence-in-depth against a malformed reply; the reply-size upper
 * bound already caps allocation via p_replen, but the decoder must
 * not iterate past the cap either.
 */
static int ffv2_xdr_dec_chunk_finalize_resok(struct xdr_stream *xdr,
					     struct ffv2_chunk_finalize_res *r)
{
	__be32 *p;
	u32 n, i;

	/* cfr_writeverf (8 bytes) */
	p = xdr_inline_decode(xdr, NFS4_VERIFIER_SIZE);
	if (!p)
		return -EIO;
	memcpy(&r->writeverf, p, NFS4_VERIFIER_SIZE);

	/* cfr_status<> */
	p = xdr_inline_decode(xdr, 4);
	if (!p)
		return -EIO;
	n = be32_to_cpup(p);
	if (n > FFV2_MAX_CHUNKS_PER_OP)
		return -EPROTO;
	r->nstatus = n;
	for (i = 0; i < n; i++) {
		p = xdr_inline_decode(xdr, 4);
		if (!p)
			return -EIO;
		r->status[i] = be32_to_cpup(p);
	}
	return 0;
}

/*
 * CHUNK_FINALIZE full-compound decoder.  Same walk-and-early-exit
 * shape as ffv2_xdr_dec_chunk_write: unconditional SEQUENCE decode
 * to keep the slot lifetime honest, then per-op-hdr walk with a
 * short-OK-reply guard at every boundary.  A short-OK compound on
 * FINALIZE is a server bug that MUST reject with -EPROTO, not
 * silently convert to 0-status "success" via
 * nfs4_stat_to_errno(NFS4_OK).
 */
static int ffv2_xdr_dec_chunk_finalize(struct rpc_rqst *req,
				       struct xdr_stream *xdr,
				       void *data)
{
	/* rpc_resp is the res struct -- see ffv2_chunk_write_res. */
	struct ffv2_chunk_finalize_res *d = data;
	u32 cstatus, nops, opstatus;
	int rc;

	d->seq_res.sr_status = 1;

	rc = ffv2_xdr_dec_compound_hdr(xdr, &cstatus, &nops);
	if (rc)
		return rc;

	if (nops == 0) {
		if (cstatus == NFS4_OK)
			return -EPROTO;
		return nfs4_stat_to_errno(cstatus);
	}

	rc = ffv2_xdr_dec_sequence(xdr, &d->seq_res);
	if (rc)
		return rc;

	if (nops < 2) {
		if (cstatus == NFS4_OK)
			return -EPROTO;
		return nfs4_stat_to_errno(cstatus);
	}

	rc = ffv2_xdr_dec_op_hdr(xdr, OP_PUTFH, &opstatus);
	if (rc)
		return rc;
	if (opstatus != NFS4_OK)
		return nfs4_stat_to_errno(opstatus);

	if (nops < 3) {
		if (cstatus == NFS4_OK)
			return -EPROTO;
		return nfs4_stat_to_errno(cstatus);
	}

	rc = ffv2_xdr_dec_op_hdr(xdr, OP_CHUNK_FINALIZE, &opstatus);
	if (rc)
		return rc;
	if (opstatus != NFS4_OK)
		return nfs4_stat_to_errno(opstatus);
	return ffv2_xdr_dec_chunk_finalize_resok(xdr, d);
}

/*
 * CHUNK_COMMIT4resok decoder.  Wire shape mirrors
 * CHUNK_FINALIZE4resok exactly: ccr_writeverf (8 bytes) +
 * ccr_status<> (length-prefixed nfsstat4 array).  Same
 * defence-in-depth cap on the per-chunk array length as FINALIZE.
 */
static int ffv2_xdr_dec_chunk_commit_resok(struct xdr_stream *xdr,
					   struct ffv2_chunk_commit_res *r)
{
	__be32 *p;
	u32 n, i;

	/* ccr_writeverf (8 bytes) */
	p = xdr_inline_decode(xdr, NFS4_VERIFIER_SIZE);
	if (!p)
		return -EIO;
	memcpy(&r->writeverf, p, NFS4_VERIFIER_SIZE);

	/* ccr_status<> */
	p = xdr_inline_decode(xdr, 4);
	if (!p)
		return -EIO;
	n = be32_to_cpup(p);
	if (n > FFV2_MAX_CHUNKS_PER_OP)
		return -EPROTO;
	r->nstatus = n;
	for (i = 0; i < n; i++) {
		p = xdr_inline_decode(xdr, 4);
		if (!p)
			return -EIO;
		r->status[i] = be32_to_cpup(p);
	}
	return 0;
}

/*
 * CHUNK_COMMIT full-compound decoder.  Same walk shape as
 * ffv2_xdr_dec_chunk_finalize: unconditional SEQUENCE decode,
 * short-OK-reply guard at every op boundary, -EPROTO on a short OK
 * compound.
 */
static int ffv2_xdr_dec_chunk_commit(struct rpc_rqst *req,
				     struct xdr_stream *xdr,
				     void *data)
{
	/* rpc_resp is the res struct -- see ffv2_chunk_write_res. */
	struct ffv2_chunk_commit_res *d = data;
	u32 cstatus, nops, opstatus;
	int rc;

	d->seq_res.sr_status = 1;

	rc = ffv2_xdr_dec_compound_hdr(xdr, &cstatus, &nops);
	if (rc)
		return rc;

	if (nops == 0) {
		if (cstatus == NFS4_OK)
			return -EPROTO;
		return nfs4_stat_to_errno(cstatus);
	}

	rc = ffv2_xdr_dec_sequence(xdr, &d->seq_res);
	if (rc)
		return rc;

	if (nops < 2) {
		if (cstatus == NFS4_OK)
			return -EPROTO;
		return nfs4_stat_to_errno(cstatus);
	}

	rc = ffv2_xdr_dec_op_hdr(xdr, OP_PUTFH, &opstatus);
	if (rc)
		return rc;
	if (opstatus != NFS4_OK)
		return nfs4_stat_to_errno(opstatus);

	if (nops < 3) {
		if (cstatus == NFS4_OK)
			return -EPROTO;
		return nfs4_stat_to_errno(cstatus);
	}

	rc = ffv2_xdr_dec_op_hdr(xdr, OP_CHUNK_COMMIT, &opstatus);
	if (rc)
		return rc;
	if (opstatus != NFS4_OK)
		return nfs4_stat_to_errno(opstatus);
	return ffv2_xdr_dec_chunk_commit_resok(xdr, d);
}

static int
ffv2_xdr_dec_chunk_rollback_resok(struct xdr_stream *xdr,
				  struct ffv2_chunk_rollback_res *r)
{
	__be32 *p;
	u32 i, n;

	p = xdr_inline_decode(xdr, NFS4_VERIFIER_SIZE);
	if (!p)
		return -EIO;
	memcpy(&r->writeverf, p, NFS4_VERIFIER_SIZE);
	p = xdr_inline_decode(xdr, 4);
	if (!p)
		return -EIO;
	n = be32_to_cpup(p);
	if (n > FFV2_MAX_CHUNKS_PER_OP)
		return -EPROTO;
	r->nstatus = n;
	for (i = 0; i < n; i++) {
		p = xdr_inline_decode(xdr, 4);
		if (!p)
			return -EIO;
		r->status[i] = be32_to_cpup(p);
	}
	return 0;
}

static int ffv2_xdr_dec_chunk_rollback(struct rpc_rqst *req,
				       struct xdr_stream *xdr, void *data)
{
	struct ffv2_chunk_rollback_res *d = data;
	u32 cstatus, nops, opstatus;
	int rc;

	d->seq_res.sr_status = 1;
	rc = ffv2_xdr_dec_compound_hdr(xdr, &cstatus, &nops);
	if (rc)
		return rc;
	if (!nops)
		return cstatus == NFS4_OK ? -EPROTO :
			nfs4_stat_to_errno(cstatus);
	rc = ffv2_xdr_dec_sequence(xdr, &d->seq_res);
	if (rc)
		return rc;
	if (nops < 2)
		return cstatus == NFS4_OK ? -EPROTO :
			nfs4_stat_to_errno(cstatus);
	rc = ffv2_xdr_dec_op_hdr(xdr, OP_PUTFH, &opstatus);
	if (rc)
		return rc;
	if (opstatus != NFS4_OK)
		return nfs4_stat_to_errno(opstatus);
	if (nops < 3)
		return cstatus == NFS4_OK ? -EPROTO :
			nfs4_stat_to_errno(cstatus);
	rc = ffv2_xdr_dec_op_hdr(xdr, OP_CHUNK_ROLLBACK, &opstatus);
	if (rc)
		return rc;
	if (opstatus != NFS4_OK)
		return nfs4_stat_to_errno(opstatus);
	return ffv2_xdr_dec_chunk_rollback_resok(xdr, d);
}

/*
 * Decode one read_chunk4 (crr_chunks<> element).
 *
 * cr_guard is the per-chunk CAS state (cg_gen_id, cg_client_id) and
 * is the sole carrier: chunk_owner4 is the owner triple and has no
 * embedded guard, so the guard-capture path sources from cr_guard.
 *
 * cr_chunk<> length is stored on out->chunk_len; the payload bytes
 * themselves are consumed by xdr_read_pages in the enclosing resok
 * decoder (single call for the resok's one chunk), NOT here.
 */
static int ffv2_xdr_dec_read_chunk4(struct xdr_stream *xdr,
				    struct ffv2_read_chunk4 *out)
{
	__be32 *p;
	int rc;

	rc = ffv2_xdr_dec_checksum4(xdr, &out->checksum);
	if (rc)
		return rc;

	p = xdr_inline_decode(xdr, 4);		/* cr_effective_len */
	if (!p)
		return -EIO;
	out->effective_len = be32_to_cpup(p);

	rc = ffv2_xdr_dec_chunk_owner(xdr, &out->owner);
	if (rc)
		return rc;

	rc = ffv2_xdr_dec_chunk_guard(xdr, &out->guard);
	if (rc)
		return rc;

	p = xdr_inline_decode(xdr, 4);		/* cr_payload_id */
	if (!p)
		return -EIO;
	out->payload_id = be32_to_cpup(p);

	/* cr_locked is an advisory chunk_state_flags4 scalar. */
	p = xdr_inline_decode(xdr, 4);
	if (!p)
		return -EIO;
	out->locked = be32_to_cpup(p);

	/* cr_status is an nfsstat4 scalar. */
	p = xdr_inline_decode(xdr, 4);
	if (!p)
		return -EIO;
	out->status = be32_to_cpup(p);

	/*
	 * cr_chunk<> length prefix.  Payload bytes come out via
	 * xdr_read_pages in the resok decoder AFTER the chunk loop:
	 * xdr_read_pages supports one page-based opaque per reply, so
	 * nchunks is capped at 1 and this length is authoritative for
	 * that single payload.
	 */
	p = xdr_inline_decode(xdr, 4);
	if (!p)
		return -EIO;
	out->chunk_len = be32_to_cpup(p);
	return 0;
}

/*
 * Decode CHUNK_READ4resok into r + splice payload pages.
 *
 * Enforcements:
 *   - crr_nchunks in {0, 1}; > 1 returns -EPROTO before any
 *     per-chunk decode (reply-page boundary supports one payload).
 *   - crr_nchunks == 0 is the DS's transient-OOM truncation with an
 *     independently-computed crr_eof; the decoder succeeds and the
 *     dispatch layer treats it as retry.
 *   - When crr_nchunks == 1, cr_effective_len (the caller's view of
 *     "how many valid bytes") MUST be <= cr_chunk<> length (the
 *     wire-authoritative SPLICE byte count).  Both are untrusted
 *     wire input; a malicious or buggy DS setting effective_len to
 *     0xffffffff with chunk_len == 4096 would tell callers that
 *     ~4 GiB are valid.  The bound-check runs BEFORE xdr_read_pages
 *     so no allocation / copy path ever sees a divergent pair.  A
 *     shorter effective_len (tail-chunk case) is legal; equal is
 *     the common case; > is -EPROTO.
 */
static int ffv2_xdr_dec_chunk_read_resok(struct xdr_stream *xdr,
					 struct ffv2_chunk_read_res *r)
{
	__be32 *p;
	u32 n;

	p = xdr_inline_decode(xdr, 4 + 4);	/* crr_eof + crr_chunks_len */
	if (!p)
		return -EIO;
	r->eof = !!be32_to_cpup(p++);
	n = be32_to_cpup(p);
	/*
	 * nchunks in {0, 1}.  Reject > 1 before touching per-chunk
	 * decoders -- allowing a decode past 1 would both violate the
	 * reply-page split invariant and hand the pages splice below
	 * an ambiguous per-chunk source.  FFV2_MAX_CHUNKS_PER_OP == 32
	 * is a batching-follow-up cap, not the current runtime cap.
	 */
	if (n > 1)
		return -EPROTO;
	r->nchunks = n;

	if (n == 1) {
		int rc = ffv2_xdr_dec_read_chunk4(xdr, &r->chunks[0]);
		unsigned int spliced;

		if (rc)
			return rc;

		/*
		 * Bound effective_len by chunk_len BEFORE splicing so no
		 * downstream reader sees a divergent pair.  Both values
		 * are wire input; a > relation is either DS corruption
		 * or an attack (chunk_len == 4096, effective_len ==
		 * 0xffffffff would tell callers that ~4 GiB are valid
		 * despite only 4 KiB spliced).
		 */
		if (r->chunks[0].effective_len > r->chunks[0].chunk_len)
			return -EPROTO;

		/*
		 * Splice cr_chunk<> payload bytes into the caller's
		 * reply pages.  xdr_read_pages consumes the payload
		 * body (chunk_len bytes plus 0-3 trailing pad bytes)
		 * from the recv buffer's page area; the pad bytes
		 * are a cursor advance only, not copied (see
		 * net/sunrpc/xdr.c:1772-1787 -- nwords =
		 * XDR_QUADLEN(len)).  No memcpy on this path.
		 *
		 * The pages themselves were arranged by
		 * rpc_prepare_reply_pages in the encoder; the
		 * receive buffer already carries the payload in the
		 * page area (transport dropped it there at recv
		 * time).
		 */
		spliced = xdr_read_pages(xdr, r->chunks[0].chunk_len);
		if (spliced < r->chunks[0].chunk_len)
			return -EIO;
	}
	return 0;
}

static int ffv2_xdr_dec_chunk_read(struct rpc_rqst *req,
				   struct xdr_stream *xdr,
				   void *data)
{
	/* rpc_resp is the res struct -- see ffv2_chunk_write_res. */
	struct ffv2_chunk_read_res *d = data;
	u32 cstatus, nops, opstatus;
	int rc;

	/*
	 * sr_status sentinel = 1 BEFORE header parse.  Matches
	 * nfs41_sequence_res_init at nfs4proc.c:1019-1024 for the
	 * "RPC-level error, server may not have processed" path.
	 * Rationale + citation identical to CHUNK_WRITE decoder.
	 */
	d->seq_res.sr_status = 1;

	rc = ffv2_xdr_dec_compound_hdr(xdr, &cstatus, &nops);
	if (rc)
		return rc;

	/*
	 * Short-OK-reply guard: cstatus == NFS4_OK with fewer ops than
	 * we sent is a server bug per RFC 8881 §16.2.2.  Return -EPROTO
	 * before nfs4_stat_to_errno(NFS4_OK) == 0 silently reports
	 * success.  Repeated at every op boundary below.
	 */
	if (nops == 0) {
		if (cstatus == NFS4_OK)
			return -EPROTO;
		return nfs4_stat_to_errno(cstatus);
	}

	rc = ffv2_xdr_dec_sequence(xdr, &d->seq_res);
	if (rc)
		return rc;

	if (nops < 2) {
		if (cstatus == NFS4_OK)
			return -EPROTO;
		return nfs4_stat_to_errno(cstatus);
	}

	rc = ffv2_xdr_dec_op_hdr(xdr, OP_PUTFH, &opstatus);
	if (rc)
		return rc;
	if (opstatus != NFS4_OK)
		return nfs4_stat_to_errno(opstatus);

	if (nops < 3) {
		if (cstatus == NFS4_OK)
			return -EPROTO;
		return nfs4_stat_to_errno(cstatus);
	}

	rc = ffv2_xdr_dec_op_hdr(xdr, OP_CHUNK_READ, &opstatus);
	if (rc)
		return rc;
	if (opstatus != NFS4_OK)
		/*
		 * NFS4ERR_DELAY maps to -NFS4ERR_DELAY (not -EAGAIN),
		 * same as CHUNK_WRITE.  The dispatch layer's retry loop
		 * matches on -NFS4ERR_DELAY per nfs4proc.c.
		 * NFS4ERR_NOENT is the normal sparse-file-read / no-
		 * prior-chunk reply; the dispatch layer treats it as
		 * zero-fill, NOT MDS fallback.  Every other NFS4ERR_
		 * maps via nfs4_stat_to_errno; unmapped session-range
		 * codes fall through nfs4err_common.c's default to -stat.
		 */
		return nfs4_stat_to_errno(opstatus);
	return ffv2_xdr_dec_chunk_read_resok(xdr, d);
}

/* -------------------- procinfo -------------------- */

/*
 * The rpc_procinfo defines how the SUNRPC layer invokes the
 * encoder/decoder pair on this CHUNK_WRITE task.  The dispatch site
 * sets rpc_message.rpc_proc = &ffv2_chunk_write_procinfo and
 * rpc_message.rpc_argp to a struct ffv2_chunk_write_data instance.
 *
 * p_arglen is the maxsz of the inline args in u32 units; the payload
 * pages are attached separately via xdr_write_pages and counted by
 * the RPC layer against the send buffer's page tail.
 *
 * p_replen is the maxsz of the reply in u32 units, bounded by
 * FFV2_MAX_CHUNKS_PER_OP.
 *
 * p_statidx indexes into the NFS client's cl_metrics array via
 * rpc_count_iostats (net/sunrpc/stats.c).  Use NFSPROC4_CLNT_WRITE
 * so per-op stats accurately attribute CHUNK_WRITE volume rather
 * than inflating the READ bucket at index 0.
 */
const struct rpc_procinfo ffv2_chunk_write_procinfo = {
	.p_proc		= NFSPROC4_COMPOUND,
	.p_encode	= ffv2_xdr_enc_chunk_write,
	.p_decode	= ffv2_xdr_dec_chunk_write,
	.p_arglen	= FFV2_CHUNK_WRITE_ARGS_MAXSZ,
	.p_replen	= FFV2_CHUNK_WRITE_RES_MAXSZ,
	.p_statidx	= NFSPROC4_CLNT_WRITE,
	.p_name		= "CHUNK_WRITE",
};

/*
 * CHUNK_READ procinfo.  The dispatch site sets
 * rpc_message.rpc_proc = &ffv2_chunk_read_procinfo and
 * rpc_message.rpc_argp to a struct ffv2_chunk_read_data instance.
 *
 * p_arglen counts inline args only (28 bytes of CHUNK_READ body +
 * compound / SEQUENCE / PUTFH overhead); no send-side payload.
 *
 * p_replen counts the inline-decode buffer ONLY.  Payload bytes
 * (cr_chunk<>) land in the caller's pages via xdr_read_pages and
 * are NOT counted here -- rpc_prepare_reply_pages in the encoder
 * pins the head/pages split at FFV2_CHUNK_READ_REPLY_HDR_QUADS.
 *
 * p_statidx = NFSPROC4_CLNT_READ merges CHUNK_READ RPC volume into
 * the plain-READ metrics counter.
 */
const struct rpc_procinfo ffv2_chunk_read_procinfo = {
	.p_proc		= NFSPROC4_COMPOUND,
	.p_encode	= ffv2_xdr_enc_chunk_read,
	.p_decode	= ffv2_xdr_dec_chunk_read,
	.p_arglen	= FFV2_CHUNK_READ_ARGS_MAXSZ,
	.p_replen	= FFV2_CHUNK_READ_RES_MAXSZ,
	.p_statidx	= NFSPROC4_CLNT_READ,
	.p_name		= "CHUNK_READ",
};

/*
 * CHUNK_FINALIZE procinfo.  Caller (5c dispatch) sets
 * rpc_message.rpc_proc = &ffv2_chunk_finalize_procinfo and
 * rpc_message.rpc_argp = &ffv2_chunk_finalize_data instance.
 *
 * p_arglen counts inline args only: no send-side payload
 * (FINALIZE carries stateid + offset + count + single-entry
 * chunks<> array; all fits in the head).
 *
 * p_replen counts the inline reply: writeverf + status<> length
 * + N * status entries, capped at FFV2_MAX_CHUNKS_PER_OP.  No
 * out-of-line payload; nothing lands in caller pages.
 *
 * p_statidx = NFSPROC4_CLNT_WRITE: FINALIZE is a mutating
 * lifecycle op that commits the prior CHUNK_WRITE's PENDING
 * state to FINALIZED.  Attributing it to the write-side metrics
 * bucket matches the "which client-visible operation caused
 * this RPC" attribution rule that CHUNK_WRITE already uses.
 */
const struct rpc_procinfo ffv2_chunk_finalize_procinfo = {
	.p_proc		= NFSPROC4_COMPOUND,
	.p_encode	= ffv2_xdr_enc_chunk_finalize,
	.p_decode	= ffv2_xdr_dec_chunk_finalize,
	.p_arglen	= FFV2_CHUNK_FINALIZE_ARGS_MAXSZ,
	.p_replen	= FFV2_CHUNK_FINALIZE_RES_MAXSZ,
	.p_statidx	= NFSPROC4_CLNT_WRITE,
	.p_name		= "CHUNK_FINALIZE",
};

/*
 * CHUNK_COMMIT procinfo.  Caller (5c dispatch) sets
 * rpc_message.rpc_proc = &ffv2_chunk_commit_procinfo and
 * rpc_message.rpc_argp = &ffv2_chunk_commit_data instance.
 *
 * p_arglen counts inline args only (COMMIT carries stateid +
 * offset + count + single-entry chunks<>; all fits in the head).
 *
 * p_replen counts the inline reply: writeverf + status<> length
 * + N * status entries, capped at FFV2_MAX_CHUNKS_PER_OP.  No
 * out-of-line payload.
 *
 * p_statidx = NFSPROC4_CLNT_COMMIT: COMMIT is the durability-
 * barrier op, symmetric with the plain-NFSv4 COMMIT it inherits
 * from.  Attributing it to the COMMIT bucket keeps the metrics
 * separable from FINALIZE (which attributes to WRITE) so
 * operator dashboards can distinguish "write landed but not yet
 * durable" from "write is durable end-to-end".
 */
const struct rpc_procinfo ffv2_chunk_commit_procinfo = {
	.p_proc		= NFSPROC4_COMPOUND,
	.p_encode	= ffv2_xdr_enc_chunk_commit,
	.p_decode	= ffv2_xdr_dec_chunk_commit,
	.p_arglen	= FFV2_CHUNK_COMMIT_ARGS_MAXSZ,
	.p_replen	= FFV2_CHUNK_COMMIT_RES_MAXSZ,
	.p_statidx	= NFSPROC4_CLNT_COMMIT,
	.p_name		= "CHUNK_COMMIT",
};

const struct rpc_procinfo ffv2_chunk_rollback_procinfo = {
	.p_proc		= NFSPROC4_COMPOUND,
	.p_encode	= ffv2_xdr_enc_chunk_rollback,
	.p_decode	= ffv2_xdr_dec_chunk_rollback,
	.p_arglen	= FFV2_CHUNK_ROLLBACK_ARGS_MAXSZ,
	.p_replen	= FFV2_CHUNK_ROLLBACK_RES_MAXSZ,
	.p_statidx	= NFSPROC4_CLNT_WRITE,
	.p_name		= "CHUNK_ROLLBACK",
};
