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
 *   + owner (12) + payload_id (4) + flags (4)
 *   + guard: cwg_check (4) + (worst case) cwg_guard (8)
 *   + chunk_size (4)
 *   + cwa_checksums length (4) + one entry:
 *       cs_algorithm (4) + cs_value length (4) + cs_value (padded up to
 *       FFV2_CHECKSUM_MAX_LEN = 64)
 *   + cwa_chunks length (4) (payload bytes go via xdr_write_pages)
 */
#define FFV2_CHUNK_WRITE_INLINE_ENC_MAXSZ \
	(4 + NFS4_STATEID_SIZE + 8 + 4 + 12 + 4 + 4 + (4 + 8) + 4 + \
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
 *     + owners<> length (4) + N * 12
 * With N capped at FFV2_MAX_CHUNKS_PER_OP.
 */
#define FFV2_CHUNK_WRITE_RES_MAXSZ_BYTES \
	((4 + 4 + 4) + \
	 (4 + 4 + NFS4_MAX_SESSIONID_LEN + 20) + \
	 (4 + 4) + \
	 (4 + 4 + 4 + 4 + NFS4_VERIFIER_SIZE + \
	  (4 + FFV2_MAX_CHUNKS_PER_OP * 4) + \
	  (4 + FFV2_MAX_CHUNKS_PER_OP * 4) + \
	  (4 + FFV2_MAX_CHUNKS_PER_OP * 12)))

/*
 * NFS ops track args/replen in u32 units.  Convert byte constants.
 */
#define BYTES_TO_U32(n)			(((n) + 3) >> 2)

#define FFV2_CHUNK_WRITE_ARGS_MAXSZ	\
	BYTES_TO_U32(FFV2_CHUNK_WRITE_ARGS_MAXSZ_BYTES)
#define FFV2_CHUNK_WRITE_RES_MAXSZ	\
	BYTES_TO_U32(FFV2_CHUNK_WRITE_RES_MAXSZ_BYTES)

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
		WARN_ONCE(1, "ffv2 CHUNK_WRITE: p_arglen under-sized (%zu bytes)\n",
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

static void ffv2_xdr_enc_chunk_owner(struct xdr_stream *xdr,
				     const struct chunk_owner4 *o)
{
	__be32 *p;

	ffv2_xdr_enc_chunk_guard(xdr, &o->co_guard);
	p = ffv2_reserve_space(xdr, 4);
	*p = cpu_to_be32(o->co_id);
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

static int ffv2_xdr_dec_chunk_owner(struct xdr_stream *xdr,
				    struct chunk_owner4 *out)
{
	__be32 *p = xdr_inline_decode(xdr, 12);

	if (!p)
		return -EIO;
	out->co_guard.cg_gen_id    = be32_to_cpup(p++);
	out->co_guard.cg_client_id = be32_to_cpup(p++);
	out->co_id                 = be32_to_cpup(p);
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
