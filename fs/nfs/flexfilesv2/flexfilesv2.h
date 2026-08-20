/* SPDX-License-Identifier: GPL-2.0 */
/*
 * NFSv4 Flexfile Version 2 layout driver data structures.
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 *
 * Wire format defined by draft-haynes-nfsv4-flexfiles-v2 and its
 * companion I-Ds (flexfiles-v2-layout, -chunks, -encoding-registry).
 */

#ifndef FS_NFS_NFS4FLEXFILES_V2_LAYOUT_H
#define FS_NFS_NFS4FLEXFILES_V2_LAYOUT_H

#include <linux/atomic.h>
#include <linux/math64.h>
#include <linux/refcount.h>
#include <linux/nfs4.h>
#include <linux/sunrpc/sched.h>
#include "../pnfs.h"

/* NFSv4 status extensions assigned by the Flex Files v2 draft. */
#define FFV2_NFS4ERR_PAYLOAD_NOT_ATOMIC	10098u
#define FFV2_NFS4ERR_CHUNK_GUARDED	10100u

/*
 * checksum_algorithm4 enum values (checksum4.cs_algorithm on the
 * wire) per draft-haynes-nfsv4-flexfiles-v2-chunks.  CRC32 and CRC32C
 * are wired; NONE means "checksum absent" and is used by non-erasure
 * paths; FLETCHER4 / SHA256 / SHA512 / BLAKE3 are
 * recognized-and-refused (client falls back to MDS via -EOPNOTSUPP).
 */
#define FFV2_CHECKSUM_ALG_NONE		0
#define FFV2_CHECKSUM_ALG_CRC32		1
#define FFV2_CHECKSUM_ALG_CRC32C	2
#define FFV2_CHECKSUM_ALG_FLETCHER4	3
#define FFV2_CHECKSUM_ALG_SHA256	4
#define FFV2_CHECKSUM_ALG_SHA512	5
#define FFV2_CHECKSUM_ALG_BLAKE3	6

/*
 * Longest supported checksum digest in bytes (SHA512 upper bound
 * per checksum4.cs_value<64> in the wire XDR).  Buffer sizing for
 * on-stack checksum output uses this.  For the currently wired
 * algorithms (CRC32 / CRC32C), 4 bytes always fits.
 */
#define FFV2_CHECKSUM_MAX_LEN		64

/*
 * CHUNK op codes per draft-haynes-nfsv4-flexfiles-v2.
 */
#define OP_CHUNK_COMMIT			78
#define OP_CHUNK_FINALIZE		80
#define OP_CHUNK_READ			83
#define OP_CHUNK_ROLLBACK		85
#define OP_CHUNK_WRITE			87

/*
 * Reply-side cap on batched chunks per CHUNK op.  Initial posture is
 * N=1 chunk per op (both CHUNK_WRITE and CHUNK_READ); the cap sizes
 * the reply arrays defensively so a malformed or malicious DS reply
 * can't force an unbounded allocation.  32 leaves room for a
 * batched-N follow-up without protocol churn.
 */
#define FFV2_MAX_CHUNKS_PER_OP		32

/* FFv2 barriers must complete when a connected DS stops replying. */
static inline void ffv2_rpc_bound_timeout(struct rpc_task *task)
{
	task->tk_flags &= ~RPC_TASK_NO_RETRANS_TIMEOUT;
	task->tk_flags |= RPC_TASK_TIMEOUT;
}

/*
 * chunk_guard4 / chunk_owner4 -- wire types shared by every non-
 * PASSTHROUGH CHUNK operation per draft-haynes-nfsv4-flexfiles-v2-
 * chunks.  Fields serialize XDR-big-endian on the wire; in-memory
 * shape here is host-endian and packed at build_chunk_owner time by
 * subsequent commits.
 *
 * cg_client_id is the writer identity the metadata server assigned
 * to this layout, echoed back on every CHUNK operation.  The data
 * server compares it against the tsa_client_id it recorded for the
 * layout stateid and rejects a mismatch with NFS4ERR_BAD_STATEID.
 * Sourced from ffv2_mirror4.ffv2m_client_id; ffv2_cg_client_id_seed
 * below is only the fallback for a metadata server that supplies a
 * reserved sentinel or no identity at all.
 *
 * cg_gen_id is assigned by the data server, not the client.  The
 * server stores old+1 on every accepted CHUNK_WRITE and reports the
 * current value in read_chunk4.cr_guard; a writer only ever echoes
 * back the generation it read.  A client that minted its own would
 * be supplying both sides of the server's compare-and-swap, which is
 * no check at all.
 */
struct chunk_guard4 {
	u32	cg_gen_id;
	u32	cg_client_id;
};

/*
 * chunk_owner4 names a write: co_cohort_id is the transaction,
 * constant across every chunk of one write; co_id says which chunk
 * of that transaction this is.  Per
 * draft-haynes-nfsv4-flexfiles-v2 sec-chunk_owner4, within a single
 * (co_cohort_id, co_client_id) all co_id values MUST be distinct.
 *
 * The guard is NOT nested here.  It is per-chunk compare-and-swap
 * state the data server owns and reports in its own wire field;
 * the owner says who wrote the chunk, the guard says what the next
 * writer must present.
 */
struct chunk_owner4 {
	u64	co_cohort_id;
	u32	co_client_id;
	u32	co_id;
};

/*
 * Per-shard guard slot for the CHUNK_READ dispatch to hand off to
 * the paired CHUNK_WRITE.  Populated by the CHUNK_READ
 * .rpc_call_done ONLY on CRC verify SUCCESS -- a guard captured
 * from unverified data would let the DS's CAS accept corruption
 * because the guard proves generation identity, not payload
 * integrity.
 *
 * `valid` is cleared alongside the fetch-counter re-arm in
 * ffv2_rmw_fetch_stripe, so a prior-cycle guard cannot sit stale
 * in the slot and be read by the paired CHUNK_WRITE.  Array sized
 * [k+m] on the ctx and every slot is a fetch target: parity chunks
 * carry a guard just as data chunks do, and their paired write
 * needs it.  A slot left .valid=false sends the {0,0} sentinel.
 * chunk_guard4 is a plain value type (two u32s), so there is no
 * leak concern for a captured-but-never-consumed guard.
 */
struct ffv2_captured_guard {
	struct chunk_guard4	guard;
	bool			valid;
};

/*
 * Sanity caps for wire-supplied array lengths.  ffv2_layout4 is
 * client-parsed from an MDS-authored buffer; every count is
 * bounds-checked against these before we allocate.
 */
#define NFS4_FFV2_MAX_MIRROR_CNT		1024
#define NFS4_FFV2_MAX_STRIPE_CNT		1024
#define NFS4_FFV2_MAX_DS_PER_STRIPE		256
#define NFS4_FFV2_MAX_VERSIONS_PER_DS		8

/*
 * Reserved sentinel values in the chunk_guard4.cg_client_id space.
 * A data server rejects either value, so layout decoding must reject
 * them before the identity reaches a CHUNK operation.
 */
#define FFV2_CG_CLIENT_ID_NONE		0u
#define FFV2_CG_CLIENT_ID_MDS		0xFFFFFFFFu

/*
 * Encoding-family values on the wire (ffv2_coding_type4 in the
 * draft XDR).  Per the draft's IANA registry
 * (draft-haynes-nfsv4-flexfiles-v2, #tbl-coding-types), the
 * standards-track range is 1..7 contiguous; SNAPRAID_CAUCHY and
 * ISA_L_RS were removed on 2026-07-30 for StreamScale US 8,683,296
 * exposure on their SIMD split-table Galois-field multiply.  Kept
 * as a private #define set rather than a shared enum for now; a
 * follow-up cross-family header can lift these when a second
 * consumer needs them.
 */
#define FFV2_ENCODING_PASSTHROUGH		1
#define FFV2_ENCODING_MOJETTE_SYSTEMATIC	2
#define FFV2_ENCODING_MOJETTE_NON_SYSTEMATIC	3
#define FFV2_ENCODING_RS_VANDERMONDE		4
#define FFV2_ENCODING_REPLICATED		5
#define FFV2_ENCODING_XOR_PARITY		6
#define FFV2_ENCODING_LINUX_MD_RAID		7

/* ffv2_flags4 values consumed by the initial read/write paths. */
#define FFV2_FLAGS_NO_IO_THRU_MDS		2u
#define FFV2_FLAGS_NO_READ_IO			4u
#define FFV2_FLAGS_ONLY_ONE_WRITER		0x10u

/*
 * ffv2_striping4 (wire enum): tells the client how per-shard bytes
 * are placed on the DS backing file.  SPARSE stores each shard at
 * its file-absolute offset (sparse file with holes for the other
 * shards); DENSE packs each shard densely at stripe_index *
 * shard_len (no holes).  The reference server uses DENSE.
 */
#define FFV2_STRIPING_NONE			0
#define FFV2_STRIPING_SPARSE			1
#define FFV2_STRIPING_DENSE			2

/*
 * Per-file in-memory layout header.  Wraps the generic pNFS layout
 * header and will grow to carry v2-specific state (encoding family,
 * per-mirror striping, checksum algorithm) as later commits land.
 */
struct nfs4_ffv2_layout {
	struct pnfs_layout_hdr generic_hdr;
	/*
	 * Per-DS commit tracking.  The generic layer reaches a layout
	 * driver's commit path only through get_ds_info() -> this, so
	 * without it pnfs_commit_list() short-circuits to
	 * PNFS_NOT_ATTEMPTED and every write is committed inband.
	 */
	struct pnfs_ds_commit_info commit_info;
};

static inline struct nfs4_ffv2_layout *
FFV2_LAYOUT_FROM_HDR(struct pnfs_layout_hdr *lo)
{
	return container_of(lo, struct nfs4_ffv2_layout, generic_hdr);
}

/*
 * One (stateid, filehandle) pair the DS accepts for this data-server
 * slot.  ffv2_file_info4 in the draft is a per-NFS-version tuple; the
 * MDS supplies one entry per version it wants us to attempt.
 */
struct nfs4_ffv2_file_info {
	nfs4_stateid		stateid;
	struct nfs_fh		fh;
};

/*
 * One data server slot within a stripe.  Corresponds to
 * ffv2_data_server4 in the draft XDR.
 */
struct nfs4_ffv2_data_server {
	struct nfs4_deviceid	devid;
	u32			commit_bucket;
	u32			efficiency;
	u32			versions_cnt;
	struct nfs4_ffv2_file_info *versions;
	u32			flags;
	/*
	 * user/group are decoded from the wire as opaque UTF-8 strings.
	 * Kernel-side idmap resolution (to kuid_t/kgid_t) is deferred to
	 * the follow-up commit that wires DS-side identity.
	 */
};

/*
 * One stripe within a mirror.  Corresponds to ffv2_stripes4.
 */
struct nfs4_ffv2_stripe {
	u32				data_servers_cnt;
	struct nfs4_ffv2_data_server	*data_servers;
};

/*
 * One mirror within an ffv2 layout.  Corresponds to ffv2_mirror4.
 */
struct nfs4_ffv2_mirror {
	u32			coding_type;
	u32			protection_data;	/* k */
	u32			protection_parity;	/* m */
	u32			striping;
	u32			striping_unit_size;
	u32			client_id;
	u32			checksum_algorithm;
	u32			stripes_cnt;
	struct nfs4_ffv2_stripe	*stripes;
};

/*
 * Per-stripe write context.  Allocated when a chunked write batch
 * starts for a given (io_completion, stripe_off); freed after all
 * k+m DS writes for that stripe complete (refcount = k+m initially,
 * one drop per write_release).
 *
 * The io_completion key ensures that ONLY sibling mirrors of the
 * SAME writer share a ctx.  A second writer to the same stripe
 * offset (different pgio descriptor -> different io_completion)
 * gets its own ctx; joining another writer's ctx would silently
 * overwrite the second writer's data with the first's, since the
 * data pages are only copied on the alloc path.
 *
 * Multiple ctxes can coexist on fls_ctx_list at once: different
 * stripes always, and same-stripe/different-writer under
 * concurrent-writer scenarios.
 */
/*
 * Stripe-context lifecycle.  One header owns a stripe from claim to
 * completion, so these transitions have a single observer rather than
 * k+m siblings watching to decide whether to dispatch or join.  They
 * remain a state machine because the read-modify-write fetch is
 * asynchronous: the owner leaves ASSEMBLING for FETCHING and comes
 * back to READY or FAILED on the fetch completion, not inline.  Set
 * under encode_lock.
 */
enum ffv2_ctx_state {
	FFV2_CTX_ASSEMBLING,	/* initial: shards being zeroed/filled */
	FFV2_CTX_FETCHING,	/* RMW only: k fetches dispatched */
	FFV2_CTX_READY,		/* stripe image complete + encoded */
	FFV2_CTX_FAILED,	/* sticky: mirrors fall back to MDS */
};

struct ffv2_stripe_ctx {
	refcount_t			refcnt;
	u64				stripe_off;	/* file-offset key */
	struct list_head		list;		/* fls->fls_ctx_list */
	u32				k, m;
	u32				shard_len;
	u32				pages_per_shard;
	/*
	 * shard_pages[i] is a length-pages_per_shard page array holding
	 * shard i of the encoded stripe.  The owning header points each
	 * dispatch's args.pages at one of them in turn.
	 */
	struct page			***shard_pages;
	struct mutex			encode_lock;
	bool				encoded;
	enum ffv2_ctx_state		state;		/* under encode_lock */
	/*
	 * RMW fetch bookkeeping (FETCHING state only).  Initialized
	 * by ffv2_rmw_fetch_stripe(); the winner atomically decrements
	 * fetch_pending from k -> 0 across dispatched RPCs and
	 * dispatch-failure paths (single-point helper); last decrement
	 * completes fetch_done.  fetch_status carries the first
	 * negative errno via cmpxchg (first failure wins).  rmw_isize
	 * is the i_size_read snapshot taken after the state gate but
	 * before dispatching fetches, used to derive per-shard
	 * expected byte counts (F6).
	 */
	atomic_t			fetch_pending;
	int				fetch_status;
	struct completion		fetch_done;
	u64				rmw_isize;
	/*
	 * Per-shard captured guard slots.  Sized [k+m], allocated by
	 * ffv2_stripe_ctx_alloc and cleared to `.valid=false` at ctx
	 * alloc and at each ffv2_rmw_fetch_stripe re-arm.  Populated by
	 * ffv2_chunk_read_dispatch_call_done_v4 ONLY on CRC verify
	 * SUCCESS; consumed by ffv2_chunk_write_dispatch_one_mirror.
	 *
	 * The contained-partial read-modify-write path fetches all k+m
	 * shards, parity included -- parity is read for its guard
	 * alone, since ffv2_encode_locked recomputes the bytes.  Paths
	 * that never fetch (full-stripe, safe-append) leave every slot
	 * .valid=false and ship the {0,0} sentinel, which the data
	 * server accepts because its compare-and-swap short-circuits
	 * on an empty chunk.
	 */
	struct ffv2_captured_guard	*captured_guard;
	struct nfs4_ffv2_layout_segment *fls;	/* back-pointer for release */
};

/*
 * In-memory ffv2 layout segment.  The trailing mirror_array carries
 * per-mirror state; the layout is decoded from wire by
 * flexfilesv2xdr.c and consumed by the read/write path in
 * subsequent commits.
 */
struct nfs4_ffv2_layout_segment {
	struct pnfs_layout_segment	generic_hdr;
	u32				flags;
	u32				stats_collect_hint;
	spinlock_t			fls_ctx_lock;
	spinlock_t			fls_pending_lock;
	struct list_head		fls_ctx_list;	/* ffv2_stripe_ctx */
	struct list_head		fls_pending_list;	/* pending chunks */
	wait_queue_head_t		fls_ctx_wq;	/* same-stripe gate */
	/*
	 * Set when this segment is being recalled or cancelled.  New
	 * stripe claims are refused from that point on: writing against
	 * a layout the server is taking back should ask for a fresh one
	 * rather than keep using this one.  Guarded by fls_ctx_lock;
	 * setting it wakes fls_ctx_wq, because a waiter blocked on a
	 * stripe whose owner finishes after the recall would otherwise
	 * sleep until some unrelated stripe was released.
	 */
	bool				fls_claim_closed;
	/*
	 * Per-lseg source of chunk_owner4.co_id.  Seeded to 1 at lseg
	 * alloc; incremented once per CHUNK_WRITE via ffv2_owner_id_next().
	 * Consumers land in subsequent commits.
	 */
	atomic_t			next_owner_id;
	u32				mirror_array_cnt;
	struct nfs4_ffv2_mirror		*mirror_array[]
					__counted_by(mirror_array_cnt);
};

static inline struct nfs4_ffv2_layout_segment *
FFV2_LSEG(struct pnfs_layout_segment *lseg)
{
	return container_of(lseg, struct nfs4_ffv2_layout_segment,
			    generic_hdr);
}

static inline bool
ffv2_avoid_read_on_rw(struct pnfs_layout_segment *lseg)
{
	return lseg->pls_range.iomode == IOMODE_RW &&
	       (FFV2_LSEG(lseg)->flags & FFV2_FLAGS_NO_READ_IO);
}

/*
 * The client must not fall back to MDS proxy I/O when this bit is set.
 * Marking the layout for return lets a later attempt obtain fresh state.
 */
static inline bool
ffv2_no_fallback_to_mds(struct pnfs_layout_segment *lseg)
{
	return FFV2_LSEG(lseg)->flags & FFV2_FLAGS_NO_IO_THRU_MDS;
}

/*
 * True when the MDS has told us we are the exclusive writer for
 * this layout (draft:2220-2227).  With this bit set, CHUNK_WRITE
 * MAY carry cwa_guard.check == FALSE; without it, the client MUST
 * set cwa_guard on every CHUNK_WRITE so chunk_guard4 CAS prevents
 * cross-writer collisions.  While the guard plumbing is not yet
 * in place, callers gate the chunked path on this bit and fall
 * back to MDS otherwise.
 */
static inline bool
ffv2_only_one_writer(struct pnfs_layout_segment *lseg)
{
	return FFV2_LSEG(lseg)->flags & FFV2_FLAGS_ONLY_ONE_WRITER;
}

/*
 * Per-NFS-version parameters the MDS advertises for this deviceid.
 * Corresponds to ff_device_versions4 in the draft, shared verbatim
 * with the FFv1 wire format.
 */
struct nfs4_ffv2_ds_version {
	u32			version;
	u32			minor_version;
	u32			rsize;
	u32			wsize;
	bool			tightly_coupled;
};

/*
 * In-memory representation of a deviceid.  Wraps the generic
 * nfs4_deviceid_node and carries the netaddr list resolved to a
 * struct nfs4_pnfs_ds plus the per-version parameters.  The DS
 * rpc_clnt is created lazily on first use, matching ffv1.
 */
struct nfs4_ffv2_layout_ds {
	struct nfs4_deviceid_node	id_node;
	u32				ds_versions_cnt;
	struct nfs4_ffv2_ds_version	*ds_versions;
	struct nfs4_pnfs_ds		*ds;
};

static inline struct nfs4_ffv2_layout_ds *
FFV2_LAYOUT_DS_FROM_NODE(struct nfs4_deviceid_node *node)
{
	return container_of(node, struct nfs4_ffv2_layout_ds, id_node);
}

/* flexfilesv2xdr.c */
struct nfs4_ffv2_layout_segment *
ffv2_decode_layout(struct nfs4_layoutget_res *lgr, gfp_t gfp_flags);
void ffv2_free_layout_segment(struct nfs4_ffv2_layout_segment *fls);

/* flexfilesv2dev.c */
struct nfs4_deviceid_node *
ffv2_alloc_deviceid_node(struct nfs_server *server, struct pnfs_device *pdev,
			 gfp_t gfp_flags);
void ffv2_free_deviceid_node(struct nfs4_deviceid_node *node);

/*
 * Erasure-encoder plug-in interface.  Each supported coding_type
 * registers one ffv2_encoder_ops.  The write path calls .encode()
 * to produce m parity shards from k systematic data shards; the
 * read path calls .repair() only when a shard is missing (healthy
 * reads bypass the encoder entirely by fetching from the systematic
 * slot).
 *
 * Buffers are caller-allocated; the encoder does not free them.
 * data[] and parity[] are indexed by shard number in the ordering
 * the wire format defines for that coding_type.
 */
struct ffv2_encoder_ops {
	u32			coding_type;
	const char		*name;
	int			(*encode)(u32 k, u32 m, u32 shard_len,
					  const u8 * const *data,
					  u8 * const *parity);
	/*
	 * Reconstruct shard `missing_idx` (in [0, k+m)) from k surviving
	 * shards.  surviving_indices[j] is the original position of
	 * surviving_shards[j] in the full 0..k+m-1 shard vector;
	 * neither array may contain missing_idx.  Order of surviving
	 * shards is caller-chosen (but must be consistent across the
	 * two arrays).  Encoders like XOR that are index-symmetric
	 * may ignore surviving_indices.
	 */
	int			(*repair)(u32 k, u32 m, u32 shard_len,
					  const u32 *surviving_indices,
					  const u8 * const *surviving_shards,
					  u32 missing_idx,
					  u8 *reconstructed);
};

/* flexfilesv2enc.c */
const struct ffv2_encoder_ops *ffv2_find_encoder(u32 coding_type);

/* Per-encoder ops instances, registered in ffv2_encoders[]. */
extern const struct ffv2_encoder_ops ffv2_encoder_xor_parity;
extern const struct ffv2_encoder_ops ffv2_encoder_linux_md;
extern const struct ffv2_encoder_ops ffv2_encoder_rs_vandermonde;
extern const struct ffv2_encoder_ops ffv2_encoder_mojette_systematic;

/* flexfilesv2_write.c */
enum pnfs_try_status
ffv2_write_pagelist_chunked(struct nfs_pgio_header *hdr, int sync);
void ffv2_claim_close(struct nfs4_ffv2_layout_segment *fls);
void ffv2_stripe_ctx_list_drain(struct nfs4_ffv2_layout_segment *fls);
void ffv2_stripe_ctx_put(struct ffv2_stripe_ctx *ctx);

/*
 * Translate a file-absolute byte offset into the DS-side byte
 * offset for the given mirror geometry, per the wire striping
 * enum:
 *
 *   SPARSE: DS stores each shard at its file-absolute offset with
 *           holes for the other shards; no translation needed.
 *   DENSE:  DS packs each shard at stripe_index * shard_len; every
 *           DS's file grows in lockstep with its share of the
 *           logical file.  This is what the reference server uses.
 *   NONE:   unspecified; treat as SPARSE (no translation) to keep
 *           older servers working.
 *
 * shard_len == 0 or a chunked lseg with k == 0 would be a malformed
 * layout; caller must have already validated those before calling.
 */
static inline u64
ffv2_ds_offset(const struct nfs4_ffv2_mirror *mirror, u64 file_off)
{
	u64 stripe_len, stripe_index, dividend;
	u32 within_shard;

	if (mirror->striping != FFV2_STRIPING_DENSE)
		return file_off;
	stripe_len = (u64)mirror->protection_data *
		     mirror->striping_unit_size;
	stripe_index = div64_u64(file_off, stripe_len);
	dividend = file_off;
	within_shard = do_div(dividend, mirror->striping_unit_size);
	return stripe_index * mirror->striping_unit_size + within_shard;
}

/*
 * Client-side chunk-guard state (module scope).
 *
 * ffv2_cg_client_id_seed: fallback writer identity, used only when
 * the layout supplies none -- ffv2m_client_id absent, or set to a
 * reserved sentinel.  Set once at module init via
 * ffv2_chunk_guard_init(): sourced from get_random_u32() and, if it
 * happens to hit either reserved sentinel, rotated to a safe value.
 * All ffv2 mounts share the one value.
 *
 * A layout that supplies an identity always wins: the data server
 * validates the presented cg_client_id against what the metadata
 * server registered for the layout stateid, so a locally invented
 * value would be rejected wherever that binding exists.
 *
 */
extern u32 ffv2_cg_client_id_seed;

void ffv2_chunk_guard_init(void);

/*
 * Set up / tear down the wait queue that parks a CHUNK_WRITE while its
 * chunk guard is re-read after an NFS4ERR_DELAY.  Module-scope, so the
 * module init/exit own the lifetime.
 */
void ffv2_guard_refresh_init(void);
void ffv2_guard_refresh_exit(void);

/*
 * Writer identity to stamp on a CHUNK operation for @mirror.
 *
 * The reserved sentinels are not identities: a client MUST NOT
 * present either, and a metadata server that leaves ffv2m_client_id
 * at one of them has told us nothing.  Fall back to the module seed
 * there rather than putting a value on the wire that the data server
 * is required to reject.
 */
static inline u32 ffv2_cg_client_id(const struct nfs4_ffv2_mirror *mirror)
{
	if (mirror && mirror->client_id != FFV2_CG_CLIENT_ID_NONE &&
	    mirror->client_id != FFV2_CG_CLIENT_ID_MDS)
		return mirror->client_id;
	return ffv2_cg_client_id_seed;
}

static inline u32
ffv2_owner_id_next(struct nfs4_ffv2_layout_segment *fls)
{
	u32 n = (u32)atomic_inc_return(&fls->next_owner_id);

	/*
	 * co_id has no reserved sentinel today, but skip 0 on wrap
	 * defensively -- a co_id of 0 could collide with the natural
	 * zero-init of an unwritten kernel struct in tests.
	 */
	if (unlikely(n == 0))
		n = (u32)atomic_inc_return(&fls->next_owner_id);
	return n;
}

/*
 * Build a fresh chunk_owner4 for one CHUNK_WRITE on this lseg.
 *
 * No generation is stamped: the data server assigns cg_gen_id and
 * reports it in cr_guard, so it is not the client's to choose.
 *
 * co_cohort_id is left 0 until cohort assignment lands.  The draft
 * requires co_id to be distinct within one (co_cohort_id,
 * co_client_id), which ffv2_owner_id_next already gives us per lseg;
 * a constant cohort collapses every write on the lseg into one
 * transaction identity, which is wrong but not yet observable -- the
 * data server matches on co_id alone.
 */
static inline void
ffv2_build_chunk_owner(struct nfs4_ffv2_layout_segment *fls,
		       const struct nfs4_ffv2_mirror *mirror,
		       struct chunk_owner4 *out)
{
	out->co_cohort_id = 0;
	out->co_client_id = ffv2_cg_client_id(mirror);
	out->co_id = ffv2_owner_id_next(fls);
}

/* flexfilesv2_checksum.c */

/*
 * Compute the checksum of `data` (`len` bytes) under `algo` into
 * `out` (writes `*out_len` bytes -- caller-supplied out MUST have
 * at least FFV2_CHECKSUM_MAX_LEN capacity).  Returns 0 on success,
 * -EOPNOTSUPP if algo isn't wired here (caller falls back to
 * MDS-inband).
 */
int ffv2_checksum_compute(u32 algo, const void *data, size_t len,
			  u8 *out, size_t *out_len);

/*
 * Page-array variant of ffv2_checksum_compute -- walks `pages`
 * starting at byte `pgbase` for `len` bytes.  Semantically equivalent
 * to flattening the range into a linear buffer and calling
 * ffv2_checksum_compute (both paths seed at 0 and use the same
 * helper's seed-and-extend contract).
 *
 * Used by the CHUNK_WRITE dispatch path to checksum shards that live
 * in the stripe ctx's shard_pages array without requiring a flat
 * kernel VA.
 */
int ffv2_checksum_compute_pages(u32 algo, struct page **pages, u32 pgbase,
				size_t len, u8 *out, size_t *out_len);

/*
 * Verify `expected` (`expected_len` bytes) against the freshly-
 * computed checksum of `data` (`len` bytes) under `algo`.  Returns
 * 0 on match, -EBADMSG on mismatch, -EOPNOTSUPP if algo isn't
 * wired here.  Constant-time comparison is not required here --
 * the checksum is a wire integrity check, not a cryptographic MAC.
 */
int ffv2_checksum_verify(u32 algo, const void *data, size_t len,
			 const u8 *expected, size_t expected_len);

/*
 * flexfilesv2_xdr_chunk.c -- CHUNK_WRITE and CHUNK_READ wire
 * scaffolds.  The args / res / task-data structs and the procinfo
 * declarations live in flexfilesv2_xdr_chunk.h so that unrelated
 * ffv2 files (encoders, xor, mojette) don't drag in the SUNRPC +
 * nfs_xdr heavy include cascade.
 */

#endif /* FS_NFS_NFS4FLEXFILES_V2_LAYOUT_H */
