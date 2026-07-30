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
#include "../pnfs.h"

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
 * CHUNK op codes per draft-haynes-nfsv4-flexfiles-v2.  CHUNK_READ,
 * CHUNK_FINALIZE and CHUNK_COMMIT are added by later commits as they
 * are wired.
 */
#define OP_CHUNK_WRITE			87

/*
 * Reply-side cap on batched chunks per CHUNK op.  The initial posture
 * is N=1 chunk per op; the cap sizes the reply arrays defensively so
 * a malformed or malicious DS reply can't force an unbounded
 * allocation.  32 leaves room for a batched-N follow-up without
 * protocol churn.
 */
#define FFV2_MAX_CHUNKS_PER_OP		32

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
 * cg_gen_id is a client-side monotonic counter (0-skipping on wrap;
 * reserved for a possible future CHUNK_GUARD_GEN_NONE sentinel).
 */
struct chunk_guard4 {
	u32	cg_gen_id;
	u32	cg_client_id;
};

struct chunk_owner4 {
	struct chunk_guard4	co_guard;
	u32			co_id;
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
 * Batch-visible ctx lifecycle.  Sibling mirrors of one pgio batch
 * observe these transitions to decide whether to dispatch, join, or
 * fall back.  Set under encode_lock; single writer of each
 * transition, arbitrary readers.
 */
enum ffv2_ctx_state {
	FFV2_CTX_ASSEMBLING,	/* initial: shards being zeroed/filled */
	FFV2_CTX_FETCHING,	/* RMW only: k fetches dispatched */
	FFV2_CTX_READY,		/* stripe image complete + encoded */
	FFV2_CTX_FAILED,	/* sticky: mirrors fall back to MDS */
};

struct ffv2_stripe_ctx {
	refcount_t			refcnt;
	void				*writer_key;	/* per-pgio key */
	u64				stripe_off;	/* file-offset key */
	struct list_head		list;		/* fls->fls_ctx_list */
	u32				k, m;
	u32				shard_len;
	u32				pages_per_shard;
	/*
	 * shard_pages[i] is a length-pages_per_shard page array;
	 * per-mirror write_pagelist points hdr->args.pages at
	 * shard_pages[mirror_idx].
	 */
	struct page			***shard_pages;
	struct mutex			encode_lock;
	bool				encoded;
	enum ffv2_ctx_state		state;		/* under encode_lock */
	/*
	 * mirror_seen and arrivals both under fls->fls_ctx_lock.
	 * mirror_seen bit N set when this batch's mirror N is
	 * admitted; arrivals counts distinct admissions.  A
	 * same-writer arrival whose bit is already set is a SECOND
	 * batch into the same stripe -- gate-waits like a
	 * cross-writer conflict.  arrivals == k+m releases the
	 * batch-anchor ref (see refcount comment).
	 */
	DECLARE_BITMAP(mirror_seen, NFS4_FFV2_MAX_DS_PER_STRIPE);
	u32				arrivals;
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
	struct list_head		fls_ctx_list;	/* ffv2_stripe_ctx */
	wait_queue_head_t		fls_ctx_wq;	/* same-stripe gate */
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
void ffv2_stripe_ctx_list_drain(struct nfs4_ffv2_layout_segment *fls);

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
 * ffv2_cg_gen_id_next_val: monotonic counter incremented per
 * CHUNK_WRITE via ffv2_cg_gen_id_next().  Seeded to 1; skips 0 on
 * wrap to keep room for a possible future CHUNK_GUARD_GEN_NONE
 * sentinel.
 */
extern u32 ffv2_cg_client_id_seed;
extern atomic_t ffv2_cg_gen_id_next_val;

void ffv2_chunk_guard_init(void);

static inline u32 ffv2_cg_client_id(const struct nfs4_ffv2_mirror *mirror)
{
	if (mirror && mirror->client_id != FFV2_CG_CLIENT_ID_NONE &&
	    mirror->client_id != FFV2_CG_CLIENT_ID_MDS)
		return mirror->client_id;
	return ffv2_cg_client_id_seed;
}

static inline u32 ffv2_cg_gen_id_next(void)
{
	u32 n = (u32)atomic_inc_return(&ffv2_cg_gen_id_next_val);

	/*
	 * atomic_inc_return returns the new value.  A wrap from 0xFFFFFFFF
	 * to 0 lands us on the reserved sentinel; skip past it.  Race-safe:
	 * a second thread that wraps at the same moment gets a distinct
	 * value from its own inc_return; both threads walk forward.
	 */
	if (unlikely(n == 0))
		n = (u32)atomic_inc_return(&ffv2_cg_gen_id_next_val);
	return n;
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
 * All three fields advance monotonically; the returned owner
 * uniquely identifies (this write, this client, this generation).
 */
static inline void
ffv2_build_chunk_owner(struct nfs4_ffv2_layout_segment *fls,
		       const struct nfs4_ffv2_mirror *mirror,
		       struct chunk_owner4 *out)
{
	out->co_guard.cg_gen_id = ffv2_cg_gen_id_next();
	out->co_guard.cg_client_id = ffv2_cg_client_id(mirror);
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
 * Verify `expected` (`expected_len` bytes) against the freshly-
 * computed checksum of `data` (`len` bytes) under `algo`.  Returns
 * 0 on match, -EBADMSG on mismatch, -EOPNOTSUPP if algo isn't
 * wired here.  Constant-time comparison is not required here --
 * the checksum is a wire integrity check, not a cryptographic MAC.
 */
int ffv2_checksum_verify(u32 algo, const void *data, size_t len,
			 const u8 *expected, size_t expected_len);

/*
 * flexfilesv2_xdr_chunk.c -- CHUNK_WRITE wire scaffold.  The args /
 * res / task-data structs and the procinfo declaration live in
 * flexfilesv2_xdr_chunk.h so that unrelated ffv2 files (encoders,
 * xor, mojette) don't drag in the SUNRPC + nfs_xdr heavy include
 * cascade.
 */

#endif /* FS_NFS_NFS4FLEXFILES_V2_LAYOUT_H */
