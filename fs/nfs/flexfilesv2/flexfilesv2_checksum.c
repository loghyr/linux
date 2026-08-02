// SPDX-License-Identifier: GPL-2.0
/*
 * NFSv4 Flexfile Version 2 chunk checksum plumbing.
 *
 * Every non-PASSTHROUGH CHUNK_WRITE carries a per-chunk checksum
 * (checksum4 in the wire XDR).  The MDS advertises the algorithm per
 * mirror at LAYOUTGET time via ffm_checksum_algorithm; every
 * CHUNK_WRITE uses that algorithm for every chunk it carries.
 *
 * CRC32 is wired here.  CRC32C is deferred until the data-server
 * implementation supports storing and validating it: accepting a
 * wire algo tag of CRC32C would let the client compute a CRC32C
 * over received bytes and successfully "verify" against a
 * matching-but-freshly-computed CRC that was never actually stored
 * at CHUNK_WRITE time -- a silent-corruption hazard analogous to
 * bit-rot laundering.  The compute path is preserved as a comment
 * so it can be re-enabled atomically once the server side lands.
 * Layouts advertising CRC32C, SHA256, SHA512, FLETCHER4, or BLAKE3
 * return -EOPNOTSUPP; the client falls
 * back to MDS-inband writes via the pNFS core's standard error path.
 * Additional algorithms are follow-up work.
 *
 * The two kernel entry points live in include/linux/crc32.h.  Both
 * take a starting seed + buffer + length and return the final u32
 * checksum.  No allocation, no context.
 *
 * Interoperability contract with the data-server protocol:
 *
 * - CRC32 uses the zlib crc32(0L, data, len) convention, i.e.
 *   CRC-32/ISO-HDLC with pre-conditioning (initial seed 0xFFFFFFFF)
 *   and post-conditioning (final XOR with 0xFFFFFFFF).  Kernel's
 *   crc32_le(0, data, len) is the raw table CRC without either
 *   conditioning -- it produces a different value for every
 *   non-empty input.  This file uses crc32_le(~0U, data, len) ^ ~0U
 *   to match zlib.
 * - cs_value is packed big-endian (network byte order).  This file
 *   emits the 4-byte checksum in big-endian order so the caller can
 *   memcpy it verbatim into the XDR opaque; do not htonl() again in
 *   the encoder.
 * - CRC32C would use the same conditioning shape (RFC 3720 iSCSI /
 *   NVMe convention: pre/post-conditioning by 0xFFFFFFFF, which
 *   crc32c(~0U, data, len) ^ ~0U produces).  The server side does
 *   not yet implement CRC32C storage; the compute path here is
 *   gated with -EOPNOTSUPP until it does.
 *
 * Known-answer vector: input "123456789" (9 bytes) MUST produce
 * CRC32 value 0xCBF43926, packed as big-endian bytes
 * {0xCB, 0xF4, 0x39, 0x26}.  This matches zlib and the CRC-32/ISO-HDLC
 * entry in the CRC catalogue.
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 */

#include <linux/crc32.h>
#include <linux/errno.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/string.h>

#include "flexfilesv2.h"

int ffv2_checksum_compute(u32 algo, const void *data, size_t len,
			  u8 *out, size_t *out_len)
{
	u32 v;

	switch (algo) {
	case FFV2_CHECKSUM_ALG_CRC32:
		/* CRC-32/ISO-HDLC: pre/post-condition to match zlib. */
		v = crc32_le(~0U, data, len) ^ ~0U;
		break;
	case FFV2_CHECKSUM_ALG_CRC32C:
		/*
		 * The server side does not yet implement CRC32C storage.
		 * Enabling client-side CRC32C compute here would let a
		 * wire algo=CRC32C reply from a broken or rogue DS pass
		 * verification against bytes that were never CRC32C-
		 * checked at store time.  Refuse via -EOPNOTSUPP; the
		 * caller falls back to MDS.  Re-enable the commented-out
		 * compute atomically with the server-side support.
		 *
		 * Future impl (RFC 3720 iSCSI convention, same shape as
		 * CRC32):
		 *     v = crc32c(~0U, data, len) ^ ~0U;
		 *     break;
		 */
		return -EOPNOTSUPP;
	case FFV2_CHECKSUM_ALG_NONE:
	case FFV2_CHECKSUM_ALG_FLETCHER4:
	case FFV2_CHECKSUM_ALG_SHA256:
	case FFV2_CHECKSUM_ALG_SHA512:
	case FFV2_CHECKSUM_ALG_BLAKE3:
	default:
		/* Recognized-and-refused and unknown collapse into a
		 * single caller-visible signal: this algo isn't wired
		 * here; caller falls back to MDS.
		 */
		return -EOPNOTSUPP;
	}

	/*
	 * Emit the u32 in big-endian (network byte order) so the caller
	 * can memcpy the bytes verbatim into the XDR opaque cs_value.
	 */
	out[0] = (u8)(v >> 24);
	out[1] = (u8)(v >> 16);
	out[2] = (u8)(v >> 8);
	out[3] = (u8)(v);
	*out_len = sizeof(v);
	return 0;
}

/*
 * Page-array variant of ffv2_checksum_compute.  Walks `pages` starting
 * at byte `pgbase` for `len` bytes, kmapping each page fragment and
 * accumulating the checksum via the underlying helper's seed-first
 * incremental API.  Both crc32_le and crc32c take a running seed as
 * the first argument, so page-by-page accumulation is bit-exact.
 *
 * Preconditions:
 *   pages   -- array of struct page * with at least
 *              ceil((pgbase + len) / PAGE_SIZE) entries.
 *   pgbase  -- byte offset from pages[0]; may exceed PAGE_SIZE for
 *              callers who compute their own page-index offset.
 *   len     -- total byte length to checksum; 0 is legal.
 *   out     -- MUST have at least FFV2_CHECKSUM_MAX_LEN capacity.
 *
 * Returns 0 on success (*out_len populated), -EOPNOTSUPP for
 * unsupported algo -- matches the flat-buffer variant's contract
 * for caller MDS-fallback.
 *
 * Semantic equivalence with ffv2_checksum_compute for the same
 * concatenated byte sequence is a hard invariant.  Both paths seed
 * at ~0U (pre-conditioning), use the same helper's seed-and-extend
 * contract, XOR the accumulated value with ~0U (post-conditioning)
 * after the last byte, and emit big-endian.
 */
int ffv2_checksum_compute_pages(u32 algo, struct page **pages, u32 pgbase,
				size_t len, u8 *out, size_t *out_len)
{
	size_t remaining = len;
	u32 seed;
	unsigned int page_idx;
	unsigned int page_off;

	/* Reject unsupported algo up front to match the flat variant's
	 * caller contract without doing any page mapping first.  CRC32C
	 * is refused with -EOPNOTSUPP pending server-side support,
	 * matching the flat-variant gate above.
	 */
	switch (algo) {
	case FFV2_CHECKSUM_ALG_CRC32:
		break;
	default:
		return -EOPNOTSUPP;
	}

	/* Pre-condition the seed to ~0U (CRC-32/ISO-HDLC + RFC 3720
	 * iSCSI convention).  Post-conditioning by XOR with ~0U happens
	 * after the accumulation loop.  Both crc32_le and crc32c produce
	 * the raw polynomial value; the conditioning must be done by the
	 * caller for zlib / iSCSI compatibility.
	 */
	seed = ~0U;

	/* Normalize pgbase: the caller may pass a byte offset >=
	 * PAGE_SIZE (the stripe ctx does not necessarily align shard
	 * starts).  Advance to the correct page index; residual becomes
	 * the per-page offset for pages[page_idx].
	 */
	page_idx = pgbase >> PAGE_SHIFT;
	page_off = pgbase & (PAGE_SIZE - 1);

	while (remaining > 0) {
		size_t chunk = min_t(size_t, remaining, PAGE_SIZE - page_off);
		void *kaddr = kmap_local_page(pages[page_idx]);
		const void *src = kaddr + page_off;

		switch (algo) {
		case FFV2_CHECKSUM_ALG_CRC32:
			seed = crc32_le(seed, src, chunk);
			break;
		/*
		 * CRC32C case would be
		 *     seed = crc32c(seed, src, chunk);
		 * Gated at the top switch above until server-side
		 * support lands.
		 */
		}
		kunmap_local(kaddr);

		remaining -= chunk;
		page_idx++;
		page_off = 0;
	}

	/* Post-condition + big-endian emit; matches the flat variant. */
	seed ^= ~0U;
	out[0] = (u8)(seed >> 24);
	out[1] = (u8)(seed >> 16);
	out[2] = (u8)(seed >> 8);
	out[3] = (u8)(seed);
	*out_len = sizeof(seed);
	return 0;
}

int ffv2_checksum_verify(u32 algo, const void *data, size_t len,
			 const u8 *expected, size_t expected_len)
{
	u8 computed[FFV2_CHECKSUM_MAX_LEN];
	size_t computed_len;
	int rc;

	rc = ffv2_checksum_compute(algo, data, len, computed, &computed_len);
	if (rc)
		return rc;
	if (computed_len != expected_len)
		return -EBADMSG;
	if (memcmp(computed, expected, computed_len) != 0)
		return -EBADMSG;
	return 0;
}
