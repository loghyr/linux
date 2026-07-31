// SPDX-License-Identifier: GPL-2.0
/*
 * NFSv4 Flexfile Version 2 chunk checksum plumbing.
 *
 * Every non-PASSTHROUGH CHUNK_WRITE carries a per-chunk checksum
 * (checksum4 in the wire XDR).  The MDS advertises the algorithm
 * per mirror at LAYOUTGET time via ffm_checksum_algorithm; every
 * CHUNK_WRITE uses that algorithm for every chunk it carries.
 *
 * CRC32 and CRC32C are wired here.  Layouts advertising SHA256,
 * SHA512, FLETCHER4 or BLAKE3 return -EOPNOTSUPP; the client falls
 * back to MDS-inband writes via the pNFS core's standard error path.
 * Additional algorithms are follow-up work.
 *
 * The two kernel entry points live in include/linux/crc32.h.  Both
 * take a starting seed + buffer + length and return the final u32
 * checksum.  No allocation, no context.
 *
 * Wire byte order for the 4-byte checksums is XDR big-endian.  This
 * file returns the raw host-endian value in the first 4 bytes of the
 * output buffer; the caller's XDR emit does the endian conversion.
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
		v = crc32_le(0, data, len);
		break;
	case FFV2_CHECKSUM_ALG_CRC32C:
		v = crc32c(0, data, len);
		break;
	case FFV2_CHECKSUM_ALG_NONE:
	case FFV2_CHECKSUM_ALG_FLETCHER4:
	case FFV2_CHECKSUM_ALG_SHA256:
	case FFV2_CHECKSUM_ALG_SHA512:
	case FFV2_CHECKSUM_ALG_BLAKE3:
	default:
		/* Recognized-and-refused vs unknown collapse into a
		 * single caller-visible signal: this algo isn't wired
		 * here; caller falls back to MDS.
		 */
		return -EOPNOTSUPP;
	}

	/*
	 * Emit the u32 in host order into out[0..3]; the caller's XDR
	 * marshal will htonl().  Callers see a 4-byte checksum for both
	 * CRC32 and CRC32C.
	 */
	memcpy(out, &v, sizeof(v));
	*out_len = sizeof(v);
	return 0;
}

/*
 * Page-array variant of ffv2_checksum_compute.  Walks `pages` starting
 * at byte `pgbase` for `len` bytes, kmapping each page fragment and
 * accumulating the checksum via the underlying helper's seed-first
 * incremental API.  See include/linux/crc32.h:72,84 -- both crc32_le
 * and crc32c take a running seed as first arg, so page-by-page
 * accumulation is bit-exact.
 *
 * Preconditions:
 *   pages       -- array of struct page * with at least ceil((pgbase+len)
 *                  / PAGE_SIZE) entries.
 *   pgbase      -- byte offset from pages[0]; may exceed PAGE_SIZE for
 *                  callers who compute their own page-index offset.
 *   len         -- total byte length to checksum; 0 is legal (returns
 *                  the algorithm's seed=0 empty-input checksum for CRC32
 *                  / CRC32C, i.e. 0).
 *   out         -- MUST have at least FFV2_CHECKSUM_MAX_LEN capacity.
 *
 * Returns 0 on success (*out_len populated), -EOPNOTSUPP for
 * unsupported algo -- matches the flat-buffer variant's contract for
 * caller MDS-fallback.
 *
 * Semantic equivalence with ffv2_checksum_compute for the same
 * concatenated byte sequence is a hard invariant.  Both paths seed
 * at 0 and use the same helper's seed-and-extend contract, so
 * equivalence follows from the helpers' own documented behavior.
 */
int ffv2_checksum_compute_pages(u32 algo, struct page **pages, u32 pgbase,
				size_t len, u8 *out, size_t *out_len)
{
	size_t remaining = len;
	u32 seed = 0;
	unsigned int page_idx;
	unsigned int page_off;

	/* Reject unsupported algo up front to match the flat variant's
	 * caller contract without doing any page mapping first.
	 */
	switch (algo) {
	case FFV2_CHECKSUM_ALG_CRC32:
	case FFV2_CHECKSUM_ALG_CRC32C:
		break;
	default:
		return -EOPNOTSUPP;
	}

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
		case FFV2_CHECKSUM_ALG_CRC32C:
			seed = crc32c(seed, src, chunk);
			break;
		}
		kunmap_local(kaddr);

		remaining -= chunk;
		page_idx++;
		page_off = 0;
	}

	/* Same host-byte-order emit as ffv2_checksum_compute; caller's
	 * XDR marshal does the endian conversion.
	 */
	memcpy(out, &seed, sizeof(seed));
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
	if (expected_len != computed_len)
		return -EBADMSG;
	if (memcmp(expected, computed, computed_len) != 0)
		return -EBADMSG;
	return 0;
}
