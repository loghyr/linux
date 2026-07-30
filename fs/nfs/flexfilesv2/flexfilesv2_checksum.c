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
#include <linux/kernel.h>
#include <linux/module.h>
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
		 * here; caller falls back to MDS. */
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
