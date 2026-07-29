// SPDX-License-Identifier: GPL-2.0
/*
 * XOR_PARITY erasure encoder for the NFSv4 Flexfile Version 2
 * layout driver.  Supports any k with m=1: parity = XOR of all k
 * data shards, computed byte-wise.
 *
 * This is the smallest useful encoder and doubles as the reference
 * implementation the other encoders' tests can cross-check against
 * for the m=1 corner (RS_VANDERMONDE with m=1 must produce the same
 * parity byte-for-byte, since the RS Vandermonde generator matrix
 * degenerates to all-ones in that case).
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

#include "flexfilesv2.h"

static int ffv2_xor_encode(u32 k, u32 m, u32 shard_len,
			   const u8 * const *data, u8 * const *parity)
{
	u32 i;

	if (m != 1 || k == 0)
		return -EINVAL;

	memcpy(parity[0], data[0], shard_len);
	for (i = 1; i < k; i++) {
		u32 j;
		const u8 *src = data[i];
		u8 *dst = parity[0];

		for (j = 0; j < shard_len; j++)
			dst[j] ^= src[j];
	}
	return 0;
}

/*
 * Single-shard repair for m=1.  If exactly one shard (data or parity)
 * is missing, reconstruct it by XORing all surviving shards --
 * mathematically the same operation as encode(), just with the
 * missing slot swapped for the parity slot.
 *
 * XOR is index-symmetric: the reconstruction result is the same
 * regardless of which surviving-shard slot maps to which original
 * index, so surviving_indices is not used here.
 */
static int ffv2_xor_repair(u32 k, u32 m, u32 shard_len,
			   const u32 *surviving_indices,
			   const u8 * const *surviving_shards,
			   u32 missing_idx, u8 *reconstructed)
{
	u32 i;

	if (m != 1 || k == 0 || missing_idx > k)
		return -EINVAL;

	memcpy(reconstructed, surviving_shards[0], shard_len);
	for (i = 1; i < k; i++) {
		u32 j;
		const u8 *src = surviving_shards[i];

		for (j = 0; j < shard_len; j++)
			reconstructed[j] ^= src[j];
	}
	return 0;
}

const struct ffv2_encoder_ops ffv2_encoder_xor_parity = {
	.coding_type	= FFV2_ENCODING_XOR_PARITY,
	.name		= "xor-parity",
	.encode		= ffv2_xor_encode,
	.repair		= ffv2_xor_repair,
};
