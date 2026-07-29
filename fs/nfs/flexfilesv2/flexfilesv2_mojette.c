// SPDX-License-Identifier: GPL-2.0
/*
 * MOJETTE_SYSTEMATIC erasure encoder for the NFSv4 Flexfile Version 2
 * layout driver -- SCAFFOLD ONLY, not yet implemented.
 *
 * This driver advertises the encoding family so the switch on
 * mirror->coding_type is exhaustive, but every encode / repair
 * invocation returns -EOPNOTSUPP.  Layouts that request Mojette then
 * fall back to MDS-inband I/O via the pNFS core's standard error
 * path.
 *
 * The full W=8 packed-projection implementation is deferred.
 *
 * Draft requirements not implemented here:
 *   - W = 8 packed little-endian uint64_t element arithmetic.
 *   - Direction set from the draft's canonical q = 1 sequence.
 *   - Per-projection variable-size buffers (Mojette projections are
 *     larger than data shards; the current CHUNK_WRITE dispatch
 *     assumes uniform shard_len).
 *   - Inverse-Mojette repair up to m missing shards.
 *
 * A future implementation must document its algorithmic and
 * licensing provenance before being enabled in the kernel.
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "flexfilesv2.h"

static int ffv2_mojette_encode(u32 k, u32 m, u32 shard_len,
			       const u8 * const *data, u8 * const *parity)
{
	return -EOPNOTSUPP;
}

const struct ffv2_encoder_ops ffv2_encoder_mojette_systematic = {
	.coding_type	= FFV2_ENCODING_MOJETTE_SYSTEMATIC,
	.name		= "mojette-systematic",
	.encode		= ffv2_mojette_encode,
	/* repair: deferred alongside the encoder implementation. */
};
