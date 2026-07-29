// SPDX-License-Identifier: GPL-2.0
/*
 * LINUX_MD_RAID erasure encoder for the NFSv4 Flexfile Version 2
 * layout driver.  Thin wrapper over lib/raid6/ so we inherit the
 * kernel's already-tuned SIMD implementations (NEON on aarch64,
 * AVX2/AVX-512 on x86_64, ...) at zero cost.
 *
 * Wire ordering: shards 0..k-1 hold data, shard k holds P (XOR),
 * shard k+1 holds Q (Reed-Solomon syndrome over GF(2^8)).  This
 * matches lib/raid6/ conventions verbatim; the wire-format spec
 * (draft-haynes-nfsv4-flexfiles-v2-encoding-registry) pins the
 * same ordering so no reindexing is needed.
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/raid/pq.h>
#include <linux/slab.h>

#include "flexfilesv2.h"

static int ffv2_md_encode(u32 k, u32 m, u32 shard_len,
			  const u8 * const *data, u8 * const *parity)
{
	void **ptrs;
	u32 i;

	if (m != 2 || k < 2 || (int)(k + m) < RAID6_MIN_DISKS)
		return -EINVAL;

	/*
	 * raid6_gen_syndrome expects a single ptrs[disks] array where
	 * ptrs[0..k-1] are data and ptrs[k], ptrs[k+1] are P and Q.
	 * The data pointers are treated as const by the encoder; the
	 * cast is safe because raid6_gen_syndrome only reads them.
	 */
	ptrs = kmalloc_array(k + m, sizeof(*ptrs), GFP_NOFS);
	if (!ptrs)
		return -ENOMEM;
	for (i = 0; i < k; i++)
		ptrs[i] = (void *)data[i];
	ptrs[k]     = parity[0];
	ptrs[k + 1] = parity[1];

	raid6_gen_syndrome(k + m, shard_len, ptrs);
	kfree(ptrs);
	return 0;
}

const struct ffv2_encoder_ops ffv2_encoder_linux_md = {
	.coding_type	= FFV2_ENCODING_LINUX_MD_RAID,
	.name		= "linux-md-raid",
	.encode		= ffv2_md_encode,
	/* repair: deferred; recovery lands with read-side recon slice. */
};
