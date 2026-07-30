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
	if (shard_len & 511)
		return -EINVAL;	/* raid6_gen_syndrome WARNs otherwise */

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

/*
 * Recover one missing shard from k+m-1 surviving shards.  Handles:
 *
 *   missing_idx < k       (data shard)  via raid6_recov_datap
 *   missing_idx == k      (P shard)     via raid6_gen_syndrome
 *   missing_idx == k+1    (Q shard)     via raid6_gen_syndrome
 *
 * The syndrome and recovery routines require:
 *   - bytes per call a multiple of 512
 *   - bytes per call <= PAGE_SIZE  (recovery only)
 *   - process context, no IRQ disabled
 *   - each buffer pointer page-aligned
 *
 * shard_len is broken into PAGE_SIZE chunks and the ptrs[] array is
 * re-slotted per chunk.  Both raid6_recov_datap and _gen_syndrome
 * scribble ptrs[disks-2] (P slot), so the recover-data path uses a
 * scratch page for P; the recover-P/Q paths reuse the caller's
 * reconstructed buffer for the wanted slot and a scratch page for
 * the discarded slot.
 *
 * All input buffers (both surviving_shards[] and reconstructed) MUST
 * be page-aligned.  The ffv2_stripe_ctx write path satisfies this
 * because shard_pages[i][*] come from alloc_page(); callers wiring
 * repair into future read-side machinery should preserve that
 * invariant.
 */
static int ffv2_md_repair(u32 k, u32 m, u32 shard_len,
			  const u32 *surviving_indices,
			  const u8 * const *surviving_shards,
			  u32 missing_idx, u8 *reconstructed)
{
	const u8 **shard_by_idx = NULL;
	void **ptrs = NULL;
	u8 *scratch_page = NULL;
	u32 i, off;
	int rc;

	if (m != 2 || k < 2 || (int)(k + m) < RAID6_MIN_DISKS)
		return -EINVAL;
	if (missing_idx >= k + m)
		return -EINVAL;
	if (shard_len & 511)
		return -EINVAL;

	/*
	 * Sort surviving shards back into position order.  For the
	 * P/Q recompute cases we only need the k data shards, but the
	 * datap recovery path additionally needs Q at position k+1.
	 */
	shard_by_idx = kcalloc(k + m, sizeof(*shard_by_idx), GFP_NOFS);
	ptrs = kmalloc_array(k + m, sizeof(*ptrs), GFP_NOFS);
	scratch_page = (u8 *)__get_free_page(GFP_NOFS);
	if (!shard_by_idx || !ptrs || !scratch_page) {
		rc = -ENOMEM;
		goto out;
	}
	for (i = 0; i < k; i++) {
		u32 si = surviving_indices[i];

		if (si >= k + m || si == missing_idx) {
			rc = -EINVAL;
			goto out;
		}
		shard_by_idx[si] = surviving_shards[i];
	}
	/* Data-recovery path additionally requires Q; P/Q recovery
	 * only reads data. */
	for (i = 0; i < k; i++) {
		if (shard_by_idx[i])
			continue;
		if (missing_idx == i)
			continue;	/* the missing data slot */
		rc = -EINVAL;		/* another data slot is absent */
		goto out;
	}
	if (missing_idx < k && !shard_by_idx[k + 1]) {
		rc = -EINVAL;		/* datap path needs Q */
		goto out;
	}

	for (off = 0; off < shard_len; off += PAGE_SIZE) {
		u32 chunk = min_t(u32, PAGE_SIZE, shard_len - off);

		for (i = 0; i < k; i++)
			ptrs[i] = (i == missing_idx) ?
				  (void *)(reconstructed + off) :
				  (void *)(shard_by_idx[i] + off);

		if (missing_idx < k) {
			/* Recover data.  Q at ptrs[k+1]; P slot at
			 * ptrs[k] is scratch (algorithm clobbers it). */
			ptrs[k]     = scratch_page;
			ptrs[k + 1] = (void *)(shard_by_idx[k + 1] + off);
			raid6_recov_datap(k + m, chunk, missing_idx, ptrs);
		} else {
			/* Recover P or Q by re-running the syndrome. */
			if (missing_idx == k) {
				ptrs[k]     = reconstructed + off;
				ptrs[k + 1] = scratch_page;
			} else {
				ptrs[k]     = scratch_page;
				ptrs[k + 1] = reconstructed + off;
			}
			raid6_gen_syndrome(k + m, chunk, ptrs);
		}
	}
	rc = 0;
out:
	if (scratch_page)
		free_page((unsigned long)scratch_page);
	kfree(ptrs);
	kfree(shard_by_idx);
	return rc;
}

const struct ffv2_encoder_ops ffv2_encoder_linux_md = {
	.coding_type	= FFV2_ENCODING_LINUX_MD_RAID,
	.name		= "linux-md-raid",
	.encode		= ffv2_md_encode,
	.repair		= ffv2_md_repair,
};
