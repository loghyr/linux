// SPDX-License-Identifier: GPL-2.0
/*
 * NFSv4 Flexfile Version 2 layout driver.
 *
 * Skeleton -- registers the pnfs_layoutdriver_type for
 * LAYOUT_FLEX_FILES_V2 and provides the layout header lifecycle
 * hooks the pNFS core requires to reach LAYOUTGET.  alloc_lseg
 * currently returns NULL, so any LAYOUTGET the MDS answers with
 * an ffv2 layout is safely refused; the core falls back to
 * layoutless I/O just as it does for an unregistered layout type.
 *
 * Subsequent commits fill in XDR decode of the ffv2 layout wire
 * format, deviceid handling, encoder ops for the on-wire encoding
 * families (RS Vandermonde, Mojette, Linux md, XOR, mirrored),
 * and the pagelist read/write path.
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 */

#include <linux/atomic.h>
#include <linux/module.h>
#include <linux/nfs4.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_page.h>
#include <linux/random.h>

#include "../internal.h"
#include "../nfs4trace.h"
#include "../pnfs.h"
#include "flexfilesv2.h"

/*
 * See flexfilesv2.h for the semantics of these two.  Definitions
 * live here so both flexfilesv2.o (this module's core) and any future
 * kunit test object can link against them via the extern declaration.
 */
u32 ffv2_cg_client_id_seed;
atomic_t ffv2_cg_gen_id_next_val = ATOMIC_INIT(1);

void ffv2_chunk_guard_init(void)
{
	u32 seed = get_random_u32();

	/*
	 * Rotate away from either reserved sentinel; the DS rejects
	 * either wire value with NFS4ERR_INVAL.  Odds are 2^-31, but
	 * the check costs one branch.
	 */
	if (unlikely(seed == FFV2_CG_CLIENT_ID_NONE))
		seed = 1;
	else if (unlikely(seed == FFV2_CG_CLIENT_ID_MDS))
		seed = FFV2_CG_CLIENT_ID_MDS - 1;
	ffv2_cg_client_id_seed = seed;
}

static struct pnfs_layout_hdr *
ffv2_alloc_layout_hdr(struct inode *inode, gfp_t gfp_flags)
{
	struct nfs4_ffv2_layout *ffv2l;

	ffv2l = kzalloc(sizeof(*ffv2l), gfp_flags);
	if (!ffv2l)
		return NULL;
	return &ffv2l->generic_hdr;
}

static void
ffv2_free_layout_hdr(struct pnfs_layout_hdr *lo)
{
	kfree(FFV2_LAYOUT_FROM_HDR(lo));
}

static struct pnfs_layout_segment *
ffv2_alloc_lseg(struct pnfs_layout_hdr *lo,
		struct nfs4_layoutget_res *lgr,
		gfp_t gfp_flags)
{
	struct nfs4_ffv2_layout_segment *fls;

	fls = ffv2_decode_layout(lgr, gfp_flags);
	if (IS_ERR(fls))
		return ERR_CAST(fls);
	return &fls->generic_hdr;
}

static void
ffv2_free_lseg(struct pnfs_layout_segment *lseg)
{
	ffv2_free_layout_segment(FFV2_LSEG(lseg));
}

/*
 * Range-ordering + merge callbacks for pnfs_generic_layout_insert_lseg.
 * The comparisons operate on generic pnfs_layout_range and are
 * layout-family-agnostic; the shape matches what ffv1 uses
 * (fs/nfs/flexfilelayout/flexfilelayout.c), duplicated here rather
 * than lifted to a shared helper so this atomic commit stands
 * alone.
 */
static bool
ffv2_lseg_range_is_after(const struct pnfs_layout_range *l1,
			 const struct pnfs_layout_range *l2)
{
	u64 end1, end2;

	if (l1->iomode != l2->iomode)
		return l1->iomode != IOMODE_READ;
	end1 = pnfs_calc_offset_end(l1->offset, l1->length);
	end2 = pnfs_calc_offset_end(l2->offset, l2->length);
	if (end1 < l2->offset)
		return false;
	if (end2 < l1->offset)
		return true;
	return l2->offset <= l1->offset;
}

static bool
ffv2_lseg_merge(struct pnfs_layout_segment *new,
		struct pnfs_layout_segment *old)
{
	/* No range-merge yet; keep new + old separate.  ffv1 has
	 * mirror-set-equality logic here that the ffv2 write path
	 * will need eventually.
	 */
	return false;
}

static void
ffv2_add_lseg(struct pnfs_layout_hdr *lo,
	      struct pnfs_layout_segment *lseg, struct list_head *free_me)
{
	pnfs_generic_layout_insert_lseg(lo, lseg,
					ffv2_lseg_range_is_after,
					ffv2_lseg_merge,
					free_me);
}

static void
ffv2_return_range(struct pnfs_layout_hdr *lo,
		  struct pnfs_layout_range *range)
{
	/*
	 * Minimal implementation: rely on the pNFS core's default
	 * behaviour, which invalidates every lseg overlapping the
	 * range and lets the next I/O trigger a fresh LAYOUTGET.
	 * A subsequent commit will add ffv2-specific per-mirror
	 * teardown here once the read/write paths carry per-lseg
	 * state that needs range-scoped release.
	 */
}

static struct pnfs_ds_commit_info *
ffv2_get_ds_info(struct inode *inode)
{
	/*
	 * The core's ds_commit_info aggregation is FFv1-shaped
	 * (per-mirror commit lists).  ffv2 will grow its own
	 * variant when the write path lands; for now returning
	 * NULL asks the core to skip per-DS commit tracking, which
	 * is the safe default for read-only mounts and for early
	 * write experiments that go through the MDS-inband path.
	 */
	return NULL;
}

static int
ffv2_prepare_layoutreturn(struct nfs4_layoutreturn_args *args)
{
	/*
	 * ffv2 will eventually send per-mirror ioerr + iostats
	 * (ffv2_layoutreturn4 in the draft), matching what ffv1
	 * sends via nfs4_flexfile_layoutreturn_args.  Returning 0
	 * with no ffv2-specific args keeps LAYOUTRETURN correct
	 * for the base case; the MDS receives a plain layout
	 * return with no extended stats.
	 */
	args->ld_private->ops = NULL;
	args->ld_private->data = NULL;
	return 0;
}

static void
ffv2_cancel_io(struct pnfs_layout_segment *lseg)
{
	/*
	 * In-flight RPCs are left to complete: they hold their own
	 * references and their completion tails do not care that the
	 * layout is going away.  What must stop is new work -- close
	 * the segment to further stripe claims and wake anyone waiting
	 * for one, so a waiter does not acquire a stripe on a layout
	 * that is being torn down.
	 */
	ffv2_claim_close(FFV2_LSEG(lseg));
}

/*
 * Page-list I/O initialisation.  Fetches a read layout covering the
 * request, then hands off to the pNFS generic pagelist assembler
 * (pnfs_generic_pg_readpages via pg_doio).  A subsequent commit adds
 * ffv2-specific mirror selection here; for now we always fall back
 * to MDS-inband I/O if LAYOUTGET fails, matching the ffv1 pattern.
 */
static void
ffv2_pg_init_read(struct nfs_pageio_descriptor *pgio, struct nfs_page *req)
{
	pnfs_generic_pg_check_layout(pgio, req);
	if (pgio->pg_lseg && ffv2_avoid_read_on_rw(pgio->pg_lseg)) {
		pnfs_put_lseg(pgio->pg_lseg);
		pgio->pg_lseg = pnfs_update_layout(pgio->pg_inode,
						   nfs_req_openctx(req),
						   req_offset(req),
						   req->wb_bytes,
						   IOMODE_READ, true,
						   nfs_io_gfp_mask());
		if (IS_ERR(pgio->pg_lseg)) {
			pgio->pg_error = PTR_ERR(pgio->pg_lseg);
			pgio->pg_lseg = NULL;
			return;
		}
	}
	if (!pgio->pg_lseg) {
		pgio->pg_lseg = pnfs_update_layout(pgio->pg_inode,
						   nfs_req_openctx(req),
						   req_offset(req),
						   req->wb_bytes,
						   IOMODE_READ,
						   false,
						   nfs_io_gfp_mask());
		if (IS_ERR(pgio->pg_lseg)) {
			pgio->pg_error = PTR_ERR(pgio->pg_lseg);
			pgio->pg_lseg = NULL;
			return;
		}
	}
	if (!pgio->pg_lseg)
		nfs_pageio_reset_read_mds(pgio);
}

static void
ffv2_pg_init_write(struct nfs_pageio_descriptor *pgio, struct nfs_page *req)
{
	pnfs_generic_pg_check_layout(pgio, req);
	if (!pgio->pg_lseg) {
		pgio->pg_lseg = pnfs_update_layout(pgio->pg_inode,
						   nfs_req_openctx(req),
						   req_offset(req),
						   req->wb_bytes,
						   IOMODE_RW,
						   false,
						   nfs_io_gfp_mask());
		if (IS_ERR(pgio->pg_lseg)) {
			pgio->pg_error = PTR_ERR(pgio->pg_lseg);
			pgio->pg_lseg = NULL;
			return;
		}
	}
	if (!pgio->pg_lseg)
		nfs_pageio_reset_write_mds(pgio);
}

/*
 * Read/write pagelist dispatchers.  These are the entry points the
 * pNFS core calls once pg_doio has assembled a request batch and
 * decided to try the layout-managed I/O path.  Returning
 * PNFS_NOT_ATTEMPTED tells the core to fall back to MDS-inband
 * I/O -- correct behaviour for a driver that hasn't yet wired
 * DS-side RPC dispatch.
 *
 * A subsequent commit replaces these stubs with real DS dispatch
 * for the MIRRORED encoding, then extends to RS_VANDERMONDE /
 * MOJETTE / LINUX_MD_RAID via the ffv2_encoder_ops table.
 */
static enum pnfs_try_status
ffv2_read_pagelist(struct nfs_pgio_header *hdr)
{
	return PNFS_NOT_ATTEMPTED;
}

static bool ffv2_lseg_is_chunked(const struct nfs4_ffv2_layout_segment *fls);

static enum pnfs_try_status
ffv2_write_pagelist(struct nfs_pgio_header *hdr, int sync)
{
	struct pnfs_layout_segment *lseg = hdr->lseg;
	struct nfs4_ffv2_layout_segment *fls = FFV2_LSEG(lseg);

	if (ffv2_lseg_is_chunked(fls))
		return ffv2_write_pagelist_chunked(hdr, sync);
	if (ffv2_no_fallback_to_mds(lseg)) {
		pnfs_error_mark_layout_for_return(hdr->inode, lseg);
		return PNFS_TRY_AGAIN;
	}
	return PNFS_NOT_ATTEMPTED;
}

static const struct nfs_pageio_ops ffv2_pg_read_ops = {
	.pg_init	= ffv2_pg_init_read,
	.pg_test	= pnfs_generic_pg_test,
	.pg_doio	= pnfs_generic_pg_readpages,
	.pg_cleanup	= pnfs_generic_pg_cleanup,
};

/*
 * Write-side pg_test.  Same shape as ffv2_pg_test but caps each
 * batch at the STRIPE boundary (k * striping_unit) rather than the
 * shard boundary: chunked writes need to see the whole stripe at
 * once to encode parity, so keeping each hdr contained in one
 * stripe is a precondition for the RMW / full-stripe / safe-append
 * decision in ffv2_write_pagelist_chunked.  Batches spanning
 * multiple stripes still fall back to MDS, but making single-stripe
 * containment structural (not incidental) narrows the fallback set
 * substantially for the writeback path where consecutive dirty
 * pages naturally land in the same stripe.
 */
static size_t
ffv2_pg_test_write(struct nfs_pageio_descriptor *pgio, struct nfs_page *prev,
		   struct nfs_page *req)
{
	struct nfs4_ffv2_layout_segment *fls;
	struct nfs4_ffv2_mirror *mirror;
	size_t size;
	u64 req_stripe, prev_stripe, in_stripe, stripe_bytes;

	size = pnfs_generic_pg_test(pgio, prev, req);
	if (!size || !pgio->pg_lseg)
		return size;
	fls = FFV2_LSEG(pgio->pg_lseg);
	if (!ffv2_lseg_is_chunked(fls))
		return size;
	mirror = fls->mirror_array[0];
	stripe_bytes = (u64)mirror->protection_data *
		       mirror->striping_unit_size;
	if (!stripe_bytes)
		return size;

	req_stripe = div64_u64_rem(req_offset(req), stripe_bytes, &in_stripe);
	if (prev) {
		prev_stripe = div64_u64(req_offset(prev), stripe_bytes);
		if (prev_stripe != req_stripe)
			return 0;
	}
	return min_t(size_t, size, stripe_bytes - in_stripe);
}

/*
 * A chunk-encoded lseg (RS/MOJETTE/XOR/LINUX_MD/... anything with
 * parity) needs k+m parallel writes -- one per data shard plus one
 * per parity shard -- rather than the mirrored-write fanout FFv1
 * uses.  PASSTHROUGH alone rides the ordinary NFS I/O path;
 * REPLICATED remains a chunk encoding despite carrying no parity.
 */
static bool ffv2_lseg_is_chunked(const struct nfs4_ffv2_layout_segment *fls)
{
	u32 ct;

	if (!fls || fls->mirror_array_cnt == 0 || !fls->mirror_array[0])
		return false;
	ct = fls->mirror_array[0]->coding_type;
	return ct != FFV2_ENCODING_PASSTHROUGH;
}

static u32
ffv2_pg_get_mirror_count_write(struct nfs_pageio_descriptor *pgio,
			       struct nfs_page *req)
{
	struct nfs4_ffv2_layout_segment *fls;

	if (!pgio->pg_lseg) {
		pgio->pg_lseg = pnfs_update_layout(pgio->pg_inode,
						   nfs_req_openctx(req),
						   req_offset(req),
						   req->wb_bytes,
						   IOMODE_RW, false,
						   nfs_io_gfp_mask());
		if (IS_ERR(pgio->pg_lseg)) {
			pgio->pg_error = PTR_ERR(pgio->pg_lseg);
			pgio->pg_lseg = NULL;
			return 1;
		}
	}
	if (!pgio->pg_lseg)
		return 1;

	fls = FFV2_LSEG(pgio->pg_lseg);
	if (!ffv2_lseg_is_chunked(fls))
		return 1;

	/*
	 * One, even for a k+m encoding.  The pgio mirror machinery
	 * expresses replication: every mirror is handed the same bytes,
	 * and the generic layer builds one header per mirror from an
	 * identical page list.  Erasure coding needs k+m *different*
	 * payloads that share a single encode of one stripe, which no
	 * arrangement of mirrors can describe -- the shards only exist
	 * after the stripe is assembled, and assembling it needs all the
	 * user bytes at once.
	 *
	 * So the layout driver takes the whole stripe in a single header
	 * and dispatches the k+m CHUNK_WRITEs itself.  filelayout, the
	 * only other in-tree striping driver, runs mirror_count == 1 for
	 * the same reason.
	 */
	return 1;
}

/*
 * Per-mirror routing.  pg_get_mirror_count only sizes the mirror
 * array; the generic layer resolves "which mirror is current"
 * through this pair.  Without them nfs_pgio_get_mirror returns
 * &desc->pg_mirrors[0] for every index and
 * nfs_pgio_set_current_mirror is a no-op (fs/nfs/pagelist.c), so a
 * chunked lseg queues all k+m shard requests onto mirror 0's list
 * and only mirror 0 is ever dispatched.  Same pair as
 * ff_layout_pg_write_ops.
 */
static u32
ffv2_pg_set_mirror_write(struct nfs_pageio_descriptor *desc, u32 idx)
{
	u32 old = desc->pg_mirror_idx;

	desc->pg_mirror_idx = idx;
	return old;
}

static struct nfs_pgio_mirror *
ffv2_pg_get_mirror_write(struct nfs_pageio_descriptor *desc, u32 idx)
{
	return &desc->pg_mirrors[idx];
}

static const struct nfs_pageio_ops ffv2_pg_write_ops = {
	.pg_init		= ffv2_pg_init_write,
	.pg_test		= ffv2_pg_test_write,
	.pg_doio		= pnfs_generic_pg_writepages,
	.pg_get_mirror_count	= ffv2_pg_get_mirror_count_write,
	.pg_get_mirror		= ffv2_pg_get_mirror_write,
	.pg_set_mirror		= ffv2_pg_set_mirror_write,
	.pg_cleanup		= pnfs_generic_pg_cleanup,
};

static struct pnfs_layoutdriver_type flexfilesv2_type = {
	.id			= LAYOUT_FLEX_FILES_V2,
	.name			= "LAYOUT_FLEX_FILES_V2",
	.owner			= THIS_MODULE,
	.alloc_layout_hdr	= ffv2_alloc_layout_hdr,
	.free_layout_hdr	= ffv2_free_layout_hdr,
	.alloc_lseg		= ffv2_alloc_lseg,
	.free_lseg		= ffv2_free_lseg,
	.alloc_deviceid_node	= ffv2_alloc_deviceid_node,
	.free_deviceid_node	= ffv2_free_deviceid_node,
	.pg_read_ops		= &ffv2_pg_read_ops,
	.pg_write_ops		= &ffv2_pg_write_ops,
	.read_pagelist		= ffv2_read_pagelist,
	.write_pagelist		= ffv2_write_pagelist,
	.add_lseg		= ffv2_add_lseg,
	.return_range		= ffv2_return_range,
	.get_ds_info		= ffv2_get_ds_info,
	.prepare_layoutreturn	= ffv2_prepare_layoutreturn,
	.cancel_io		= ffv2_cancel_io,
	.sync			= pnfs_nfs_generic_sync,
};

static int __init nfs4flexfilesv2_init(void)
{
	pr_info("%s: NFSv4 Flexfile v2 Layout Driver Registering...\n",
		__func__);
	ffv2_chunk_guard_init();
	return pnfs_register_layoutdriver(&flexfilesv2_type);
}

static void __exit nfs4flexfilesv2_exit(void)
{
	pr_info("%s: NFSv4 Flexfile v2 Layout Driver Unregistering...\n",
		__func__);
	pnfs_unregister_layoutdriver(&flexfilesv2_type);
}

MODULE_ALIAS("nfs-layouttype4-6");

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("The NFSv4 flexfile v2 layout driver");

module_init(nfs4flexfilesv2_init);
module_exit(nfs4flexfilesv2_exit);
