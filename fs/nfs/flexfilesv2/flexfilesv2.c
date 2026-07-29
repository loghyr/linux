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

#include <linux/module.h>
#include <linux/nfs4.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_page.h>

#include "flexfilesv2.h"

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
	 * ffv1 cancels outstanding DS RPCs here so they don't try
	 * to complete against a torn-down lseg.  ffv2 has no
	 * outstanding-RPC tracking yet (read/write not wired), so
	 * this is a no-op; the callback exists so the pNFS core's
	 * layout-recall path has a symbol to jump to.
	 */
}

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
