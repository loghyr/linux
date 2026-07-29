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
	/*
	 * Skeleton: refuse every layout by returning NULL.  The pNFS
	 * core treats this as LAYOUTGET failure and falls back to
	 * layoutless I/O.  A subsequent commit will implement XDR
	 * decode of ffv2_layout4 and return a real lseg.
	 */
	return NULL;
}

static void
ffv2_free_lseg(struct pnfs_layout_segment *lseg)
{
	/* Unreachable while ffv2_alloc_lseg returns NULL. */
}

static struct pnfs_layoutdriver_type flexfilesv2_type = {
	.id			= LAYOUT_FLEX_FILES_V2,
	.name			= "LAYOUT_FLEX_FILES_V2",
	.owner			= THIS_MODULE,
	.alloc_layout_hdr	= ffv2_alloc_layout_hdr,
	.free_layout_hdr	= ffv2_free_layout_hdr,
	.alloc_lseg		= ffv2_alloc_lseg,
	.free_lseg		= ffv2_free_lseg,
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
