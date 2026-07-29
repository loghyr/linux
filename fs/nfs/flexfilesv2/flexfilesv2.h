/* SPDX-License-Identifier: GPL-2.0 */
/*
 * NFSv4 Flexfile Version 2 layout driver data structures.
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 *
 * Wire format defined by draft-haynes-nfsv4-flexfiles-v2 and its
 * companion I-Ds (flexfiles-v2-layout, -chunks, -encoding-registry).
 */

#ifndef FS_NFS_NFS4FLEXFILES_V2_LAYOUT_H
#define FS_NFS_NFS4FLEXFILES_V2_LAYOUT_H

#include <linux/refcount.h>
#include "../pnfs.h"

/*
 * Per-file in-memory layout header.  Wraps the generic pNFS layout
 * header and will grow to carry v2-specific state (encoding family,
 * per-mirror striping, checksum algorithm) as later commits land.
 */
struct nfs4_ffv2_layout {
	struct pnfs_layout_hdr generic_hdr;
};

static inline struct nfs4_ffv2_layout *
FFV2_LAYOUT_FROM_HDR(struct pnfs_layout_hdr *lo)
{
	return container_of(lo, struct nfs4_ffv2_layout, generic_hdr);
}

#endif /* FS_NFS_NFS4FLEXFILES_V2_LAYOUT_H */
