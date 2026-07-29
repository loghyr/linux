// SPDX-License-Identifier: GPL-2.0
/*
 * NFSv4 Flexfile Version 2 deviceid handling.
 *
 * The ffv2 layout type reuses the ff_device_addr4 wire structure
 * defined for flexfiles v1 -- the deviceid wire format is
 * layout-family-agnostic within flexfiles, carrying a multipath
 * netaddr list plus per-NFS-version parameters (rsize/wsize/
 * tightly_coupled).  This decoder is intentionally near-symmetric
 * with fs/nfs/flexfilelayout/flexfilelayoutdev.c so a shared
 * helper is a natural follow-up refactor once the v2 driver is
 * proven; keeping them separate for now to keep this atomic
 * commit standalone.
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/nfs_fs.h>
#include <linux/sunrpc/xdr.h>

#include "../internal.h"
#include "../nfs4session.h"
#include "../pnfs.h"
#include "flexfilesv2.h"

#define NFS4_FFV2_MAX_DS_VERSIONS	8

struct nfs4_deviceid_node *
ffv2_alloc_deviceid_node(struct nfs_server *server, struct pnfs_device *pdev,
			 gfp_t gfp_flags)
{
	struct nfs4_ffv2_layout_ds *new_ds = NULL;
	struct nfs4_ffv2_ds_version *ds_versions = NULL;
	struct nfs4_pnfs_ds_addr *da;
	struct xdr_stream stream;
	struct xdr_buf buf;
	struct folio *scratch;
	struct list_head dsaddrs;
	struct net *net = server->nfs_client->cl_net;
	__be32 *p;
	u32 mp_count, version_count;
	u32 i;
	int ret = -ENOMEM;

	scratch = folio_alloc(gfp_flags, 0);
	if (!scratch)
		return ERR_PTR(-ENOMEM);

	new_ds = kzalloc(sizeof(*new_ds), gfp_flags);
	if (!new_ds)
		goto out_scratch;

	nfs4_init_deviceid_node(&new_ds->id_node, server, &pdev->dev_id);
	INIT_LIST_HEAD(&dsaddrs);

	xdr_init_decode_pages(&stream, &buf, pdev->pages, pdev->pglen);
	xdr_set_scratch_folio(&stream, scratch);

	/* multipath ds list */
	p = xdr_inline_decode(&stream, 4);
	if (unlikely(!p)) {
		ret = -EIO;
		goto out_err_drain;
	}
	mp_count = be32_to_cpup(p);
	/*
	 * mp_count is MDS-supplied and untrusted.  Cap it at a value
	 * comfortably above any plausible multipath fanout so a hostile
	 * or buggy MDS cannot drive this loop indefinitely (each
	 * nfs4_decode_mp_ds_addr can return NULL once the buffer is
	 * exhausted).  128 matches the ffv1 driver's implicit ceiling
	 * (NFS4_FF_LAYOUT_ADDR_MAX_ADDRS).
	 */
	if (mp_count > 128) {
		ret = -EINVAL;
		goto out_err_drain;
	}
	for (i = 0; i < mp_count; i++) {
		da = nfs4_decode_mp_ds_addr(net, &stream, gfp_flags);
		if (da)
			list_add_tail(&da->da_node, &dsaddrs);
	}
	if (list_empty(&dsaddrs)) {
		ret = -ENOMEDIUM;
		goto out_err_drain;
	}

	/* per-version parameters */
	p = xdr_inline_decode(&stream, 4);
	if (unlikely(!p)) {
		ret = -EIO;
		goto out_err_drain;
	}
	version_count = be32_to_cpup(p);
	if (version_count == 0 || version_count > NFS4_FFV2_MAX_DS_VERSIONS) {
		ret = -EINVAL;
		goto out_err_drain;
	}

	ds_versions = kcalloc(version_count, sizeof(*ds_versions), gfp_flags);
	if (!ds_versions)
		goto out_err_drain;

	for (i = 0; i < version_count; i++) {
		/* version(4) + minor(4) + rsize(4) + wsize(4) + tightly_coupled(4) */
		p = xdr_inline_decode(&stream, 5 * 4);
		if (unlikely(!p)) {
			ret = -EIO;
			goto out_err_free_versions;
		}
		ds_versions[i].version		= be32_to_cpup(p++);
		ds_versions[i].minor_version	= be32_to_cpup(p++);
		ds_versions[i].rsize		= nfs_io_size(be32_to_cpup(p++),
						    server->nfs_client->cl_proto);
		ds_versions[i].wsize		= nfs_io_size(be32_to_cpup(p++),
						    server->nfs_client->cl_proto);
		ds_versions[i].tightly_coupled	= be32_to_cpup(p);

		if (ds_versions[i].rsize > NFS_MAX_FILE_IO_SIZE)
			ds_versions[i].rsize = NFS_MAX_FILE_IO_SIZE;
		if (ds_versions[i].wsize > NFS_MAX_FILE_IO_SIZE)
			ds_versions[i].wsize = NFS_MAX_FILE_IO_SIZE;

		/*
		 * We accept NFSv3 and NFSv4.0/4.1/4.2 DSes to match
		 * ffv1's supported matrix; ffv2 does not add a
		 * different constraint here.
		 */
		if (!((ds_versions[i].version == 3 &&
		       ds_versions[i].minor_version == 0) ||
		      (ds_versions[i].version == 4 &&
		       ds_versions[i].minor_version < 3))) {
			ret = -EPROTONOSUPPORT;
			goto out_err_free_versions;
		}
	}

	new_ds->ds = nfs4_pnfs_ds_add(net, &dsaddrs, gfp_flags);
	if (!new_ds->ds)
		goto out_err_free_versions;
	while (!list_empty(&dsaddrs)) {
		da = list_first_entry(&dsaddrs, struct nfs4_pnfs_ds_addr,
				      da_node);
		list_del(&da->da_node);
		kfree(da->da_netid);
		kfree(da->da_remotestr);
		kfree(da);
	}

	new_ds->ds_versions = ds_versions;
	new_ds->ds_versions_cnt = version_count;

	folio_put(scratch);
	return &new_ds->id_node;

out_err_free_versions:
	kfree(ds_versions);
out_err_drain:
	while (!list_empty(&dsaddrs)) {
		da = list_first_entry(&dsaddrs, struct nfs4_pnfs_ds_addr,
				      da_node);
		list_del(&da->da_node);
		kfree(da->da_netid);
		kfree(da->da_remotestr);
		kfree(da);
	}
	kfree(new_ds);
out_scratch:
	folio_put(scratch);
	return ERR_PTR(ret);
}

void ffv2_free_deviceid_node(struct nfs4_deviceid_node *node)
{
	struct nfs4_ffv2_layout_ds *ffv2_ds = FFV2_LAYOUT_DS_FROM_NODE(node);

	if (ffv2_ds->ds)
		nfs4_pnfs_ds_put(ffv2_ds->ds);
	kfree(ffv2_ds->ds_versions);
	kfree(ffv2_ds);
}
