// SPDX-License-Identifier: GPL-2.0
/*
 * Chunk-encoded write path for the NFSv4 Flexfile Version 2 layout
 * driver.  When the lseg's coding_type has parity (RS_VANDERMONDE,
 * MOJETTE, XOR_PARITY, LINUX_MD_RAID, ...), a single user write
 * batch expands to k+m parallel DS writes: k data-shard slices of
 * the stripe, m parity-shard buffers produced by the encoder.
 *
 * The mirror-fanout at the pageio layer gives us k+m per-mirror
 * hdrs "for free": pg_get_mirror_count_write returns k+m and the
 * generic pgio path duplicates the request across N mirrors.  Our
 * per-mirror ffv2_write_pagelist():
 *   1. Reaches the shared stripe context stashed on the lseg.
 *   2. First mirror to arrive under encode_lock does the encode.
 *   3. Overrides hdr->args.pages with its shard's private page
 *      array, so the RPC WRITE ships shard bytes -- not user pages.
 *   4. Dispatches the WRITE via nfs_initiate_pgio.
 *
 * Serialization: only one chunked stripe assembles per lseg at a
 * time; concurrent writers see fls_stripe_busy set and fall back
 * to MDS-inband writes.  Multi-concurrent chunk-stripe support is
 * a follow-up commit and requires shifting stripe state off the
 * lseg (e.g. onto a per-inode radix tree keyed by stripe offset).
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 */

#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/nfs4.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_page.h>
#include <linux/slab.h>
#include <linux/sunrpc/metrics.h>

#include "../internal.h"
#include "../nfs4_fs.h"
#include "../pnfs.h"
#include "flexfilesv2.h"

static void ffv2_stripe_ctx_free(struct ffv2_stripe_ctx *ctx)
{
	u32 i, j;

	if (!ctx)
		return;
	if (ctx->shard_pages) {
		for (i = 0; i < ctx->k + ctx->m; i++) {
			if (!ctx->shard_pages[i])
				continue;
			for (j = 0; j < ctx->pages_per_shard; j++)
				if (ctx->shard_pages[i][j])
					__free_page(ctx->shard_pages[i][j]);
			kfree(ctx->shard_pages[i]);
		}
		kfree(ctx->shard_pages);
	}
	kfree(ctx);
}

static void ffv2_stripe_ctx_put(struct ffv2_stripe_ctx *ctx)
{
	struct nfs4_ffv2_layout_segment *fls;

	if (!ctx || !refcount_dec_and_test(&ctx->refcnt))
		return;
	fls = ctx->fls;
	if (fls) {
		fls->fls_stripe_ctx = NULL;
		atomic_set(&fls->fls_stripe_busy, 0);
	}
	ffv2_stripe_ctx_free(ctx);
}

static struct ffv2_stripe_ctx *
ffv2_stripe_ctx_alloc(struct nfs4_ffv2_layout_segment *fls,
		      u32 k, u32 m, u32 shard_len, gfp_t gfp)
{
	struct ffv2_stripe_ctx *ctx;
	u32 i, j, pages_per_shard;

	pages_per_shard = DIV_ROUND_UP(shard_len, PAGE_SIZE);
	if (!pages_per_shard)
		return ERR_PTR(-EINVAL);

	ctx = kzalloc(sizeof(*ctx), gfp);
	if (!ctx)
		return ERR_PTR(-ENOMEM);
	refcount_set(&ctx->refcnt, k + m);
	ctx->k = k;
	ctx->m = m;
	ctx->shard_len = shard_len;
	ctx->pages_per_shard = pages_per_shard;
	ctx->fls = fls;
	mutex_init(&ctx->encode_lock);

	ctx->shard_pages = kcalloc(k + m, sizeof(*ctx->shard_pages), gfp);
	if (!ctx->shard_pages)
		goto out_free;
	for (i = 0; i < k + m; i++) {
		ctx->shard_pages[i] = kcalloc(pages_per_shard,
					      sizeof(**ctx->shard_pages), gfp);
		if (!ctx->shard_pages[i])
			goto out_free;
		for (j = 0; j < pages_per_shard; j++) {
			ctx->shard_pages[i][j] = alloc_page(gfp);
			if (!ctx->shard_pages[i][j])
				goto out_free;
		}
	}
	return ctx;

out_free:
	ffv2_stripe_ctx_free(ctx);
	return ERR_PTR(-ENOMEM);
}

/*
 * Copy the user's data pages (in hdr->args) into the ctx's per-shard
 * page arrays, splitting a contiguous stripe of k*shard_len bytes
 * into k slices of shard_len bytes each.
 */
static void ffv2_copy_user_to_shards(struct ffv2_stripe_ctx *ctx,
				     struct nfs_pgio_header *hdr)
{
	u32 shard, off_in_shard;
	u32 total = ctx->k * ctx->shard_len;
	u32 pos = 0;
	u32 page_idx = 0;
	u32 page_off = hdr->args.pgbase;
	struct page **user_pages = hdr->args.pages;

	shard = 0;
	off_in_shard = 0;
	while (pos < total) {
		u32 in_page = PAGE_SIZE - page_off;
		u32 in_shard = ctx->shard_len - off_in_shard;
		struct page *dst_page;
		u32 dst_page_idx = off_in_shard >> PAGE_SHIFT;
		u32 dst_off = off_in_shard & (PAGE_SIZE - 1);
		u32 in_dst_page = PAGE_SIZE - dst_off;
		u32 chunk = min3(in_page, in_shard, total - pos);
		void *src, *dst;

		/*
		 * Also clamp to destination-page room.  Source and shard
		 * page boundaries diverge whenever pgbase != 0 (O_DIRECT)
		 * or shard_len is not a multiple of PAGE_SIZE (MDS may
		 * pick any striping_unit_size >= 64), so a chunk that
		 * fits the source page can still overrun the shard's
		 * per-page allocation.
		 */
		chunk = min_t(u32, chunk, in_dst_page);

		if (WARN_ON(!user_pages || !user_pages[page_idx]))
			return;
		dst_page = ctx->shard_pages[shard][dst_page_idx];

		src = kmap_local_page(user_pages[page_idx]);
		dst = kmap_local_page(dst_page);
		memcpy(dst + dst_off, src + page_off, chunk);
		kunmap_local(dst);
		kunmap_local(src);

		pos += chunk;
		off_in_shard += chunk;
		page_off += chunk;
		if (page_off == PAGE_SIZE) {
			page_off = 0;
			page_idx++;
		}
		if (off_in_shard == ctx->shard_len) {
			off_in_shard = 0;
			shard++;
		}
	}
}

/*
 * Encode: walk the shard pages k+m at a time, k data + m parity,
 * page-by-page.  For each page position: kmap all k+m pages, call
 * the encoder on the byte buffers, kunmap.
 *
 * A real implementation should encode a whole shard at once (or
 * larger blocks) rather than page-by-page; page-by-page is chosen
 * here so kmap window stays small and the code is straightforward
 * to review.  Bulk encoding is a follow-up.
 */
static int ffv2_encode_locked(struct ffv2_stripe_ctx *ctx,
			      const struct ffv2_encoder_ops *enc)
{
	const u8 **data;
	u8 **parity;
	u32 pg, i;
	int rc = 0;

	data   = kcalloc(ctx->k, sizeof(*data), GFP_NOFS);
	parity = kcalloc(ctx->m, sizeof(*parity), GFP_NOFS);
	if (!data || !parity) {
		rc = -ENOMEM;
		goto out;
	}

	for (pg = 0; pg < ctx->pages_per_shard; pg++) {
		u32 nbytes = min_t(u32, PAGE_SIZE,
				   ctx->shard_len - pg * PAGE_SIZE);

		for (i = 0; i < ctx->k; i++)
			data[i] = kmap_local_page(ctx->shard_pages[i][pg]);
		for (i = 0; i < ctx->m; i++)
			parity[i] = kmap_local_page(
				ctx->shard_pages[ctx->k + i][pg]);

		rc = enc->encode(ctx->k, ctx->m, nbytes, data, parity);

		for (i = ctx->m; i-- > 0; )
			kunmap_local(parity[i]);
		for (i = ctx->k; i-- > 0; )
			kunmap_local((void *)data[i]);

		if (rc)
			break;
	}

out:
	kfree(parity);
	kfree(data);
	return rc;
}

static int ffv2_ensure_encoded(struct ffv2_stripe_ctx *ctx,
			       const struct ffv2_encoder_ops *enc)
{
	int rc = 0;

	mutex_lock(&ctx->encode_lock);
	if (!ctx->encoded) {
		rc = ffv2_encode_locked(ctx, enc);
		if (!rc)
			ctx->encoded = true;
	}
	mutex_unlock(&ctx->encode_lock);
	return rc;
}

/*
 * Per-mirror-N write RPC glue.  Symmetric with the read path
 * (ffv2_read_prepare_v4 etc.), with an added release-time drop of
 * the shared stripe-ctx reference.
 */
static void ffv2_write_prepare_v4(struct rpc_task *task, void *data)
{
	struct nfs_pgio_header *hdr = data;

	if (nfs4_setup_sequence(hdr->ds_clp,
				&hdr->args.seq_args,
				&hdr->res.seq_res,
				task))
		return;
	rpc_call_start(task);
}

static void ffv2_write_call_done(struct rpc_task *task, void *data)
{
	struct nfs_pgio_header *hdr = data;

	if (test_bit(NFS_IOHDR_REDO, &hdr->flags) &&
	    task->tk_status == 0) {
		nfs4_sequence_done(task, &hdr->res.seq_res);
		return;
	}
	hdr->mds_ops->rpc_call_done(task, hdr);
}

static void ffv2_write_count_stats(struct rpc_task *task, void *data)
{
	struct nfs_pgio_header *hdr = data;

	rpc_count_iostats_metrics(task,
	    &NFS_CLIENT(hdr->inode)->cl_metrics[NFSPROC4_CLNT_WRITE]);
}

static void ffv2_write_release(void *data)
{
	struct nfs_pgio_header *hdr = data;
	struct pnfs_layout_segment *lseg = hdr->lseg;
	struct nfs4_ffv2_layout_segment *fls = lseg ? FFV2_LSEG(lseg) : NULL;

	if (fls)
		ffv2_stripe_ctx_put(fls->fls_stripe_ctx);
	pnfs_generic_rw_release(data);
}

static const struct rpc_call_ops ffv2_write_call_ops_v4 = {
	.rpc_call_prepare	= ffv2_write_prepare_v4,
	.rpc_call_done		= ffv2_write_call_done,
	.rpc_count_stats	= ffv2_write_count_stats,
	.rpc_release		= ffv2_write_release,
};

/*
 * Chunk-encoded write dispatch.  Called once per mirror index by
 * pnfs_do_write; pageio processes mirrors sequentially so mirror 0
 * arrives first, allocates + populates + encodes the stripe context,
 * and publishes it on the lseg for mirrors 1..k+m-1 to consume.
 *
 * Refcount discipline: the ctx starts at 1 (mirror 0's ref); each
 * subsequent mirror inc's before its dispatch.  Each successful
 * dispatch has its ref dropped by ffv2_write_release() at RPC
 * completion.  A dispatch failure drops the ref inline before
 * returning PNFS_NOT_ATTEMPTED.
 */
enum pnfs_try_status
ffv2_write_pagelist_chunked(struct nfs_pgio_header *hdr, int sync)
{
	struct pnfs_layout_segment *lseg = hdr->lseg;
	struct nfs4_ffv2_layout_segment *fls = FFV2_LSEG(lseg);
	struct nfs4_ffv2_mirror *mirror = fls->mirror_array[0];
	struct ffv2_stripe_ctx *ctx;
	struct nfs4_ffv2_stripe *stripe;
	struct nfs4_ffv2_data_server *ds_slot;
	struct nfs4_ffv2_file_info *fi;
	struct nfs4_deviceid_node *devnode;
	struct nfs4_ffv2_layout_ds *layout_ds;
	struct nfs4_pnfs_ds *ds;
	struct nfs_server *mds_srv = NFS_SERVER(hdr->inode);
	struct rpc_clnt *ds_clnt;
	const struct ffv2_encoder_ops *enc;
	u32 k = mirror->protection_data;
	u32 m = mirror->protection_parity;
	u32 mirror_idx = hdr->pgio_mirror_idx;
	int rc;

	enc = ffv2_find_encoder(mirror->coding_type);
	if (!enc || !enc->encode)
		return PNFS_NOT_ATTEMPTED;

	if (mirror_idx == 0) {
		/* First mirror -- take busy gate, allocate, encode. */
		if (hdr->args.count != k * mirror->striping_unit_size ||
		    hdr->args.offset % (k * mirror->striping_unit_size))
			return PNFS_NOT_ATTEMPTED;
		if (atomic_cmpxchg(&fls->fls_stripe_busy, 0, 1) != 0)
			return PNFS_NOT_ATTEMPTED;

		ctx = ffv2_stripe_ctx_alloc(fls, k, m,
					    mirror->striping_unit_size,
					    nfs_io_gfp_mask());
		if (IS_ERR(ctx)) {
			atomic_set(&fls->fls_stripe_busy, 0);
			return PNFS_NOT_ATTEMPTED;
		}
		refcount_set(&ctx->refcnt, 1);
		ffv2_copy_user_to_shards(ctx, hdr);
		if (ffv2_ensure_encoded(ctx, enc)) {
			ffv2_stripe_ctx_free(ctx);
			atomic_set(&fls->fls_stripe_busy, 0);
			return PNFS_NOT_ATTEMPTED;
		}
		smp_store_release(&fls->fls_stripe_ctx, ctx);
	} else {
		ctx = smp_load_acquire(&fls->fls_stripe_ctx);
		if (!ctx || mirror_idx >= ctx->k + ctx->m)
			return PNFS_NOT_ATTEMPTED;
		refcount_inc(&ctx->refcnt);
	}

	/* From here on the ctx ref belongs to this dispatch. */
	if (mirror->stripes_cnt == 0)
		goto out_put_ctx;
	stripe = &mirror->stripes[0];
	if (mirror_idx >= stripe->data_servers_cnt)
		goto out_put_ctx;
	ds_slot = &stripe->data_servers[mirror_idx];
	if (ds_slot->versions_cnt == 0)
		goto out_put_ctx;
	fi = &ds_slot->versions[0];

	devnode = nfs4_find_get_deviceid(mds_srv, &ds_slot->devid,
					 hdr->cred, nfs_io_gfp_mask());
	if (!devnode)
		goto out_put_ctx;
	layout_ds = FFV2_LAYOUT_DS_FROM_NODE(devnode);
	ds = layout_ds->ds;
	if (!ds || layout_ds->ds_versions_cnt == 0 ||
	    layout_ds->ds_versions[0].version != 4) {
		nfs4_put_deviceid_node(devnode);
		goto out_put_ctx;
	}

	rc = nfs4_pnfs_ds_connect(mds_srv, ds, devnode,
				  NFS_DEF_TCP_TIMEO, 0,
				  layout_ds->ds_versions[0].version,
				  layout_ds->ds_versions[0].minor_version);
	if (rc || !ds->ds_clp) {
		nfs4_put_deviceid_node(devnode);
		goto out_put_ctx;
	}
	ds_clnt = ds->ds_clp->cl_rpcclient;

	refcount_inc(&ds->ds_clp->cl_count);
	hdr->ds_clp = ds->ds_clp;
	hdr->args.fh = &fi->fh;
	hdr->args.stateid = fi->stateid;
	hdr->mds_offset = hdr->args.offset;

	/* Override user pages with this mirror's shard pages. */
	hdr->args.pages  = ctx->shard_pages[mirror_idx];
	hdr->args.pgbase = 0;
	hdr->args.count  = ctx->shard_len;
	hdr->args.offset = ffv2_ds_offset(mirror, hdr->args.offset);

	nfs_initiate_pgio(ds_clnt, hdr, hdr->cred,
			  ds->ds_clp->rpc_ops, &ffv2_write_call_ops_v4,
			  sync, RPC_TASK_SOFTCONN, NULL);
	nfs4_put_deviceid_node(devnode);
	return PNFS_ATTEMPTED;

out_put_ctx:
	ffv2_stripe_ctx_put(ctx);
	return PNFS_NOT_ATTEMPTED;
}
