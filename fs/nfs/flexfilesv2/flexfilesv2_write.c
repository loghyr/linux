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
		spin_lock(&fls->fls_ctx_lock);
		list_del(&ctx->list);
		spin_unlock(&fls->fls_ctx_lock);
	}
	ffv2_stripe_ctx_free(ctx);
}

/*
 * Per-pgio-descriptor identifier used as a sibling-mirror key.
 * hdr->io_completion is set for buffered writeback; hdr->dreq for
 * O_DIRECT.  Both are shared across mirrors of the same pgio but
 * differ between distinct writers.  Callers use whichever is
 * non-NULL; if both are NULL (rare kernel-internal write helpers)
 * we fall through to a NULL key -- safe because i_rwsem serialises
 * such writers at inode granularity, so only one is ever in flight
 * against this lseg at a time.
 */
static void *ffv2_writer_key(const struct nfs_pgio_header *hdr)
{
	if (hdr->io_completion)
		return (void *)hdr->io_completion;
	return (void *)hdr->dreq;
}

/*
 * Look up an in-flight stripe context matching (writer_key,
 * stripe_off) on `fls`; if none exists, install `alloc`.  On
 * success returns with the refcount already incremented for the
 * caller (so the caller does not need refcount_inc).
 *
 * Keying on the per-pgio writer_key as well as stripe_off ensures
 * sibling mirrors of the SAME writer share a ctx while a DIFFERENT
 * writer to the same stripe gets its own ctx.  Sharing across
 * writers would silently overwrite the second writer's user data
 * with the first's, since data pages are copied only on the alloc
 * path.
 *
 * `alloc` is the caller-preallocated candidate.  The caller
 * allocates upfront (before taking the lock) so
 * ffv2_stripe_ctx_alloc's page-alloc loop stays out of the
 * spinlock's critical section.
 */
static struct ffv2_stripe_ctx *
ffv2_stripe_ctx_find_or_add(struct nfs4_ffv2_layout_segment *fls,
			    void *writer_key, u64 stripe_off,
			    struct ffv2_stripe_ctx *alloc)
{
	struct ffv2_stripe_ctx *ctx;

	spin_lock(&fls->fls_ctx_lock);
	list_for_each_entry(ctx, &fls->fls_ctx_list, list) {
		if (ctx->writer_key != writer_key ||
		    ctx->stripe_off != stripe_off)
			continue;
		/*
		 * refcount_inc_not_zero handles the "about to be freed"
		 * race: if another release just dropped this ctx's ref
		 * to zero and is inside ffv2_stripe_ctx_put waiting for
		 * our spinlock to run list_del, we skip past it and
		 * treat the lookup as a miss.  The blocked _put will
		 * then complete list_del before we install our new
		 * candidate.
		 */
		if (refcount_inc_not_zero(&ctx->refcnt)) {
			spin_unlock(&fls->fls_ctx_lock);
			return ctx;
		}
	}
	alloc->writer_key = writer_key;
	alloc->stripe_off = stripe_off;
	list_add(&alloc->list, &fls->fls_ctx_list);
	spin_unlock(&fls->fls_ctx_lock);
	return alloc;
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
	/*
	 * Refcount is set by the caller after find_or_add resolves the
	 * winner: the alloc-winner gets 1, then each subsequent-mirror
	 * lookup inc's via refcount_inc_not_zero.
	 */
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
 * Zero every byte of every shard buffer in the ctx.  Used before a
 * partial-stripe write to establish deterministic content for the
 * bytes the user did not supply (safe only when the untouched
 * region is entirely beyond current EOF -- see the append-past-EOF
 * path in ffv2_write_pagelist_chunked).
 */
static void ffv2_zero_shards(struct ffv2_stripe_ctx *ctx)
{
	u32 i, j;

	for (i = 0; i < ctx->k + ctx->m; i++) {
		for (j = 0; j < ctx->pages_per_shard; j++) {
			void *p = kmap_local_page(ctx->shard_pages[i][j]);

			memset(p, 0, PAGE_SIZE);
			kunmap_local(p);
		}
	}
}

/*
 * Copy `count` bytes from the user's data pages (in hdr->args) into
 * the ctx's per-shard page arrays, starting at byte
 * `dst_off_in_stripe` within the flattened k*shard_len stripe view.
 * dst_off_in_stripe + count MUST fit within k*shard_len.  For a
 * full-stripe write the caller passes (0, k*shard_len).
 */
static void ffv2_copy_user_to_shards_at(struct ffv2_stripe_ctx *ctx,
					struct nfs_pgio_header *hdr,
					u32 dst_off_in_stripe, u32 count)
{
	u32 shard, off_in_shard;
	u32 pos = 0;
	u32 page_idx = 0;
	u32 page_off = hdr->args.pgbase;
	struct page **user_pages = hdr->args.pages;

	shard = dst_off_in_stripe / ctx->shard_len;
	off_in_shard = dst_off_in_stripe % ctx->shard_len;
	while (pos < count) {
		u32 in_page = PAGE_SIZE - page_off;
		u32 in_shard = ctx->shard_len - off_in_shard;
		struct page *dst_page;
		u32 dst_page_idx = off_in_shard >> PAGE_SHIFT;
		u32 dst_off = off_in_shard & (PAGE_SIZE - 1);
		u32 in_dst_page = PAGE_SIZE - dst_off;
		u32 chunk = min3(in_page, in_shard, count - pos);
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

/*
 * DS-side write completion hook.  On DS-side transport failure set
 * NFS_IOHDR_RESEND_MDS so ffv2_write_release() reissues the write
 * against the MDS via pnfs_write_done_resend_to_mds().  Returning
 * task->tk_status (a negative errno) makes nfs_pgio_result() skip
 * nfs_set_pgio_error(), which is what we want: the resend will drive
 * the pages to completion, we do not want the failed DS attempt to
 * flip the pages to a "completed with error" state that
 * nfs_write_completion() might interpret as done.
 *
 * Per-DS-ioerr tracking for LAYOUTRETURN is a follow-up.
 */
static int ffv2_write_done_cb(struct rpc_task *task,
			      struct nfs_pgio_header *hdr)
{
	if (task->tk_status < 0) {
		if (!test_and_set_bit(NFS_IOHDR_RESEND_MDS, &hdr->flags))
			pnfs_error_mark_layout_for_return(hdr->inode,
							  hdr->lseg);
		return task->tk_status;
	}
	return 0;
}

static void ffv2_write_release(void *data)
{
	struct nfs_pgio_header *hdr = data;
	struct pnfs_layout_segment *lseg = hdr->lseg;
	struct nfs4_ffv2_layout_segment *fls = lseg ? FFV2_LSEG(lseg) : NULL;

	if (fls && fls->mirror_array_cnt > 0 && fls->mirror_array[0]) {
		struct nfs4_ffv2_mirror *mirror = fls->mirror_array[0];
		u64 stripe_bytes = (u64)mirror->protection_data *
				   mirror->striping_unit_size;
		struct ffv2_stripe_ctx *ctx;
		u64 stripe_off;
		void *writer_key = ffv2_writer_key(hdr);

		/*
		 * Derive the stripe-aligned key from hdr->mds_offset by
		 * rounding down; mds_offset itself keeps its
		 * file-absolute, pre-conversion meaning for
		 * layoutcommit / RESEND_MDS bookkeeping.  Unaligned
		 * safe-append / RMW batches would otherwise miss the
		 * ctx and leak the shard-page arrays until lseg
		 * teardown.
		 */
		if (stripe_bytes)
			stripe_off = div64_u64(hdr->mds_offset, stripe_bytes) *
				     stripe_bytes;
		else
			stripe_off = hdr->mds_offset;

		spin_lock(&fls->fls_ctx_lock);
		list_for_each_entry(ctx, &fls->fls_ctx_list, list) {
			if (ctx->writer_key != writer_key ||
			    ctx->stripe_off != stripe_off)
				continue;
			spin_unlock(&fls->fls_ctx_lock);
			ffv2_stripe_ctx_put(ctx);
			goto done;
		}
		spin_unlock(&fls->fls_ctx_lock);
	}
done:
	/*
	 * If ffv2_write_done_cb marked this hdr for MDS resend on a DS
	 * error, actually drive that resend now.  Without this hook the
	 * RESEND_MDS bit would be set but never consumed, and
	 * nfs_write_completion would mark the pages as committed --
	 * silent data loss.  Matches ff_layout_write_release.
	 */
	if (test_bit(NFS_IOHDR_RESEND_MDS, &hdr->flags) &&
	    !test_and_set_bit(NFS_IOHDR_REDO, &hdr->flags))
		hdr->task.tk_status = pnfs_write_done_resend_to_mds(hdr);
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

	/*
	 * Chunked DS-direct is defined only for DENSE striping: SPARSE
	 * has no natural file-offset home for parity shards, and NONE
	 * is unspecified.  Anything else falls back to MDS.
	 */
	if (mirror->striping != FFV2_STRIPING_DENSE)
		return PNFS_NOT_ATTEMPTED;

	{
		u64 stripe_bytes = (u64)k * mirror->striping_unit_size;
		u64 stripe_off, off_in_stripe;
		bool full_stripe, safe_partial;
		struct ffv2_stripe_ctx *cand, *found;

		stripe_off = hdr->args.offset - (hdr->args.offset % stripe_bytes);
		off_in_stripe = hdr->args.offset - stripe_off;
		full_stripe = (off_in_stripe == 0 &&
			       hdr->args.count == stripe_bytes);
		/*
		 * Partial-stripe safe-append: the user write is fully
		 * contained within a single stripe, AND the stripe starts
		 * at or past current EOF so the un-user-supplied bytes are
		 * definitively beyond the file and reading them would
		 * return short.  Zero-filling those bytes then encoding is
		 * indistinguishable from what a read after this write
		 * would observe.  Reads of an existing stripe we would
		 * overwrite need RMW (fetch, modify, encode); that is
		 * deferred and falls back to MDS below.
		 */
		safe_partial = !full_stripe &&
			       off_in_stripe + hdr->args.count <= stripe_bytes &&
			       i_size_read(hdr->inode) <= stripe_off;
		if (!full_stripe && !safe_partial)
			return PNFS_NOT_ATTEMPTED;

		/*
		 * Preallocate (page-alloc loop is heavy, keep it out of
		 * the spinlock); publish under lock via find_or_add.
		 * If someone raced us and registered a ctx for the same
		 * stripe_off first, we free `cand` and use theirs.
		 */
		cand = ffv2_stripe_ctx_alloc(fls, k, m,
					     mirror->striping_unit_size,
					     nfs_io_gfp_mask());
		if (IS_ERR(cand))
			return PNFS_NOT_ATTEMPTED;
		refcount_set(&cand->refcnt, 1);

		found = ffv2_stripe_ctx_find_or_add(fls, ffv2_writer_key(hdr),
						    stripe_off, cand);
		if (found != cand) {
			ffv2_stripe_ctx_free(cand);
			ctx = found;	/* refcount already inc'd */
		} else {
			ctx = cand;	/* refcount initialized to 1 above */
			if (!full_stripe)
				ffv2_zero_shards(ctx);
			ffv2_copy_user_to_shards_at(ctx, hdr,
						    (u32)off_in_stripe,
						    hdr->args.count);
		}
	}

	if (ffv2_ensure_encoded(ctx, enc)) {
		ffv2_stripe_ctx_put(ctx);
		return PNFS_NOT_ATTEMPTED;
	}
	if (mirror_idx >= ctx->k + ctx->m) {
		ffv2_stripe_ctx_put(ctx);
		return PNFS_NOT_ATTEMPTED;
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
	hdr->pgio_done_cb = ffv2_write_done_cb;

	/*
	 * Override user pages with this mirror's shard pages.  The DS
	 * offset is derived from the stripe-aligned ctx->stripe_off,
	 * not from the (possibly unaligned) hdr->args.offset -- the
	 * latter is what ffv2_ds_offset was originally called with and
	 * that shifts DS placement for any off_in_stripe != 0 batch.
	 */
	hdr->args.pages  = ctx->shard_pages[mirror_idx];
	hdr->args.pgbase = 0;
	hdr->args.count  = ctx->shard_len;
	hdr->args.offset = ffv2_ds_offset(mirror, ctx->stripe_off);

	nfs_initiate_pgio(ds_clnt, hdr, hdr->cred,
			  ds->ds_clp->rpc_ops, &ffv2_write_call_ops_v4,
			  sync, RPC_TASK_SOFTCONN, NULL);
	nfs4_put_deviceid_node(devnode);
	return PNFS_ATTEMPTED;

out_put_ctx:
	ffv2_stripe_ctx_put(ctx);
	return PNFS_NOT_ATTEMPTED;
}
