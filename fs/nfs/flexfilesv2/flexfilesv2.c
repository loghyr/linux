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
#include <linux/sched/mm.h>
#include <linux/sunrpc/metrics.h>

#include "../internal.h"
#include "../nfs4_fs.h"
#include "../nfs4trace.h"
#include "../pnfs.h"
#include "flexfilesv2.h"
#include "flexfilesv2_xdr_chunk.h"

/*
 * See flexfilesv2.h for the semantics.  The definition lives here so
 * both flexfilesv2.o (this module's core) and any future kunit test
 * object can link against it via the extern declaration.
 */
u32 ffv2_cg_client_id_seed;

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

/* Defined below, next to the commit path it belongs to. */
static const struct pnfs_commit_ops ffv2_commit_ops;

static struct pnfs_layout_hdr *
ffv2_alloc_layout_hdr(struct inode *inode, gfp_t gfp_flags)
{
	struct nfs4_ffv2_layout *ffv2l;

	ffv2l = kzalloc(sizeof(*ffv2l), gfp_flags);
	if (!ffv2l)
		return NULL;
	pnfs_init_ds_commit_info(&ffv2l->commit_info);
	ffv2l->commit_info.ops = &ffv2_commit_ops;
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
	/* The pNFS core invalidates overlapping lsegs and reacquires them. */
}

/* A stripe header covers all shards, so commit tracking uses one bucket. */
static void
ffv2_setup_ds_info(struct pnfs_ds_commit_info *fl_cinfo,
		   struct pnfs_layout_segment *lseg)
{
	struct inode *inode = lseg->pls_layout->plh_inode;
	struct pnfs_commit_array *array, *new;

	new = pnfs_alloc_commit_array(1, nfs_io_gfp_mask());
	if (!new)
		return;
	spin_lock(&inode->i_lock);
	array = pnfs_add_commit_array(fl_cinfo, new, lseg);
	spin_unlock(&inode->i_lock);
	if (array != new)
		pnfs_free_commit_array(new);
}

static void
ffv2_release_ds_info(struct pnfs_ds_commit_info *fl_cinfo,
		     struct inode *inode)
{
	spin_lock(&inode->i_lock);
	pnfs_generic_ds_cinfo_destroy(fl_cinfo);
	spin_unlock(&inode->i_lock);
}

/* Commit entry point for FFv2 writes using NFS_UNSTABLE. */
static int
ffv2_commit_pagelist(struct inode *inode, struct list_head *mds_pages,
		     int how, struct nfs_commit_info *cinfo)
{
	return PNFS_NOT_ATTEMPTED;
}

static const struct pnfs_commit_ops ffv2_commit_ops = {
	.setup_ds_info		= ffv2_setup_ds_info,
	.release_ds_info	= ffv2_release_ds_info,
	.mark_request_commit	= pnfs_layout_mark_request_commit,
	.clear_request_commit	= pnfs_generic_clear_request_commit,
	.scan_commit_lists	= pnfs_generic_scan_commit_lists,
	.recover_commit_reqs	= pnfs_generic_recover_commit_reqs,
	.commit_pagelist	= ffv2_commit_pagelist,
};

static struct pnfs_ds_commit_info *
ffv2_get_ds_info(struct inode *inode)
{
	struct pnfs_layout_hdr *layout = NFS_I(inode)->layout;

	if (layout == NULL)
		return NULL;
	return &FFV2_LAYOUT_FROM_HDR(layout)->commit_info;
}

/*
 * ffv2_layoutreturn4 is two variable-length arrays, so the shortest
 * legal encoding is eight bytes -- a zero count for each -- not an
 * absent body.  encode_layoutreturn()'s fallback for a layout driver
 * with no encode op writes a zero-length lrf_body instead, which a
 * metadata server that validates the body rejects with
 * NFS4ERR_BADXDR.  Emit the empty arrays explicitly.
 *
 * No per-mirror reports are emitted yet; the empty arrays preserve the
 * required layoutreturn body shape.
 */
static void
ffv2_encode_layoutreturn(struct xdr_stream *xdr, const void *voidargs,
			 const struct nfs4_xdr_opaque_data *ff_opaque)
{
	__be32 *p = xdr_reserve_space(xdr, 12);

	if (WARN_ON_ONCE(!p))
		return;

	*p++ = cpu_to_be32(8);	/* lrf_body length */
	*p++ = cpu_to_be32(0);	/* ffv2lr_ioerr_report<>   */
	*p = cpu_to_be32(0);	/* ffv2lr_iostats_report<> */
}

/*
 * No .free: ld_private->data stays NULL, and every caller of .free
 * tests it first.
 */
static const struct nfs4_xdr_opaque_ops ffv2_layoutreturn_ops = {
	.encode = ffv2_encode_layoutreturn,
};

static int
ffv2_prepare_layoutreturn(struct nfs4_layoutreturn_args *args)
{
	args->ld_private->ops = &ffv2_layoutreturn_ops;
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
 * Reissue a failed data-server read through the metadata server.
 *
 * Mark the layout for return first, so the next LAYOUTGET can hand
 * out a segment that does not name the data server that just failed.
 * NFS_IOHDR_REDO makes this one-shot and tells nfs_read_completion to
 * leave the pages alone -- the resent header owns them now.
 *
 * Called from .rpc_release, not from the done callback, matching
 * ff_layout_reset_read: nfs_pageio_resend runs the whole pageio
 * machinery, which must not run underneath the RPC that is still
 * completing.
 */
static void ffv2_reset_read_to_mds(struct nfs_pgio_header *hdr)
{
	pnfs_error_mark_layout_for_return(hdr->inode, hdr->lseg);
	if (!test_and_set_bit(NFS_IOHDR_REDO, &hdr->flags))
		hdr->task.tk_status = pnfs_read_done_resend_to_mds(hdr);
}

/* ---------- chunk-encoded shard read ---------------------------- */

/*
 * One page-cache read of one shard, carried by CHUNK_READ.
 *
 * A chunk-encoded data server does not answer plain NFSv4 READ -- it
 * has no notion of a byte offset into a file it only ever sees as
 * numbered chunks -- so the read path cannot reuse nfs_initiate_pgio
 * the way the MIRRORED path does.  This wrapper is the read-side
 * counterpart of ffv2_chunk_read_fetch_dispatch: same wire op, same
 * procinfo, but it completes an nfs_pgio_header instead of feeding a
 * stripe context.
 *
 * The payload needs no bounce buffer.  args.pages below is the
 * header's own page vector, so the decoder splices the chunk straight
 * into the pages the reader is waiting on.
 */
struct ffv2_shard_read {
	struct nfs_pgio_header	*hdr;		/* owned; we complete it */
	struct pnfs_layout_segment *lseg;	/* holds one lseg ref */
	struct nfs_client	*ds_clp;	/* holds one cl_count ref */
	int			retry_attempts;
	struct ffv2_chunk_read_data data;
	/*
	 * Embedded rpc_task: a caller-supplied task never carries
	 * RPC_TASK_DYNAMIC and the RPC core snapshots tk_flags before
	 * .rpc_release runs, so freeing the wrapper from inside release
	 * is safe.
	 */
	struct rpc_task		task;
};

/* Account the RPC through the wrapper's pgio header. */
static void ffv2_shard_read_count_stats(struct rpc_task *task, void *data)
{
	struct ffv2_shard_read *r = data;

	rpc_count_iostats_metrics(task,
	    &NFS_CLIENT(r->hdr->inode)->cl_metrics[NFSPROC4_CLNT_READ]);
}

static void ffv2_shard_read_prepare(struct rpc_task *task, void *data)
{
	struct ffv2_shard_read *r = data;

	if (nfs4_setup_sequence(r->ds_clp, &r->data.seq_args,
				&r->data.res.seq_res, task))
		return;
	rpc_call_start(task);
}

/*
 * Wire-integrity check over the spliced payload.  Fail closed: an
 * algorithm the client cannot compute, or one the data server names
 * that the layout does not, means the bytes go unverified, and
 * unverified bytes must not reach the page cache.  A failure here
 * lands the read on the metadata server like any other error.
 *
 * This certifies the wire only.  Whether the data server's stored
 * copy has rotted is its own concern; the client can only catch flips
 * between the two.
 */
static int ffv2_shard_read_verify(struct ffv2_shard_read *r,
				  const struct nfs4_ffv2_mirror *mirror,
				  const struct ffv2_read_chunk4 *chunk)
{
	u8 computed[FFV2_CHECKSUM_MAX_LEN];
	size_t computed_len;
	int rc;

	if (mirror->checksum_algorithm != FFV2_CHECKSUM_ALG_CRC32)
		return -EBADMSG;
	if (chunk->checksum.algorithm != FFV2_CHECKSUM_ALG_CRC32) {
		WARN_ONCE(1, "ffv2 CHUNK_READ: layout CRC32 vs wire algo %u\n",
			  chunk->checksum.algorithm);
		return -EBADMSG;
	}
	rc = ffv2_checksum_compute_pages(FFV2_CHECKSUM_ALG_CRC32,
					 r->data.args.pages,
					 r->data.args.pgbase,
					 chunk->chunk_len,
					 computed, &computed_len);
	if (rc)
		return rc == -EOPNOTSUPP ? -EBADMSG : rc;

	/* memcmp, not crypto_memneq: an integrity check, not a MAC. */
	if (computed_len != 4 || chunk->checksum.value_len != 4 ||
	    memcmp(computed, chunk->checksum.value, 4) != 0)
		return -EBADMSG;
	return 0;
}

static void ffv2_shard_read_call_done(struct rpc_task *task, void *data)
{
	struct ffv2_shard_read *r = data;
	struct nfs_pgio_header *hdr = r->hdr;
	struct nfs4_ffv2_layout_segment *fls = FFV2_LSEG(r->lseg);
	const struct ffv2_read_chunk4 *chunk;
	unsigned int good;
	loff_t end;
	u32 count;
	int rc;

	/*
	 * Return the session slot first, and stop if the sequence layer
	 * restarted the call: it clears tk_status, so the nchunks check
	 * below would read an undecoded reply and fail the read with
	 * -EIO instead of letting the retry run.  Harmless when no slot
	 * was acquired, and skipping the slot return on an rpc_exit path
	 * leaks a slot per failed read until the data server wedges.
	 */
	if (!nfs4_sequence_done(task, &r->data.res.seq_res))
		return;

	if (task->tk_status < 0) {
		unsigned long delay_ms;

		if (task->tk_status != -NFS4ERR_DELAY)
			goto out_err;
		if (++r->retry_attempts > FFV2_CHUNK_READ_MAX_DELAY_ATTEMPTS) {
			/*
			 * -NFS4ERR_DELAY is not an errno.  The decoder
			 * leaves it raw so the retry above can match on
			 * it; past the cap it would be recorded as
			 * hdr->error and read back by userspace as a
			 * nonsense value.
			 */
			task->tk_status = -EIO;
			goto out_err;
		}
		delay_ms = min_t(unsigned long,
				 r->retry_attempts *
					FFV2_CHUNK_READ_DELAY_BASE_MS,
				 FFV2_CHUNK_READ_DELAY_CAP_MS);
		rpc_delay(task, msecs_to_jiffies(delay_ms));
		rpc_restart_call_prepare(task);
		return;
	}

	/*
	 * nchunks == 0 with NFS4_OK is the data server's transient-OOM
	 * truncation reply, which carries a separately-computed eof.  It
	 * is not a clean end of file and chunks[0] is untouched kzalloc
	 * memory, so nothing below may look at it.
	 */
	if (r->data.res.nchunks == 0) {
		task->tk_status = -EIO;
		goto out_err;
	}
	chunk = &r->data.res.chunks[0];
	if (chunk->status != NFS4_OK && chunk->status != NFS4ERR_NOENT) {
		task->tk_status =
			chunk->status == FFV2_NFS4ERR_PAYLOAD_NOT_ATOMIC ?
			-EBADMSG : -EIO;
		goto out_err;
	}

	rc = ffv2_shard_read_verify(r, fls->mirror_array[0], chunk);
	if (rc) {
		task->tk_status = rc;
		goto out_err;
	}

	count = min_t(u32, chunk->effective_len, hdr->args.count);
	hdr->res.count = count;
	end = hdr->args.offset + count;

	if (count < hdr->args.count) {
		/*
		 * The chunk held less than was asked for.  That is the
		 * file ending inside this shard, or it is a data server
		 * that has lost bytes -- and the two are told apart only
		 * by the size the metadata server reports.  Short of end
		 * of file there is no in-place retry channel here (the
		 * next chunk lives on a different data server), so hand
		 * the read to the metadata server instead of returning a
		 * hole the reader would take for real zeroes.
		 */
		if (end < i_size_read(hdr->inode)) {
			task->tk_status = -EIO;
			goto out_err;
		}
		good = end - hdr->io_start;
		hdr->res.eof = 1;
		if (hdr->good_bytes > good) {
			hdr->good_bytes = good;
			set_bit(NFS_IOHDR_EOF, &hdr->flags);
			clear_bit(NFS_IOHDR_ERROR, &hdr->flags);
		}
	} else {
		hdr->res.eof = end >= i_size_read(hdr->inode);
	}
	return;

out_err:
	nfs_set_pgio_error(hdr, task->tk_status, hdr->args.offset);
	set_bit(NFS_IOHDR_RESEND_MDS, &hdr->flags);
}

static void ffv2_shard_read_release(void *data)
{
	struct ffv2_shard_read *r = data;
	struct nfs_pgio_header *hdr = r->hdr;
	struct pnfs_layout_segment *lseg = r->lseg;
	struct nfs_client *ds_clp = r->ds_clp;

	/*
	 * Order: resend decision first (it still needs the header), then
	 * free the wrapper, then complete the header -- completion frees
	 * it -- and only then drop the lseg ref, which the header's own
	 * ref no longer covers once it is gone.
	 */
	if (test_bit(NFS_IOHDR_RESEND_MDS, &hdr->flags))
		ffv2_reset_read_to_mds(hdr);
	kfree(r);
	nfs_put_client(ds_clp);
	hdr->completion_ops->completion(hdr);
	pnfs_put_lseg(lseg);
}

static const struct rpc_call_ops ffv2_shard_read_call_ops = {
	.rpc_call_prepare	= ffv2_shard_read_prepare,
	.rpc_call_done		= ffv2_shard_read_call_done,
	.rpc_count_stats	= ffv2_shard_read_count_stats,
	.rpc_release		= ffv2_shard_read_release,
};

/*
 * Issue one shard's CHUNK_READ for a chunk-encoded layout.
 *
 * The header must start on a chunk boundary.  CHUNK_READ names a
 * whole chunk, and the decoder splices its payload at args.pgbase, so
 * there is nowhere to put the leading bytes of a chunk the reader did
 * not ask for.  Readahead does hand down headers that start mid-chunk
 * whenever the striping unit is larger than a page, and those take
 * the metadata-server path until a later commit gives this one a
 * landing buffer.
 *
 * A header that starts on the boundary but asks for less than the
 * chunk holds is not caught here, because the chunk's length is not
 * known until the reply arrives.  It fails safely instead: the
 * decoder refuses to splice a payload longer than the room it was
 * given, and the read falls back to the metadata server.  The same
 * landing buffer would fix that case too.
 */
static enum pnfs_try_status
ffv2_read_dispatch_chunk(struct nfs_pgio_header *hdr,
			 struct nfs4_ffv2_mirror *mirror, u32 shard_idx,
			 u32 in_chunk)
{
	struct nfs4_ffv2_stripe *stripe;
	struct nfs4_ffv2_data_server *ds_slot;
	struct nfs4_ffv2_file_info *fi;
	struct nfs4_deviceid_node *devnode;
	struct nfs4_ffv2_layout_ds *layout_ds;
	struct nfs4_pnfs_ds *ds;
	struct nfs_server *mds_srv = NFS_SERVER(hdr->inode);
	struct ffv2_shard_read *r;
	struct rpc_message msg;
	struct rpc_task_setup task_setup;
	struct rpc_task *task;
	u64 chunk_index;
	int rc;

	if (in_chunk != 0)
		return PNFS_NOT_ATTEMPTED;
	if (mirror->stripes_cnt == 0)
		return PNFS_NOT_ATTEMPTED;
	stripe = &mirror->stripes[0];
	if (shard_idx >= stripe->data_servers_cnt)
		return PNFS_NOT_ATTEMPTED;
	ds_slot = &stripe->data_servers[shard_idx];
	if (ds_slot->versions_cnt == 0)
		return PNFS_NOT_ATTEMPTED;
	fi = &ds_slot->versions[0];

	devnode = nfs4_find_get_deviceid(mds_srv, &ds_slot->devid,
					 hdr->cred, nfs_io_gfp_mask());
	if (!devnode)
		return PNFS_NOT_ATTEMPTED;
	layout_ds = FFV2_LAYOUT_DS_FROM_NODE(devnode);
	ds = layout_ds->ds;
	if (!ds || layout_ds->ds_versions_cnt == 0)
		goto out_put_devnode;
	/*
	 * CHUNK_READ is a v4.2 operation; the encoder hard-codes
	 * minorversion 2 in the compound header.  A v3 or v4.0/4.1 data
	 * server cannot serve a chunk-encoded shard at all, so there is
	 * no fallback dispatch to try -- the read goes to the metadata
	 * server.
	 */
	if (layout_ds->ds_versions[0].version != 4 ||
	    layout_ds->ds_versions[0].minor_version < 2)
		goto out_put_devnode;

	rc = nfs4_pnfs_ds_connect(mds_srv, ds, devnode, NFS_DEF_TCP_TIMEO, 0,
				  layout_ds->ds_versions[0].version,
				  layout_ds->ds_versions[0].minor_version);
	if (rc || !ds->ds_clp)
		goto out_put_devnode;

	{
		unsigned int noflags = memalloc_nofs_save();

		r = kzalloc(sizeof(*r), nfs_io_gfp_mask());
		memalloc_nofs_restore(noflags);
	}
	if (!r)
		goto out_put_devnode;

	/*
	 * cra_offset is a chunk index, not a byte offset.  ffv2_ds_offset
	 * maps the file offset onto the data server's own file under this
	 * mirror's striping; dividing by the striping unit turns that
	 * into the index the data server numbers its chunks by.  The
	 * header starts on a chunk boundary, so there is no remainder to
	 * lose here.
	 */
	chunk_index = ffv2_ds_offset(mirror, hdr->args.offset);
	do_div(chunk_index, mirror->striping_unit_size);

	r->data.args.stateid = fi->stateid;
	r->data.args.offset = chunk_index;
	r->data.args.count = 1;
	r->data.args.pages = hdr->args.pages;
	r->data.args.pgbase = hdr->args.pgbase;
	r->data.args.pglen = hdr->args.count;
	memcpy(&r->data.fh, &fi->fh, sizeof(r->data.fh));
	nfs4_init_sequence(ds->ds_clp, &r->data.seq_args,
			   &r->data.res.seq_res, 0, 0);

	refcount_inc(&ds->ds_clp->cl_count);
	r->hdr = hdr;
	r->lseg = pnfs_get_lseg(hdr->lseg);
	r->ds_clp = ds->ds_clp;

	msg = (struct rpc_message){
		.rpc_proc	= &ffv2_chunk_read_procinfo,
		.rpc_argp	= &r->data,
		.rpc_resp	= &r->data.res,
		.rpc_cred	= hdr->cred,
	};
	task_setup = (struct rpc_task_setup){
		.rpc_client	= r->ds_clp->cl_rpcclient,
		.task		= &r->task,
		.rpc_message	= &msg,
		.callback_ops	= &ffv2_shard_read_call_ops,
		.callback_data	= r,
		.workqueue	= nfsiod_workqueue,
		.flags		= RPC_TASK_ASYNC | RPC_TASK_SOFTCONN |
				  RPC_TASK_SOFT,
	};

	task = rpc_run_task(&task_setup);
	nfs4_put_deviceid_node(devnode);
	if (IS_ERR(task)) {
		/* Release will not fire; unwind by hand. */
		nfs_put_client(r->ds_clp);
		pnfs_put_lseg(r->lseg);
		kfree(r);
		return PNFS_NOT_ATTEMPTED;
	}
	rpc_put_task(task);
	return PNFS_ATTEMPTED;

out_put_devnode:
	nfs4_put_deviceid_node(devnode);
	return PNFS_NOT_ATTEMPTED;
}

/*
 * Read a chunk-encoded lseg (XOR_PARITY / RS_VANDERMONDE /
 *     LINUX_MD_RAID / ...): per-shard CHUNK_READ from data-server N
 *     where N is derived from hdr->args.offset within the stripe.
 *     Relies on ffv2_pg_test forcing each shard into its own hdr
 *     via a batch boundary at every striping_unit_size.  Parity-
 *     shard reads (recovery) are deferred to a follow-up commit.
 *
 * PASSTHROUGH falls through to MDS-inband.  Multi-stripe DS layouts
 * remain unsupported.
 */
static enum pnfs_try_status
ffv2_read_pagelist(struct nfs_pgio_header *hdr)
{
	struct pnfs_layout_segment *lseg = hdr->lseg;
	struct nfs4_ffv2_layout_segment *fls = FFV2_LSEG(lseg);
	struct nfs4_ffv2_mirror *mirror;

	if (fls->mirror_array_cnt == 0)
		goto out_fallback;
	mirror = fls->mirror_array[0];
	if (!mirror)
		goto out_fallback;

	/* Chunk-encoded: derive shard index from stripe-relative offset. */
	if (mirror->coding_type != FFV2_ENCODING_PASSTHROUGH) {
		u32 k = mirror->protection_data;
		u32 shard_len = mirror->striping_unit_size;
		u64 stripe_off;
		u32 shard_idx;
		u32 in_shard;

		if (k == 0 || shard_len == 0)
			goto out_fallback;
		div64_u64_rem(hdr->args.offset, (u64)k * shard_len,
			      &stripe_off);
		shard_idx = div_u64_rem(stripe_off, shard_len, &in_shard);
		if (shard_idx >= k)
			goto out_fallback;
		return ffv2_read_dispatch_chunk(hdr, mirror, shard_idx,
						in_shard);
	}
out_fallback:
	if (ffv2_no_fallback_to_mds(lseg)) {
		pnfs_error_mark_layout_for_return(hdr->inode, lseg);
		return PNFS_TRY_AGAIN;
	}
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

/*
 * For chunk-encoded lseg, force each pg_test to cap the pgio batch
 * at the current shard boundary so every batch (and thus every
 * dispatched hdr) covers at most one shard.  ffv2_read_pagelist can
 * then derive the DS index from hdr->args.offset and dispatch a
 * single-DS read per batch -- no custom pg_doio or multi-hdr fan-
 * out needed.
 *
 * Shard boundaries here MUST be file-absolute (req_offset / shard_len),
 * not lseg-relative (subtracting pls_range.offset first).  The
 * downstream ffv2_read_pagelist / ffv2_write_pagelist_chunked derive
 * the DS index from hdr->args.offset directly, which is a file
 * offset -- if pg_test batched by lseg-relative boundaries and the
 * lseg did not start at a stripe-aligned offset, batches would span
 * DS shard boundaries and get misrouted.
 *
 * (Filelayout's pg_test uses seg-relative because filelayout striping
 * is defined per-lseg; our chunk encoding is stripe-absolute.)
 */
static size_t
ffv2_pg_test(struct nfs_pageio_descriptor *pgio, struct nfs_page *prev,
	     struct nfs_page *req)
{
	struct nfs4_ffv2_layout_segment *fls;
	struct nfs4_ffv2_mirror *mirror;
	size_t size;
	u64 req_shard, prev_shard, in_shard;
	u32 shard_len;

	size = pnfs_generic_pg_test(pgio, prev, req);
	if (!size || !pgio->pg_lseg)
		return size;
	fls = FFV2_LSEG(pgio->pg_lseg);
	if (!ffv2_lseg_is_chunked(fls))
		return size;
	mirror = fls->mirror_array[0];
	shard_len = mirror->striping_unit_size;
	if (!shard_len)
		return size;

	req_shard = req_offset(req);
	do_div(req_shard, shard_len);
	if (prev) {
		prev_shard = req_offset(prev);
		do_div(prev_shard, shard_len);
		if (prev_shard != req_shard)
			return 0;	/* force new batch */
	}
	in_shard = req_offset(req) % shard_len;
	return min_t(size_t, size, shard_len - in_shard);
}

static const struct nfs_pageio_ops ffv2_pg_read_ops = {
	.pg_init	= ffv2_pg_init_read,
	.pg_test	= ffv2_pg_test,
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
	/*
	 * Always one, whatever the encoding.  The pgio mirror machinery
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
	 *
	 * The callback stays registered even though the count is
	 * constant: this is the first hook the generic layer calls for a
	 * request (nfs_pageio_setup_mirroring runs ahead of pg_init), so
	 * it is where the layout is fetched.
	 */
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
		}
	}
	return 1;
}

/*
 * No pg_get_mirror / pg_set_mirror pair.  They exist to resolve
 * "which mirror is current" for a driver that runs more than one, and
 * this one does not: pg_get_mirror_count above returns 1 for every
 * layout.  At a count of 1 the generic fallbacks -- mirror 0 for any
 * index, and a no-op set -- give the same answer the callbacks would.
 *
 * They were registered when a chunk-encoded lseg ran k+m pgio mirrors
 * and needed each shard's requests kept on their own list.  That
 * arrangement is gone; see pg_get_mirror_count_write for why it could
 * not express erasure coding.
 */
static const struct nfs_pageio_ops ffv2_pg_write_ops = {
	.pg_init		= ffv2_pg_init_write,
	.pg_test		= ffv2_pg_test_write,
	.pg_doio		= pnfs_generic_pg_writepages,
	.pg_get_mirror_count	= ffv2_pg_get_mirror_count_write,
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
	ffv2_guard_refresh_init();
	return pnfs_register_layoutdriver(&flexfilesv2_type);
}

static void __exit nfs4flexfilesv2_exit(void)
{
	pr_info("%s: NFSv4 Flexfile v2 Layout Driver Unregistering...\n",
		__func__);
	pnfs_unregister_layoutdriver(&flexfilesv2_type);
	ffv2_guard_refresh_exit();
}

MODULE_ALIAS("nfs-layouttype4-6");

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("The NFSv4 flexfile v2 layout driver");

module_init(nfs4flexfilesv2_init);
module_exit(nfs4flexfilesv2_exit);
