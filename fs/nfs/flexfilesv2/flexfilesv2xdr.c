// SPDX-License-Identifier: GPL-2.0
/*
 * XDR decoders for the NFSv4 Flexfile Version 2 layout wire
 * format defined by draft-haynes-nfsv4-flexfiles-v2-layout.
 *
 * There is no automatic XDR generator; every field is hand-parsed
 * against a scratch page via the standard xdr_inline_decode()
 * primitive, matching the pattern in the FFv1 driver.  The wire
 * shape is:
 *
 *   ffv2_layout4 = {
 *     mirror_cnt: u32,
 *     mirrors:    ffv2_mirror4[mirror_cnt],
 *     flags:      u32,
 *     stats_hint: u32,
 *   }
 *
 *   ffv2_mirror4 = {
 *     coding_type:        u32,
 *     protection_data:    u32,
 *     protection_parity:  u32,
 *     striping:           u32,
 *     striping_unit_size: u32,
 *     client_id:          u32,
 *     checksum_algorithm: u32,
 *     stripes_cnt:        u32,
 *     stripes:            ffv2_stripes4[stripes_cnt],
 *   }
 *
 *   ffv2_stripes4 = {
 *     data_servers_cnt: u32,
 *     data_servers:     ffv2_data_server4[data_servers_cnt],
 *   }
 *
 *   ffv2_data_server4 = {
 *     deviceid:     u8[16],
 *     efficiency:   u32,
 *     versions_cnt: u32,
 *     versions:     ffv2_file_info4[versions_cnt],
 *     user:         string,
 *     group:        string,
 *     flags:        u32,
 *   }
 *
 * Every count is sanity-capped before allocation; the wire buffer
 * is MDS-authored but not trusted.
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 */

#include <linux/slab.h>
#include <linux/nfs4.h>
#include <linux/nfs_fs.h>
#include <linux/sunrpc/xdr.h>

#include "../pnfs.h"
#include "flexfilesv2.h"

static int ffv2_decode_deviceid(struct xdr_stream *xdr,
				struct nfs4_deviceid *devid)
{
	__be32 *p = xdr_inline_decode(xdr, NFS4_DEVICEID4_SIZE);

	if (unlikely(!p))
		return -EIO;
	memcpy(devid->data, p, NFS4_DEVICEID4_SIZE);
	return 0;
}

static int ffv2_decode_stateid(struct xdr_stream *xdr,
			       nfs4_stateid *stateid)
{
	__be32 *p = xdr_inline_decode(xdr, NFS4_STATEID_SIZE);

	if (unlikely(!p))
		return -EIO;
	memcpy(stateid->data, p, NFS4_STATEID_SIZE);
	return 0;
}

static int ffv2_decode_fh(struct xdr_stream *xdr, struct nfs_fh *fh)
{
	__be32 *p;
	u32 len;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(!p))
		return -EIO;
	len = be32_to_cpup(p);
	if (len > NFS_MAXFHSIZE)
		return -EINVAL;
	p = xdr_inline_decode(xdr, len);
	if (unlikely(!p))
		return -EIO;
	fh->size = len;
	memcpy(fh->data, p, len);
	return 0;
}

/* Consume a wire opaque string but do not retain -- caller has no use
 * for user/group in this commit; identity resolution is a follow-up. */
static int ffv2_decode_opaque_skip(struct xdr_stream *xdr)
{
	__be32 *p;
	u32 len;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(!p))
		return -EIO;
	len = be32_to_cpup(p);
	if (len == 0)
		return 0;
	p = xdr_inline_decode(xdr, xdr_align_size(len));
	if (unlikely(!p))
		return -EIO;
	return 0;
}

static void ffv2_free_data_server(struct nfs4_ffv2_data_server *ds)
{
	kfree(ds->versions);
	ds->versions = NULL;
}

static int ffv2_decode_data_server(struct xdr_stream *xdr,
				   struct nfs4_ffv2_data_server *ds,
				   gfp_t gfp_flags)
{
	__be32 *p;
	u32 versions_cnt, i;
	int rc;

	rc = ffv2_decode_deviceid(xdr, &ds->devid);
	if (rc)
		return rc;

	p = xdr_inline_decode(xdr, 4 + 4);
	if (unlikely(!p))
		return -EIO;
	ds->efficiency = be32_to_cpup(p++);
	versions_cnt = be32_to_cpup(p);

	if (versions_cnt == 0 ||
	    versions_cnt > NFS4_FFV2_MAX_VERSIONS_PER_DS)
		return -EINVAL;

	ds->versions = kcalloc(versions_cnt, sizeof(*ds->versions),
			       gfp_flags);
	if (!ds->versions)
		return -ENOMEM;
	ds->versions_cnt = versions_cnt;

	for (i = 0; i < versions_cnt; i++) {
		rc = ffv2_decode_stateid(xdr, &ds->versions[i].stateid);
		if (rc)
			goto out_err;
		rc = ffv2_decode_fh(xdr, &ds->versions[i].fh);
		if (rc)
			goto out_err;
	}

	/* user + group opaque strings; identity resolution deferred. */
	rc = ffv2_decode_opaque_skip(xdr);
	if (rc)
		goto out_err;
	rc = ffv2_decode_opaque_skip(xdr);
	if (rc)
		goto out_err;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(!p)) {
		rc = -EIO;
		goto out_err;
	}
	ds->flags = be32_to_cpup(p);
	return 0;

out_err:
	ffv2_free_data_server(ds);
	return rc;
}

static void ffv2_free_stripe(struct nfs4_ffv2_stripe *st)
{
	u32 i;

	for (i = 0; i < st->data_servers_cnt; i++)
		ffv2_free_data_server(&st->data_servers[i]);
	kfree(st->data_servers);
	st->data_servers = NULL;
}

static int ffv2_decode_stripe(struct xdr_stream *xdr,
			      struct nfs4_ffv2_stripe *st, gfp_t gfp_flags)
{
	__be32 *p;
	u32 ds_cnt, i;
	int rc;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(!p))
		return -EIO;
	ds_cnt = be32_to_cpup(p);
	if (ds_cnt == 0 || ds_cnt > NFS4_FFV2_MAX_DS_PER_STRIPE)
		return -EINVAL;

	st->data_servers = kcalloc(ds_cnt, sizeof(*st->data_servers),
				   gfp_flags);
	if (!st->data_servers)
		return -ENOMEM;
	st->data_servers_cnt = ds_cnt;

	for (i = 0; i < ds_cnt; i++) {
		rc = ffv2_decode_data_server(xdr, &st->data_servers[i],
					     gfp_flags);
		if (rc) {
			ffv2_free_stripe(st);
			return rc;
		}
	}
	return 0;
}

static void ffv2_free_mirror(struct nfs4_ffv2_mirror *m)
{
	u32 i;

	if (!m)
		return;
	for (i = 0; i < m->stripes_cnt; i++)
		ffv2_free_stripe(&m->stripes[i]);
	kfree(m->stripes);
	kfree(m);
}

static struct nfs4_ffv2_mirror *
ffv2_decode_mirror(struct xdr_stream *xdr, gfp_t gfp_flags)
{
	struct nfs4_ffv2_mirror *m;
	__be32 *p;
	u32 stripes_cnt, i;
	int rc;

	m = kzalloc(sizeof(*m), gfp_flags);
	if (!m)
		return ERR_PTR(-ENOMEM);

	p = xdr_inline_decode(xdr, 4 * 8);
	if (unlikely(!p)) {
		rc = -EIO;
		goto out_err;
	}
	m->coding_type		= be32_to_cpup(p++);
	m->protection_data	= be32_to_cpup(p++);
	m->protection_parity	= be32_to_cpup(p++);
	m->striping		= be32_to_cpup(p++);
	m->striping_unit_size	= be32_to_cpup(p++);
	m->client_id		= be32_to_cpup(p++);
	m->checksum_algorithm	= be32_to_cpup(p++);
	stripes_cnt		= be32_to_cpup(p);

	if (!m->protection_data || !m->striping_unit_size) {
		rc = -EINVAL;
		goto out_err;
	}
	if (m->client_id == FFV2_CG_CLIENT_ID_NONE ||
	    m->client_id == FFV2_CG_CLIENT_ID_MDS) {
		rc = -EINVAL;
		goto out_err;
	}
	if (m->coding_type == FFV2_ENCODING_MOJETTE_NON_SYSTEMATIC ||
	    m->coding_type == FFV2_ENCODING_REPLICATED) {
		rc = -EOPNOTSUPP;
		goto out_err;
	}

	if (stripes_cnt == 0 || stripes_cnt > NFS4_FFV2_MAX_STRIPE_CNT) {
		rc = -EINVAL;
		goto out_err;
	}
	/*
	 * The wire format allows up to NFS4_FFV2_MAX_STRIPE_CNT stripes
	 * per mirror, but every dispatch site in this driver (read,
	 * write, RMW fetch) currently selects `mirror->stripes[0]`
	 * unconditionally.  A multi-stripe layout would silently send
	 * every subsequent stripe's I/O to the wrong DS set.  Refuse
	 * the layout here so the pNFS core falls back to MDS-inband
	 * I/O until real stripe routing lands.
	 */
	if (stripes_cnt > 1) {
		rc = -EOPNOTSUPP;
		goto out_err;
	}

	m->stripes = kcalloc(stripes_cnt, sizeof(*m->stripes), gfp_flags);
	if (!m->stripes) {
		rc = -ENOMEM;
		goto out_err;
	}
	m->stripes_cnt = stripes_cnt;

	for (i = 0; i < stripes_cnt; i++) {
		rc = ffv2_decode_stripe(xdr, &m->stripes[i], gfp_flags);
		if (rc)
			goto out_err;
	}
	return m;

out_err:
	ffv2_free_mirror(m);
	return ERR_PTR(rc);
}

void ffv2_free_layout_segment(struct nfs4_ffv2_layout_segment *fls)
{
	u32 i;

	if (!fls)
		return;
	/*
	 * pNFS core guarantees free_lseg fires only after all inflight
	 * I/O against this lseg drains, so fls_ctx_list must be empty
	 * here in the normal case.  Drain any stragglers left behind by
	 * a mirror whose I/O never arrived: the anchor ref that pins them
	 * is released by the write path's drain helper; last user's put
	 * frees.
	 */
	ffv2_stripe_ctx_list_drain(fls);
	for (i = 0; i < fls->mirror_array_cnt; i++)
		ffv2_free_mirror(fls->mirror_array[i]);
	kfree(fls);
}

struct nfs4_ffv2_layout_segment *
ffv2_decode_layout(struct nfs4_layoutget_res *lgr, gfp_t gfp_flags)
{
	struct nfs4_ffv2_layout_segment *fls;
	struct xdr_stream stream;
	struct xdr_buf buf;
	struct folio *scratch;
	__be32 *p;
	u32 mirror_cnt, i;
	int rc = -EIO;

	scratch = folio_alloc(gfp_flags, 0);
	if (!scratch)
		return ERR_PTR(-ENOMEM);

	xdr_init_decode_pages(&stream, &buf, lgr->layoutp->pages,
			      lgr->layoutp->len);
	xdr_set_scratch_folio(&stream, scratch);

	p = xdr_inline_decode(&stream, 4);
	if (unlikely(!p))
		goto out_free_scratch;
	mirror_cnt = be32_to_cpup(p);
	if (mirror_cnt == 0 || mirror_cnt > NFS4_FFV2_MAX_MIRROR_CNT) {
		rc = -EINVAL;
		goto out_free_scratch;
	}

	fls = kzalloc(struct_size(fls, mirror_array, mirror_cnt),
		      gfp_flags);
	if (!fls) {
		rc = -ENOMEM;
		goto out_free_scratch;
	}
	fls->mirror_array_cnt = mirror_cnt;
	spin_lock_init(&fls->fls_ctx_lock);
	INIT_LIST_HEAD(&fls->fls_ctx_list);
	init_waitqueue_head(&fls->fls_ctx_wq);
	atomic_set(&fls->next_owner_id, 1);

	for (i = 0; i < mirror_cnt; i++) {
		struct nfs4_ffv2_mirror *m;

		m = ffv2_decode_mirror(&stream, gfp_flags);
		if (IS_ERR(m)) {
			rc = PTR_ERR(m);
			goto out_free_fls;
		}
		fls->mirror_array[i] = m;
	}

	p = xdr_inline_decode(&stream, 4 + 4);
	if (unlikely(!p)) {
		rc = -EIO;
		goto out_free_fls;
	}
	fls->flags		= be32_to_cpup(p++);
	fls->stats_collect_hint	= be32_to_cpup(p);

	folio_put(scratch);
	return fls;

out_free_fls:
	ffv2_free_layout_segment(fls);
out_free_scratch:
	folio_put(scratch);
	return ERR_PTR(rc);
}
