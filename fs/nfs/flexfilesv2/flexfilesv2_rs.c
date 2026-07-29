// SPDX-License-Identifier: GPL-2.0
/*
 * RS_VANDERMONDE erasure encoder for the NFSv4 Flexfile Version 2
 * layout driver.  Reed-Solomon over GF(2^8) with the wire-format
 * matrix defined by draft-haynes-nfsv4-flexfiles-v2-encoding-registry:
 *
 *   - Irreducible polynomial:  x^8 + x^4 + x^3 + x^2 + 1  (0x11d)
 *   - Generator (primitive):   g = 2  (order 255)
 *   - Vandermonde eval points: alpha_i = i + 1  (i = 0 .. k+m-1)
 *   - Systematic form:         normalize by inverting the top k*k
 *                              sub-matrix; parity is the bottom m*k
 *
 * The GF(2^8) exp/log tables are built once at first use.  The
 * per-(k, m) parity coefficients are recomputed each encode; caching
 * them on the encoder ops or on the lseg is a follow-up.
 *
 * This is the scalar reference implementation.  SIMD paths (NEON /
 * SSSE3 pshufb-style split-nibble tables) will land in follow-up
 * commits.
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "flexfilesv2.h"

#define GF_POLY  0x11d
#define GF_ORDER 255

static u8 gf_exp[512];
static u8 gf_log[256];
static bool gf_tables_ready;
static DEFINE_MUTEX(gf_tables_lock);

static void gf_init_tables(void)
{
	int i, x = 1;

	for (i = 0; i < GF_ORDER; i++) {
		gf_exp[i] = (u8)x;
		gf_log[(u8)x] = (u8)i;
		x <<= 1;
		if (x & 0x100)
			x ^= GF_POLY;
	}
	for (i = GF_ORDER; i < 512; i++)
		gf_exp[i] = gf_exp[i - GF_ORDER];
	/* gf_log[0] is a sentinel; never consulted for valid mul. */
}

static void gf_ensure_ready(void)
{
	/* Pair with the release that publishes the completed tables. */
	if (smp_load_acquire(&gf_tables_ready))
		return;
	mutex_lock(&gf_tables_lock);
	if (!gf_tables_ready) {
		gf_init_tables();
		/* Publish every table entry before advertising readiness. */
		smp_store_release(&gf_tables_ready, true);
	}
	mutex_unlock(&gf_tables_lock);
}

static inline u8 gf_mul(u8 a, u8 b)
{
	if (a == 0 || b == 0)
		return 0;
	return gf_exp[gf_log[a] + gf_log[b]];
}

static inline u8 gf_inv(u8 a)
{
	/* a must be non-zero; caller enforces via matrix-pivot search. */
	return gf_exp[GF_ORDER - gf_log[a]];
}

static u8 gf_pow(u8 a, u8 n)
{
	if (n == 0)
		return 1;
	if (a == 0)
		return 0;
	return gf_exp[((int)gf_log[a] * n) % GF_ORDER];
}

/*
 * Gauss-Jordan invert an (n * n) matrix in place using a companion
 * augmented identity.  Returns 0 on success, -EINVAL if singular
 * (which cannot happen for our Vandermonde submatrix with distinct
 * non-zero evaluation points but is checked defensively).
 *
 * `mat` and `inv` are row-major u8 arrays of size n * n.  On entry
 * `mat` holds the matrix to invert and `inv` holds the identity; on
 * successful return `mat` is the identity and `inv` is the inverse.
 */
static int gf_invert_square(u8 *mat, u8 *inv, u32 n)
{
	u32 col, row, k;

	for (col = 0; col < n; col++) {
		/* Find a non-zero pivot in this column at row >= col. */
		if (mat[col * n + col] == 0) {
			for (row = col + 1; row < n; row++)
				if (mat[row * n + col] != 0)
					break;
			if (row == n)
				return -EINVAL;
			/* Swap rows row <-> col in both mat and inv. */
			for (k = 0; k < n; k++) {
				u8 t;

				t = mat[col * n + k];
				mat[col * n + k] = mat[row * n + k];
				mat[row * n + k] = t;
				t = inv[col * n + k];
				inv[col * n + k] = inv[row * n + k];
				inv[row * n + k] = t;
			}
		}
		/* Normalize pivot row so mat[col][col] == 1. */
		{
			u8 piv_inv = gf_inv(mat[col * n + col]);

			for (k = 0; k < n; k++) {
				mat[col * n + k] =
					gf_mul(mat[col * n + k], piv_inv);
				inv[col * n + k] =
					gf_mul(inv[col * n + k], piv_inv);
			}
		}
		/* Eliminate this column from all other rows. */
		for (row = 0; row < n; row++) {
			u8 f;

			if (row == col)
				continue;
			f = mat[row * n + col];
			if (f == 0)
				continue;
			for (k = 0; k < n; k++) {
				mat[row * n + k] ^=
					gf_mul(f, mat[col * n + k]);
				inv[row * n + k] ^=
					gf_mul(f, inv[col * n + k]);
			}
		}
	}
	return 0;
}

/*
 * Build the m*k systematic parity coefficient matrix for this (k, m).
 *
 * Dispatched by m per draft-haynes-nfsv4-flexfiles-v2-rs-vandermonde
 * ("At m = 1 ... At m = 2 ... At m >= 3"):
 *
 *   m == 1:  row 0 = all-ones P  (XOR-of-data, RAID5-shape).
 *   m == 2:  row 0 = all-ones P
 *            row 1 = g^c Q       (Anvin/Linux MD RAID6-compatible).
 *   m >= 3:  ALL m rows are normalized Vandermonde -- this encoding
 *            stands on its own at m >= 3; no P/Q special-case.
 *            Step 1: raw Vandermonde V of shape (k+m) * k,
 *                    V[r][c] = (r+1)^c.
 *            Step 2: invert the top k*k block, call it T.
 *            Step 3: parity[p][c] = sum over c' of V[k+p][c'] * T[c'][c].
 *
 * These branches are MUTUALLY EXCLUSIVE, not composable: at m == 2 the
 * caller sees P + Q, not P + Q + Vandermonde.
 *
 * Returned buffer is kmalloc'd (caller kfrees); NULL on OOM/singular.
 */
static u8 *ffv2_rs_build_parity(u32 k, u32 m)
{
	u8 *top = NULL, *inv = NULL, *parity;
	u32 r, c, cc;
	int rc;

	if (k + m > 255)
		return NULL;

	parity = kcalloc(m * k, sizeof(u8), GFP_NOFS);
	if (!parity)
		return NULL;

	if (m <= 2) {
		/* P row: all ones. */
		for (c = 0; c < k; c++)
			parity[c] = 1;
		if (m == 2) {
			/* Q row: g^c with g = 2 in GF(2^8), poly 0x11d. */
			for (c = 0; c < k; c++)
				parity[k + c] = gf_pow(2, (u8)c);
		}
		return parity;
	}

	/* m >= 3: normalized Vandermonde for all m rows. */
	top = kcalloc(k * k, sizeof(u8), GFP_NOFS);
	inv = kcalloc(k * k, sizeof(u8), GFP_NOFS);
	if (!top || !inv)
		goto out_fail;

	/* Top-k Vandermonde into `top`; identity into `inv`. */
	for (r = 0; r < k; r++) {
		for (c = 0; c < k; c++)
			top[r * k + c] = gf_pow((u8)(r + 1), (u8)c);
		inv[r * k + r] = 1;
	}
	rc = gf_invert_square(top, inv, k);
	if (rc)
		goto out_fail;

	/* Multiply bottom-m Vandermonde rows by inv to get parity. */
	for (r = 0; r < m; r++) {
		for (c = 0; c < k; c++) {
			u8 sum = 0;

			for (cc = 0; cc < k; cc++)
				sum ^= gf_mul(gf_pow((u8)(k + r + 1), (u8)cc),
					      inv[cc * k + c]);
			parity[r * k + c] = sum;
		}
	}
	kfree(top);
	kfree(inv);
	return parity;

out_fail:
	kfree(top);
	kfree(inv);
	kfree(parity);
	return NULL;
}

static int ffv2_rs_encode(u32 k, u32 m, u32 shard_len,
			  const u8 * const *data, u8 * const *parity)
{
	u8 *pmat;
	u32 p, d, b;

	if (k == 0 || m == 0 || k + m > 255)
		return -EINVAL;

	gf_ensure_ready();
	pmat = ffv2_rs_build_parity(k, m);
	if (!pmat)
		return -ENOMEM;

	for (p = 0; p < m; p++)
		memset(parity[p], 0, shard_len);

	for (p = 0; p < m; p++) {
		for (d = 0; d < k; d++) {
			u8 coef = pmat[p * k + d];
			const u8 *src = data[d];
			u8 *dst = parity[p];

			if (coef == 0)
				continue;
			for (b = 0; b < shard_len; b++)
				dst[b] ^= gf_mul(coef, src[b]);
		}
	}

	kfree(pmat);
	return 0;
}

/*
 * Reconstruct one missing shard from k surviving shards.
 *
 * The full (k+m) * k systematic encoding matrix E has identity in
 * its top k rows (data pass-through) and the parity coefficients in
 * its bottom m rows.  Let S be the k * k submatrix formed by the k
 * rows of E corresponding to surviving_indices.  If S is invertible
 * (which it always is for Vandermonde-derived E with distinct non-
 * zero eval points), the recovered data shards satisfy
 *
 *     D = S^-1 * surviving
 *
 * and the coefficient row for reconstructing shard `missing_idx`
 * from the k surviving shards is:
 *
 *     missing_idx  <  k :  coef = row `missing_idx` of  S^-1
 *     missing_idx  >= k :  coef = parity_matrix[missing_idx-k] * S^-1
 *
 * Reconstructed byte b then equals XOR over j of gf_mul(coef[j],
 * surviving[j][b]) -- the same shape as encode, just with different
 * coefficients.  Memory footprint is O(k^2) coefficients, not
 * O(k * shard_len), so this works even for large shards.
 */
static int ffv2_rs_repair(u32 k, u32 m, u32 shard_len,
			  const u32 *surviving_indices,
			  const u8 * const *surviving_shards,
			  u32 missing_idx, u8 *reconstructed)
{
	u8 *pmat = NULL;
	u8 *S = NULL, *S_inv = NULL;
	u8 *coef = NULL;
	u32 i, j, b;
	int rc;

	if (k == 0 || m == 0 || k + m > 255 || missing_idx >= k + m)
		return -EINVAL;

	gf_ensure_ready();
	pmat = ffv2_rs_build_parity(k, m);
	if (!pmat)
		return -ENOMEM;

	S     = kcalloc(k * k, sizeof(u8), GFP_NOFS);
	S_inv = kcalloc(k * k, sizeof(u8), GFP_NOFS);
	coef  = kcalloc(k,     sizeof(u8), GFP_NOFS);
	if (!S || !S_inv || !coef) {
		rc = -ENOMEM;
		goto out;
	}

	/* Assemble S: row i of E for surviving index surviving_indices[i]. */
	for (i = 0; i < k; i++) {
		u32 si = surviving_indices[i];

		if (si >= k + m || si == missing_idx) {
			rc = -EINVAL;
			goto out;
		}
		if (si < k) {
			/* Row si of the identity: column si is 1, rest 0. */
			S[i * k + si] = 1;
		} else {
			/* Row si-k of the parity submatrix. */
			u32 pj;

			for (pj = 0; pj < k; pj++)
				S[i * k + pj] = pmat[(si - k) * k + pj];
		}
		/* Corresponding identity row in S_inv for Gauss-Jordan. */
		S_inv[i * k + i] = 1;
	}

	rc = gf_invert_square(S, S_inv, k);
	if (rc)
		goto out;

	/* Compute coef[j] for j in [0, k). */
	if (missing_idx < k) {
		for (j = 0; j < k; j++)
			coef[j] = S_inv[missing_idx * k + j];
	} else {
		u32 pi = missing_idx - k;

		for (j = 0; j < k; j++) {
			u8 sum = 0;

			for (i = 0; i < k; i++)
				sum ^= gf_mul(pmat[pi * k + i],
					      S_inv[i * k + j]);
			coef[j] = sum;
		}
	}

	/* Apply coefficients to reconstruct the missing shard. */
	memset(reconstructed, 0, shard_len);
	for (j = 0; j < k; j++) {
		u8 c = coef[j];
		const u8 *src = surviving_shards[j];

		if (c == 0)
			continue;
		for (b = 0; b < shard_len; b++)
			reconstructed[b] ^= gf_mul(c, src[b]);
	}
	rc = 0;

out:
	kfree(coef);
	kfree(S_inv);
	kfree(S);
	kfree(pmat);
	return rc;
}

const struct ffv2_encoder_ops ffv2_encoder_rs_vandermonde = {
	.coding_type	= FFV2_ENCODING_RS_VANDERMONDE,
	.name		= "rs-vandermonde",
	.encode		= ffv2_rs_encode,
	.repair		= ffv2_rs_repair,
};
