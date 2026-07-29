// SPDX-License-Identifier: GPL-2.0
/*
 * Erasure-encoder plug-in registry for the NFSv4 Flexfile Version 2
 * layout driver.  Each encoder is a static ffv2_encoder_ops instance
 * declared in its own translation unit and listed in ffv2_encoders[]
 * below.  Adding a new encoding_type is a single-line edit here plus
 * the encoder implementation itself.
 *
 * No dynamic registration: every in-tree encoder ships in the same
 * module (nfs_layout_flexfilesv2.ko), so a plain array beats a lock-
 * protected list.  Out-of-tree encoders can add themselves via an
 * export layer in a follow-up commit if the need materialises.
 *
 * Copyright (c) 2026 Thomas Haynes <loghyr@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "flexfilesv2.h"

static const struct ffv2_encoder_ops * const ffv2_encoders[] = {
	&ffv2_encoder_xor_parity,
	&ffv2_encoder_linux_md,
};

const struct ffv2_encoder_ops *ffv2_find_encoder(u32 coding_type)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(ffv2_encoders); i++)
		if (ffv2_encoders[i]->coding_type == coding_type)
			return ffv2_encoders[i];
	return NULL;
}
