/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NFSD_FFV2_TRUST_H
#define _NFSD_FFV2_TRUST_H

#include <linux/bits.h>
#include <linux/types.h>

enum nfsd_ffv2_caller_class {
	NFSD_FFV2_CALLER_NONE,
	NFSD_FFV2_CALLER_MDS_CONTROL,
	NFSD_FFV2_CALLER_DATA_CLIENT,
	NFSD_FFV2_CALLER_REPAIR_ACTOR,
};

enum nfsd_ffv2_iomode_policy {
	NFSD_FFV2_IOMODE_ANY,
	NFSD_FFV2_IOMODE_READ_OR_RW,
	NFSD_FFV2_IOMODE_RW_ONLY,
};

#define NFSD_FFV2_CALLERS(class)	BIT(NFSD_FFV2_CALLER_##class)

struct nfsd_ffv2_op_profile {
	u32				callers;
	enum nfsd_ffv2_iomode_policy	iomode;
	u32				profile_bit;
	bool				writer_identity;
	bool				no_filehandle;
};

#define NFSD_FFV2_PROFILE_READ_DATA		BIT(0)
#define NFSD_FFV2_PROFILE_READ_METADATA		BIT(1)
#define NFSD_FFV2_PROFILE_WRITE_DATA		BIT(2)
#define NFSD_FFV2_PROFILE_REPAIR_WRITE		BIT(3)
#define NFSD_FFV2_PROFILE_WRITE_LIFECYCLE	BIT(4)
#define NFSD_FFV2_PROFILE_LOCK_CONTROL		BIT(5)
#define NFSD_FFV2_PROFILE_REPORT_ERROR		BIT(6)
#define NFSD_FFV2_PROFILE_REPORT_REPAIRED	BIT(7)
#define NFSD_FFV2_PROFILE_ALL			GENMASK(7, 0)

const struct nfsd_ffv2_op_profile *nfsd_ffv2_op_profile(u32 opnum);
bool nfsd_ffv2_op_no_filehandle(u32 opnum);

#endif /* _NFSD_FFV2_TRUST_H */
