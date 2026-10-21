/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NFSD_FFV2_TRUST_H
#define _NFSD_FFV2_TRUST_H

#include <linux/bits.h>
#include <linux/types.h>
#include "state.h"
#include "ffv2.h"

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

struct nfsd_ffv2_actor_id {
	u32 client_id;
	bool present;
	clientid_t target;
	bool target_present;
};

__be32 nfsd_ffv2_validate_operation(struct svc_rqst *rqstp, struct svc_fh *fhp,
				    struct nfsd4_session *session, u32 opnum,
				    const stateid_t *stateid,
				    const struct nfsd_ffv2_actor_id *actor,
				    struct nfsd_ffv2_admission *admission);

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST) || IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
#define NFSD_FFV2_TRUST_PRINCIPAL_MAX 1024
#define NFSD_FFV2_TRUST_ENTRIES_MAX 4096
#define NFSD_FFV2_TRUST_BYTES_MAX (4U * 1024U * 1024U)

struct nfsd_ffv2_trust_request {
	enum nfsd_ffv2_caller_class actor;
	stateid_t stateid;
	const u8 *object_uuid;
	clientid_t pnfs_clientid;
	u32 client_id;
	u32 iomode;
	u32 profile_mask;
	struct timespec64 expires;
	const char *principal;
};

#endif
#if IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
__be32 nfsd_ffv2_trust_install_active(struct nfsd_net *nn,
				      const struct nfsd_ffv2_trust_request *request);
#endif
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
__be32 nfsd_ffv2_test_trust_update(struct nfsd_net *nn, const struct nfsd_ffv2_trust_request *req,
				   bool revoke);
struct nfsd_ffv2_trust_stats {
	unsigned int entries;
	unsigned int holds;
	size_t bytes;
	u64 generation;
	u64 epoch;
};

void *nfsd_ffv2_test_trust_get(struct nfsd_net *nn, const stateid_t *stateid);
bool nfsd_ffv2_test_trust_snapshot(struct nfsd_net *nn, struct nfsd_ffv2_trust_stats *stats);
__be32 nfsd_ffv2_test_entry_validate(void *entry, u64 generation, const u8 object_uuid[16],
				     u64 epoch, u32 profile, const char *principal);
unsigned int nfsd_ffv2_test_admitted(struct nfsd_ffv2_admission *observer);

#endif

#endif /* _NFSD_FFV2_TRUST_H */
