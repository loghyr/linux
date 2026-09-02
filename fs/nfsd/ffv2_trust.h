/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NFSD_FFV2_TRUST_H
#define _NFSD_FFV2_TRUST_H

#include <linux/time64.h>

#include "ffv2.h"
#include "state.h"

struct nfsd_ffv2_authority;
struct nfsd_ffv2_object;
struct nfsd_ffv2_trust_entry;
struct nfsd_ffv2_trust_registry;

/*
 * Trusted FFv2 stateids.
 *
 * A trusted stateid is a layout stateid issued by an external metadata
 * server for a pNFS client.  It is not state this server issued, so it
 * cannot be represented by struct nfs4_stid or found through
 * nfsd4_lookup_stateid(): that would consult an unrelated local client's
 * IDR.  The registry below is therefore separate, and every lookup is keyed
 * by the exact issued bytes rather than by anything this server allocates.
 */

/* Bounds are per generation, and per issuer for retained principal bytes. */
#define NFSD_FFV2_TRUST_PRINCIPAL_MAX	1024
#define NFSD_FFV2_TRUST_ENTRIES_MAX	4096
#define NFSD_FFV2_TRUST_BYTES_MAX	(4U * 1024U * 1024U)

/* One explicit bit per enabled operation; never inferred from iomode. */
#define NFSD_FFV2_PROFILE_READ_DATA		BIT(0)
#define NFSD_FFV2_PROFILE_READ_METADATA		BIT(1)
#define NFSD_FFV2_PROFILE_WRITE_DATA		BIT(2)
#define NFSD_FFV2_PROFILE_REPAIR_WRITE		BIT(3)
#define NFSD_FFV2_PROFILE_WRITE_LIFECYCLE	BIT(4)
#define NFSD_FFV2_PROFILE_LOCK_CONTROL		BIT(5)
#define NFSD_FFV2_PROFILE_REPORT_ERROR		BIT(6)
#define NFSD_FFV2_PROFILE_REPORT_REPAIRED	BIT(7)
#define NFSD_FFV2_PROFILE_ALL			GENMASK(7, 0)

/*
 * Immutable description of one trust registration.  Every field is copied
 * into the entry, so a caller cannot retain an alias into registry state.
 */
struct nfsd_ffv2_trust_request {
	stateid_t	stateid;
	const u8	*object_uuid;
	clientid_t	pnfs_clientid;
	u32		client_id;
	u32		iomode;
	u32		profile_mask;
	struct timespec64 expires;
	const char	*principal;
};

int nfsd_ffv2_trust_registry_init(struct nfsd_ffv2_trust_registry *registry);
void nfsd_ffv2_trust_registry_destroy(struct nfsd_ffv2_trust_registry *registry);
__be32 nfsd_ffv2_trust_install(struct nfsd_ffv2_trust_registry *registry,
			       struct nfsd_ffv2_authority *authority,
			       struct nfsd_ffv2_object *object,
			       u64 generation_id,
			       const struct nfsd_ffv2_trust_request *request);
struct nfsd_ffv2_trust_entry *
nfsd_ffv2_trust_lookup(struct nfsd_ffv2_trust_registry *registry,
		       const stateid_t *stateid, const u8 object_uuid[16],
		       u64 authority_epoch);
void nfsd_ffv2_trust_entry_put(struct nfsd_ffv2_trust_entry *entry);
__be32 nfsd_ffv2_trust_validate(const struct nfsd_ffv2_trust_entry *entry,
				u64 generation_id, const u8 object_uuid[16],
				u64 authority_epoch, u32 profile_bit,
				const char *principal);
bool nfsd_ffv2_trust_revoke(struct nfsd_ffv2_trust_registry *registry,
			    const stateid_t *stateid, const u8 object_uuid[16],
			    u64 authority_epoch);
unsigned int
nfsd_ffv2_trust_bulk_revoke(struct nfsd_ffv2_trust_registry *registry,
			    u64 authority_epoch,
			    const clientid_t *target);
void nfsd_ffv2_trust_retire(struct nfsd_ffv2_trust_registry *registry);

struct nfsd_ffv2_trust_registry *nfsd_ffv2_test_trust_registry_alloc(void);
void nfsd_ffv2_test_trust_registry_free(struct nfsd_ffv2_trust_registry *reg);
unsigned int
nfsd_ffv2_test_trust_entries(const struct nfsd_ffv2_trust_registry *registry);
size_t
nfsd_ffv2_test_trust_bytes(const struct nfsd_ffv2_trust_registry *registry);
bool nfsd_ffv2_test_trust_replaced(const struct nfsd_ffv2_trust_entry *entry);
bool nfsd_ffv2_test_trust_revoked(const struct nfsd_ffv2_trust_entry *entry);
u32 nfsd_ffv2_test_trust_iomode(const struct nfsd_ffv2_trust_entry *entry);

#endif /* _NFSD_FFV2_TRUST_H */
