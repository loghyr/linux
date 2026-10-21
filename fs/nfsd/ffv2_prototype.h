/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NFSD_FFV2_PROTOTYPE_H
#define _NFSD_FFV2_PROTOTYPE_H

#include <linux/completion.h>
#include <linux/refcount.h>
#include <linux/nfs4.h>
#include <linux/time64.h>
#include <linux/uidgid.h>
#include <linux/wait.h>

struct net;
struct nfsd_net;
struct nfsd_ffv2_prototype_ctx;
struct nfsd_ffv2_prototype_provider;
struct dentry;
struct svc_export;
struct svc_fh;
struct user_namespace;
struct nfsd_ffv2_chunk_request;
struct nfsd_ffv2_chunk_result;
struct nfsd_ffv2_store_file;
struct nfsd_ffv2_store;
struct nfsd_ffv2_visible_chunk;

enum nfsd_ffv2_prototype_state {
	NFSD_FFV2_PROTOTYPE_OFF,
	NFSD_FFV2_PROTOTYPE_ENABLING,
	NFSD_FFV2_PROTOTYPE_OPEN,
	NFSD_FFV2_PROTOTYPE_READY,
	NFSD_FFV2_PROTOTYPE_CLOSING,
};

#define NFSD_FFV2_PROTOTYPE_NONCE_LEN 32
#define NFSD_FFV2_PROTOTYPE_NONCE_TTL_NS (60ULL * NSEC_PER_SEC)
#define NFSD_FFV2_PROTOTYPE_OBJECT_MAX 4

struct nfsd_ffv2_prototype_owner {
	kuid_t uid;
	struct user_namespace *userns;
	const struct net *net;
	u32 secid;
	bool secid_valid;
	bool valid;
};

struct nfsd_ffv2_prototype {
	enum nfsd_ffv2_prototype_state state;

	unsigned int users;
	wait_queue_head_t users_wait;

	unsigned int setup_ref;

	bool close_claimed;
	bool exiting;
	struct completion setup_done;
	struct completion close_done;
	struct nfsd_ffv2_prototype_owner owner;

	bool owns_ctx;
	bool owns_anchor;
	bool owns_source;
	bool owns_provider;
	bool owns_generation;
	struct nfsd_ffv2_prototype_ctx *ctx;
	struct nfsd_ffv2_prototype_provider *provider;

	u64 generation;
	u8 source_uuid[16];

	unsigned int close_waiters;
};

struct nfsd_ffv2_prototype_request {
	const u8 *nonce;
	const char *auth_domain;
	const u8 *handle;
	u32 handle_len;
	u32 chunk_size;
	u32 data_count;
	u32 parity_count;
	const u8 *store_uuid;
	const u8 *binding_token;
	const u8 *persisted_handle;
	u32 writer_id;
	u64 pnfs_clientid;
	u32 object_count;
	struct {
		const u8 *handle;
		u32 handle_len;
		const u8 *persisted_handle;
	} objects[NFSD_FFV2_PROTOTYPE_OBJECT_MAX];
};

struct nfsd_ffv2_prototype_bundle {
	u8 source_uuid[16];
	u8 service_uuid[16];
	u8 replay_uuid[16];
	u64 generation;

	u8 stateid[NFS4_STATEID_SIZE];

	u8 handle[NFS4_FHSIZE];
	u32 handle_len;
	u32 object_count;
	struct {
		u8 stateid[NFS4_STATEID_SIZE];
		u8 handle[NFS4_FHSIZE];
		u32 handle_len;
	} objects[NFSD_FFV2_PROTOTYPE_OBJECT_MAX];
};

#if IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
void nfsd_ffv2_prototype_net_init(struct nfsd_net *nn);
int nfsd_ffv2_prototype_register(struct nfsd_net *nn, const struct net *net,
				 const struct nfsd_ffv2_prototype_request *req,
				 struct nfsd_ffv2_prototype_bundle *bundle);
int nfsd_ffv2_prototype_unregister(struct nfsd_net *nn, const struct net *net,
				   const u8 source_uuid[16], u64 generation);
int nfsd_ffv2_prototype_challenge(struct nfsd_net *nn, const struct net *net,
				  u8 nonce[NFSD_FFV2_PROTOTYPE_NONCE_LEN], u64 *expires);
int nfsd_ffv2_prototype_op_admit(struct nfsd_net *nn, bool *counted);
void nfsd_ffv2_prototype_op_release(struct nfsd_net *nn);
void nfsd_ffv2_prototype_net_pre_exit(struct nfsd_net *nn);
void nfsd_ffv2_prototype_net_destroy(struct nfsd_net *nn);
int nfsd_ffv2_prototype_enable(struct nfsd_net *nn, const struct net *net);
int nfsd_ffv2_prototype_disable(struct nfsd_net *nn, const struct net *net);
enum nfsd_ffv2_prototype_state nfsd_ffv2_prototype_state_get(struct nfsd_net *nn);
bool nfsd_ffv2_prototype_ds_role(struct nfsd_net *nn);
#else
static inline void nfsd_ffv2_prototype_net_init(struct nfsd_net *nn)
{
}

static inline void nfsd_ffv2_prototype_net_pre_exit(struct nfsd_net *nn)
{
}

static inline void nfsd_ffv2_prototype_net_destroy(struct nfsd_net *nn)
{
}

static inline bool nfsd_ffv2_prototype_ds_role(struct nfsd_net *nn)
{
	return false;
}

static inline int nfsd_ffv2_prototype_op_admit(struct nfsd_net *nn, bool *counted)
{
	*counted = false;
	return 0;
}

static inline void nfsd_ffv2_prototype_op_release(struct nfsd_net *nn)
{
}
#endif

enum nfsd_ffv2_prototype_test_site {
	NFSD_FFV2_TEST_PROTO_SETUP,
	NFSD_FFV2_TEST_PROTO_RESOLVE,
	NFSD_FFV2_TEST_PROTO_PUBLISHED,
	NFSD_FFV2_TEST_PROTO_STORE_OPEN,
	NFSD_FFV2_TEST_PROTO_FILE_LOOKUP,
	NFSD_FFV2_TEST_PROTO_ADMITTED,
	NFSD_FFV2_TEST_PROTO_PROVIDER,
	NFSD_FFV2_TEST_PROTO_TRUST,
	NFSD_FFV2_TEST_PROTO_READY,
	NFSD_FFV2_TEST_PROTO_CLOSE,
	NFSD_FFV2_TEST_PROTO_RESULT,
	NFSD_FFV2_TEST_PROTO_READ_ALLOC,
	NFSD_FFV2_TEST_PROTO_RELEASE,
	NFSD_FFV2_TEST_PROTO_WORK_ALLOC,
	NFSD_FFV2_TEST_PROTO_AUTH_ALLOC,
	NFSD_FFV2_TEST_PROTO_OBJECT_ALLOC,
	NFSD_FFV2_TEST_PROTO_PROVIDER_ALLOC,
	NFSD_FFV2_TEST_PROTO_STORE_ALLOC,
	NFSD_FFV2_TEST_PROTO_SUPER_FILE,
	NFSD_FFV2_TEST_PROTO_WAL_FILE,
	NFSD_FFV2_TEST_PROTO_PAYLOAD_FILE,
};

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST) && IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
void nfsd_ffv2_prototype_test_age(struct nfsd_net *nn, const u8 value[32]);
u32 nfsd4_test_ffv2_roles(struct nfsd_net *nn, u32 flags);
struct nfsd_ffv2_store_write;
struct nfsd_ffv2_store_mutation_result;
struct knfsd_fh;
int nfsd_ffv2_test_prototype_handle(struct nfsd_net *nn, u32 member, struct knfsd_fh *fh);
unsigned int nfsd_ffv2_test_active_admissions(struct nfsd_net *nn);
int nfsd_ffv2_prototype_test_write(struct nfsd_net *nn, u32 member,
				   struct nfsd_ffv2_store_write *request,
				   struct nfsd_ffv2_store_mutation_result *result);
struct nfsd_ffv2_recovery_input;
/* Installed before workers start, withdrawn after all workers have joined. */
struct nfsd_ffv2_prototype_test {
	int (*event)(void *data, enum nfsd_ffv2_prototype_test_site site, u32 member);
	int (*resolve)(void *data, const u8 *handle, u32 len, struct svc_fh *fhp);
	void *data;
	const struct nfsd_ffv2_recovery_input *input;
};

int nfsd_ffv2_prototype_test_member(struct nfsd_net *nn, enum nfsd_ffv2_prototype_test_site site,
				    u32 member);
int nfsd_ffv2_prototype_test_event(struct nfsd_net *nn, enum nfsd_ffv2_prototype_test_site site);
#else
static inline int nfsd_ffv2_prototype_test_member(struct nfsd_net *nn,
						  enum nfsd_ffv2_prototype_test_site site,
						  u32 member)
{
	return 0;
}

static inline int nfsd_ffv2_prototype_test_event(struct nfsd_net *nn,
						 enum nfsd_ffv2_prototype_test_site site)
{
	return 0;
}
#endif
#endif /* _NFSD_FFV2_PROTOTYPE_H */
