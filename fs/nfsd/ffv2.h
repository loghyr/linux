/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NFSD_FFV2_H
#define _NFSD_FFV2_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/completion.h>

#include "ffv2_prototype.h"

struct knfsd_fh;
struct net;
struct nfsd_net;
struct nfsd_ffv2_generation;
struct path;
struct nfsd_ffv2_reservation;
struct svc_fh;
struct svc_export;
struct svc_rqst;
struct svc_xprt;
struct task_struct;
struct nfsd_ffv2_authority;
struct nfsd_ffv2_object;
struct nfsd4_session;
struct svc_cred;

#if !IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
#define nfsd_ffv2_test_registration_fault(...) false
#endif

#ifdef CONFIG_NFSD_FFV2
#define NFSD_FFV2_FH_HEADER_SIZE	56
#define NFSD_FFV2_FH_INNER_MAX	72
#define NFSD_FFV2_FH_MAX		128

struct nfsd_ffv2_fh_info {
	u64		generation;
	u8		object_uuid[16];
	u8		export_uuid[16];
	/* Borrows bytes from the supplied handle. */
	const u8	*inner;
	u16		inner_len;
};

struct nfsd_ffv2_binding;

void nfsd_ffv2_binding_get(struct nfsd_ffv2_binding *binding);
void nfsd_ffv2_binding_put(struct nfsd_ffv2_binding *binding);
__be32 nfsd_ffv2_fh_map(struct svc_rqst *rqstp, struct svc_fh *fhp);
__be32 nfsd4_ffv2_export_policy_check(struct svc_export *exp, u32 opnum);

int nfsd_ffv2_fh_parse(const struct knfsd_fh *fh, struct nfsd_ffv2_fh_info *info);
int nfsd_ffv2_fh_encode(struct knfsd_fh *fh,
			const struct nfsd_ffv2_fh_info *info);

enum nfsd_ffv2_net_state {
	NFSD_FFV2_NET_LIVE,
	NFSD_FFV2_NET_EXITING,
};

enum nfsd_ffv2_service_state {
	NFSD_FFV2_SERVICE_DOWN,
	NFSD_FFV2_SERVICE_UP,
	NFSD_FFV2_SERVICE_STOPPING,
	NFSD_FFV2_SERVICE_DRAIN_FAILED,
};

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
enum nfsd_ffv2_test_registration_fault {
	NFSD_FFV2_TEST_NONE,
	NFSD_FFV2_TEST_OBJECT_ALLOC,
	NFSD_FFV2_TEST_REPLY_ALLOC,
	NFSD_FFV2_TEST_REPLY_HEADER,
	NFSD_FFV2_TEST_AUTH_ALLOC,
	NFSD_FFV2_TEST_CRED_PRINCIPAL,
	NFSD_FFV2_TEST_CRED_RAW,
	NFSD_FFV2_TEST_CRED_TARGET,
	NFSD_FFV2_TEST_AUTH_LINK_DEATH,
	NFSD_FFV2_TEST_AUTH_PUBLISH_DEATH,
	NFSD_FFV2_TEST_AUTH_DOMAIN,
	NFSD_FFV2_TEST_EXPORT_PATH,
	NFSD_FFV2_TEST_OBJECT_PATH,
	NFSD_FFV2_TEST_EXPORT_LOOKUP,
	NFSD_FFV2_TEST_FH_COMPOSE,
	NFSD_FFV2_TEST_TEMPLATE,
	NFSD_FFV2_TEST_TEMPLATE_UUID,
	NFSD_FFV2_TEST_TEMPLATE_ARRAY,
	NFSD_FFV2_TEST_TEMPLATE_HOST,
	NFSD_FFV2_TEST_TEMPLATE_PATH,
	NFSD_FFV2_TEST_RESERVATION,
	NFSD_FFV2_TEST_CONTEXT_ALLOC,
	NFSD_FFV2_TEST_HASH_INIT,
	NFSD_FFV2_TEST_GENERATION,
	NFSD_FFV2_TEST_ENCODE,
	NFSD_FFV2_TEST_EXACT_REPLACE,
	NFSD_FFV2_TEST_REPLY_BUILD,
	NFSD_FFV2_TEST_REPLY_SEND,
	NFSD_FFV2_TEST_WORK_ALLOC,
	NFSD_FFV2_TEST_MAP_ALLOC,
	NFSD_FFV2_TEST_MAP_NET,
	NFSD_FFV2_TEST_TRUST_ALLOC,
	NFSD_FFV2_TEST_TRUST_PRINCIPAL,
	NFSD_FFV2_TEST_TRUST_REPLACE,
	NFSD_FFV2_TEST_TRUST_INSERT,
};

struct nfsd_ffv2_registration_test {
	atomic_t fault;
	atomic_t hit;
	atomic_t contexts;
	atomic_t registries;
	atomic_t authorities;
	atomic_t published_refusals;
	atomic_t reply_consumed;
	atomic_t bindings;
	atomic_t dispatch_calls;
	unsigned int read_copy_fault;
	struct completion **provider_drain_wait;
	struct completion *validation_entered;
	struct completion *validation_continue;
	struct completion *execute_entered;
	struct completion *execute_continue;
	struct completion *map_verified;
	struct completion *map_continue;
	struct completion *before_publish;
	struct completion *publish_continue;
	struct completion *export_wait;
	struct completion *work_entered;
	struct completion *work_continue;
};

bool nfsd_ffv2_test_registration_fault(struct nfsd_net *nn,
				       enum nfsd_ffv2_test_registration_fault fault);
#endif

struct nfsd_ffv2_provider;
struct nfsd_ffv2_admission;

#define NFSD_FFV2_CHUNK_HEADER_READ_MAX 1024
#define NFSD_FFV2_CHECKSUM_VALUE_MAX 64

#define NFSD_FFV2_CHECKSUM_ALG_NONE 0
#define NFSD_FFV2_CHECKSUM_ALG_CRC32 1

#define NFSD_FFV2_CHECKSUM_CRC32_LEN 4

#define NFSD_FFV2_MAX_PAYLOAD_BYTES 4194304U

#define NFSD_FFV2_GUARD_CLIENT_ID_NONE 0U

#define NFSD4_FFV2_READ_FIXED_WORDS (2 + 1 + 1)
#define NFSD4_FFV2_READ_ENT_WORDS 14

struct nfsd_ffv2_chunk_owner {
	u64 co_cohort_id;
	u32 co_client_id;
	u32 co_id;
};

struct nfsd_ffv2_chunk_guard {
	u32 cg_gen_id;
	u32 cg_client_id;
};

struct nfsd_ffv2_checksum {
	u32 cs_algorithm;
	u32 cs_len;
	u8 cs_value[NFSD_FFV2_CHECKSUM_VALUE_MAX];
};

enum nfsd_ffv2_retained_disposition {
	NFSD_FFV2_RETAINED_ABSENT,
	NFSD_FFV2_RETAINED_PRESENT,
	NFSD_FFV2_RETAINED_ERRORED,
};

struct nfsd_ffv2_retained {
	enum nfsd_ffv2_retained_disposition disposition;
	struct nfsd_ffv2_chunk_owner rp_owner;
};

struct nfsd_ffv2_read_chunk {
	struct nfsd_ffv2_checksum cr_checksum;
	u32 cr_effective_len;
	struct nfsd_ffv2_chunk_owner cr_owner;
	struct nfsd_ffv2_chunk_guard cr_guard;
	u32 cr_payload_id;
	u32 cr_locked;
	__be32 cr_status;
	const u8 *cr_chunk;
};

struct nfsd_ffv2_chunk_request {
	u64 offset;
	u32 count;
};

struct nfsd_ffv2_chunk_result {
	bool eof;
	u32 count;
	void *private;
	void (*release)(void *private);
	union {
		struct {
			const struct nfsd_ffv2_read_chunk *chunks;
		} read;
		struct {
			const __be32 *status;
			const u32 *locked;
			const struct nfsd_ffv2_chunk_owner *owners;
			const struct nfsd_ffv2_chunk_guard *guards;
			const struct nfsd_ffv2_retained *predecessors;
		} header;
	};
};

/*
 * Callbacks and result release may sleep. Borrowed arrays and payload stay
 * immutable until admission completion. A non-NULL private/release pair
 * transfers cleanup ownership even when the callback returns an error.
 * One admission may retain only one such owner; further callbacks must not
 * replace it. The operations vector and data outlive provider removal.
 */
struct nfsd_ffv2_provider_ops {
	__be32 (*chunk_read)(void *provider,
			     const struct nfsd_ffv2_object *object,
			     const struct nfsd_ffv2_chunk_request *request,
			     struct nfsd_ffv2_chunk_result *result);
	__be32 (*chunk_header_read)(void *provider, const struct nfsd_ffv2_object *object,
				    const struct nfsd_ffv2_chunk_request *request,
		struct nfsd_ffv2_chunk_result *result);
};

__be32 nfsd_ffv2_provider_probe(struct svc_rqst *rqstp, struct svc_fh *fhp,
				u32 opnum,
				const struct nfsd_ffv2_chunk_request *request,
				struct nfsd_ffv2_chunk_result *result,
				u32 available,
				struct nfsd_ffv2_admission *admission);

enum nfsd_ffv2_source {
	NFSD_FFV2_SOURCE_NONE,
	NFSD_FFV2_SOURCE_MDS,
	NFSD_FFV2_SOURCE_PROTOTYPE,
};

struct nfsd_ffv2_anchor {
	/* Keeps the embedded anchor alive across admitted callbacks. */
	refcount_t			ref;
	struct nfsd_ffv2_provider __rcu *provider;
	struct completion		released;
	/* Serializes service state, generation publication, and admission. */
	struct mutex			lock;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	struct completion		*test_destroy_waiting;
	struct nfsd_ffv2_registration_test test_registration;
#endif
	enum nfsd_ffv2_net_state	net_state;
	enum nfsd_ffv2_service_state	service_state;
	u64				next_generation;
	struct nfsd_ffv2_generation *pending;
	bool registration_pending;
	/* Serializes source ownership and prototype gate transitions. */
	spinlock_t prototype_gate_lock;
	enum nfsd_ffv2_source source;
#if IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
	struct nfsd_ffv2_prototype prototype;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	const struct nfsd_ffv2_prototype_test *test_prototype;
#endif
#endif
	/* Serializes epoch allocation and retirement-work admission. */
	spinlock_t authority_lock;
	wait_queue_head_t authority_wait;
	u64 next_authority_epoch;
	unsigned int authority_work;
	bool authority_work_open;
	struct nfsd_ffv2_generation	*active;
	struct nfsd_ffv2_generation	*retiring;
};

struct nfsd_ffv2_participant {
	/* Registry membership and reservations use nfsd_ffv2_registry_lock. */
	struct list_head node;
	struct list_head reservations;
	refcount_t ref;
	struct completion released;
	struct net *net;
	/* Admission count and epoch serialize with stop and namespace exit. */
	spinlock_t		update_lock;
	wait_queue_head_t		update_wait;
	unsigned int		update_count;
	u64			update_epoch;
	bool			updates_open;
	bool			updates_closing;
	/* The inventory tracks live cache exports without pinning them. */
	struct mutex		inventory_lock;
	struct list_head	inventory;
	wait_queue_head_t	inventory_wait;
	unsigned int		inventory_count;
	bool			attached;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	atomic_t		test_reservation_alloc_failure;
	struct completion	*test_update_validated;
	struct completion	*test_update_continue;
	struct completion	*test_inventory_wait_entered;
	struct completion	*test_inventory_wait_done;
	struct completion	*test_inventory_postwait_entered;
	struct completion	*test_inventory_postwait_continue;
	struct completion	*test_inventory_lock_entered;
	struct completion	*test_inventory_destroy_continue;
	struct task_struct	**test_inventory_task;
	unsigned int		*test_inventory_wait_count;
	struct completion	*test_release_count_zero;
	struct completion	*test_release_continue;
#endif
};

struct nfsd_ffv2_export_update {
	struct nfsd_ffv2_participant *participant;
	u64				epoch;
	bool				admitted;
	bool				policy_locked;
	bool registration_slot;
	bool source_claimed;
	struct nfsd_ffv2_authority *authority;
};

struct nfsd_ffv2_object_request {
	const char *auth_domain;
	const char *export_path;
	const char *object_path;
	const u8 *object_uuid;
	const u8 *store_uuid;
	const u8 *binding_token;
	u64 control_root;
};

int nfsd_ffv2_registration_begin(struct nfsd_net *nn, struct nfsd_ffv2_export_update *registration);
void nfsd_ffv2_registration_end(struct nfsd_net *nn, struct nfsd_ffv2_export_update *registration);
struct nfsd_ffv2_object *nfsd_ffv2_object_alloc(void);
void nfsd_ffv2_object_free(struct nfsd_ffv2_object *object);
int nfsd_ffv2_object_register(struct nfsd_net *nn, struct nfsd_ffv2_export_update *registration,
			      struct nfsd_ffv2_object *object,
			      const struct nfsd_ffv2_object_request *request,
			      struct knfsd_fh *outer_fh, u64 *generation_id);
int nfsd_ffv2_object_unregister(struct nfsd_net *nn, u64 generation_id, const u8 object_uuid[16]);
int nfsd_ffv2_authority_register(struct nfsd_net *nn, struct net *net, const u8 sessionid[16],
				 struct nfsd_ffv2_authority **result);
void nfsd_ffv2_session_init(struct nfsd4_session *session);
void nfsd_ffv2_session_free(struct nfsd4_session *session);
void nfsd_ffv2_session_dead_locked(struct nfsd4_session *session);

struct svc_export;
int nfsd_ffv2_participant_register(struct nfsd_net *nn, struct net *net);
void nfsd_ffv2_participant_detach_begin(struct nfsd_net *nn);
void nfsd_ffv2_participant_detach_finish(struct nfsd_net *nn);
int nfsd_ffv2_export_update_begin(struct svc_export *exp,
				  struct nfsd_ffv2_export_update *update);
int nfsd_ffv2_export_update_validate(struct nfsd_ffv2_export_update *update);
void nfsd_ffv2_export_update_end(struct svc_export *exp,
				 struct nfsd_ffv2_export_update *update);
void nfsd_ffv2_export_update_abort(struct nfsd_ffv2_export_update *update);
void nfsd_ffv2_export_release(struct svc_export *exp);

int nfsd_ffv2_reservation_claim(struct nfsd_net *owner, const struct path *root,
				const u8 store_uuid[16], const u8 export_uuid[16],
				const u8 binding_token[32],
				struct nfsd_ffv2_reservation **result);
int nfsd_ffv2_reservation_claim_expected(struct nfsd_net *owner,
					 const struct path *root,
					 const u8 store_uuid[16],
					 const u8 binding_token[32],
					 struct svc_export *expected,
					 struct nfsd_ffv2_reservation **result);
int nfsd_ffv2_reservation_gate_io(struct nfsd_ffv2_reservation *reservation);
void nfsd_ffv2_reservation_abort(struct nfsd_ffv2_reservation *reservation);
void nfsd_ffv2_reservation_fence(struct nfsd_ffv2_reservation *reservation);
bool nfsd4_ffv2_mount_crossing_allowed(const struct path *path);

void nfsd_ffv2_net_init(struct nfsd_net *nn);
void nfsd_ffv2_net_pre_exit(struct nfsd_net *nn);
void nfsd_ffv2_net_destroy(struct nfsd_net *nn);
int nfsd_ffv2_service_up(struct nfsd_net *nn);
struct nfsd_ffv2_generation *
nfsd_ffv2_service_stop_begin(struct nfsd_net *nn);
void nfsd_ffv2_service_stop_finish(struct nfsd_net *nn,
				   struct nfsd_ffv2_generation *generation);
void nfsd_ffv2_service_stop_failed(struct nfsd_net *nn,
				   struct nfsd_ffv2_generation *generation);
void nfsd_ffv2_service_stop_put(struct nfsd_ffv2_generation *generation);
void nfsd_ffv2_service_down(struct nfsd_net *nn);
bool nfsd_ffv2_requested_zero_threads(int n, const int *nthreads,
				      unsigned int nrpools);

struct nfsd_ffv2_admission {
	struct list_head			node;
	struct nfsd_ffv2_anchor		*anchor;
	struct nfsd_ffv2_generation	*generation;
	struct task_struct		*task;
	struct nfsd_ffv2_provider *provider;
	void *provider_result;
	void (*provider_result_release)(void *result);
};

int nfsd_ffv2_admit(struct svc_rqst *rqstp,
		    struct nfsd_ffv2_admission *admission);
void nfsd_ffv2_complete(struct nfsd_ffv2_admission *admission);

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST) || IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
int nfsd_ffv2_provider_install(struct nfsd_net *nn,
			       const struct nfsd_ffv2_provider_ops *ops,
			       void *data, u32 chunk_size);
void nfsd_ffv2_provider_remove(struct nfsd_net *nn);
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
void nfsd_ffv2_test_provider_drain_hook(struct nfsd_net *nn,
					struct completion **waiting);
void nfsd_ffv2_test_read_copy_fault(struct nfsd_net *nn, unsigned int stage);
void nfsd_ffv2_test_object_geometry(struct svc_fh *fhp, u32 chunk_size);
struct nfsd4_compound_state;
struct nfsd4_op;
__be32 nfsd_ffv2_test_dispatch_op(struct svc_rqst *rqstp,
				  struct nfsd4_compound_state *cstate,
				  struct nfsd4_op *op);
unsigned int nfsd_ffv2_test_binding_refs(struct nfsd_ffv2_binding *binding);
bool nfsd_ffv2_test_binding_waiting(struct nfsd_ffv2_binding *binding);
void nfsd_ffv2_test_session_hash(struct nfsd_net *nn, struct nfsd4_session *session);
void nfsd_ffv2_test_session_unhash(struct nfsd_net *nn, struct nfsd4_session *session,
				   bool client_expiry);
int nfsd_ffv2_test_authority_state(struct nfsd_ffv2_authority *authority);
bool nfsd_ffv2_test_authority_copy(struct nfsd_ffv2_authority *authority,
				   const struct svc_cred *cred);
void *nfsd_ffv2_test_trust_hold(struct nfsd_net *nn);
void nfsd_ffv2_test_trust_put(void *entry);
void nfsd_ffv2_test_work_drain(struct nfsd_net *nn);
bool nfsd_ffv2_test_work_waiting(struct nfsd_net *nn);
int nfsd_ffv2_test_active_authority_state(struct nfsd_net *nn);
bool nfsd_ffv2_test_export_waiting(struct svc_export *exp);
bool nfsd_ffv2_test_trust_waiting(void *entry);
void nfsd_ffv2_test_wrong_unregister_kind(struct nfsd_net *nn, bool wrong);
void nfsd_ffv2_test_fail_reservation_alloc(struct nfsd_net *nn);
bool nfsd_ffv2_test_reservation_waiting(struct nfsd_ffv2_reservation *reservation);
int nfsd_ffv2_test_reservation_claim(struct nfsd_net *owner,
				     const struct path *root,
				     const u8 store_uuid[16],
				     const u8 binding_token[32],
				     struct nfsd_ffv2_reservation **result);
int nfsd_ffv2_test_reservation_claim_expected(struct nfsd_net *owner,
					      const struct path *root,
					      const u8 store_uuid[16],
					      const u8 binding_token[32],
					      struct svc_export *expected,
					      struct nfsd_ffv2_reservation **result);

int nfsd_ffv2_test_publish(struct nfsd_net *nn, void *payload,
			   void (*release)(void *), u64 *generation);
int nfsd_ffv2_test_admit(struct nfsd_net *nn,
			 struct nfsd_ffv2_admission *admission);
int nfsd_ffv2_test_unregister(struct nfsd_net *nn, u64 generation);
bool nfsd_ffv2_test_generation_retired(struct nfsd_ffv2_generation *generation);
bool nfsd_ffv2_test_admission_retired(struct nfsd_ffv2_admission *admission);
unsigned int nfsd_ffv2_test_waiters(struct nfsd_ffv2_admission *admission);
unsigned int nfsd_ffv2_test_anchor_refcount(struct nfsd_net *nn);
bool nfsd_ffv2_test_anchor_hold(struct nfsd_net *nn);
void nfsd_ffv2_test_anchor_release(struct nfsd_net *nn);
void nfsd_ffv2_test_destroy_waiting(struct nfsd_net *nn,
				    struct completion *entered);
void nfsd_ffv2_test_worker(struct svc_rqst *rqstp, struct svc_xprt *xprt);
void nfsd_ffv2_test_set_start_failure(bool fail);
bool nfsd_ffv2_test_start_failure(void);
void nfsd_ffv2_test_try_reopen_updates(struct nfsd_net *nn);

#endif

#else
static inline void nfsd_ffv2_session_dead_locked(struct nfsd4_session *session)
{
}
static inline void nfsd_ffv2_net_init(struct nfsd_net *nn) { }
static inline void nfsd_ffv2_net_pre_exit(struct nfsd_net *nn) { }
static inline void nfsd_ffv2_net_destroy(struct nfsd_net *nn) { }
static inline void nfsd_ffv2_service_down(struct nfsd_net *nn) { }
static inline void
nfsd_ffv2_service_stop_finish(struct nfsd_net *nn,
			      struct nfsd_ffv2_generation *generation) { }
static inline void
nfsd_ffv2_service_stop_failed(struct nfsd_net *nn,
			      struct nfsd_ffv2_generation *generation) { }
static inline void
nfsd_ffv2_service_stop_put(struct nfsd_ffv2_generation *generation) { }
static inline struct nfsd_ffv2_generation *
nfsd_ffv2_service_stop_begin(struct nfsd_net *nn)
{
	return NULL;
}

static inline int nfsd_ffv2_service_up(struct nfsd_net *nn)
{
	return 0;
}

static inline bool
nfsd_ffv2_requested_zero_threads(int n, const int *nthreads,
				 unsigned int nrpools)
{
	return false;
}
#endif

#ifdef CONFIG_NFSD_FFV2
int nfsd_ffv2_source_claim_gated(struct nfsd_ffv2_anchor *anchor, enum nfsd_ffv2_source source);
void nfsd_ffv2_source_release_gated(struct nfsd_ffv2_anchor *anchor, enum nfsd_ffv2_source source);
enum nfsd_ffv2_source nfsd_ffv2_source_get(struct nfsd_net *nn);
bool nfsd_ffv2_anchor_hold(struct nfsd_net *nn);
void nfsd_ffv2_anchor_release(struct nfsd_net *nn);
int nfsd_ffv2_service_generation_retire(struct nfsd_net *nn, u64 generation);
#if IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
struct nfsd_ffv2_store;
int nfsd_ffv2_registration_begin_prototype(struct nfsd_net *nn,
					   struct nfsd_ffv2_export_update *registration);
int nfsd_ffv2_authority_prototype_create(struct nfsd_net *nn, struct nfsd_ffv2_authority **result);
int nfsd_ffv2_object_register_fhs(struct nfsd_net *nn, struct nfsd_ffv2_export_update *registration,
				  struct svc_fh *fhps, const u8 persisted[][32], u32 count,
				  u32 chunk_size, const u8 store_uuid[16], const u8 token[32],
				  const struct cred *cred, bool validate_backend,
				  const u8 unregister_uuid[16], u8 object_uuids[][16],
				  struct knfsd_fh *outer_fhs, u64 *generation);
/* Caller holds nn->ffv2.lock across the READY decision. */
bool nfsd_ffv2_prototype_generation_matches(struct nfsd_net *nn, const u8 uuid[16], u64 generation);
int nfsd_ffv2_store_open_generation(struct nfsd_net *nn, u64 generation,
				    struct nfsd_ffv2_store **result);
const u8 *nfsd_ffv2_object_uuid(const struct nfsd_ffv2_object *object);
#endif
int nfsd_ffv2_reservation_store_root(struct nfsd_ffv2_reservation *reservation, struct path *root,
				     u8 store_uuid[16], u8 export_uuid[16], u8 token[32]);
int nfsd_ffv2_reservation_store_begin(struct nfsd_ffv2_reservation *reservation);
void nfsd_ffv2_reservation_store_end(struct nfsd_ffv2_reservation *reservation);
void nfsd_ffv2_reservation_store_put(struct nfsd_ffv2_reservation *reservation);

#endif
#endif /* _NFSD_FFV2_H */
