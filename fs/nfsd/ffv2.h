/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NFSD_FFV2_H
#define _NFSD_FFV2_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/completion.h>

struct knfsd_fh;
struct net;
struct nfsd_net;
struct nfsd_ffv2_generation;
struct path;
struct nfsd_ffv2_reservation;
struct svc_fh;
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
};

struct nfsd_ffv2_registration_test {
	atomic_t fault;
	atomic_t hit;
	atomic_t contexts;
	atomic_t registries;
	atomic_t authorities;
	atomic_t published_refusals;
	atomic_t reply_consumed;
	struct completion *before_publish;
	struct completion *publish_continue;
	struct completion *export_wait;
	struct completion *work_entered;
	struct completion *work_continue;
};

bool nfsd_ffv2_test_registration_fault(struct nfsd_net *nn,
				       enum nfsd_ffv2_test_registration_fault fault);
#endif

struct nfsd_ffv2_anchor {
	/* Keeps the embedded anchor alive across admitted callbacks. */
	refcount_t			ref;
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
	/* Serializes the source claim and its final release. */
	spinlock_t source_lock;
	bool source_claimed;
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
};

int nfsd_ffv2_admit(struct svc_rqst *rqstp,
		    struct nfsd_ffv2_admission *admission);
void nfsd_ffv2_complete(struct nfsd_ffv2_admission *admission);

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
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

#endif /* _NFSD_FFV2_H */
