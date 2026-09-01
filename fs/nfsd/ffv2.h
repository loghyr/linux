/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NFSD_FFV2_H
#define _NFSD_FFV2_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/completion.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

struct net;
struct nfsd_net;
struct nfsd_ffv2_generation;
struct nfsd_ffv2_object;
struct nfsd_ffv2_binding;
struct nfsd_ffv2_reservation;
struct nfsd_ffv2_service_context;
struct cred;
struct path;
struct seq_file;
struct svc_rqst;
struct svc_fh;
struct svc_export;
struct svc_xprt;
struct task_struct;
struct knfsd_fh;
struct dentry;

#define NFSD_FFV2_FH_HEADER_SIZE	56
#define NFSD_FFV2_FH_INNER_MAX	72
#define NFSD_FFV2_FH_MAX		128

struct nfsd_ffv2_fh_info {
	u64		generation;
	u8		object_uuid[16];
	u8		export_uuid[16];
	const u8	*inner;
	u16		inner_len;
};

struct nfsd_ffv2_object_request {
	const char	*auth_domain;
	const char	*export_path;
	const char	*object_path;
	const u8	*object_uuid;
	const u8	*store_uuid;
	const u8	*binding_token;
	u64		control_root;
};

struct nfsd_ffv2_participant {
	struct list_head		node;
	struct list_head		reservations;
	refcount_t		ref;
	struct completion	released;
	/* Serializes export-update admission with service stop. */
	spinlock_t		update_lock;
	wait_queue_head_t	update_wait;
	unsigned int		update_count;
	u64			update_epoch;
	bool			updates_open;
	/* Protects the complete live-export inventory. */
	struct mutex		inventory_lock;
	struct list_head		inventory;
	wait_queue_head_t	inventory_wait;
	unsigned int		inventory_count;
	struct net		*net;
	bool			attached;
};

struct nfsd_ffv2_export_update {
	struct nfsd_ffv2_participant *participant;
	struct nfsd_ffv2_reservation *reservation;
	u64				epoch;
	bool				admitted;
	bool				entry_locked;
	bool				policy_locked;
	bool				registration_slot;
};

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

struct nfsd_ffv2_anchor {
	/* Keeps the embedded anchor alive across admitted callbacks. */
	refcount_t			ref;
	struct completion		released;
	/* Serializes service state, generation publication, and admission. */
	struct mutex			lock;
	enum nfsd_ffv2_net_state	net_state;
	enum nfsd_ffv2_service_state	service_state;
	u64				next_generation;
	struct nfsd_ffv2_generation	*pending;
	struct nfsd_ffv2_generation	*active;
	struct nfsd_ffv2_generation	*retiring;
	bool				registration_pending;
};

void nfsd_ffv2_net_init(struct nfsd_net *nn);
void nfsd_ffv2_net_pre_exit(struct nfsd_net *nn);
void nfsd_ffv2_net_destroy(struct nfsd_net *nn);
int nfsd_ffv2_participant_register(struct nfsd_net *nn, struct net *net);
void nfsd_ffv2_participant_detach_begin(struct nfsd_net *nn);
void nfsd_ffv2_participant_detach_finish(struct nfsd_net *nn);
int nfsd_ffv2_export_update_begin(struct svc_export *exp,
				  struct svc_export *old,
				  struct nfsd_ffv2_export_update *update);
int nfsd_ffv2_export_update_validate(struct nfsd_ffv2_export_update *update);
int nfsd_ffv2_export_update_end(struct svc_export *exp,
				struct nfsd_ffv2_export_update *update);
void nfsd_ffv2_export_update_abort(struct nfsd_ffv2_export_update *update);
int nfsd_ffv2_registration_begin(struct nfsd_net *nn,
				 struct nfsd_ffv2_export_update *registration);
void nfsd_ffv2_registration_end(struct nfsd_net *nn,
				struct nfsd_ffv2_export_update *registration);
struct nfsd_ffv2_object *nfsd_ffv2_object_alloc(void);
void nfsd_ffv2_object_free(struct nfsd_ffv2_object *object);
int nfsd_ffv2_object_register(struct nfsd_net *nn,
			      struct nfsd_ffv2_export_update *registration,
			      struct nfsd_ffv2_object *object,
			      const struct nfsd_ffv2_object_request *request,
			      struct knfsd_fh *outer_fh, u64 *generation_id);
int nfsd_ffv2_object_unregister(struct nfsd_net *nn, u64 generation_id,
				const u8 object_uuid[16]);
void
nfsd_ffv2_export_update_rollback_wait(struct nfsd_ffv2_service_context *context);
void nfsd_ffv2_export_release(struct svc_export *exp);
int nfsd_ffv2_reservation_claim(struct nfsd_net *owner, const struct path *root,
				const u8 store_uuid[16],
				const u8 binding_token[32],
				struct nfsd_ffv2_reservation **result);
int nfsd_ffv2_reservation_gate_io(struct nfsd_ffv2_reservation *reservation);
int nfsd_ffv2_reservation_claim_expected(struct nfsd_net *owner,
					 const struct path *root,
					 const u8 store_uuid[16],
					 const u8 binding_token[32],
					 struct svc_export *expected,
					 struct nfsd_ffv2_reservation **result);
void nfsd_ffv2_reservation_abort(struct nfsd_ffv2_reservation *reservation);
void nfsd_ffv2_reservation_fence(struct nfsd_ffv2_reservation *reservation);
bool nfsd4_ffv2_mount_crossing_allowed(const struct path *path);
int nfsd_ffv2_service_export_publish(struct nfsd_net *owner,
				     struct svc_export *exp,
				     const struct path *root,
				     const u8 store_uuid[16],
				     const u8 binding_token[32],
				     const struct cred *cred, u64 control_root,
				     u64 *generation_id);
int nfsd_ffv2_service_generation_retire(struct nfsd_net *nn,
					u64 generation_id);
void nfsd_ffv2_service_context_release(void *payload);
__be32 nfsd4_ffv2_export_policy_check(struct svc_export *exp, u32 opnum);
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
int nfsd_ffv2_register(struct nfsd_net *nn);
int nfsd_ffv2_fh_parse(const struct knfsd_fh *fh, struct nfsd_ffv2_fh_info *info);
int nfsd_ffv2_fh_encode(struct knfsd_fh *fh,
			const struct nfsd_ffv2_fh_info *info);
__be32 nfsd_ffv2_fh_map(struct svc_rqst *rqstp, struct svc_fh *fhp);
void nfsd_ffv2_binding_get(struct nfsd_ffv2_binding *binding);
void nfsd_ffv2_binding_put(struct nfsd_ffv2_binding *binding);
__be32 nfsd_ffv2_provider_probe(struct svc_rqst *rqstp, struct svc_fh *fhp,
				u32 opnum);
int nfsd_ffv2_provider_probe_show(struct seq_file *m, void *v);

struct nfsd_ffv2_admission {
	struct list_head			node;
	struct nfsd_ffv2_anchor		*anchor;
	struct nfsd_ffv2_generation	*generation;
	struct task_struct		*task;
};

int nfsd_ffv2_admit(struct svc_rqst *rqstp,
		    struct nfsd_ffv2_admission *admission);
void nfsd_ffv2_complete(struct nfsd_ffv2_admission *admission);

enum nfsd_ffv2_live_test_stage {
	NFSD_FFV2_LIVE_TEST_NONE,
	NFSD_FFV2_LIVE_TEST_TRANSITION,
	NFSD_FFV2_LIVE_TEST_PRE_PUBLISH,
	NFSD_FFV2_LIVE_TEST_POLICY,
	NFSD_FFV2_LIVE_TEST_CONTEXT_CLEAR,
};

enum nfsd_ffv2_fault_phase {
	NFSD_FFV2_FAULT_NONE,
	NFSD_FFV2_FAULT_REPLY_SKB,
	NFSD_FFV2_FAULT_OBJECT_ALLOC,
	NFSD_FFV2_FAULT_AUTH_DOMAIN,
	NFSD_FFV2_FAULT_EXPORT_PATH,
	NFSD_FFV2_FAULT_OBJECT_PATH,
	NFSD_FFV2_FAULT_EXPORT_LOOKUP,
	NFSD_FFV2_FAULT_FH_COMPOSE,
	NFSD_FFV2_FAULT_RESERVATION_CLAIM,
	NFSD_FFV2_FAULT_CONTEXT_ALLOC,
	NFSD_FFV2_FAULT_GENERATION_ALLOC,
	NFSD_FFV2_FAULT_TEMPLATE_CLONE,
	NFSD_FFV2_FAULT_EXACT_CURRENT,
	NFSD_FFV2_FAULT_CACHE_REPLACE,
	NFSD_FFV2_FAULT_REGISTRY_INSERT,
	NFSD_FFV2_FAULT_GENERATION_ACTIVATE,
	NFSD_FFV2_FAULT_REPLY_BUILD,
};

#if IS_ENABLED(CONFIG_NFSD_FFV2_LIVE_TEST) || \
	IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
bool nfsd_ffv2_fault_inject(enum nfsd_ffv2_fault_phase phase);
void nfsd_ffv2_fault_arm(enum nfsd_ffv2_fault_phase phase);
enum nfsd_ffv2_fault_phase nfsd_ffv2_fault_armed(void);
enum nfsd_ffv2_fault_phase nfsd_ffv2_fault_hit(void);
#else
static inline bool
nfsd_ffv2_fault_inject(enum nfsd_ffv2_fault_phase phase)
{
	return false;
}
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_LIVE_TEST)
int nfsd_ffv2_live_test_checkpoint(enum nfsd_ffv2_live_test_stage stage,
				   struct svc_export *exp);
int nfsd_ffv2_live_state_show(struct seq_file *m, void *v);
void nfsd_ffv2_live_test_debugfs_init(struct dentry *parent);
void nfsd_ffv2_live_test_exit(void);
#else
static inline int
nfsd_ffv2_live_test_checkpoint(enum nfsd_ffv2_live_test_stage stage,
			       struct svc_export *exp)
{
	return 0;
}

static inline void nfsd_ffv2_live_test_debugfs_init(struct dentry *parent) { }
static inline void nfsd_ffv2_live_test_exit(void) { }
#endif

int nfsd_ffv2_test_publish(struct nfsd_net *nn, void *payload,
			   void (*release)(void *), u64 *generation);
int nfsd_ffv2_test_admit(struct nfsd_net *nn,
			 struct nfsd_ffv2_admission *admission);
void nfsd_ffv2_test_complete(struct nfsd_ffv2_admission *admission);
int nfsd_ffv2_test_unregister(struct nfsd_net *nn, u64 generation);
int nfsd_ffv2_test_retire_waiting(struct nfsd_net *nn, u64 generation,
				  struct completion *waiting);
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
int
nfsd_ffv2_test_service_export_publish(struct nfsd_net *owner,
				      struct svc_export *exp,
				      const struct path *root,
				      const u8 store_uuid[16],
				      const u8 binding_token[32],
				      const struct cred *cred,
				      u64 control_root, u64 *generation_id);
int nfsd_ffv2_test_transition_publish(struct nfsd_net *owner,
				      struct nfsd_ffv2_export_update *registration,
				      struct nfsd_ffv2_object *object,
				      struct knfsd_fh *outer_fh,
				      struct svc_export *template,
				      struct svc_export *expected,
				      const struct path *root,
				      const u8 store_uuid[16],
				      const u8 binding_token[32],
				      const struct cred *cred,
				      u64 control_root, u64 *generation_id);
int nfsd_ffv2_test_object_init(struct nfsd_ffv2_object *object,
			       struct auth_domain *client,
			       const struct path *export_path,
			       const struct path *object_path, const u8 *inner,
			       u16 inner_len, const u8 object_uuid[16],
			       const u8 export_uuid[16]);
struct nfsd_ffv2_binding *
nfsd_ffv2_test_binding_create(struct nfsd_net *nn,
			      const struct nfsd_ffv2_fh_info *info);
bool nfsd_ffv2_test_generation_retired(struct nfsd_ffv2_generation *generation);
bool nfsd_ffv2_test_admission_retired(struct nfsd_ffv2_admission *admission);
unsigned int nfsd_ffv2_test_refcount(struct nfsd_ffv2_admission *admission);
unsigned int nfsd_ffv2_test_anchor_refcount(struct nfsd_net *nn);
void nfsd_ffv2_test_worker(struct svc_rqst *rqstp, struct svc_xprt *xprt);
void nfsd_ffv2_test_set_start_failure(bool fail);
bool nfsd_ffv2_test_start_failure(void);
void nfsd_ffv2_test_fault_arm(enum nfsd_ffv2_fault_phase phase);

#endif /* _NFSD_FFV2_H */
