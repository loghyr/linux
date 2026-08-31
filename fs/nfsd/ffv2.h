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
struct nfsd_ffv2_reservation;
struct nfsd_ffv2_service_context;
struct cred;
struct path;
struct svc_rqst;
struct svc_export;
struct svc_xprt;
struct task_struct;
struct knfsd_fh;

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

struct nfsd_ffv2_admission {
	struct list_head			node;
	struct nfsd_ffv2_anchor		*anchor;
	struct nfsd_ffv2_generation	*generation;
	struct task_struct		*task;
};

int nfsd_ffv2_admit(struct svc_rqst *rqstp,
		    struct nfsd_ffv2_admission *admission);
void nfsd_ffv2_complete(struct nfsd_ffv2_admission *admission);

int nfsd_ffv2_test_publish(struct nfsd_net *nn, void *payload,
			   void (*release)(void *), u64 *generation);
int nfsd_ffv2_test_admit(struct nfsd_net *nn,
			 struct nfsd_ffv2_admission *admission);
void nfsd_ffv2_test_complete(struct nfsd_ffv2_admission *admission);
int nfsd_ffv2_test_unregister(struct nfsd_net *nn, u64 generation);
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
				      struct svc_export *template,
				      struct svc_export *expected,
				      const struct path *root,
				      const u8 store_uuid[16],
				      const u8 binding_token[32],
				      const struct cred *cred,
				      u64 control_root, u64 *generation_id);
bool nfsd_ffv2_test_generation_retired(struct nfsd_ffv2_generation *generation);
bool nfsd_ffv2_test_admission_retired(struct nfsd_ffv2_admission *admission);
unsigned int nfsd_ffv2_test_refcount(struct nfsd_ffv2_admission *admission);
unsigned int nfsd_ffv2_test_anchor_refcount(struct nfsd_net *nn);
void nfsd_ffv2_test_worker(struct svc_rqst *rqstp, struct svc_xprt *xprt);
void nfsd_ffv2_test_set_start_failure(bool fail);
bool nfsd_ffv2_test_start_failure(void);

#endif /* _NFSD_FFV2_H */
