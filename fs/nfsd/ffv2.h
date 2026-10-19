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

struct nfsd_ffv2_anchor {
	/* Keeps the embedded anchor alive across admitted callbacks. */
	refcount_t			ref;
	struct completion		released;
	/* Serializes service state, generation publication, and admission. */
	struct mutex			lock;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	struct completion		*test_destroy_waiting;
#endif
	enum nfsd_ffv2_net_state	net_state;
	enum nfsd_ffv2_service_state	service_state;
	u64				next_generation;
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
};

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
