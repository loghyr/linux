/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NFSD_FFV2_H
#define _NFSD_FFV2_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/completion.h>

struct net;
struct nfsd_net;
struct nfsd_ffv2_generation;
struct svc_rqst;
struct task_struct;

#ifdef CONFIG_NFSD_FFV2
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
	struct nfsd_ffv2_generation	*active;
	struct nfsd_ffv2_generation	*retiring;
};

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
