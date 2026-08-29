// SPDX-License-Identifier: GPL-2.0-only
#include <linux/completion.h>
#include <linux/lockdep.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/wait.h>

#include "ffv2.h"
#include "nfsd.h"
#include "netns.h"

enum nfsd_ffv2_identity_state {
	NFSD_FFV2_IDENTITY_LIVE,
	NFSD_FFV2_IDENTITY_RETIRED,
};

enum nfsd_ffv2_generation_state {
	NFSD_FFV2_GENERATION_ACTIVE,
	NFSD_FFV2_GENERATION_STOPPING,
	NFSD_FFV2_GENERATION_FINALIZING,
	NFSD_FFV2_GENERATION_STOPPED,
};

struct nfsd_ffv2_identity {
	refcount_t	ref;
	u64		generation;
	int		state;
};

struct nfsd_ffv2_generation {
	refcount_t			ref;
	struct nfsd_ffv2_identity	*identity;
	atomic_t			state;
	atomic_t			admitted;
	/* Protects callback-task records removed without the anchor lock. */
	spinlock_t			admissions_lock;
	struct list_head		admissions;
	wait_queue_head_t		admitted_wait;
	struct completion		retired;
	void				*payload;
	void				(*release)(void *payload);
};

static void nfsd_ffv2_identity_put(struct nfsd_ffv2_identity *identity)
{
	if (refcount_dec_and_test(&identity->ref))
		kfree(identity);
}

static void nfsd_ffv2_generation_put(struct nfsd_ffv2_generation *generation)
{
	if (!refcount_dec_and_test(&generation->ref))
		return;

	WARN_ON_ONCE(atomic_read(&generation->admitted));
	WARN_ON_ONCE(!list_empty(&generation->admissions));
	WARN_ON_ONCE(generation->payload);
	nfsd_ffv2_identity_put(generation->identity);
	kfree(generation);
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
static struct nfsd_ffv2_generation *
nfsd_ffv2_generation_alloc(void *payload, void (*release)(void *))
{
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_identity *identity;

	identity = kzalloc_obj(*identity, GFP_KERNEL);
	if (!identity)
		return NULL;

	generation = kzalloc_obj(*generation, GFP_KERNEL);
	if (!generation) {
		kfree(identity);
		return NULL;
	}

	refcount_set(&identity->ref, 1);
	WRITE_ONCE(identity->state, NFSD_FFV2_IDENTITY_LIVE);
	refcount_set(&generation->ref, 1);
	generation->identity = identity;
	atomic_set(&generation->state, NFSD_FFV2_GENERATION_ACTIVE);
	atomic_set(&generation->admitted, 0);
	spin_lock_init(&generation->admissions_lock);
	INIT_LIST_HEAD(&generation->admissions);
	init_waitqueue_head(&generation->admitted_wait);
	init_completion(&generation->retired);
	generation->payload = payload;
	generation->release = release;
	return generation;
}
#endif

static struct nfsd_ffv2_generation *
nfsd_ffv2_retire_begin_locked(struct nfsd_ffv2_anchor *anchor)
{
	struct nfsd_ffv2_generation *generation = anchor->active;

	lockdep_assert_held(&anchor->lock);
	if (generation) {
		anchor->active = NULL;
		anchor->retiring = generation;
		/* Publish the tombstone before a future binding rejects it. */
		smp_store_release(&generation->identity->state,
				  NFSD_FFV2_IDENTITY_RETIRED);
		atomic_set(&generation->state,
			   NFSD_FFV2_GENERATION_STOPPING);
	} else {
		generation = anchor->retiring;
	}
	if (generation)
		refcount_inc(&generation->ref);
	return generation;
}

static void
nfsd_ffv2_release_payload(struct nfsd_ffv2_generation *generation)
{
	void *payload = xchg(&generation->payload, NULL);

	if (payload && generation->release)
		generation->release(payload);
}

static void nfsd_ffv2_retire_finish(struct nfsd_ffv2_anchor *anchor,
				    struct nfsd_ffv2_generation *generation,
				    bool wait)
{
	bool unpublished = false;

	if (!generation)
		return;

	if (wait) {
		wait_event(generation->admitted_wait,
			   atomic_read(&generation->admitted) == 0);
	} else if (WARN_ON_ONCE(atomic_read(&generation->admitted))) {
		goto out_put;
	}

	if (atomic_cmpxchg(&generation->state,
			   NFSD_FFV2_GENERATION_STOPPING,
			   NFSD_FFV2_GENERATION_FINALIZING) ==
			   NFSD_FFV2_GENERATION_STOPPING) {
		nfsd_ffv2_release_payload(generation);

		mutex_lock(&anchor->lock);
		if (WARN_ON_ONCE(anchor->retiring != generation)) {
			mutex_unlock(&anchor->lock);
			goto out_complete;
		}
		anchor->retiring = NULL;
		atomic_set_release(&generation->state,
				   NFSD_FFV2_GENERATION_STOPPED);
		unpublished = true;
		mutex_unlock(&anchor->lock);

out_complete:
		complete_all(&generation->retired);
		if (unpublished)
			nfsd_ffv2_generation_put(generation);
	} else if (wait) {
		wait_for_completion(&generation->retired);
	}

out_put:
	nfsd_ffv2_generation_put(generation);
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
static int nfsd_ffv2_publish(struct nfsd_ffv2_anchor *anchor,
			     struct nfsd_ffv2_generation *generation,
			     u64 *generation_id)
{
	int error = 0;

	mutex_lock(&anchor->lock);
	if (anchor->net_state != NFSD_FFV2_NET_LIVE ||
	    anchor->service_state == NFSD_FFV2_SERVICE_STOPPING) {
		error = -ESHUTDOWN;
	} else if (anchor->service_state == NFSD_FFV2_SERVICE_DOWN) {
		error = -ENXIO;
	} else if (anchor->active || anchor->retiring) {
		error = -EBUSY;
	} else if (!anchor->next_generation) {
		error = -EOVERFLOW;
	} else {
		generation->identity->generation = anchor->next_generation++;
		refcount_inc(&generation->ref);
		anchor->active = generation;
		if (generation_id)
			*generation_id = generation->identity->generation;
	}
	mutex_unlock(&anchor->lock);
	return error;
}
#endif

void nfsd_ffv2_net_init(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	mutex_init(&anchor->lock);
	anchor->net_state = NFSD_FFV2_NET_LIVE;
	anchor->service_state = NFSD_FFV2_SERVICE_DOWN;
	anchor->next_generation = 1;
	anchor->active = NULL;
	anchor->retiring = NULL;
}

void nfsd_ffv2_net_pre_exit(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;

	mutex_lock(&anchor->lock);
	anchor->net_state = NFSD_FFV2_NET_EXITING;
	anchor->service_state = NFSD_FFV2_SERVICE_STOPPING;
	generation = nfsd_ffv2_retire_begin_locked(anchor);
	mutex_unlock(&anchor->lock);

	nfsd_ffv2_retire_finish(anchor, generation, true);
}

void nfsd_ffv2_net_destroy(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	mutex_lock(&anchor->lock);
	WARN_ON_ONCE(anchor->net_state != NFSD_FFV2_NET_EXITING);
	WARN_ON_ONCE(anchor->service_state != NFSD_FFV2_SERVICE_STOPPING);
	WARN_ON_ONCE(anchor->active);
	WARN_ON_ONCE(anchor->retiring);
	mutex_unlock(&anchor->lock);
	mutex_destroy(&anchor->lock);
}

void nfsd_ffv2_service_up(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	lockdep_assert_held(&nfsd_mutex);
	mutex_lock(&anchor->lock);
	if (anchor->net_state == NFSD_FFV2_NET_LIVE &&
	    anchor->service_state == NFSD_FFV2_SERVICE_DOWN)
		anchor->service_state = NFSD_FFV2_SERVICE_UP;
	mutex_unlock(&anchor->lock);
}

struct nfsd_ffv2_generation *
nfsd_ffv2_service_stop_begin(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation = NULL;

	lockdep_assert_held(&nfsd_mutex);
	mutex_lock(&anchor->lock);
	if (anchor->service_state == NFSD_FFV2_SERVICE_UP) {
		anchor->service_state = NFSD_FFV2_SERVICE_STOPPING;
		generation = nfsd_ffv2_retire_begin_locked(anchor);
	}
	mutex_unlock(&anchor->lock);
	return generation;
}

void nfsd_ffv2_service_stop_finish(struct nfsd_net *nn,
				   struct nfsd_ffv2_generation *generation)
{
	lockdep_assert_held(&nfsd_mutex);
	nfsd_ffv2_retire_finish(&nn->ffv2, generation, false);
}

void nfsd_ffv2_service_down(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	lockdep_assert_held(&nfsd_mutex);
	mutex_lock(&anchor->lock);
	if (anchor->net_state == NFSD_FFV2_NET_LIVE)
		anchor->service_state = NFSD_FFV2_SERVICE_DOWN;
	mutex_unlock(&anchor->lock);
}

bool nfsd_ffv2_requested_zero_threads(int n, const int *nthreads,
				      unsigned int nrpools)
{
	unsigned int i;

	if (n <= 0)
		return false;
	for (i = 0; i < min_t(unsigned int, n, nrpools); i++)
		if (nthreads[i])
			return false;
	return true;
}

int nfsd_ffv2_register(struct nfsd_net *nn)
{
	lockdep_assert_held(&nfsd_mutex);
	(void)nn;
	return -EOPNOTSUPP;
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
int nfsd_ffv2_test_publish(struct nfsd_net *nn, void *payload,
			   void (*release)(void *), u64 *generation_id)
{
	struct nfsd_ffv2_generation *generation;
	int error;

	lockdep_assert_held(&nfsd_mutex);
	generation = nfsd_ffv2_generation_alloc(payload, release);
	if (!generation)
		return -ENOMEM;
	error = nfsd_ffv2_publish(&nn->ffv2, generation, generation_id);
	if (error)
		generation->payload = NULL;
	nfsd_ffv2_generation_put(generation);
	return error;
}

int nfsd_ffv2_test_admit(struct nfsd_net *nn,
			 struct nfsd_ffv2_admission *admission)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	int error = 0;

	INIT_LIST_HEAD(&admission->node);
	admission->generation = NULL;
	admission->task = NULL;
	mutex_lock(&anchor->lock);
	generation = anchor->active;
	if (anchor->net_state != NFSD_FFV2_NET_LIVE ||
	    anchor->service_state != NFSD_FFV2_SERVICE_UP || !generation) {
		error = -ESHUTDOWN;
	} else {
		refcount_inc(&generation->ref);
		atomic_inc(&generation->admitted);
		admission->generation = generation;
		admission->task = current;
		spin_lock(&generation->admissions_lock);
		list_add(&admission->node, &generation->admissions);
		spin_unlock(&generation->admissions_lock);
	}
	mutex_unlock(&anchor->lock);
	return error;
}

void nfsd_ffv2_test_complete(struct nfsd_ffv2_admission *admission)
{
	struct nfsd_ffv2_generation *generation = admission->generation;

	spin_lock(&generation->admissions_lock);
	list_del_init(&admission->node);
	spin_unlock(&generation->admissions_lock);
	admission->generation = NULL;
	if (atomic_dec_and_test(&generation->admitted))
		wake_up_all(&generation->admitted_wait);
	nfsd_ffv2_generation_put(generation);
}

static bool
nfsd_ffv2_generation_has_task(struct nfsd_ffv2_generation *generation,
			      struct task_struct *task)
{
	struct nfsd_ffv2_admission *admission;
	bool found = false;

	spin_lock(&generation->admissions_lock);
	list_for_each_entry(admission, &generation->admissions, node) {
		if (admission->task == task) {
			found = true;
			break;
		}
	}
	spin_unlock(&generation->admissions_lock);
	return found;
}

int nfsd_ffv2_test_unregister(struct nfsd_net *nn, u64 generation_id)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	int error = 0;

	lockdep_assert_held(&nfsd_mutex);
	mutex_lock(&anchor->lock);
	generation = anchor->active;
	if (!generation ||
	    generation->identity->generation != generation_id)
		generation = anchor->retiring;
	if (!generation ||
	    generation->identity->generation != generation_id) {
		error = -ENOENT;
		generation = NULL;
	} else if (nfsd_ffv2_generation_has_task(generation, current)) {
		error = -EDEADLK;
		generation = NULL;
	} else if (generation == anchor->active) {
		generation = nfsd_ffv2_retire_begin_locked(anchor);
	} else {
		refcount_inc(&generation->ref);
	}
	mutex_unlock(&anchor->lock);
	if (error)
		return error;
	mutex_unlock(&nfsd_mutex);
	nfsd_ffv2_retire_finish(anchor, generation, true);
	mutex_lock(&nfsd_mutex);
	return error;
}

bool
nfsd_ffv2_test_generation_retired(struct nfsd_ffv2_generation *generation)
{
	/* Pair with retirement publication before dereferencing an identity. */
	return smp_load_acquire(&generation->identity->state) ==
			NFSD_FFV2_IDENTITY_RETIRED;
}

bool
nfsd_ffv2_test_admission_retired(struct nfsd_ffv2_admission *admission)
{
	return nfsd_ffv2_test_generation_retired(admission->generation);
}

unsigned int nfsd_ffv2_test_refcount(struct nfsd_ffv2_admission *admission)
{
	return refcount_read(&admission->generation->ref);
}
#endif
