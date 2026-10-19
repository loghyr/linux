// SPDX-License-Identifier: GPL-2.0-only
#include <linux/completion.h>
#include <linux/lockdep.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/sunrpc/svc_xprt.h>
#include <linux/wait.h>

#include "ffv2.h"
#include "export.h"
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
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	atomic_t			test_waiters;
#endif
	void				*payload;
	void				(*release)(void *payload);
};

static bool nfsd_ffv2_anchor_get(struct nfsd_ffv2_anchor *anchor)
{
	return refcount_inc_not_zero(&anchor->ref);
}

static void nfsd_ffv2_anchor_put(struct nfsd_ffv2_anchor *anchor)
{
	if (refcount_dec_and_test(&anchor->ref))
		complete(&anchor->released);
}

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
static atomic_t nfsd_ffv2_start_failure;

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
	atomic_set(&generation->test_waiters, 0);
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

static void nfsd_ffv2_wait_admitted(struct nfsd_ffv2_generation *generation)
{
	DEFINE_WAIT(wait);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	bool reported = false;
#endif

	for (;;) {
		prepare_to_wait(&generation->admitted_wait, &wait,
				TASK_UNINTERRUPTIBLE);
		if (!atomic_read(&generation->admitted))
			break;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
		if (!reported) {
			atomic_inc(&generation->test_waiters);
			reported = true;
		}
#endif
		schedule();
	}
	finish_wait(&generation->admitted_wait, &wait);
}

static void nfsd_ffv2_retire_finish(struct nfsd_ffv2_anchor *anchor,
				    struct nfsd_ffv2_generation *generation)
{
	bool unpublished = false;

	if (!generation)
		return;

	nfsd_ffv2_wait_admitted(generation);

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
	} else {
		wait_for_completion(&generation->retired);
	}

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
	    anchor->service_state == NFSD_FFV2_SERVICE_STOPPING ||
	    anchor->service_state == NFSD_FFV2_SERVICE_DRAIN_FAILED) {
		error = -ESHUTDOWN;
	} else if (anchor->service_state == NFSD_FFV2_SERVICE_DOWN) {
		error = -ENXIO;
	} else if (anchor->active || anchor->retiring) {
		error = -EBUSY;
	} else if (!anchor->next_generation ||
		   anchor->next_generation == U64_MAX) {
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

/**
 * nfsd_ffv2_net_init - initialize the namespace anchor
 * @nn: namespace with no FFv2 users
 *
 * Context: Called before the namespace is exposed. Does not sleep.
 */
void nfsd_ffv2_net_init(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	refcount_set(&anchor->ref, 1);
	init_completion(&anchor->released);
	mutex_init(&anchor->lock);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	anchor->test_destroy_waiting = NULL;
#endif
	anchor->net_state = NFSD_FFV2_NET_LIVE;
	anchor->service_state = NFSD_FFV2_SERVICE_DOWN;
	anchor->next_generation = 1;
	anchor->active = NULL;
	anchor->retiring = NULL;
}

static void nfsd_ffv2_updates_set_open(struct nfsd_ffv2_participant *p,
				       bool open)
{
	spin_lock(&p->update_lock);
	if (open && p->updates_closing)
		goto out;
	if (p->updates_open != open) {
		p->updates_open = open;
		if (!++p->update_epoch)
			++p->update_epoch;
	}
out:
	spin_unlock(&p->update_lock);
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
void nfsd_ffv2_test_try_reopen_updates(struct nfsd_net *nn)
{
	nfsd_ffv2_updates_set_open(&nn->ffv2_participant, true);
}
#endif

static void nfsd_ffv2_updates_close_permanent(struct nfsd_ffv2_participant *p)
{
	spin_lock(&p->update_lock);
	p->updates_closing = true;
	if (p->updates_open) {
		p->updates_open = false;
		if (!++p->update_epoch)
			++p->update_epoch;
	}
	spin_unlock(&p->update_lock);
}

static void nfsd_ffv2_updates_wait(struct nfsd_ffv2_participant *p)
{
	wait_event(p->update_wait, !READ_ONCE(p->update_count));
}

int nfsd_ffv2_participant_register(struct nfsd_net *nn)
{
	struct nfsd_ffv2_participant *p = &nn->ffv2_participant;

	spin_lock_init(&p->update_lock);
	init_waitqueue_head(&p->update_wait);
	p->update_count = 0;
	p->update_epoch = 1;
	p->updates_open = true;
	p->updates_closing = false;
	mutex_init(&p->inventory_lock);
	INIT_LIST_HEAD(&p->inventory);
	init_waitqueue_head(&p->inventory_wait);
	p->inventory_count = 0;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	p->test_update_validated = NULL;
	p->test_update_continue = NULL;
	p->test_inventory_wait_entered = NULL;
	p->test_inventory_wait_done = NULL;
	p->test_inventory_postwait_entered = NULL;
	p->test_inventory_postwait_continue = NULL;
	p->test_inventory_lock_entered = NULL;
	p->test_inventory_destroy_continue = NULL;
	p->test_inventory_task = NULL;
	p->test_inventory_wait_count = NULL;
	p->test_release_count_zero = NULL;
	p->test_release_continue = NULL;
#endif
	WRITE_ONCE(p->attached, true);
	return 0;
}

void nfsd_ffv2_participant_detach_begin(struct nfsd_net *nn)
{
	struct nfsd_ffv2_participant *p = &nn->ffv2_participant;

	nfsd_ffv2_updates_close_permanent(p);
	nfsd_ffv2_updates_wait(p);
	WRITE_ONCE(p->attached, false);
}

void nfsd_ffv2_participant_detach_finish(struct nfsd_net *nn)
{
	struct nfsd_ffv2_participant *p = &nn->ffv2_participant;

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (READ_ONCE(p->test_inventory_wait_count))
		*READ_ONCE(p->test_inventory_wait_count) = p->inventory_count;
	if (READ_ONCE(p->test_inventory_wait_entered))
		complete(READ_ONCE(p->test_inventory_wait_entered));
#endif
	wait_event(p->inventory_wait, !READ_ONCE(p->inventory_count));
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (READ_ONCE(p->test_inventory_postwait_entered)) {
		get_task_struct(current);
		*READ_ONCE(p->test_inventory_task) = current;
		complete(READ_ONCE(p->test_inventory_postwait_entered));
		wait_for_completion(READ_ONCE(p->test_inventory_postwait_continue));
		complete(READ_ONCE(p->test_inventory_lock_entered));
	}
#endif
	/* The final put can publish zero before dropping inventory_lock. */
	mutex_lock(&p->inventory_lock);
	mutex_unlock(&p->inventory_lock);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (READ_ONCE(p->test_inventory_wait_done))
		complete(READ_ONCE(p->test_inventory_wait_done));
	if (READ_ONCE(p->test_inventory_destroy_continue))
		wait_for_completion(READ_ONCE(p->test_inventory_destroy_continue));
#endif
	mutex_destroy(&p->inventory_lock);
}

static void nfsd_ffv2_export_update_put(struct nfsd_ffv2_export_update *update)
{
	struct nfsd_ffv2_participant *p = update->participant;
	bool wake;

	if (!update->admitted)
		return;
	spin_lock(&p->update_lock);
	if (WARN_ON_ONCE(!p->update_count)) {
		spin_unlock(&p->update_lock);
		return;
	}
	wake = !--p->update_count;
	update->admitted = false;
	spin_unlock(&p->update_lock);
	if (wake)
		wake_up_all(&p->update_wait);
}

int nfsd_ffv2_export_update_begin(struct svc_export *exp,
				  struct nfsd_ffv2_export_update *update)
{
	struct nfsd_net *nn = net_generic(exp->cd->net, nfsd_net_id);
	struct nfsd_ffv2_participant *p = &nn->ffv2_participant;
	int error = 0;

	memset(update, 0, sizeof(*update));
	spin_lock(&p->update_lock);
	if (!p->updates_open || !READ_ONCE(p->attached)) {
		error = -ESHUTDOWN;
	} else {
		p->update_count++;
		update->participant = p;
		update->epoch = p->update_epoch;
		update->admitted = true;
	}
	spin_unlock(&p->update_lock);
	return error;
}

int nfsd_ffv2_export_update_validate(struct nfsd_ffv2_export_update *update)
{
	struct nfsd_ffv2_participant *p = update->participant;
	int error = 0;

	spin_lock(&p->update_lock);
	if (!p->updates_open || p->update_epoch != update->epoch)
		error = -ESHUTDOWN;
	spin_unlock(&p->update_lock);
	return error;
}

void nfsd_ffv2_export_update_end(struct svc_export *exp,
				 struct nfsd_ffv2_export_update *update)
{
	struct nfsd_ffv2_participant *p = update->participant;

	mutex_lock(&p->inventory_lock);
	if (!test_bit(CACHE_NEGATIVE, &exp->h.flags) &&
	    !exp->ex_ffv2_listed) {
		exp->ex_ffv2_path = exp->ex_path;
		path_get(&exp->ex_ffv2_path);
		exp->ex_ffv2_participant = p;
		exp->ex_ffv2_listed = true;
		list_add_tail(&exp->ex_ffv2_inventory, &p->inventory);
		p->inventory_count++;
	}
	mutex_unlock(&p->inventory_lock);
	nfsd_ffv2_export_update_put(update);
}

void nfsd_ffv2_export_update_abort(struct nfsd_ffv2_export_update *update)
{
	nfsd_ffv2_export_update_put(update);
}

void nfsd_ffv2_export_release(struct svc_export *exp)
{
	struct nfsd_ffv2_participant *p = exp->ex_ffv2_participant;

	if (!p)
		return;
	mutex_lock(&p->inventory_lock);
	if (exp->ex_ffv2_listed) {
		list_del_init(&exp->ex_ffv2_inventory);
		exp->ex_ffv2_listed = false;
		exp->ex_ffv2_participant = NULL;
		p->inventory_count--;
		path_put(&exp->ex_ffv2_path);
		if (!p->inventory_count)
			wake_up_all(&p->inventory_wait);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
		if (!p->inventory_count && READ_ONCE(p->test_release_count_zero)) {
			complete(READ_ONCE(p->test_release_count_zero));
			wait_for_completion(READ_ONCE(p->test_release_continue));
		}
#endif
	}
	mutex_unlock(&p->inventory_lock);
}

/**
 * nfsd_ffv2_net_pre_exit - fence and drain a departing namespace
 * @nn: namespace whose anchor remains allocated
 *
 * Context: Sleeps. Called without nfsd_mutex before net_destroy.
 */
void nfsd_ffv2_net_pre_exit(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;

	if (WARN_ON_ONCE(!nfsd_ffv2_anchor_get(anchor)))
		return;
	if (READ_ONCE(nn->ffv2_participant.attached)) {
		nfsd_ffv2_updates_close_permanent(&nn->ffv2_participant);
		nfsd_ffv2_updates_wait(&nn->ffv2_participant);
	}
	mutex_lock(&anchor->lock);
	/* Pair with admission's lockless rejection before taking ->lock. */
	smp_store_release(&anchor->net_state, NFSD_FFV2_NET_EXITING);
	anchor->service_state = NFSD_FFV2_SERVICE_STOPPING;
	generation = nfsd_ffv2_retire_begin_locked(anchor);
	mutex_unlock(&anchor->lock);

	nfsd_ffv2_retire_finish(anchor, generation);
	nfsd_ffv2_anchor_put(anchor);
}

/**
 * nfsd_ffv2_net_destroy - release the namespace anchor
 * @nn: namespace already fenced by net_pre_exit
 *
 * Context: Sleeps until all anchor holders release their references.
 */
void nfsd_ffv2_net_destroy(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	mutex_lock(&anchor->lock);
	WARN_ON_ONCE(anchor->net_state != NFSD_FFV2_NET_EXITING);
	WARN_ON_ONCE(anchor->service_state != NFSD_FFV2_SERVICE_STOPPING);
	WARN_ON_ONCE(anchor->active);
	WARN_ON_ONCE(anchor->retiring);
	mutex_unlock(&anchor->lock);
	nfsd_ffv2_anchor_put(anchor);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (READ_ONCE(anchor->test_destroy_waiting))
		complete(READ_ONCE(anchor->test_destroy_waiting));
#endif
	wait_for_completion(&anchor->released);
	mutex_destroy(&anchor->lock);
}

/**
 * nfsd_ffv2_service_up - open service admission
 * @nn: namespace whose service is starting
 *
 * Context: Sleeps. Caller holds nfsd_mutex.
 * Return: 0 on success, -ESHUTDOWN at namespace exit, or -EAGAIN during drain.
 */
int nfsd_ffv2_service_up(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	int error = 0;

	lockdep_assert_held(&nfsd_mutex);
	if (WARN_ON_ONCE(!nfsd_ffv2_anchor_get(anchor)))
		return -ESHUTDOWN;
	mutex_lock(&anchor->lock);
	if (anchor->net_state != NFSD_FFV2_NET_LIVE)
		error = -ESHUTDOWN;
	else if (anchor->service_state == NFSD_FFV2_SERVICE_STOPPING ||
		 anchor->service_state == NFSD_FFV2_SERVICE_DRAIN_FAILED)
		error = -EAGAIN;
	else if (anchor->service_state == NFSD_FFV2_SERVICE_DOWN)
		anchor->service_state = NFSD_FFV2_SERVICE_UP;
	mutex_unlock(&anchor->lock);
	if (!error)
		nfsd_ffv2_updates_set_open(&nn->ffv2_participant, true);
	nfsd_ffv2_anchor_put(anchor);
	return error;
}

/**
 * nfsd_ffv2_service_stop_begin - close service admission before worker drain
 * @nn: namespace whose service is stopping
 *
 * Context: Sleeps. Caller holds nfsd_mutex.
 * Return: A retirement reference, or NULL when no generation needs retirement.
 * Consume it with nfsd_ffv2_service_stop_finish(),
 * nfsd_ffv2_service_stop_failed(), or nfsd_ffv2_service_stop_put().
 */
struct nfsd_ffv2_generation *
nfsd_ffv2_service_stop_begin(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation = NULL;

	lockdep_assert_held(&nfsd_mutex);
	if (WARN_ON_ONCE(!nfsd_ffv2_anchor_get(anchor)))
		return NULL;
	nfsd_ffv2_updates_set_open(&nn->ffv2_participant, false);
	mutex_lock(&anchor->lock);
	if (anchor->service_state == NFSD_FFV2_SERVICE_UP)
		anchor->service_state = NFSD_FFV2_SERVICE_STOPPING;
	else if (anchor->service_state == NFSD_FFV2_SERVICE_DRAIN_FAILED)
		anchor->service_state = NFSD_FFV2_SERVICE_STOPPING;
	if (anchor->service_state == NFSD_FFV2_SERVICE_STOPPING)
		generation = nfsd_ffv2_retire_begin_locked(anchor);
	mutex_unlock(&anchor->lock);
	nfsd_ffv2_anchor_put(anchor);
	return generation;
}

/**
 * nfsd_ffv2_service_stop_finish - drain and retire a stopped generation
 * @nn: namespace that owns the generation
 * @generation: retirement reference to consume, or NULL
 *
 * Context: Sleeps. Called after worker drain without nfsd_mutex.
 */
void nfsd_ffv2_service_stop_finish(struct nfsd_net *nn,
				   struct nfsd_ffv2_generation *generation)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	lockdep_assert_not_held(&nfsd_mutex);
	if (WARN_ON_ONCE(!nfsd_ffv2_anchor_get(anchor))) {
		if (generation)
			nfsd_ffv2_generation_put(generation);
		return;
	}
	nfsd_ffv2_updates_wait(&nn->ffv2_participant);
	nfsd_ffv2_retire_finish(anchor, generation);
	nfsd_ffv2_anchor_put(anchor);
}

/**
 * nfsd_ffv2_service_stop_failed - fence admission after failed drain
 * @nn: namespace whose workers failed to drain
 * @generation: retirement reference to consume, or NULL
 *
 * Context: Sleeps. Caller holds nfsd_mutex.
 */
void nfsd_ffv2_service_stop_failed(struct nfsd_net *nn,
				   struct nfsd_ffv2_generation *generation)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	bool reopen = false;

	lockdep_assert_held(&nfsd_mutex);
	if (WARN_ON_ONCE(!nfsd_ffv2_anchor_get(anchor)))
		goto out_put;
	mutex_lock(&anchor->lock);
	if (anchor->net_state == NFSD_FFV2_NET_LIVE &&
	    anchor->service_state == NFSD_FFV2_SERVICE_STOPPING) {
		anchor->service_state = NFSD_FFV2_SERVICE_DRAIN_FAILED;
		reopen = true;
	}
	mutex_unlock(&anchor->lock);
	if (reopen)
		nfsd_ffv2_updates_set_open(&nn->ffv2_participant, true);
	nfsd_ffv2_anchor_put(anchor);
out_put:
	nfsd_ffv2_service_stop_put(generation);
}

/**
 * nfsd_ffv2_service_stop_put - drop an unused retirement reference
 * @generation: retirement reference to consume, or NULL
 *
 * Context: Does not sleep.
 */
void nfsd_ffv2_service_stop_put(struct nfsd_ffv2_generation *generation)
{
	if (generation)
		nfsd_ffv2_generation_put(generation);
}

/**
 * nfsd_ffv2_service_down - finish service shutdown
 * @nn: namespace after payload retirement
 *
 * Context: Sleeps. Caller holds nfsd_mutex.
 */
void nfsd_ffv2_service_down(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	bool reopen = false;

	lockdep_assert_held(&nfsd_mutex);
	if (WARN_ON_ONCE(!nfsd_ffv2_anchor_get(anchor)))
		return;
	mutex_lock(&anchor->lock);
	if (anchor->net_state == NFSD_FFV2_NET_LIVE) {
		anchor->service_state = NFSD_FFV2_SERVICE_DOWN;
		reopen = true;
	}
	mutex_unlock(&anchor->lock);
	if (reopen)
		nfsd_ffv2_updates_set_open(&nn->ffv2_participant, true);
	nfsd_ffv2_anchor_put(anchor);
}

/**
 * nfsd_ffv2_requested_zero_threads - classify a service-stop request
 * @n: number of requested pool counts
 * @nthreads: array of n requested thread counts
 * @nrpools: number of existing service pools
 *
 * Context: Does not sleep.
 * Return: True for a positive request with only zero counts for existing pools.
 */
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

static int
nfsd_ffv2_admit_generation(struct nfsd_net *nn,
			   struct nfsd_ffv2_admission *admission)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	int error = 0;

	INIT_LIST_HEAD(&admission->node);
	admission->anchor = NULL;
	admission->generation = NULL;
	admission->task = NULL;
	if (!nfsd_ffv2_anchor_get(anchor))
		return -ESHUTDOWN;
	/* EXITING is published before the owner reference is released. */
	if (smp_load_acquire(&anchor->net_state) != NFSD_FFV2_NET_LIVE) {
		nfsd_ffv2_anchor_put(anchor);
		return -ESHUTDOWN;
	}

	mutex_lock(&anchor->lock);
	generation = anchor->active;
	if (anchor->net_state != NFSD_FFV2_NET_LIVE ||
	    anchor->service_state != NFSD_FFV2_SERVICE_UP || !generation) {
		error = -ESHUTDOWN;
	} else {
		refcount_inc(&generation->ref);
		atomic_inc(&generation->admitted);
		admission->anchor = anchor;
		admission->generation = generation;
		admission->task = current;
		spin_lock(&generation->admissions_lock);
		list_add(&admission->node, &generation->admissions);
		spin_unlock(&generation->admissions_lock);
	}
	mutex_unlock(&anchor->lock);
	if (error)
		nfsd_ffv2_anchor_put(anchor);
	return error;
}

/**
 * nfsd_ffv2_admit - hold the active generation for one NFSD request
 * @rqstp: current NFSD worker request with a transport
 * @admission: unused caller-owned record that remains live until completion
 *
 * Context: Sleeps. Called by the NFSD worker that owns rqstp.
 * Return: 0 with owned anchor and generation references, or a negative errno.
 */
int nfsd_ffv2_admit(struct svc_rqst *rqstp,
		    struct nfsd_ffv2_admission *admission)
{
	struct nfsd_net *nn;

	if (nfsd_current_rqst() != rqstp || !rqstp->rq_xprt)
		return -EOPNOTSUPP;
	nn = net_generic(rqstp->rq_xprt->xpt_net, nfsd_net_id);
	return nfsd_ffv2_admit_generation(nn, admission);
}

/**
 * nfsd_ffv2_complete - consume an admission once
 * @admission: admitted record or an already completed record
 *
 * Context: Does not sleep. Serial or concurrent repeat completion is harmless.
 */
void nfsd_ffv2_complete(struct nfsd_ffv2_admission *admission)
{
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_anchor *anchor;

	generation = xchg(&admission->generation, NULL);
	if (!generation)
		return;
	anchor = admission->anchor;

	spin_lock(&generation->admissions_lock);
	list_del_init(&admission->node);
	spin_unlock(&generation->admissions_lock);
	admission->anchor = NULL;
	admission->task = NULL;
	if (atomic_dec_and_test(&generation->admitted))
		wake_up_all(&generation->admitted_wait);
	nfsd_ffv2_generation_put(generation);
	nfsd_ffv2_anchor_put(anchor);
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
/**
 * nfsd_ffv2_test_publish - publish a synthetic generation
 * @nn: live namespace with its service up
 * @payload: caller-owned payload transferred only on success
 * @release: callback that consumes payload after admitted work drains
 * @generation_id: optional output for the nonzero generation number
 *
 * Context: Sleeps. Caller holds nfsd_mutex.
 * Return: 0 on publication, or a negative errno without consuming payload.
 */
int nfsd_ffv2_test_publish(struct nfsd_net *nn, void *payload,
			   void (*release)(void *), u64 *generation_id)
{
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	int error;

	lockdep_assert_held(&nfsd_mutex);
	if (!nfsd_ffv2_anchor_get(anchor))
		return -ESHUTDOWN;
	generation = nfsd_ffv2_generation_alloc(payload, release);
	if (!generation) {
		nfsd_ffv2_anchor_put(anchor);
		return -ENOMEM;
	}
	error = nfsd_ffv2_publish(anchor, generation, generation_id);
	if (error)
		generation->payload = NULL;
	nfsd_ffv2_generation_put(generation);
	nfsd_ffv2_anchor_put(anchor);
	return error;
}

/**
 * nfsd_ffv2_test_admit - admit synthetic work through the lifecycle gate
 * @nn: live namespace with a published generation
 * @admission: unused caller-owned record retained until completion
 *
 * Context: Sleeps.
 * Return: 0 with owned anchor and generation references, or a negative errno.
 */
int nfsd_ffv2_test_admit(struct nfsd_net *nn,
			 struct nfsd_ffv2_admission *admission)
{
	return nfsd_ffv2_admit_generation(nn, admission);
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

/**
 * nfsd_ffv2_test_unregister - retire one synthetic generation
 * @nn: namespace whose anchor remains allocated
 * @generation_id: generation to retire
 *
 * Context: Sleeps. Drops and reacquires the caller-held nfsd_mutex.
 * Return: 0 after retirement, -EDEADLK if the caller is admitted, or another errno.
 */
int nfsd_ffv2_test_unregister(struct nfsd_net *nn, u64 generation_id)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	int error = 0;

	lockdep_assert_held(&nfsd_mutex);
	if (!nfsd_ffv2_anchor_get(anchor))
		return -ESHUTDOWN;
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
	if (error) {
		nfsd_ffv2_anchor_put(anchor);
		return error;
	}
	mutex_unlock(&nfsd_mutex);
	nfsd_ffv2_retire_finish(anchor, generation);
	mutex_lock(&nfsd_mutex);
	nfsd_ffv2_anchor_put(anchor);
	return error;
}

/**
 * nfsd_ffv2_test_generation_retired - observe a generation tombstone
 * @generation: generation kept alive by the caller
 *
 * Context: Does not sleep.
 * Return: True after retirement begins.
 */
bool
nfsd_ffv2_test_generation_retired(struct nfsd_ffv2_generation *generation)
{
	/* Pair with retirement publication before dereferencing an identity. */
	return smp_load_acquire(&generation->identity->state) ==
			NFSD_FFV2_IDENTITY_RETIRED;
}

/**
 * nfsd_ffv2_test_admission_retired - observe an admitted generation tombstone
 * @admission: admission whose completion remains blocked
 *
 * Context: Does not sleep.
 * Return: True after the admitted generation begins retirement.
 */
bool
nfsd_ffv2_test_admission_retired(struct nfsd_ffv2_admission *admission)
{
	return nfsd_ffv2_test_generation_retired(admission->generation);
}

/**
 * nfsd_ffv2_test_waiters - read retirement wait entries
 * @admission: admission whose completion remains blocked
 *
 * Context: Does not sleep.
 * Return: Number of retirement callers that observed outstanding admissions.
 */
unsigned int nfsd_ffv2_test_waiters(struct nfsd_ffv2_admission *admission)
{
	return atomic_read(&admission->generation->test_waiters);
}

/**
 * nfsd_ffv2_test_anchor_refcount - read namespace anchor holders
 * @nn: namespace whose anchor remains allocated
 *
 * Context: Does not sleep.
 * Return: Snapshot of the anchor reference count.
 */
unsigned int nfsd_ffv2_test_anchor_refcount(struct nfsd_net *nn)
{
	return refcount_read(&nn->ffv2.ref);
}

/**
 * nfsd_ffv2_test_anchor_hold - hold an anchor across namespace destruction
 * @nn: namespace whose anchor remains allocated
 *
 * Context: Does not sleep.
 * Return: True if a reference was acquired; pair success with anchor_release.
 */
bool nfsd_ffv2_test_anchor_hold(struct nfsd_net *nn)
{
	return nfsd_ffv2_anchor_get(&nn->ffv2);
}

/**
 * nfsd_ffv2_test_anchor_release - drop a fixture-owned anchor reference
 * @nn: namespace pinned by anchor_hold
 *
 * Context: Does not sleep.
 */
void nfsd_ffv2_test_anchor_release(struct nfsd_net *nn)
{
	nfsd_ffv2_anchor_put(&nn->ffv2);
}

/**
 * nfsd_ffv2_test_destroy_waiting - observe namespace anchor destruction
 * @nn: namespace whose destruction has not started
 * @entered: completion kept alive until destruction returns
 *
 * Context: Does not sleep. Arm before the destruction worker starts.
 */
void nfsd_ffv2_test_destroy_waiting(struct nfsd_net *nn,
				    struct completion *entered)
{
	WRITE_ONCE(nn->ffv2.test_destroy_waiting, entered);
}

/**
 * nfsd_ffv2_test_set_start_failure - arm a test-only service-start failure
 * @fail: whether the next successful worker adjustment should fail
 *
 * Context: does not sleep.
 */
void nfsd_ffv2_test_set_start_failure(bool fail)
{
	atomic_set(&nfsd_ffv2_start_failure, fail);
}

/**
 * nfsd_ffv2_test_start_failure - consume a test-only service-start failure
 *
 * Context: does not sleep.
 * Return: true when the current worker adjustment should report failure.
 */
bool nfsd_ffv2_test_start_failure(void)
{
	return atomic_xchg(&nfsd_ffv2_start_failure, 0);
}
#endif
