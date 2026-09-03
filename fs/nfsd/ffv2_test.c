// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>
#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/fs_struct.h>
#include <linux/iopoll.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/sunrpc/gss_api.h>
#include <linux/sunrpc/svcsock.h>
#include <linux/sunrpc/svc_xprt.h>
#include <net/net_namespace.h>

#include "ffv2.h"
#include "ffv2_trust.h"
#include "export.h"
#include "filecache.h"
#include "nfsd.h"
#include "nfsfh.h"
#include "netns.h"
#include "vfs.h"
#include "xdr4.h"

struct nfsd_ffv2_unregister_ctx {
	struct nfsd_net	*nn;
	u64		generation;
	int		result;
	struct completion done;
};

struct nfsd_ffv2_object_unregister_ctx {
	struct nfsd_net	*nn;
	u64		generation;
	u8		object_uuid[16];
	int		result;
	struct completion done;
};

struct nfsd_ffv2_exit_ctx {
	struct nfsd_net	*nn;
	struct completion done;
};

struct nfsd_ffv2_worker_ctx {
	struct net		*net;
	refcount_t		ref;
	struct completion	released;
	atomic_t		claimed;
	struct completion	run;
	struct completion	admitted;
	struct completion	allow_complete;
	struct completion	returned;
	struct nfsd_ffv2_admission	*admission;
	int			admit_result;
};

struct nfsd_ffv2_release_ctx {
	atomic_t		releases;
	struct completion	started;
	struct completion	proceed;
};

struct nfsd_ffv2_shutdown_ctx {
	struct net		*net;
	struct completion	done;
};

struct nfsd_ffv2_update_stop_ctx {
	struct nfsd_net		*nn;
	struct nfsd_ffv2_generation *generation;
	struct completion	done;
};

struct nfsd_ffv2_transition_publish_ctx {
	struct nfsd_net		*owner;
	struct nfsd_ffv2_export_update *registration;
	struct nfsd_ffv2_object *object;
	struct knfsd_fh		*outer_fh;
	struct svc_export	*template;
	struct svc_export	*expected;
	const struct path	*root;
	const u8		*store_uuid;
	const u8		*binding_token;
	const struct cred	*cred;
	u64			control_root;
	u64			generation_id;
	int			result;
	struct completion	done;
};

static DEFINE_SPINLOCK(nfsd_ffv2_worker_lock);
static struct nfsd_ffv2_worker_ctx *nfsd_ffv2_worker_ctx;

static void nfsd_ffv2_test_thread_park(void);

static int nfsd_ffv2_update_stop_thread(void *data)
{
	struct nfsd_ffv2_update_stop_ctx *ctx = data;

	nfsd_ffv2_service_stop_finish(ctx->nn, ctx->generation);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static int nfsd_ffv2_transition_publish_thread(void *data)
{
	struct nfsd_ffv2_transition_publish_ctx *ctx = data;

	ctx->result = nfsd_ffv2_test_transition_publish(ctx->owner,
							ctx->registration,
							ctx->object,
							ctx->outer_fh,
							ctx->template,
							ctx->expected,
							ctx->root,
							ctx->store_uuid,
							ctx->binding_token,
							ctx->cred,
							ctx->control_root,
							&ctx->generation_id);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static void nfsd_ffv2_worker_ctx_put(struct nfsd_ffv2_worker_ctx *ctx)
{
	if (refcount_dec_and_test(&ctx->ref))
		complete(&ctx->released);
}

static struct nfsd_ffv2_worker_ctx *
nfsd_ffv2_worker_ctx_get(struct net *net)
{
	struct nfsd_ffv2_worker_ctx *ctx;

	spin_lock(&nfsd_ffv2_worker_lock);
	ctx = nfsd_ffv2_worker_ctx;
	if (!ctx || ctx->net != net ||
	    !refcount_inc_not_zero(&ctx->ref))
		ctx = NULL;
	spin_unlock(&nfsd_ffv2_worker_lock);
	return ctx;
}

static int
nfsd_ffv2_worker_ctx_install(struct nfsd_ffv2_worker_ctx *ctx,
			     struct net *net)
{
	int error = 0;

	ctx->net = net;
	refcount_set(&ctx->ref, 1);
	init_completion(&ctx->released);
	atomic_set(&ctx->claimed, 0);
	init_completion(&ctx->run);
	init_completion(&ctx->admitted);
	init_completion(&ctx->allow_complete);
	init_completion(&ctx->returned);
	ctx->admit_result = -EINPROGRESS;
	ctx->admission = NULL;

	spin_lock(&nfsd_ffv2_worker_lock);
	if (nfsd_ffv2_worker_ctx)
		error = -EBUSY;
	else
		nfsd_ffv2_worker_ctx = ctx;
	spin_unlock(&nfsd_ffv2_worker_lock);
	return error;
}

static void
nfsd_ffv2_worker_ctx_remove(struct nfsd_ffv2_worker_ctx *ctx)
{
	spin_lock(&nfsd_ffv2_worker_lock);
	if (WARN_ON_ONCE(nfsd_ffv2_worker_ctx != ctx)) {
		spin_unlock(&nfsd_ffv2_worker_lock);
		return;
	}
	nfsd_ffv2_worker_ctx = NULL;
	spin_unlock(&nfsd_ffv2_worker_lock);

	nfsd_ffv2_worker_ctx_put(ctx);
	wait_for_completion(&ctx->released);
}

/**
 * nfsd_ffv2_test_worker - run one admission on a real nfsd worker
 * @rqstp: request context owned by the current nfsd worker
 * @xprt: permanent transport that identifies the worker's network namespace
 *
 * This hook exists only in the private KUnit configuration.  It does not
 * register a provider or make an NFS operation dispatchable.
 */
void nfsd_ffv2_test_worker(struct svc_rqst *rqstp, struct svc_xprt *xprt)
{
	struct nfsd_ffv2_worker_ctx *ctx;
	struct nfsd_ffv2_admission admission = {};

	ctx = nfsd_ffv2_worker_ctx_get(xprt->xpt_net);
	if (!ctx)
		return;
	if (atomic_cmpxchg(&ctx->claimed, 0, 1))
		goto out_put;

	wait_for_completion(&ctx->run);
	if (WARN_ON_ONCE(rqstp->rq_xprt)) {
		ctx->admit_result = -EBUSY;
		goto out_admitted;
	}
	rqstp->rq_xprt = xprt;
	ctx->admit_result = nfsd_ffv2_admit(rqstp, &admission);
	rqstp->rq_xprt = NULL;
	if (!ctx->admit_result)
		WRITE_ONCE(ctx->admission, &admission);
out_admitted:
	complete(&ctx->admitted);
	if (!ctx->admit_result) {
		wait_for_completion(&ctx->allow_complete);
		nfsd_ffv2_complete(&admission);
		WRITE_ONCE(ctx->admission, NULL);
	}
	complete(&ctx->returned);
out_put:
	nfsd_ffv2_worker_ctx_put(ctx);
}

static void nfsd_ffv2_blocking_release(void *payload)
{
	struct nfsd_ffv2_release_ctx *ctx = payload;

	atomic_inc(&ctx->releases);
	complete(&ctx->started);
	wait_for_completion(&ctx->proceed);
}

static bool
nfsd_ffv2_worker_admission_retired(struct nfsd_ffv2_worker_ctx *ctx)
{
	struct nfsd_ffv2_admission *admission = READ_ONCE(ctx->admission);

	return admission && nfsd_ffv2_test_admission_retired(admission);
}

static int nfsd_ffv2_shutdown_thread(void *data)
{
	struct nfsd_ffv2_shutdown_ctx *ctx = data;

	nfsd_shutdown_threads(ctx->net);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static void
nfsd_ffv2_shutdown_ctx_init(struct nfsd_ffv2_shutdown_ctx *ctx,
			    struct net *net)
{
	ctx->net = get_net(net);
	init_completion(&ctx->done);
}

static void nfsd_ffv2_shutdown_ctx_put(struct nfsd_ffv2_shutdown_ctx *ctx)
{
	put_net(ctx->net);
	ctx->net = NULL;
}

static struct task_struct *
nfsd_ffv2_shutdown_thread_start(struct nfsd_ffv2_shutdown_ctx *ctx,
				bool fail)
{
	if (fail)
		return ERR_PTR(-ENOMEM);
	return kthread_run(nfsd_ffv2_shutdown_thread, ctx,
			   "nfsd-ffv2-netns-shutdown-test");
}

static void nfsd_ffv2_count_release(void *payload)
{
	atomic_inc(payload);
}

static int
nfsd_ffv2_start_test_service(struct net *net,
			     struct nfsd_ffv2_worker_ctx *worker)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	bool cleanup = false;
	int threads = 1;
	int error;

	mutex_lock(&nfsd_mutex);
	error = nfsd_create_serv(net);
	if (error)
		goto out_unlock;
	error = svc_xprt_create(nn->nfsd_serv, "tcp", net, PF_INET, 0,
				SVC_SOCK_ANONYMOUS, current_cred());
	if (error < 0)
		goto out_destroy;
	nfsd_vers(nn, 2, NFSD_CLEAR);
	nfsd_vers(nn, 3, NFSD_CLEAR);
	nfsd_vers(nn, 4, NFSD_SET);
	error = nfsd_svc(1, &threads, net, current_cred(), NULL);
	if (error == 1) {
		error = 0;
	} else if (error >= 0) {
		error = -EIO;
	} else if (nn->nfsd_serv) {
		if (worker) {
			complete_all(&worker->run);
			complete_all(&worker->allow_complete);
		}
		cleanup = true;
	}
	goto out_unlock;

out_destroy:
	nfsd_destroy_serv(net);
out_unlock:
	mutex_unlock(&nfsd_mutex);
	if (cleanup) {
		nfsd_shutdown_threads(net);
		mutex_lock(&nfsd_mutex);
		if (WARN_ON_ONCE(nn->nfsd_serv))
			error = -EBUSY;
		mutex_unlock(&nfsd_mutex);
	}
	return error;
}

static struct nfsd_net *nfsd_ffv2_test_net(struct kunit *test)
{
	struct nfsd_net *nn;

	nn = kunit_kzalloc(test, sizeof(*nn), GFP_KERNEL);
	if (!nn)
		return NULL;
	nfsd_ffv2_net_init(nn);
	/*
	 * A zeroed nfsd_net is not a registered participant, but the service
	 * paths under test still take these locks.  Initialise them so
	 * lockdep sees real keys instead of disabling itself on the first
	 * acquisition, which would void lock validation for the whole run.
	 */
	spin_lock_init(&nn->ffv2_participant.update_lock);
	init_waitqueue_head(&nn->ffv2_participant.update_wait);
	mutex_init(&nn->ffv2_participant.inventory_lock);
	init_waitqueue_head(&nn->ffv2_participant.inventory_wait);
	INIT_LIST_HEAD(&nn->ffv2_participant.node);
	INIT_LIST_HEAD(&nn->ffv2_participant.reservations);
	INIT_LIST_HEAD(&nn->ffv2_participant.inventory);
	spin_lock_init(&nn->client_lock);
	return nn;
}

static void nfsd_ffv2_test_net_exit(void *data)
{
	struct nfsd_net *nn = data;

	nfsd_ffv2_net_pre_exit(nn);
	nfsd_ffv2_net_destroy(nn);
}

static void nfsd_ffv2_test_net_destroy(struct kunit *test,
				       struct nfsd_net *nn)
{
	kunit_remove_action(test, nfsd_ffv2_test_net_exit, nn);
	nfsd_ffv2_test_net_exit(nn);
}

static void nfsd_ffv2_test_thread_park(void)
{
	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (!kthread_should_stop())
			schedule();
	}
	__set_current_state(TASK_RUNNING);
}

static int nfsd_ffv2_unregister_thread(void *data)
{
	struct nfsd_ffv2_unregister_ctx *ctx = data;

	mutex_lock(&nfsd_mutex);
	ctx->result = nfsd_ffv2_test_unregister(ctx->nn, ctx->generation);
	mutex_unlock(&nfsd_mutex);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static int nfsd_ffv2_object_unregister_thread(void *data)
{
	struct nfsd_ffv2_object_unregister_ctx *ctx = data;

	mutex_lock(&nfsd_mutex);
	ctx->result = nfsd_ffv2_object_unregister(ctx->nn, ctx->generation,
						  ctx->object_uuid);
	mutex_unlock(&nfsd_mutex);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static bool nfsd_ffv2_test_export_has_context(struct svc_export *exp)
{
	bool has_context;

	rcu_read_lock();
	has_context = rcu_access_pointer(exp->ex_ffv2_context);
	rcu_read_unlock();
	return has_context;
}

static bool
nfsd_ffv2_test_binding_rejected(struct nfsd_net *nn,
				const struct nfsd_ffv2_fh_info *info)
{
	struct nfsd_ffv2_binding *binding = NULL;

	binding = nfsd_ffv2_test_binding_create(nn, info);
	if (!IS_ERR(binding)) {
		nfsd_ffv2_binding_put(binding);
		return false;
	}
	return PTR_ERR(binding) == -ESTALE;
}

static int nfsd_ffv2_exit_thread(void *data)
{
	struct nfsd_ffv2_exit_ctx *ctx = data;

	nfsd_ffv2_net_pre_exit(ctx->nn);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static void nfsd_ffv2_lifecycle_test(struct kunit *test)
{
	struct nfsd_ffv2_admission admission = {};
	struct nfsd_ffv2_generation *generation;
	struct svc_rqst rqstp = {};
	struct nfsd_net *nn;
	atomic_t *releases;
	u64 generation_id = 0;
	int error;

	releases = kunit_kzalloc(test, sizeof(*releases), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, releases);
	atomic_set(releases, 0);
	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_test_net_exit, nn);
	KUNIT_ASSERT_EQ(test, error, 0);
	KUNIT_EXPECT_EQ(test, nn->ffv2.net_state, NFSD_FFV2_NET_LIVE);
	KUNIT_EXPECT_EQ(test, nn->ffv2.service_state,
			NFSD_FFV2_SERVICE_DOWN);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_admit(&rqstp, &admission),
			-EOPNOTSUPP);

	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_test_publish(nn, releases,
				       nfsd_ffv2_count_release, NULL);
	KUNIT_EXPECT_EQ(test, error, -ENXIO);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_service_up(nn), 0);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_register(nn), -EOPNOTSUPP);
	error = nfsd_ffv2_test_publish(nn, releases,
				       nfsd_ffv2_count_release,
				       &generation_id);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_EQ(test, generation_id, 1ULL);
	error = nfsd_ffv2_test_publish(nn, releases,
				       nfsd_ffv2_count_release, NULL);
	KUNIT_EXPECT_EQ(test, error, -EBUSY);
	generation = nfsd_ffv2_service_stop_begin(nn);
	KUNIT_EXPECT_NOT_NULL(test, generation);
	if (generation)
		KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_generation_retired(generation));
	nfsd_ffv2_service_stop_failed(nn, generation);
	KUNIT_EXPECT_EQ(test, nn->ffv2.service_state,
			NFSD_FFV2_SERVICE_DRAIN_FAILED);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_service_up(nn), -EAGAIN);
	generation = nfsd_ffv2_service_stop_begin(nn);
	KUNIT_EXPECT_NOT_NULL(test, generation);
	mutex_unlock(&nfsd_mutex);
	nfsd_ffv2_service_stop_finish(nn, generation);
	mutex_lock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, atomic_read(releases), 1);
	nfsd_ffv2_service_down(nn);

	KUNIT_EXPECT_EQ(test, nfsd_ffv2_service_up(nn), 0);
	error = nfsd_ffv2_test_publish(nn, releases,
				       nfsd_ffv2_count_release,
				       &generation_id);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_EQ(test, generation_id, 2ULL);
	mutex_unlock(&nfsd_mutex);

	nfsd_ffv2_net_pre_exit(nn);
	KUNIT_EXPECT_EQ(test, atomic_read(releases), 2);
	KUNIT_EXPECT_EQ(test, nn->ffv2.net_state, NFSD_FFV2_NET_EXITING);
	KUNIT_EXPECT_EQ(test, nn->ffv2.service_state,
			NFSD_FFV2_SERVICE_STOPPING);

	mutex_lock(&nfsd_mutex);
	nfsd_ffv2_service_down(nn);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_service_up(nn), -ESHUTDOWN);
	error = nfsd_ffv2_test_publish(nn, releases,
				       nfsd_ffv2_count_release, NULL);
	KUNIT_EXPECT_EQ(test, error, -ESHUTDOWN);
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, nn->ffv2.service_state,
			NFSD_FFV2_SERVICE_STOPPING);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_admit(nn, &admission),
			-ESHUTDOWN);
	nfsd_ffv2_test_net_destroy(test, nn);
}

static void nfsd_ffv2_admission_unregister_test(struct kunit *test)
{
	struct nfsd_ffv2_unregister_ctx ctx;
	struct nfsd_ffv2_admission admission = {};
	struct task_struct *task;
	struct nfsd_net *nn;
	atomic_t *releases;
	bool retired;
	u64 generation_id;
	unsigned long timeout;
	int error;

	releases = kunit_kzalloc(test, sizeof(*releases), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, releases);
	atomic_set(releases, 0);
	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_test_net_exit, nn);
	KUNIT_ASSERT_EQ(test, error, 0);
	mutex_lock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_service_up(nn), 0);
	error = nfsd_ffv2_test_publish(nn, releases,
				       nfsd_ffv2_count_release,
				       &generation_id);
	mutex_unlock(&nfsd_mutex);
	KUNIT_ASSERT_EQ(test, error, 0);
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_test_admit(nn, &admission), 0);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_anchor_refcount(nn), 2U);
	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_test_unregister(nn, generation_id);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_register(nn), -EOPNOTSUPP);
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, error, -EDEADLK);

	ctx.nn = nn;
	ctx.generation = generation_id;
	ctx.result = -EINPROGRESS;
	init_completion(&ctx.done);
	task = kthread_run(nfsd_ffv2_unregister_thread, &ctx,
			   "nfsd-ffv2-unregister-test");
	if (IS_ERR(task)) {
		nfsd_ffv2_test_complete(&admission);
		nfsd_ffv2_test_net_destroy(test, nn);
		KUNIT_FAIL(test, "failed to start unregister thread");
		return;
	}

	error = read_poll_timeout(nfsd_ffv2_test_admission_retired,
				  retired, retired,
				  10, USEC_PER_SEC, false, &admission);
	if (error) {
		nfsd_ffv2_test_complete(&admission);
		wait_for_completion(&ctx.done);
		kthread_stop(task);
		nfsd_ffv2_test_net_destroy(test, nn);
		KUNIT_FAIL(test, "unregister did not retire generation");
		return;
	}
	KUNIT_EXPECT_FALSE(test, completion_done(&ctx.done));
	KUNIT_EXPECT_EQ(test, atomic_read(releases), 0);

	nfsd_ffv2_test_complete(&admission);
	nfsd_ffv2_test_complete(&admission);
	timeout = wait_for_completion_timeout(&ctx.done, HZ);
	KUNIT_EXPECT_NE(test, timeout, 0UL);
	kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ctx.result, 0);
	KUNIT_EXPECT_EQ(test, atomic_read(releases), 1);

	nfsd_ffv2_net_pre_exit(nn);
	nfsd_ffv2_test_net_destroy(test, nn);
}

static void nfsd_ffv2_zero_threads_test(struct kunit *test)
{
	const int overlong[] = { 0, 1 };
	const int active[] = { 1, 0 };

	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_requested_zero_threads(2, overlong, 1));
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_requested_zero_threads(2, active, 1));
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_requested_zero_threads(0, overlong, 1));
}

static void nfsd_ffv2_generation_boundary_test(struct kunit *test)
{
	struct nfsd_ffv2_generation *generation;
	struct nfsd_net *nn;
	atomic_t *releases;
	u64 generation_id = 0;
	int error;

	releases = kunit_kzalloc(test, sizeof(*releases), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, releases);
	atomic_set(releases, 0);
	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_test_net_exit, nn);
	KUNIT_ASSERT_EQ(test, error, 0);

	mutex_lock(&nfsd_mutex);
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_service_up(nn), 0);
	mutex_lock(&nn->ffv2.lock);
	nn->ffv2.next_generation = U64_MAX - 1;
	mutex_unlock(&nn->ffv2.lock);
	error = nfsd_ffv2_test_publish(nn, releases,
				       nfsd_ffv2_count_release,
				       &generation_id);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_EQ(test, generation_id, U64_MAX - 1);
	KUNIT_EXPECT_EQ(test, nn->ffv2.next_generation, U64_MAX);
	generation = nfsd_ffv2_service_stop_begin(nn);
	mutex_unlock(&nfsd_mutex);
	KUNIT_ASSERT_NOT_NULL(test, generation);
	nfsd_ffv2_service_stop_finish(nn, generation);
	mutex_lock(&nfsd_mutex);
	nfsd_ffv2_service_down(nn);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_service_up(nn), 0);
	generation_id = 0;
	error = nfsd_ffv2_test_publish(nn, releases,
				       nfsd_ffv2_count_release,
				       &generation_id);
	KUNIT_EXPECT_EQ(test, error, -EOVERFLOW);
	KUNIT_EXPECT_EQ(test, generation_id, 0ULL);
	KUNIT_EXPECT_EQ(test, nn->ffv2.next_generation, U64_MAX);
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, atomic_read(releases), 1);
	nfsd_ffv2_test_net_destroy(test, nn);
}

static void nfsd_ffv2_multi_retirement_test(struct kunit *test)
{
	struct nfsd_ffv2_unregister_ctx unregister[2];
	struct nfsd_ffv2_generation *stop_generation = NULL;
	struct nfsd_ffv2_admission admission = {};
	struct task_struct *unregister_task[2] = {};
	struct nfsd_ffv2_exit_ctx exit_ctx;
	struct task_struct *exit_task = NULL;
	struct nfsd_net *nn;
	atomic_t *releases;
	unsigned int anchor_refs;
	unsigned int refs;
	u64 generation_id;
	bool admitted = false;
	int error;
	unsigned int i;

	releases = kunit_kzalloc(test, sizeof(*releases), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, releases);
	atomic_set(releases, 0);
	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_test_net_exit, nn);
	KUNIT_ASSERT_EQ(test, error, 0);

	mutex_lock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_service_up(nn), 0);
	error = nfsd_ffv2_test_publish(nn, releases,
				       nfsd_ffv2_count_release,
				       &generation_id);
	mutex_unlock(&nfsd_mutex);
	if (error)
		goto fail;
	error = nfsd_ffv2_test_admit(nn, &admission);
	if (error)
		goto fail;
	admitted = true;

	for (i = 0; i < ARRAY_SIZE(unregister); i++) {
		unregister[i].nn = nn;
		unregister[i].generation = generation_id;
		unregister[i].result = -EINPROGRESS;
		init_completion(&unregister[i].done);
		unregister_task[i] = kthread_run(nfsd_ffv2_unregister_thread,
						 &unregister[i],
						 "nfsd-ffv2-unregister-%u", i);
		if (IS_ERR(unregister_task[i])) {
			unregister_task[i] = NULL;
			error = -ECHILD;
			goto fail;
		}
	}

	error = read_poll_timeout(nfsd_ffv2_test_refcount, refs, refs >= 4,
				  10, USEC_PER_SEC, false, &admission);
	if (error)
		goto fail;
	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_test_publish(nn, releases,
				       nfsd_ffv2_count_release, NULL);
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, error, -EBUSY);

	mutex_lock(&nfsd_mutex);
	stop_generation = nfsd_ffv2_service_stop_begin(nn);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_service_up(nn), -EAGAIN);
	mutex_unlock(&nfsd_mutex);
	if (!stop_generation) {
		error = -ENOENT;
		goto fail;
	}
	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_test_publish(nn, releases,
				       nfsd_ffv2_count_release, NULL);
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, error, -ESHUTDOWN);

	exit_ctx.nn = nn;
	init_completion(&exit_ctx.done);
	exit_task = kthread_run(nfsd_ffv2_exit_thread, &exit_ctx,
				"nfsd-ffv2-exit-test");
	if (IS_ERR(exit_task)) {
		exit_task = NULL;
		error = -ECHILD;
		goto fail;
	}
	error = read_poll_timeout(nfsd_ffv2_test_refcount, refs, refs >= 6,
				  10, USEC_PER_SEC, false, &admission);
	if (error)
		goto fail;
	error = read_poll_timeout(nfsd_ffv2_test_anchor_refcount,
				  anchor_refs, anchor_refs >= 5,
				  10, USEC_PER_SEC, false, nn);
	if (error)
		goto fail;

	nfsd_ffv2_test_complete(&admission);
	admitted = false;
	nfsd_ffv2_service_stop_finish(nn, stop_generation);
	stop_generation = NULL;

	for (i = 0; i < ARRAY_SIZE(unregister); i++) {
		wait_for_completion(&unregister[i].done);
		KUNIT_EXPECT_EQ(test, unregister[i].result, 0);
		kthread_stop(unregister_task[i]);
		unregister_task[i] = NULL;
	}
	wait_for_completion(&exit_ctx.done);
	kthread_stop(exit_task);
	exit_task = NULL;
	KUNIT_EXPECT_EQ(test, atomic_read(releases), 1);
	nfsd_ffv2_test_net_destroy(test, nn);
	return;

fail:
	if (admitted)
		nfsd_ffv2_test_complete(&admission);
	if (stop_generation) {
		nfsd_ffv2_service_stop_finish(nn, stop_generation);
	}
	for (i = 0; i < ARRAY_SIZE(unregister_task); i++) {
		if (!unregister_task[i])
			continue;
		wait_for_completion(&unregister[i].done);
		kthread_stop(unregister_task[i]);
	}
	if (exit_task) {
		wait_for_completion(&exit_ctx.done);
		kthread_stop(exit_task);
	}
	nfsd_ffv2_test_net_destroy(test, nn);
	KUNIT_FAIL(test, "failed to establish retirement race: %d", error);
}

static void nfsd_ffv2_service_integration_test(struct kunit *test)
{
	struct nfsd_ffv2_worker_ctx worker = {};
	struct nfsd_ffv2_release_ctx release = {};
	struct nfsd_ffv2_shutdown_ctx shutdown;
	struct nfsd_ffv2_admission rejected = {};
	struct task_struct *shutdown_task = NULL;
	struct nfsd_net *nn;
	struct net *net;
	unsigned long timeout;
	bool service_up = false;
	bool worker_installed = false;
	bool shutdown_initialized = false;
	bool shutdown_started = false;
	bool retired;
	int threads = 1;
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "failed to create test netns: %ld", PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	atomic_set(&release.releases, 0);
	init_completion(&release.started);
	init_completion(&release.proceed);
	error = nfsd_ffv2_worker_ctx_install(&worker, net);
	if (error)
		goto out_put_net;
	worker_installed = true;

	error = nfsd_ffv2_start_test_service(net, &worker);
	if (error)
		goto out_cleanup;
	service_up = true;

	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_test_publish(nn, &release,
				       nfsd_ffv2_blocking_release, NULL);
	mutex_unlock(&nfsd_mutex);
	if (error)
		goto out_cleanup;
	complete(&worker.run);
	timeout = wait_for_completion_timeout(&worker.admitted, HZ);
	if (!timeout || worker.admit_result) {
		error = timeout ? worker.admit_result : -ETIMEDOUT;
		goto out_cleanup;
	}
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_anchor_refcount(nn), 2U);

	nfsd_ffv2_shutdown_ctx_init(&shutdown, net);
	shutdown_initialized = true;
	shutdown_task = nfsd_ffv2_shutdown_thread_start(&shutdown, false);
	if (IS_ERR(shutdown_task)) {
		error = PTR_ERR(shutdown_task);
		shutdown_task = NULL;
		goto out_cleanup;
	}
	shutdown_started = true;
	error = read_poll_timeout(nfsd_ffv2_worker_admission_retired,
				  retired, retired, 10, USEC_PER_SEC, false,
				  &worker);
	/*
	 * The worker owns the production admission, so observe STOPPING via a
	 * rejected test admission while the SUNRPC drain is blocked on it.
	 */
	if (error) {
		error = -ETIMEDOUT;
		goto out_cleanup;
	}
	KUNIT_EXPECT_FALSE(test, completion_done(&shutdown.done));
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_admit(nn, &rejected),
			-ESHUTDOWN);

	complete(&worker.allow_complete);
	timeout = wait_for_completion_timeout(&worker.returned, HZ);
	if (!timeout) {
		error = -ETIMEDOUT;
		goto out_cleanup;
	}
	timeout = wait_for_completion_timeout(&release.started, HZ);
	if (!timeout) {
		error = -ETIMEDOUT;
		goto out_cleanup;
	}

	mutex_lock(&nfsd_mutex);
	KUNIT_EXPECT_TRUE(test, nn->nfsd_shutdown_in_progress);
	KUNIT_EXPECT_EQ(test, nfsd_create_serv(net), -EAGAIN);
	KUNIT_EXPECT_EQ(test, nfsd_set_nrthreads(1, &threads, net), -EAGAIN);
	KUNIT_EXPECT_EQ(test,
			nfsd_svc(1, &threads, net, current_cred(), NULL),
			-EAGAIN);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_register(nn), -EOPNOTSUPP);
	mutex_unlock(&nfsd_mutex);

	complete(&release.proceed);
	timeout = wait_for_completion_timeout(&shutdown.done, HZ);
	if (!timeout) {
		error = -ETIMEDOUT;
		goto out_cleanup;
	}
	kthread_stop(shutdown_task);
	shutdown_task = NULL;
	shutdown_started = false;
	service_up = false;
	KUNIT_EXPECT_EQ(test, atomic_read(&release.releases), 1);
	KUNIT_EXPECT_FALSE(test, nn->nfsd_shutdown_in_progress);
	KUNIT_EXPECT_PTR_EQ(test, nn->nfsd_serv, NULL);

	error = nfsd_ffv2_start_test_service(net, &worker);
	if (error)
		goto out_cleanup;
	service_up = true;
	nfsd_shutdown_threads(net);
	service_up = false;
	KUNIT_EXPECT_FALSE(test, nn->nfsd_shutdown_in_progress);
	error = 0;

out_cleanup:
	complete_all(&worker.run);
	complete_all(&worker.allow_complete);
	complete_all(&release.proceed);
	if (shutdown_started) {
		wait_for_completion(&shutdown.done);
		kthread_stop(shutdown_task);
		service_up = false;
	}
	if (service_up)
		nfsd_shutdown_threads(net);
	if (worker_installed)
		nfsd_ffv2_worker_ctx_remove(&worker);
	if (shutdown_initialized)
		nfsd_ffv2_shutdown_ctx_put(&shutdown);
out_put_net:
	put_net(net);
	net_ns_barrier();
	if (error)
		KUNIT_FAIL(test, "integrated service lifecycle failed: %d", error);
}

static void nfsd_ffv2_netns_integration_test(struct kunit *test)
{
	struct nfsd_ffv2_admission admission = {};
	struct nfsd_net *nn;
	struct net *net;
	atomic_t releases;
	bool retired;
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "failed to create test netns: %ld", PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	atomic_set(&releases, 0);
	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_service_up(nn);
	if (!error)
		error = nfsd_ffv2_test_publish(nn, &releases,
					       nfsd_ffv2_count_release, NULL);
	mutex_unlock(&nfsd_mutex);
	if (error)
		goto out_put_net;

	error = nfsd_ffv2_test_admit(nn, &admission);
	if (error)
		goto out_put_net;
	put_net(net);
	net = NULL;
	error = read_poll_timeout(nfsd_ffv2_test_admission_retired,
				  retired, retired, 10, USEC_PER_SEC, false,
				  &admission);
	KUNIT_EXPECT_EQ(test, atomic_read(&releases), 0);
	nfsd_ffv2_test_complete(&admission);
	net_ns_barrier();
	KUNIT_EXPECT_EQ(test, atomic_read(&releases), 1);
	if (error)
		KUNIT_FAIL(test, "registered netns pre-exit did not retire");
	return;

out_put_net:
	if (net) {
		put_net(net);
		net_ns_barrier();
	}
	KUNIT_FAIL(test, "integrated netns lifecycle failed: %d", error);
}

static void nfsd_ffv2_production_netns_integration_test(struct kunit *test)
{
	struct nfsd_ffv2_worker_ctx worker = {};
	struct nfsd_ffv2_shutdown_ctx shutdown;
	struct task_struct *shutdown_task = NULL;
	struct nfsd_net *nn;
	struct net *net;
	atomic_t releases;
	unsigned long timeout;
	bool worker_installed = false;
	bool shutdown_initialized = false;
	bool shutdown_started = false;
	bool service_up = false;
	bool retired;
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "failed to create test netns: %ld", PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	atomic_set(&releases, 0);
	error = nfsd_ffv2_worker_ctx_install(&worker, net);
	if (error)
		goto out_cleanup;
	worker_installed = true;
	error = nfsd_ffv2_start_test_service(net, &worker);
	if (error)
		goto out_cleanup;
	service_up = true;

	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_test_publish(nn, &releases,
				       nfsd_ffv2_count_release, NULL);
	mutex_unlock(&nfsd_mutex);
	if (error)
		goto out_cleanup;
	complete(&worker.run);
	timeout = wait_for_completion_timeout(&worker.admitted, HZ);
	if (!timeout || worker.admit_result) {
		error = timeout ? worker.admit_result : -ETIMEDOUT;
		goto out_cleanup;
	}
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_anchor_refcount(nn), 2U);

	nfsd_ffv2_shutdown_ctx_init(&shutdown, net);
	shutdown_initialized = true;
	put_net(net);
	net = NULL;
	shutdown_task = nfsd_ffv2_shutdown_thread_start(&shutdown, false);
	if (IS_ERR(shutdown_task)) {
		error = PTR_ERR(shutdown_task);
		shutdown_task = NULL;
		goto out_cleanup;
	}
	shutdown_started = true;
	error = read_poll_timeout(nfsd_ffv2_worker_admission_retired,
				  retired, retired, 10, USEC_PER_SEC, false,
				  &worker);
	if (error) {
		error = -ETIMEDOUT;
		goto out_cleanup;
	}
	KUNIT_EXPECT_FALSE(test, completion_done(&shutdown.done));
	KUNIT_EXPECT_EQ(test, atomic_read(&releases), 0);
	complete(&worker.allow_complete);
	timeout = wait_for_completion_timeout(&worker.returned, HZ);
	if (!timeout) {
		error = -ETIMEDOUT;
		goto out_cleanup;
	}
	timeout = wait_for_completion_timeout(&shutdown.done, HZ);
	if (!timeout) {
		error = -ETIMEDOUT;
		goto out_cleanup;
	}
	kthread_stop(shutdown_task);
	shutdown_task = NULL;
	shutdown_started = false;
	service_up = false;
	KUNIT_EXPECT_EQ(test, atomic_read(&releases), 1);
	KUNIT_EXPECT_PTR_NE(test, shutdown.net, NULL);
	mutex_lock(&nfsd_mutex);
	KUNIT_EXPECT_PTR_EQ(test, nn->nfsd_serv, NULL);
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_anchor_refcount(nn), 1U);
	error = 0;

out_cleanup:
	complete_all(&worker.run);
	complete_all(&worker.allow_complete);
	if (shutdown_started) {
		wait_for_completion(&shutdown.done);
		kthread_stop(shutdown_task);
		service_up = false;
	} else if (service_up) {
		nfsd_shutdown_threads(net ? net : shutdown.net);
		service_up = false;
	}
	if (worker_installed)
		nfsd_ffv2_worker_ctx_remove(&worker);
	if (net)
		put_net(net);
	if (shutdown_initialized)
		nfsd_ffv2_shutdown_ctx_put(&shutdown);
	net_ns_barrier();
	if (error)
		KUNIT_FAIL(test, "production netns lifecycle failed: %d", error);
}

static void nfsd_ffv2_production_pre_exit_overlap_test(struct kunit *test)
{
	struct nfsd_ffv2_worker_ctx worker = {};
	struct nfsd_ffv2_exit_ctx exit_ctx;
	struct task_struct *exit_task = NULL;
	struct nfsd_net *nn;
	struct net *net;
	atomic_t releases;
	unsigned long timeout;
	bool worker_installed = false;
	bool service_up = false;
	bool retired;
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "failed to create test netns: %ld", PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	atomic_set(&releases, 0);
	error = nfsd_ffv2_worker_ctx_install(&worker, net);
	if (error)
		goto out_cleanup;
	worker_installed = true;
	error = nfsd_ffv2_start_test_service(net, &worker);
	if (error)
		goto out_cleanup;
	service_up = true;

	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_test_publish(nn, &releases,
				       nfsd_ffv2_count_release, NULL);
	mutex_unlock(&nfsd_mutex);
	if (error)
		goto out_cleanup;
	complete(&worker.run);
	timeout = wait_for_completion_timeout(&worker.admitted, HZ);
	if (!timeout || worker.admit_result) {
		error = timeout ? worker.admit_result : -ETIMEDOUT;
		goto out_cleanup;
	}
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_anchor_refcount(nn), 2U);

	exit_ctx.nn = nn;
	init_completion(&exit_ctx.done);
	exit_task = kthread_run(nfsd_ffv2_exit_thread, &exit_ctx,
				"nfsd-ffv2-production-exit-test");
	if (IS_ERR(exit_task)) {
		error = PTR_ERR(exit_task);
		exit_task = NULL;
		goto out_cleanup;
	}
	error = read_poll_timeout(nfsd_ffv2_worker_admission_retired,
				  retired, retired, 10, USEC_PER_SEC, false,
				  &worker);
	if (error) {
		error = -ETIMEDOUT;
		goto out_cleanup;
	}
	KUNIT_EXPECT_FALSE(test, completion_done(&exit_ctx.done));
	KUNIT_EXPECT_EQ(test, atomic_read(&releases), 0);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_anchor_refcount(nn), 3U);
	complete(&worker.allow_complete);
	timeout = wait_for_completion_timeout(&worker.returned, HZ);
	if (!timeout) {
		error = -ETIMEDOUT;
		goto out_cleanup;
	}
	timeout = wait_for_completion_timeout(&exit_ctx.done, HZ);
	if (!timeout) {
		error = -ETIMEDOUT;
		goto out_cleanup;
	}
	kthread_stop(exit_task);
	exit_task = NULL;
	KUNIT_EXPECT_EQ(test, atomic_read(&releases), 1);
	KUNIT_EXPECT_EQ(test, nn->ffv2.net_state, NFSD_FFV2_NET_EXITING);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_anchor_refcount(nn), 1U);

	nfsd_shutdown_threads(net);
	service_up = false;
	error = 0;

out_cleanup:
	complete_all(&worker.run);
	complete_all(&worker.allow_complete);
	if (exit_task) {
		wait_for_completion(&exit_ctx.done);
		kthread_stop(exit_task);
	}
	if (service_up)
		nfsd_shutdown_threads(net);
	if (worker_installed)
		nfsd_ffv2_worker_ctx_remove(&worker);
	put_net(net);
	net_ns_barrier();
	if (error)
		KUNIT_FAIL(test, "production pre-exit overlap failed: %d", error);
}

static void nfsd_ffv2_shutdown_start_failure_test(struct kunit *test)
{
	struct nfsd_ffv2_shutdown_ctx shutdown;
	struct task_struct *shutdown_task;
	struct nfsd_net *nn;
	struct net *net;
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "failed to create test netns: %ld", PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	error = nfsd_ffv2_start_test_service(net, NULL);
	if (error)
		goto out_put_net;

	nfsd_ffv2_shutdown_ctx_init(&shutdown, net);
	put_net(net);
	net = NULL;
	shutdown_task = nfsd_ffv2_shutdown_thread_start(&shutdown, true);
	KUNIT_EXPECT_TRUE(test, IS_ERR(shutdown_task));
	KUNIT_EXPECT_EQ(test, PTR_ERR(shutdown_task), -ENOMEM);
	KUNIT_EXPECT_PTR_NE(test, shutdown.net, NULL);
	nfsd_shutdown_threads(shutdown.net);
	mutex_lock(&nfsd_mutex);
	KUNIT_EXPECT_PTR_EQ(test, nn->nfsd_serv, NULL);
	mutex_unlock(&nfsd_mutex);
	nfsd_ffv2_shutdown_ctx_put(&shutdown);
	net_ns_barrier();
	return;

out_put_net:
	put_net(net);
	net_ns_barrier();
	KUNIT_FAIL(test, "failed to start test service: %d", error);
}

static void nfsd_ffv2_listener_only_integration_test(struct kunit *test)
{
	struct nfsd_net *nn;
	struct net *net;
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "failed to create test netns: %ld", PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	mutex_lock(&nfsd_mutex);
	error = nfsd_create_serv(net);
	if (!error) {
		KUNIT_EXPECT_FALSE(test, nn->nfsd_net_up);
		KUNIT_EXPECT_PTR_NE(test, nn->nfsd_serv, NULL);
		nfsd_destroy_serv(net);
		KUNIT_EXPECT_PTR_EQ(test, nn->nfsd_serv, NULL);
		KUNIT_EXPECT_FALSE(test, nn->nfsd_shutdown_in_progress);
	}
	mutex_unlock(&nfsd_mutex);
	put_net(net);
	net_ns_barrier();
	if (error)
		KUNIT_FAIL(test, "listener-only lifecycle failed: %d", error);
}

static void nfsd_ffv2_partial_start_cleanup_test(struct kunit *test)
{
	struct nfsd_net *nn;
	struct net *net;
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "failed to create test netns: %ld", PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	nfsd_ffv2_test_set_start_failure(true);
	error = nfsd_ffv2_start_test_service(net, NULL);
	nfsd_ffv2_test_set_start_failure(false);
	KUNIT_EXPECT_EQ(test, error, -EIO);
	mutex_lock(&nfsd_mutex);
	KUNIT_EXPECT_PTR_EQ(test, nn->nfsd_serv, NULL);
	KUNIT_EXPECT_FALSE(test, nn->nfsd_shutdown_in_progress);
	mutex_unlock(&nfsd_mutex);
	put_net(net);
	net_ns_barrier();
}

static void nfsd_ffv2_init_test_export(struct svc_export *exp,
				       struct nfsd_net *nn,
				       struct auth_domain *domain,
				       const struct path *root)
{
	memset(exp, 0, sizeof(*exp));
	exp->cd = nn->svc_export_cache;
	exp->ex_client = domain;
	exp->ex_path = *root;
	exp->h.expiry_time = TIME64_MAX;
	exp->ex_anon_uid = GLOBAL_ROOT_UID;
	exp->ex_anon_gid = GLOBAL_ROOT_GID;
	exp->ex_xprtsec_modes = NFSEXP_XPRTSEC_ALL;
}

static void nfsd_ffv2_reservation_context_test(struct kunit *test)
{
	struct nfsd_ffv2_object_unregister_ctx retire_ctx = {};
	struct nfsd_ffv2_transition_publish_ctx publish_ctx = {};
	struct nfsd_ffv2_object_request request;
	const struct nfsd_ffv2_chunk_request chunks = { .offset = 0,
							.count = 1 };
	struct nfsd_ffv2_chunk_result chunk_result;
	struct nfsd_ffv2_admission probe_admission = {};
	struct nfsd_ffv2_export_update registration = {};
	struct nfsd_ffv2_export_update second = {};
	struct nfsd_ffv2_object *object = NULL;
	struct nfsd_ffv2_object *published_object = NULL;
	struct nfsd_ffv2_binding *binding = NULL;
	struct nfsd_ffv2_fh_info decoded;
	struct nfsd_ffv2_fh_info wrong;
	struct nfsd_ffv2_reservation *reservation = NULL;
	struct nfsd_ffv2_generation *generation;
	struct auth_domain *domain;
	struct svc_export *published;
	struct svc_export *replacement;
	struct svc_export *selected;
	struct svc_export *stale;
	struct svc_export *retained = NULL;
	struct svc_export exp;
	struct svc_rqst *rqstp;
	struct svc_xprt *xprt;
	struct svc_fh *derived;
	struct svc_fh *duplicate;
	struct svc_fh *mapped;
	struct svc_fh *ordinary;
	struct knfsd_fh outer_fh = {};
	struct nfsd_net *nn;
	struct nfsd_net *nn2;
	struct dentry *object_dentry = NULL;
	struct inode *object_inode;
	struct path nonroot;
	struct path object_path;
	struct path root;
	struct net *net;
	struct net *net2;
	struct task_struct *publish_task;
	struct task_struct *retire_task = NULL;
	struct completion retire_waiting;
	bool filecache_up = false;
	bool mount_crossing_allowed;
	bool registration_open = false;
	bool service_up = false;
	int second_error;
	char domain_name[] = "ffv2-kunit";
	u8 token[32] = { 1 };
	u8 uuid[16] = { 2 };
	u8 wrong_uuid[16] = { 9 };
	const u8 inner[] = { 1, 0, 1, 1, 0xaa, 0xbb, 0xcc, 0xdd };
	u64 generation_id;
	__be32 status;
	int error;

	ordinary = kunit_kzalloc(test, sizeof(*ordinary), GFP_KERNEL);
	derived = kunit_kzalloc(test, sizeof(*derived), GFP_KERNEL);
	duplicate = kunit_kzalloc(test, sizeof(*duplicate), GFP_KERNEL);
	mapped = kunit_kzalloc(test, sizeof(*mapped), GFP_KERNEL);
	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	xprt = kunit_kzalloc(test, sizeof(*xprt), GFP_KERNEL);
	if (!ordinary || !derived || !duplicate || !mapped || !rqstp || !xprt) {
		KUNIT_FAIL(test, "failed to allocate transition handles");
		return;
	}
	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "failed to create reservation test netns: %ld",
			   PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	xprt->xpt_net = net;
	rqstp->rq_xprt = xprt;
	net2 = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net2)) {
		KUNIT_FAIL(test, "failed to create second test netns: %ld",
			   PTR_ERR(net2));
		put_net(net);
		net_ns_barrier();
		return;
	}
	nn2 = net_generic(net2, nfsd_net_id);
	domain = unix_domain_find(domain_name);
	if (!domain) {
		KUNIT_FAIL(test, "failed to create test auth domain");
		goto out_nets;
	}
	get_fs_root(current->fs, &root);
	object_dentry = d_alloc_name(root.dentry, "ffv2-kunit-object");
	if (!object_dentry) {
		KUNIT_FAIL(test, "failed to allocate object dentry");
		goto out_root;
	}
	object_inode = new_inode(root.mnt->mnt_sb);
	if (!object_inode) {
		KUNIT_FAIL(test, "failed to allocate object inode");
		goto out_root;
	}
	object_inode->i_mode = S_IFREG | 0600;
	object_inode->i_ino = get_next_ino();
	set_nlink(object_inode, 1);
	d_add(object_dentry, object_inode);
	object_path.mnt = root.mnt;
	object_path.dentry = object_dentry;
	object = nfsd_ffv2_object_alloc();
	published_object = nfsd_ffv2_object_alloc();
	if (!object || !published_object) {
		KUNIT_FAIL(test, "failed to preallocate registry objects");
		goto out_root;
	}

	error = nfsd_ffv2_reservation_claim(nn, &root, uuid, token,
					    &reservation);
	if (!error) {
		nfsd_ffv2_reservation_abort(reservation);
		reservation = NULL;
	} else {
		KUNIT_EXPECT_EQ(test, error, -EOPNOTSUPP);
	}

	nfsd_ffv2_init_test_export(&exp, nn, domain, &root);
	exp.ex_uuid = kmemdup(uuid, sizeof(uuid), GFP_KERNEL);
	if (!exp.ex_uuid) {
		KUNIT_FAIL(test, "failed to allocate test export UUID");
		goto out_root;
	}
	published = nfsd_export_cache_update(&exp);
	if (IS_ERR(published)) {
		KUNIT_FAIL(test, "real inventory publication failed: %ld",
			   PTR_ERR(published));
		kfree(exp.ex_uuid);
		exp.ex_uuid = NULL;
		goto out_root;
	}
	error = nfsd_ffv2_export_access_get(published);
	if (error) {
		KUNIT_FAIL(test, "ordinary export admission failed: %d", error);
		exp_put(published);
		goto out_root;
	}
	selected = nfsd_ffv2_export_select(nn->svc_export_cache, domain, &root);
	if (IS_ERR(selected)) {
		KUNIT_FAIL(test, "ordinary export selection failed: %ld",
			   PTR_ERR(selected));
		nfsd_ffv2_export_access_put(published);
		exp_put(published);
		goto out_root;
	}
	KUNIT_EXPECT_PTR_EQ(test, selected, published);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_access_get(published), -ESTALE);
	nfsd_ffv2_export_access_put(published);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_transition_wait(published), 0);
	error = nfsd_ffv2_test_reservation_claim_expected(nn2, &root, uuid,
							  token, published,
							  &reservation);
	if (error) {
		KUNIT_FAIL(test, "exact-E0 reservation failed: %d", error);
		nfsd_ffv2_export_transition_abort_exact(published);
		exp_put(selected);
		exp_put(published);
		goto out_root;
	}
	nfsd_ffv2_reservation_abort(reservation);
	reservation = NULL;
	KUNIT_EXPECT_TRUE(test,
			  nfsd_ffv2_export_transition_abort_exact(published));
	exp_put(selected);
	error = nfsd_ffv2_export_template_clone(&exp, published);
	if (error) {
		KUNIT_FAIL(test, "export template clone failed: %d", error);
		exp_put(published);
		goto out_root;
	}
	replacement = nfsd_ffv2_test_export_update_exact(&exp, published);
	nfsd_ffv2_export_template_free(&exp);
	if (IS_ERR(replacement)) {
		KUNIT_FAIL(test, "exact export replacement failed: %ld",
			   PTR_ERR(replacement));
		exp_put(published);
		goto out_root;
	}
	error = nfsd_ffv2_export_template_clone(&exp, replacement);
	if (error) {
		KUNIT_FAIL(test, "stale template clone failed: %d", error);
		exp_put(replacement);
		exp_put(published);
		goto out_root;
	}
	stale = nfsd_ffv2_test_export_update_exact(&exp, published);
	nfsd_ffv2_export_template_free(&exp);
	KUNIT_EXPECT_TRUE(test, IS_ERR(stale));
	if (IS_ERR(stale))
		KUNIT_EXPECT_EQ(test, PTR_ERR(stale), -ESTALE);
	else
		exp_put(stale);
	exp_put(replacement);
	exp_put(published);
	KUNIT_EXPECT_EQ(test, nn->ffv2_participant.inventory_count, 1U);
	error = nfsd_ffv2_test_reservation_claim(nn2, &root, uuid, token,
						 &reservation);
	KUNIT_EXPECT_EQ(test, error, -EBUSY);
	nfsd_export_flush(net);
	KUNIT_EXPECT_EQ(test, nn->ffv2_participant.inventory_count, 0U);

	nfsd_ffv2_init_test_export(&exp, nn, domain, &root);
	set_bit(CACHE_NEGATIVE, &exp.h.flags);
	published = nfsd_export_cache_update(&exp);
	if (IS_ERR(published)) {
		KUNIT_FAIL(test, "negative seed publication failed: %ld",
			   PTR_ERR(published));
		goto out_root;
	}
	exp_put(published);

	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_service_up(nn);
	service_up = !error;
	mutex_unlock(&nfsd_mutex);
	if (error) {
		KUNIT_FAIL(test, "failed to start transaction service: %d", error);
		goto out_root;
	}
	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_registration_begin(nn, &registration);
	KUNIT_EXPECT_EQ(test, error, 0);
	second_error = nfsd_ffv2_registration_begin(nn, &second);
	KUNIT_EXPECT_EQ(test, second_error, -EBUSY);
	if (!second_error)
		nfsd_ffv2_registration_end(nn, &second);
	nfsd_ffv2_registration_end(nn, &registration);
	if (!error)
		error = nfsd_ffv2_registration_begin(nn, &registration);
	KUNIT_EXPECT_EQ(test, error, 0);
	registration_open = !error;
	mutex_unlock(&nfsd_mutex);
	if (error)
		goto out_root;
	mutex_lock(&nfsd_mutex);
	error = nfsd_file_ffv2_test_cache_start();
	mutex_unlock(&nfsd_mutex);
	if (error) {
		KUNIT_FAIL(test, "failed to start transaction filecache: %d",
			   error);
		goto out_root;
	}
	filecache_up = true;
	nfsd_ffv2_init_test_export(&exp, nn, domain, &root);
	nfsd_ffv2_test_fail_export_alloc(true);
	error = nfsd_ffv2_test_service_export_publish(nn, &exp, &root, uuid,
						      token, current_cred(), 1,
						      &generation_id);
	KUNIT_EXPECT_EQ(test, error, -ENOMEM);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(exp.ex_ffv2_context), NULL);
	KUNIT_EXPECT_TRUE(test, nfsd4_ffv2_mount_crossing_allowed(&root));

	nfsd_ffv2_init_test_export(&exp, nn, domain, &root);
	exp.ex_uuid = kmemdup(uuid, sizeof(uuid), GFP_KERNEL);
	if (!exp.ex_uuid) {
		KUNIT_FAIL(test, "failed to allocate transition export UUID");
		goto out_root;
	}
	published = nfsd_export_cache_update(&exp);
	if (IS_ERR(published)) {
		KUNIT_FAIL(test, "ordinary transition seed failed: %ld",
			   PTR_ERR(published));
		kfree(exp.ex_uuid);
		exp.ex_uuid = NULL;
		goto out_root;
	}
	exp_put(published);
	memset(&request, 0, sizeof(request));
	request.auth_domain = domain_name;
	request.export_path = "/";
	request.object_path = "/";
	request.object_uuid = uuid;
	request.store_uuid = uuid;
	request.binding_token = token;
	request.control_root = 1;
	error = nfsd_ffv2_object_register(nn, &registration, object, &request,
					  &outer_fh, &generation_id);
	object = NULL;
	KUNIT_EXPECT_EQ(test, error, -ESTALE);
	selected = nfsd_ffv2_export_lookup(nn->svc_export_cache, domain, &root);
	if (IS_ERR(selected)) {
		KUNIT_FAIL(test, "transition export lookup failed: %ld",
			   PTR_ERR(selected));
		goto out_root;
	}
	fh_init(ordinary, NFS4_FHSIZE);
	status = fh_compose(ordinary, selected, root.dentry, NULL);
	if (status) {
		KUNIT_FAIL(test, "ordinary handle composition failed: %u",
			   be32_to_cpu(status));
		exp_put(selected);
		goto out_root;
	}
	error = nfsd_ffv2_export_transition_exact(selected);
	if (error) {
		KUNIT_FAIL(test, "exact export transition failed: %d", error);
		exp_put(selected);
		goto out_root;
	}
	fh_init(derived, NFS4_FHSIZE);
	status = fh_compose(derived, selected, root.dentry, ordinary);
	if (status) {
		KUNIT_FAIL(test, "transition handle composition failed: %u",
			   be32_to_cpu(status));
		nfsd_ffv2_export_transition_abort_exact(selected);
		exp_put(selected);
		goto out_root;
	}
	fh_init(duplicate, NFS4_FHSIZE);
	status = nfsd_ffv2_test_fh_dup2(duplicate, ordinary);
	if (status) {
		KUNIT_FAIL(test, "transition handle duplication failed: %u",
			   be32_to_cpu(status));
		nfsd_ffv2_export_transition_abort_exact(selected);
		exp_put(selected);
		goto out_root;
	}
	error = nfsd_ffv2_export_template_clone(&exp, selected);
	if (error) {
		KUNIT_FAIL(test, "service template clone failed: %d", error);
		nfsd_ffv2_export_transition_abort_exact(selected);
		exp_put(selected);
		goto out_root;
	}
	error = nfsd_ffv2_test_object_init(published_object, domain, &root,
					   &object_path, inner, sizeof(inner),
					   uuid, uuid);
	if (error) {
		KUNIT_FAIL(test, "failed to initialize registry object: %d",
			   error);
		nfsd_ffv2_export_template_free(&exp);
		nfsd_ffv2_export_transition_abort_exact(selected);
		exp_put(selected);
		goto out_root;
	}
	publish_ctx.owner = nn;
	publish_ctx.registration = &registration;
	publish_ctx.object = published_object;
	publish_ctx.outer_fh = &outer_fh;
	publish_ctx.template = &exp;
	publish_ctx.expected = selected;
	publish_ctx.root = &root;
	publish_ctx.store_uuid = uuid;
	publish_ctx.binding_token = token;
	publish_ctx.cred = get_current_cred();
	publish_ctx.control_root = 1;
	publish_ctx.result = -EINPROGRESS;
	init_completion(&publish_ctx.done);
	publish_task = kthread_run(nfsd_ffv2_transition_publish_thread,
				   &publish_ctx, "nfsd-ffv2-publish");
	if (IS_ERR(publish_task)) {
		error = PTR_ERR(publish_task);
		KUNIT_FAIL(test, "failed to start transition publisher: %d",
			   error);
		put_cred(publish_ctx.cred);
		nfsd_ffv2_export_template_free(&exp);
		nfsd_ffv2_export_transition_abort_exact(selected);
		exp_put(selected);
		goto out_root;
	}
	error = read_poll_timeout(nfsd4_ffv2_mount_crossing_allowed,
				  mount_crossing_allowed,
				  !mount_crossing_allowed, 10,
				  USEC_PER_SEC, false, &root);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_FALSE(test, completion_done(&publish_ctx.done));
	fh_put(ordinary);
	KUNIT_EXPECT_FALSE(test, completion_done(&publish_ctx.done));
	fh_put(derived);
	KUNIT_EXPECT_FALSE(test, completion_done(&publish_ctx.done));
	fh_put(duplicate);
	KUNIT_EXPECT_NE(test,
			wait_for_completion_timeout(&publish_ctx.done, 5 * HZ),
			0UL);
	kthread_stop(publish_task);
	put_cred(publish_ctx.cred);
	error = publish_ctx.result;
	generation_id = publish_ctx.generation_id;
	nfsd_ffv2_export_template_free(&exp);
	exp_put(selected);
	if (!error)
		published_object = NULL;
	if (registration_open) {
		nfsd_ffv2_registration_end(nn, &registration);
		registration_open = false;
	}
	if (error) {
		KUNIT_FAIL(test, "atomic service transaction failed: %d", error);
		goto out_root;
	}
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_fh_parse(&outer_fh, &decoded), 0);
	KUNIT_EXPECT_EQ(test, decoded.generation, generation_id);
	KUNIT_EXPECT_MEMEQ(test, decoded.object_uuid, uuid, sizeof(uuid));
	KUNIT_EXPECT_MEMEQ(test, decoded.export_uuid, uuid, sizeof(uuid));
	KUNIT_EXPECT_MEMEQ(test, decoded.inner, inner, sizeof(inner));
	wrong = decoded;
	wrong.object_uuid[0] ^= 0xff;
	binding = nfsd_ffv2_test_binding_create(nn, &wrong);
	KUNIT_EXPECT_TRUE(test, IS_ERR(binding));
	if (!IS_ERR(binding))
		nfsd_ffv2_binding_put(binding);
	binding = NULL;
	binding = nfsd_ffv2_test_binding_create(nn, &decoded);
	if (IS_ERR(binding)) {
		KUNIT_FAIL(test, "binding admission failed: %ld",
			   PTR_ERR(binding));
		binding = NULL;
		goto out_root;
	}
	nfsd_ffv2_binding_get(binding);
	nfsd_ffv2_binding_put(binding);
	KUNIT_EXPECT_FALSE(test, nfsd4_ffv2_mount_crossing_allowed(&root));
	nfsd_ffv2_init_test_export(&exp, nn, domain, &root);
	published = nfsd_ffv2_test_export_lookup(&exp);
	if (!published) {
		KUNIT_FAIL(test, "published service export not found");
		goto out_root;
	}
	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_export_policy_check(published, OP_GETATTR),
			nfserr_notsupp);
	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_export_policy_check(published, OP_PUTFH),
			nfs_ok);
	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_export_policy_check(published, OP_PUTROOTFH),
			nfs_ok);
	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_export_policy_check(published, OP_PUTPUBFH),
			nfs_ok);
	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_export_policy_check(published, OP_SAVEFH),
			nfs_ok);
	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_export_policy_check(published, OP_RESTOREFH),
			nfs_ok);
	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_export_policy_check(published, OP_CHUNK_HEADER_READ),
			nfs_ok);
	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_export_policy_check(published, OP_CHUNK_READ),
			nfs_ok);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_access_get(published), -ESTALE);

	/* Model a successfully mapped handle retaining both owners. */
	fh_init(mapped, NFS4_FHSIZE);
	mapped->fh_handle = outer_fh;
	mapped->fh_export = nfsd_export_get(published);
	mapped->fh_dentry = dget(object_dentry);
	mapped->fh_ffv2_binding = binding;
	binding = NULL;
	retained = published;
	/*
	 * The boundary requires an admission even where no provider can be
	 * reached, so hand it a zeroed one; completing that is a no-op.
	 */
	KUNIT_EXPECT_EQ(test,
			nfsd_ffv2_provider_probe(rqstp, mapped, OP_CHUNK_READ,
						 &chunks, &chunk_result,
						 &probe_admission),
			nfserr_notsupp);
	KUNIT_EXPECT_EQ(test,
			nfsd_ffv2_provider_probe(rqstp, mapped,
						 OP_CHUNK_HEADER_READ,
						 &chunks, &chunk_result,
						 &probe_admission),
			nfserr_notsupp);
	KUNIT_EXPECT_EQ(test,
			nfsd_ffv2_provider_probe(rqstp, ordinary,
						 OP_CHUNK_READ,
						 &chunks, &chunk_result,
						 &probe_admission),
			nfserr_stale);

	nfsd_ffv2_init_test_export(&exp, nn, domain, &root);
	published = nfsd_export_cache_update(&exp);
	if (IS_ERR(published)) {
		KUNIT_EXPECT_EQ(test, PTR_ERR(published), -EBUSY);
	} else {
		KUNIT_FAIL(test, "service export replacement was accepted");
		exp_put(published);
	}
	set_bit(CACHE_NEGATIVE, &exp.h.flags);
	published = nfsd_export_cache_update(&exp);
	if (IS_ERR(published)) {
		KUNIT_EXPECT_EQ(test, PTR_ERR(published), -EAGAIN);
	} else {
		KUNIT_FAIL(test, "service export negative update was accepted");
		exp_put(published);
	}

	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_object_unregister(nn, generation_id, wrong_uuid);
	KUNIT_EXPECT_EQ(test, error, -ENOENT);
	mutex_unlock(&nfsd_mutex);
	retire_ctx.nn = nn;
	retire_ctx.generation = generation_id;
	memcpy(retire_ctx.object_uuid, uuid, sizeof(uuid));
	retire_ctx.result = -EINPROGRESS;
	init_completion(&retire_ctx.done);
	init_completion(&retire_waiting);
	error = nfsd_ffv2_test_retire_waiting(nn, generation_id,
					      &retire_waiting);
	if (error) {
		KUNIT_FAIL(test, "failed to arm retirement wait: %d", error);
		goto out_root;
	}
	retire_task = kthread_run(nfsd_ffv2_object_unregister_thread,
				  &retire_ctx, "nfsd-ffv2-object-retire");
	if (IS_ERR(retire_task)) {
		error = PTR_ERR(retire_task);
		retire_task = NULL;
		nfsd_ffv2_test_retire_waiting(nn, generation_id, NULL);
		KUNIT_FAIL(test, "failed to start object retirement: %d", error);
		goto out_root;
	}
	KUNIT_EXPECT_NE(test,
			wait_for_completion_timeout(&retire_waiting, 5 * HZ),
			0UL);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_binding_rejected(nn, &decoded));
	KUNIT_EXPECT_FALSE(test, completion_done(&retire_ctx.done));
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_export_has_context(retained));

	/* The binding admission must delay payload release. */
	fh_put(mapped);
	error = read_poll_timeout(nfsd_ffv2_test_export_has_context,
				  mount_crossing_allowed,
				  !mount_crossing_allowed, 10,
				  USEC_PER_SEC, false, retained);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_FALSE(test, completion_done(&retire_ctx.done));
	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_export_policy_check(retained, OP_GETATTR),
			nfserr_notsupp);
	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_export_policy_check(retained, OP_PUTFH),
			nfs_ok);
	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_export_policy_check(retained, OP_PUTROOTFH),
			nfs_ok);
	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_export_policy_check(retained, OP_PUTPUBFH),
			nfs_ok);
	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_export_policy_check(retained, OP_SAVEFH),
			nfs_ok);
	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_export_policy_check(retained, OP_RESTOREFH),
			nfs_ok);
	exp_put(retained);
	retained = NULL;
	if (!wait_for_completion_timeout(&retire_ctx.done, 5 * HZ)) {
		KUNIT_FAIL(test, "object retirement did not complete");
		goto out_root;
	}
	kthread_stop(retire_task);
	retire_task = NULL;
	KUNIT_EXPECT_EQ(test, retire_ctx.result, 0);
	KUNIT_EXPECT_TRUE(test, nfsd4_ffv2_mount_crossing_allowed(&root));
	published = nfsd_export_cache_update(&exp);
	KUNIT_EXPECT_FALSE(test, IS_ERR(published));
	if (!IS_ERR(published))
		exp_put(published);

	mutex_lock(&nfsd_mutex);
	generation = nfsd_ffv2_service_stop_begin(nn);
	mutex_unlock(&nfsd_mutex);
	nfsd_ffv2_service_stop_finish(nn, generation);
	service_up = false;
	mutex_lock(&nfsd_mutex);
	nfsd_ffv2_service_down(nn);
	mutex_unlock(&nfsd_mutex);
	nfsd_export_flush(net);

	error = nfsd_ffv2_test_reservation_claim(nn2, &root, uuid, token,
						 &reservation);
	if (error) {
		KUNIT_FAIL(test, "owner reservation failed: %d", error);
		goto out_root;
	}
	nfsd_ffv2_participant_detach_begin(nn2);
	nfsd_ffv2_participant_detach_finish(nn2);
	KUNIT_EXPECT_TRUE(test, nfsd4_ffv2_mount_crossing_allowed(&root));
	nfsd_ffv2_reservation_abort(reservation);
	reservation = NULL;
	error = nfsd_ffv2_participant_register(nn2, net2);
	if (error) {
		KUNIT_FAIL(test, "failed to restore test participant: %d", error);
		goto out_root;
	}

	error = kern_path("/proc/self", LOOKUP_FOLLOW, &nonroot);
	if (!error) {
		error = nfsd_ffv2_reservation_claim(nn, &nonroot, uuid, token,
						    &reservation);
		KUNIT_EXPECT_EQ(test, error, -EOPNOTSUPP);
		path_put(&nonroot);
	}
	goto out_root;

out_root:
	if (retire_task) {
		fh_put(mapped);
		if (retained) {
			exp_put(retained);
			retained = NULL;
		}
		kthread_stop(retire_task);
	}
	if (binding)
		nfsd_ffv2_binding_put(binding);
	if (retained)
		exp_put(retained);
	fh_put(mapped);
	fh_put(duplicate);
	fh_put(derived);
	fh_put(ordinary);
	nfsd_ffv2_object_free(object);
	nfsd_ffv2_object_free(published_object);
	if (registration_open)
		nfsd_ffv2_registration_end(nn, &registration);
	if (service_up) {
		mutex_lock(&nfsd_mutex);
		generation = nfsd_ffv2_service_stop_begin(nn);
		mutex_unlock(&nfsd_mutex);
		nfsd_ffv2_service_stop_finish(nn, generation);
		mutex_lock(&nfsd_mutex);
		nfsd_ffv2_service_down(nn);
		mutex_unlock(&nfsd_mutex);
	}
	nfsd_ffv2_test_fail_export_alloc(false);
	nfsd_export_flush(net);
	if (filecache_up) {
		mutex_lock(&nfsd_mutex);
		nfsd_file_cache_shutdown();
		mutex_unlock(&nfsd_mutex);
	}
	dput(object_dentry);
	path_put(&root);
	auth_domain_put(domain);
out_nets:
	if (net2)
		put_net(net2);
	put_net(net);
	net_ns_barrier();
}

static void nfsd_ffv2_export_update_stop_test(struct kunit *test)
{
	struct nfsd_ffv2_update_stop_ctx stop;
	struct nfsd_ffv2_export_update update;
	struct task_struct *task = NULL;
	struct svc_export exp = {};
	struct nfsd_net *nn;
	struct path root;
	struct net *net;
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "failed to create update-stop netns: %ld",
			   PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	get_fs_root(current->fs, &root);
	exp.cd = nn->svc_export_cache;
	exp.ex_path = root;

	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_service_up(nn);
	mutex_unlock(&nfsd_mutex);
	if (error) {
		KUNIT_FAIL(test, "failed to open update epoch: %d", error);
		goto out_root;
	}
	error = nfsd_ffv2_export_update_begin(&exp, &exp, &update);
	if (error) {
		KUNIT_FAIL(test, "failed to admit export update: %d", error);
		goto out_down;
	}
	stop.nn = nn;
	init_completion(&stop.done);
	mutex_lock(&nfsd_mutex);
	stop.generation = nfsd_ffv2_service_stop_begin(nn);
	mutex_unlock(&nfsd_mutex);
	task = kthread_run(nfsd_ffv2_update_stop_thread, &stop,
			   "nfsd-ffv2-update-stop");
	if (IS_ERR(task)) {
		KUNIT_FAIL(test, "failed to start update-stop thread: %ld",
			   PTR_ERR(task));
		task = NULL;
		nfsd_ffv2_export_update_abort(&update);
		nfsd_ffv2_service_stop_finish(nn, stop.generation);
		goto out_down;
	}
	KUNIT_EXPECT_EQ(test,
			wait_for_completion_timeout(&stop.done, 1), 0UL);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_update_validate(&update),
			-ESHUTDOWN);
	nfsd_ffv2_export_update_abort(&update);
	KUNIT_EXPECT_NE(test,
			wait_for_completion_timeout(&stop.done, 5 * HZ), 0UL);
	kthread_stop(task);
	task = NULL;

out_down:
	mutex_lock(&nfsd_mutex);
	nfsd_ffv2_service_down(nn);
	mutex_unlock(&nfsd_mutex);
out_root:
	path_put(&root);
	put_net(net);
	net_ns_barrier();
}

static void nfsd_ffv2_filehandle_format_test(struct kunit *test)
{
	const u8 inner[] = { 1, 0, 1, 1, 0xaa, 0xbb, 0xcc, 0xdd };
	const u8 unaligned_inner[] = { 1, 0, 1, 1, 0xaa, 0xbb, 0xcc,
				       0xdd, 0xee };
	struct nfsd_ffv2_fh_info encoded = {
		.generation = 7,
		.object_uuid = { 1 },
		.export_uuid = { 2 },
		.inner = inner,
		.inner_len = sizeof(inner),
	};
	struct nfsd_ffv2_fh_info decoded;
	struct knfsd_fh fh = {};
	u8 saved;

	KUNIT_ASSERT_EQ(test, nfsd_ffv2_fh_encode(&fh, &encoded), 0);
	KUNIT_ASSERT_EQ(test, fh.fh_size,
			NFSD_FFV2_FH_HEADER_SIZE + sizeof(inner));
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_fh_parse(&fh, &decoded), 0);
	KUNIT_EXPECT_EQ(test, decoded.generation, 7ULL);
	KUNIT_EXPECT_EQ(test, decoded.inner_len, (u16)sizeof(inner));
	KUNIT_EXPECT_MEMEQ(test, decoded.object_uuid, encoded.object_uuid, 16);
	KUNIT_EXPECT_MEMEQ(test, decoded.export_uuid, encoded.export_uuid, 16);
	KUNIT_EXPECT_MEMEQ(test, decoded.inner, inner, sizeof(inner));

	encoded.inner = unaligned_inner;
	encoded.inner_len = sizeof(unaligned_inner);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_fh_encode(&fh, &encoded), -EINVAL);
	encoded.inner = inner;
	encoded.inner_len = sizeof(inner);

	saved = fh.fh_raw[0];
	fh.fh_raw[0] = 1;
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_fh_parse(&fh, &decoded), -EBADMSG);
	fh.fh_raw[0] = saved;
	fh.fh_raw[9] = 1;
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_fh_parse(&fh, &decoded), -EBADMSG);
	fh.fh_raw[9] = 0;
	fh.fh_raw[56] = 0xff;
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_fh_parse(&fh, &decoded), -EBADMSG);
	fh.fh_raw[56] = 1;
	fh.fh_size--;
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_fh_parse(&fh, &decoded), -EBADMSG);
	fh.fh_size = NFSD_FFV2_FH_HEADER_SIZE + 4;
	put_unaligned_be16(fh.fh_size, fh.fh_raw + 12);
	put_unaligned_be16(4, fh.fh_raw + 14);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_fh_parse(&fh, &decoded), -EBADMSG);
	fh.fh_size = NFSD_FFV2_FH_HEADER_SIZE + sizeof(unaligned_inner);
	put_unaligned_be16(fh.fh_size, fh.fh_raw + 12);
	put_unaligned_be16(sizeof(unaligned_inner), fh.fh_raw + 14);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_fh_parse(&fh, &decoded), -EBADMSG);
}

static void nfsd_ffv2_filecache_gate_test(struct kunit *test)
{
	struct nfsd_ffv2_reservation *reservation = NULL;
	struct nfsd_file_ffv2_gate gate;
	struct nfsd_file *blocked, *nf;
	struct nfsd_net *nn;
	struct inode *inode;
	struct path root;
	struct net *net;
	u8 token[32] = { 3 };
	u8 uuid[16] = { 4 };
	int error;

	mutex_lock(&nfsd_mutex);
	error = nfsd_file_ffv2_test_cache_start();
	mutex_unlock(&nfsd_mutex);
	if (error) {
		KUNIT_FAIL(test, "failed to start test filecache: %d", error);
		return;
	}
	get_fs_root(current->fs, &root);
	inode = d_inode(root.dentry);
	nf = nfsd_file_ffv2_test_alloc(inode, NFSD_MAY_READ, false);
	if (!nf) {
		KUNIT_FAIL(test, "failed to allocate test nfsd_file");
		goto out_root;
	}
	error = nfsd_file_ffv2_gate_begin(&gate, inode);
	KUNIT_EXPECT_EQ(test, error, -EBUSY);
	nfsd_file_put(nf);
	if (!error)
		nfsd_file_ffv2_gate_end(&gate);
	if (error != -EBUSY)
		goto out_root;
	nf = nfsd_file_ffv2_test_alloc(inode,
				      NFSD_MAY_READ | NFSD_MAY_LOCALIO,
				      false);
	if (!nf) {
		KUNIT_FAIL(test, "failed to allocate localio test nfsd_file");
		goto out_root;
	}
	error = nfsd_file_ffv2_gate_begin(&gate, inode);
	if (error) {
		KUNIT_FAIL(test, "failed to install filecache gate: %d", error);
		nfsd_file_put(nf);
		goto out_root;
	}
	KUNIT_EXPECT_EQ(test, gate.live, 1U);
	blocked = nfsd_file_ffv2_test_alloc(inode, NFSD_MAY_READ, false);
	KUNIT_EXPECT_PTR_EQ(test, blocked, NULL);
	if (blocked)
		nfsd_file_put(blocked);
	nfsd_file_put(nf);
	KUNIT_EXPECT_EQ(test, nfsd_file_ffv2_gate_wait(&gate), 0);
	KUNIT_EXPECT_EQ(test, gate.live, 0U);
	nfsd_file_ffv2_gate_end(&gate);

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "failed to create reservation gate netns: %ld",
			   PTR_ERR(net));
		goto out_root;
	}
	nn = net_generic(net, nfsd_net_id);
	error = nfsd_ffv2_test_reservation_claim(nn, &root, uuid, token,
						 &reservation);
	if (error) {
		KUNIT_FAIL(test, "failed to claim gate reservation: %d", error);
		goto out_net;
	}
	error = nfsd_ffv2_reservation_gate_io(reservation);
	if (error) {
		KUNIT_FAIL(test, "failed to install reservation gates: %d", error);
		goto out_reservation;
	}
	blocked = nfsd_file_ffv2_test_alloc(inode, NFSD_MAY_READ, false);
	KUNIT_EXPECT_PTR_EQ(test, blocked, NULL);
	if (blocked)
		nfsd_file_put(blocked);
	nfsd_ffv2_reservation_abort(reservation);
	reservation = NULL;
	nf = nfsd_file_ffv2_test_alloc(inode, NFSD_MAY_READ, false);
	KUNIT_EXPECT_NOT_NULL(test, nf);
	if (nf)
		nfsd_file_put(nf);

out_reservation:
	if (reservation)
		nfsd_ffv2_reservation_abort(reservation);
out_net:
	put_net(net);
	net_ns_barrier();
	nf = nfsd_file_ffv2_test_alloc(inode, NFSD_MAY_READ, false);
	KUNIT_EXPECT_NOT_NULL(test, nf);
	if (nf)
		nfsd_file_put(nf);
out_root:
	path_put(&root);
	mutex_lock(&nfsd_mutex);
	nfsd_file_cache_shutdown();
	mutex_unlock(&nfsd_mutex);
}

static void nfsd_ffv2_compound_digest_test(struct kunit *test)
{
	static const u8 expected[NFSD4_FFV2_DIGEST_SIZE] = {
		0xa8, 0x97, 0x8f, 0xb3, 0xb7, 0x5b, 0xba, 0x40,
		0x2f, 0xce, 0x4b, 0x78, 0xb0, 0xbb, 0x68, 0xa5,
		0xf2, 0xfa, 0x34, 0x9f, 0xae, 0x98, 0x33, 0xfe,
		0x68, 0x13, 0x6a, 0x8a, 0x65, 0x3d, 0x32, 0x0d,
	};
	u8 wire[] = {
		0xde, 0xad, 0xbe, 0xef,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x00,
	};
	u8 changed[NFSD4_FFV2_DIGEST_SIZE];
	u8 digest[NFSD4_FFV2_DIGEST_SIZE];
	struct xdr_buf buf;

	xdr_buf_init(&buf, wire, sizeof(wire));
	buf.len = sizeof(wire);
	KUNIT_ASSERT_EQ(test,
			nfsd4_ffv2_compound_digest(&buf, 4, sizeof(wire) - 4,
						   digest),
			0);
	KUNIT_EXPECT_MEMEQ(test, digest, expected, sizeof(expected));

	wire[sizeof(wire) - 1] = 1;
	KUNIT_ASSERT_EQ(test,
			nfsd4_ffv2_compound_digest(&buf, 4, sizeof(wire) - 4,
						   changed),
			0);
	KUNIT_EXPECT_MEMNEQ(test, digest, changed, sizeof(digest));
}

static void nfsd_ffv2_replay_identity_test(struct kunit *test)
{
	struct nfsd4_compoundargs *args;
	struct nfsd4_slot *slot;

	args = kunit_kzalloc(test, sizeof(*args), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, args);
	slot = kunit_kzalloc(test, sizeof(*slot), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, slot);

	KUNIT_EXPECT_TRUE(test,
			  nfsd4_ffv2_replay_identity_match(args, slot));
	args->ffv2_present = true;
	args->ffv2_digest_valid = true;
	memset(args->ffv2_digest, 0x5a, sizeof(args->ffv2_digest));
	KUNIT_EXPECT_FALSE(test,
			   nfsd4_ffv2_replay_identity_match(args, slot));
	slot->sl_ffv2_present = true;
	memcpy(slot->sl_ffv2_digest, args->ffv2_digest,
	       sizeof(slot->sl_ffv2_digest));
	KUNIT_EXPECT_TRUE(test,
			  nfsd4_ffv2_replay_identity_match(args, slot));
	args->ffv2_digest[0] ^= 1;
	KUNIT_EXPECT_FALSE(test,
			   nfsd4_ffv2_replay_identity_match(args, slot));
	args->ffv2_digest[0] ^= 1;
	args->ffv2_digest_valid = false;
	KUNIT_EXPECT_FALSE(test,
			   nfsd4_ffv2_replay_identity_match(args, slot));
}

static void nfsd_ffv2_malformed_later_op_test(struct kunit *test)
{
	struct nfsd4_compoundargs *args;
	struct nfsd4_compound_state *cstate;
	struct nfsd_thread_local_info *ntli;
	struct svc_rqst *rqstp;
	struct auth_ops auth = {
		.flavour = RPC_AUTH_NULL,
	};
	struct xdr_stream xdr;
	struct xdr_buf buf;
	__be32 request[32];
	__be32 *later_op;
	__be32 *p = request;
	__be32 status;
	size_t request_len;
	int i;

	args = kunit_kzalloc(test, sizeof(*args), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, args);
	cstate = kunit_kzalloc(test, sizeof(*cstate), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, cstate);
	ntli = kunit_kzalloc(test, sizeof(*ntli), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ntli);
	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, rqstp);

	*p++ = cpu_to_be32(0);		/* tag */
	*p++ = cpu_to_be32(2);		/* minorversion */
	*p++ = cpu_to_be32(4);		/* opcount */
	*p++ = cpu_to_be32(OP_SEQUENCE);
	for (i = 0; i < 4; i++)
		*p++ = cpu_to_be32(0);	/* sessionid */
	*p++ = cpu_to_be32(1);		/* sequenceid */
	*p++ = cpu_to_be32(0);		/* slotid */
	*p++ = cpu_to_be32(0);		/* highest slotid */
	*p++ = cpu_to_be32(1);		/* cachethis */
	*p++ = cpu_to_be32(OP_PUTFH);
	*p++ = cpu_to_be32(4);
	*p++ = cpu_to_be32(0x01020304);
	*p++ = cpu_to_be32(OP_CHUNK_READ);
	for (i = 0; i < 4; i++)
		*p++ = cpu_to_be32(i);	/* stateid */
	*p++ = cpu_to_be32(0);		/* offset */
	*p++ = cpu_to_be32(0);
	*p++ = cpu_to_be32(1);		/* count */
	later_op = p;
	*p++ = cpu_to_be32(OP_GETATTR);	/* missing bitmap */

	request_len = (char *)p - (char *)request;
	xdr_buf_init(&buf, request, request_len);
	buf.len = request_len;
	xdr_init_decode(&xdr, &buf, request, NULL);
	rqstp->rq_argp = args;
	rqstp->rq_private = ntli;
	rqstp->rq_authop = &auth;
	KUNIT_ASSERT_TRUE(test, nfs4svc_decode_compoundargs(rqstp, &xdr));
	KUNIT_EXPECT_TRUE(test, args->ffv2_present);
	KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);
	KUNIT_EXPECT_EQ(test, args->ffv2_decode_class,
			NFSD4_FFV2_DECODE_BADXDR);
	KUNIT_ASSERT_EQ(test, args->opcnt, 4U);
	KUNIT_ASSERT_NOT_NULL(test, args->ops[2].opdesc);
	status = args->ops[2].opdesc->op_func(rqstp, cstate,
					     &args->ops[2].u);
	KUNIT_EXPECT_EQ(test, status, nfserr_bad_xdr);
	nfsd4_release_compoundargs(rqstp);

	p = later_op;
	*p++ = cpu_to_be32(OP_CHUNK_FINALIZE);
	for (i = 0; i < 4; i++)
		*p++ = cpu_to_be32(i);	/* stateid */
	*p++ = cpu_to_be32(0);		/* offset */
	*p++ = cpu_to_be32(0);
	*p++ = cpu_to_be32(U32_MAX);
	request_len = (char *)p - (char *)request;
	xdr_buf_init(&buf, request, request_len);
	buf.len = request_len;
	xdr_init_decode(&xdr, &buf, request, NULL);
	KUNIT_ASSERT_TRUE(test, nfs4svc_decode_compoundargs(rqstp, &xdr));
	KUNIT_EXPECT_TRUE(test, args->ffv2_present);
	KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);
	KUNIT_EXPECT_EQ(test, args->ffv2_decode_class,
			NFSD4_FFV2_DECODE_ERROR);
	KUNIT_EXPECT_EQ(test, args->ffv2_decode_status, nfserr_inval);
	KUNIT_ASSERT_EQ(test, args->opcnt, 4U);
	KUNIT_ASSERT_NOT_NULL(test, args->ops[2].opdesc);
	status = args->ops[2].opdesc->op_func(rqstp, cstate,
					     &args->ops[2].u);
	KUNIT_EXPECT_EQ(test, status, nfserr_inval);
	nfsd4_release_compoundargs(rqstp);
}

/*
 * Authority tests.  These drive the production epoch, link, publication, and
 * admission paths; only the session lookup and credential copy are bypassed,
 * because a live NFS client cannot be established inside KUnit.
 */

static struct nfsd_net *nfsd_ffv2_authority_test_net(struct kunit *test)
{
	struct nfsd_net *nn = nfsd_ffv2_test_net(test);

	if (!nn)
		return NULL;
	return nn;
}

static struct nfsd4_session *nfsd_ffv2_test_session(struct kunit *test)
{
	struct nfsd4_session *session;

	session = kunit_kzalloc(test, sizeof(*session), GFP_KERNEL);
	if (session)
		nfsd_ffv2_session_init(session);
	return session;
}

static void nfsd_ffv2_authority_qualify_test(struct kunit *test)
{
	struct gss_api_mech *mech;
	struct nfs4_client clp;

	mech = gss_mech_get_by_pseudoflavor(RPC_AUTH_GSS_KRB5I);
	if (!mech)
		kunit_skip(test, "krb5 GSS mechanism unavailable");

	/* A fully qualified MDS control client. */
	memset(&clp, 0, sizeof(clp));
	clp.cl_minorversion = 1;
	clp.cl_exchange_flags = EXCHGID4_FLAG_USE_PNFS_MDS;
	clp.cl_mach_cred = true;
	clp.cl_cred.cr_gss_mech = mech;
	clp.cl_cred.cr_flavor = RPC_AUTH_GSS_KRB5I;
	clp.cl_cred.cr_principal = "nfs@ds.example.net";
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_authority_qualify(&clp));

	/* Privacy also qualifies. */
	clp.cl_cred.cr_flavor = RPC_AUTH_GSS_KRB5P;
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_authority_qualify(&clp));

	/* A raw principal alone is sufficient. */
	clp.cl_cred.cr_principal = NULL;
	clp.cl_cred.cr_raw_principal = "nfs/ds.example.net@EXAMPLE.NET";
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_authority_qualify(&clp));
	clp.cl_cred.cr_principal = "nfs@ds.example.net";

	/* Minor version 0 has no session and cannot be a control root. */
	clp.cl_minorversion = 0;
	KUNIT_EXPECT_EQ(test, -EACCES, nfsd_ffv2_authority_qualify(&clp));
	clp.cl_minorversion = 1;

	/* The self-declared PNFS-MDS flag is necessary. */
	clp.cl_exchange_flags = 0;
	KUNIT_EXPECT_EQ(test, -EACCES, nfsd_ffv2_authority_qualify(&clp));
	clp.cl_exchange_flags = EXCHGID4_FLAG_USE_PNFS_MDS;

	/* ... but not sufficient without an active machine credential. */
	clp.cl_mach_cred = false;
	KUNIT_EXPECT_EQ(test, -EACCES, nfsd_ffv2_authority_qualify(&clp));
	clp.cl_mach_cred = true;

	/* AUTH_SYS is not accepted as MDS control authority. */
	clp.cl_cred.cr_gss_mech = NULL;
	clp.cl_cred.cr_flavor = RPC_AUTH_UNIX;
	KUNIT_EXPECT_EQ(test, -EACCES, nfsd_ffv2_authority_qualify(&clp));
	clp.cl_cred.cr_gss_mech = mech;

	/* GSS without integrity or privacy is not accepted either. */
	clp.cl_cred.cr_flavor = RPC_AUTH_GSS_KRB5;
	KUNIT_EXPECT_EQ(test, -EACCES, nfsd_ffv2_authority_qualify(&clp));
	clp.cl_cred.cr_flavor = RPC_AUTH_GSS_KRB5I;

	/* A missing principal is rejected. */
	clp.cl_cred.cr_principal = NULL;
	clp.cl_cred.cr_raw_principal = NULL;
	KUNIT_EXPECT_EQ(test, -EACCES, nfsd_ffv2_authority_qualify(&clp));

	gss_mech_put(mech);
}

static void nfsd_ffv2_authority_epoch_test(struct kunit *test)
{
	struct nfsd_net *nn;
	u64 first = 0, second = 0;

	nn = nfsd_ffv2_authority_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);

	/* Epochs start nonzero and increment. */
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_test_authority_epoch_alloc(nn,
								      &first));
	KUNIT_EXPECT_NE(test, 0ULL, first);
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_test_authority_epoch_alloc(nn,
								      &second));
	KUNIT_EXPECT_EQ(test, first + 1, second);

	/* A zero counter never issues zero. */
	nfsd_ffv2_test_authority_epoch_set(nn, 0);
	KUNIT_EXPECT_EQ(test, -EOVERFLOW,
			nfsd_ffv2_test_authority_epoch_alloc(nn, &second));

	/* Exhaustion fails closed rather than wrapping or reusing. */
	nfsd_ffv2_test_authority_epoch_set(nn, U64_MAX);
	KUNIT_EXPECT_EQ(test, -EOVERFLOW,
			nfsd_ffv2_test_authority_epoch_alloc(nn, &second));

	/* The last usable epoch is still issued exactly once. */
	nfsd_ffv2_test_authority_epoch_set(nn, U64_MAX - 1);
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_test_authority_epoch_alloc(nn,
								      &second));
	KUNIT_EXPECT_EQ(test, U64_MAX - 1, second);
	KUNIT_EXPECT_EQ(test, -EOVERFLOW,
			nfsd_ffv2_test_authority_epoch_alloc(nn, &second));

	nfsd_ffv2_test_net_destroy(test, nn);
}

static void nfsd_ffv2_authority_unknown_locator_test(struct kunit *test)
{
	static const u8 locator[NFS4_MAX_SESSIONID_LEN] = {
		0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4,
		5, 6, 7, 8, 9, 10, 11, 12,
	};
	struct nfsd_ffv2_authority *authority = NULL;
	struct nfsd_ffv2_worker_ctx worker = {};
	bool worker_installed = false;
	bool service_up = false;
	struct nfsd_net *nn;
	struct net *net;
	int error;

	/*
	 * A running service is required: registration is only reachable once
	 * nfsd has started in this namespace and the session table exists.
	 */
	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "failed to create test netns: %ld",
			   PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	error = nfsd_ffv2_worker_ctx_install(&worker, net);
	if (error)
		goto out_cleanup;
	worker_installed = true;
	error = nfsd_ffv2_start_test_service(net, &worker);
	if (error)
		goto out_cleanup;
	service_up = true;

	/*
	 * An unknown locator, and one naming a session in another namespace,
	 * are indistinguishable here: neither is visible in this table.
	 */
	KUNIT_EXPECT_EQ(test, -ENOENT,
			nfsd_ffv2_authority_register(nn, net, locator,
						     &authority));
	KUNIT_EXPECT_NULL(test, authority);
	error = 0;

out_cleanup:
	complete_all(&worker.run);
	complete_all(&worker.allow_complete);
	if (service_up)
		nfsd_shutdown_threads(net);
	if (worker_installed)
		nfsd_ffv2_worker_ctx_remove(&worker);
	put_net(net);
	net_ns_barrier();
	if (error)
		KUNIT_FAIL(test, "unknown locator lifecycle failed: %d", error);
}

static void nfsd_ffv2_authority_publish_test(struct kunit *test)
{
	struct nfsd_ffv2_authority *authority;
	struct nfsd4_session *session;
	struct nfsd_net *nn;

	nn = nfsd_ffv2_authority_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	session = nfsd_ffv2_test_session(test);
	KUNIT_ASSERT_NOT_NULL(test, session);

	authority = nfsd_ffv2_test_authority_create(nn, session);
	KUNIT_ASSERT_NOT_NULL(test, authority);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_authority_linked(authority));
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_test_authority_published(authority));
	KUNIT_EXPECT_NE(test, 0ULL,
			nfsd_ffv2_test_authority_epoch(authority));

	/* PREPARED is consumed exactly once, recording the generation. */
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_authority_publish(authority, 7));
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_authority_published(authority));
	KUNIT_EXPECT_EQ(test, 7ULL,
			nfsd_ffv2_test_authority_gen(authority));
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_authority_publish(authority, 9));
	KUNIT_EXPECT_EQ(test, 7ULL,
			nfsd_ffv2_test_authority_gen(authority));

	/* Detach is idempotent from every trigger. */
	nfsd_ffv2_authority_detach(authority);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_authority_dead(authority));
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_test_authority_linked(authority));
	nfsd_ffv2_authority_detach(authority);
	nfsd_ffv2_authority_detach(authority);
	spin_lock(&nn->client_lock);
	nfsd_ffv2_session_dead_locked(session);
	spin_unlock(&nn->client_lock);
	KUNIT_EXPECT_TRUE(test, list_empty(&session->se_ffv2_authorities));

	nfsd_ffv2_authority_put(authority);
	nfsd_ffv2_test_net_destroy(test, nn);
}

static void nfsd_ffv2_authority_death_race_test(struct kunit *test)
{
	struct nfsd_ffv2_authority *authority;
	struct nfsd4_session *session;
	struct nfsd_net *nn;

	nn = nfsd_ffv2_authority_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	session = nfsd_ffv2_test_session(test);
	KUNIT_ASSERT_NOT_NULL(test, session);

	/* Linearization 1: session death wins, so publication must abort. */
	authority = nfsd_ffv2_test_authority_create(nn, session);
	KUNIT_ASSERT_NOT_NULL(test, authority);
	spin_lock(&nn->client_lock);
	nfsd_ffv2_session_dead_locked(session);
	spin_unlock(&nn->client_lock);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_authority_dead(authority));
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_authority_publish(authority, 11));
	KUNIT_EXPECT_EQ(test, -ESHUTDOWN,
			nfsd_ffv2_authority_token_get(authority));
	KUNIT_EXPECT_EQ(test, 0ULL,
			nfsd_ffv2_test_authority_gen(authority));
	nfsd_ffv2_authority_put(authority);

	/* Linearization 2: publication wins, then death makes it unusable. */
	authority = nfsd_ffv2_test_authority_create(nn, session);
	KUNIT_ASSERT_NOT_NULL(test, authority);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_authority_publish(authority, 12));
	spin_lock(&nn->client_lock);
	nfsd_ffv2_session_dead_locked(session);
	spin_unlock(&nn->client_lock);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_authority_dead(authority));
	KUNIT_EXPECT_TRUE(test, list_empty(&session->se_ffv2_authorities));
	KUNIT_EXPECT_EQ(test, -ESHUTDOWN,
			nfsd_ffv2_authority_token_get(authority));
	nfsd_ffv2_authority_put(authority);

	/* Drains the retirement work queued by the second linearization. */
	nfsd_ffv2_test_net_destroy(test, nn);
}

static void nfsd_ffv2_authority_admission_test(struct kunit *test)
{
	struct nfsd_ffv2_authority *authority;
	struct nfsd4_session *session;
	struct nfsd_net *nn;

	nn = nfsd_ffv2_authority_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	session = nfsd_ffv2_test_session(test);
	KUNIT_ASSERT_NOT_NULL(test, session);
	authority = nfsd_ffv2_test_authority_create(nn, session);
	KUNIT_ASSERT_NOT_NULL(test, authority);

	/* Tokens and work are admitted while the gates are open. */
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_authority_admissions_idle(nn));
	KUNIT_EXPECT_EQ(test, -ESHUTDOWN,
			nfsd_ffv2_authority_token_get(authority));
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_authority_publish(authority, 1));
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_authority_token_get(authority));
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_test_authority_admissions_idle(nn));
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_authority_work_admit(nn));

	/* Closing the gates rejects new admissions but not existing ones. */
	nfsd_ffv2_test_authority_admissions_close(nn);
	KUNIT_EXPECT_EQ(test, -ESHUTDOWN,
			nfsd_ffv2_authority_token_get(authority));
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_test_authority_work_admit(nn));
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_test_authority_admissions_idle(nn));

	/* Both counters must reach zero before teardown may proceed. */
	nfsd_ffv2_authority_token_put(authority);
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_test_authority_admissions_idle(nn));
	nfsd_ffv2_test_authority_work_done(nn);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_authority_admissions_idle(nn));

	nfsd_ffv2_authority_detach(authority);
	nfsd_ffv2_authority_put(authority);
	nfsd_ffv2_test_net_destroy(test, nn);
}

static void nfsd_ffv2_authority_provider_gate_test(struct kunit *test)
{
	struct nfsd_net *nn;

	nn = nfsd_ffv2_authority_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);

	/* Authority registration does not open the provider gate. */
	mutex_lock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP, nfsd_ffv2_register(nn));
	mutex_unlock(&nfsd_mutex);

	nfsd_ffv2_test_net_destroy(test, nn);
}

/*
 * Trusted stateid registry tests.  These drive the production registry,
 * lookup, renewal, revoke, and teardown paths.  Authorities are built with
 * the test constructor and published so that installation can bind to a
 * real issuer epoch.
 */

static const u8 nfsd_ffv2_test_uuid_a[16] = {
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
};

static const u8 nfsd_ffv2_test_uuid_b[16] = {
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
};

static stateid_t nfsd_ffv2_test_stateid(u32 seqid, u32 boot, u32 id, u32 so)
{
	stateid_t stateid;

	memset(&stateid, 0, sizeof(stateid));
	stateid.si_generation = seqid;
	stateid.si_opaque.so_clid.cl_boot = boot;
	stateid.si_opaque.so_clid.cl_id = id;
	stateid.si_opaque.so_id = so;
	return stateid;
}

static void nfsd_ffv2_test_trust_request(struct nfsd_ffv2_trust_request *req,
					 const stateid_t *stateid,
					 const u8 *uuid, u32 iomode,
					 const char *principal, int seconds)
{
	struct timespec64 now;

	memset(req, 0, sizeof(*req));
	/* Ordinary data client unless a test overrides it. */
	req->actor = NFSD_FFV2_CALLER_DATA_CLIENT;
	req->stateid = *stateid;
	req->object_uuid = uuid;
	req->pnfs_clientid.cl_boot = stateid->si_opaque.so_clid.cl_boot;
	req->pnfs_clientid.cl_id = stateid->si_opaque.so_clid.cl_id;
	req->client_id = 7;
	req->iomode = iomode;
	req->profile_mask = NFSD_FFV2_PROFILE_READ_DATA |
			    NFSD_FFV2_PROFILE_READ_METADATA;
	ktime_get_real_ts64(&now);
	req->expires.tv_sec = now.tv_sec + seconds;
	req->expires.tv_nsec = 0;
	req->principal = principal;
}

struct nfsd_ffv2_trust_fixture {
	struct nfsd_net			*nn;
	struct nfsd4_session		*session;
	struct nfsd_ffv2_authority	*authority;
	struct nfsd_ffv2_trust_registry	*registry;
	u64				epoch;
};

static bool nfsd_ffv2_trust_fixture_init(struct kunit *test,
					 struct nfsd_ffv2_trust_fixture *f,
					 u64 generation_id)
{
	f->nn = nfsd_ffv2_authority_test_net(test);
	if (!f->nn)
		return false;
	f->session = nfsd_ffv2_test_session(test);
	if (!f->session)
		return false;
	f->authority = nfsd_ffv2_test_authority_create(f->nn, f->session);
	if (!f->authority)
		return false;
	if (!nfsd_ffv2_authority_publish(f->authority, generation_id))
		return false;
	if (!nfsd_ffv2_authority_published(f->authority, &f->epoch))
		return false;
	f->registry = nfsd_ffv2_test_trust_registry_alloc();
	return f->registry;
}

static void nfsd_ffv2_trust_fixture_exit(struct kunit *test,
					 struct nfsd_ffv2_trust_fixture *f)
{
	if (f->registry)
		nfsd_ffv2_test_trust_registry_free(f->registry);
	if (f->authority) {
		nfsd_ffv2_authority_detach(f->authority);
		nfsd_ffv2_authority_put(f->authority);
	}
	if (f->nn)
		nfsd_ffv2_test_net_destroy(test, f->nn);
}

static void nfsd_ffv2_trust_lookup_test(struct kunit *test)
{
	struct nfsd_ffv2_trust_fixture f = {};
	struct nfsd_ffv2_trust_entry *entry;
	struct nfsd_ffv2_trust_request req;
	stateid_t sid, other;

	KUNIT_ASSERT_TRUE(test, nfsd_ffv2_trust_fixture_init(test, &f, 31));

	sid = nfsd_ffv2_test_stateid(1, 0x11, 0x22, 0x33);
	nfsd_ffv2_test_trust_request(&req, &sid, nfsd_ffv2_test_uuid_a,
				     IOMODE_RW, NULL, 3600);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						31, &req));
	KUNIT_EXPECT_EQ(test, 1U, nfsd_ffv2_test_trust_entries(f.registry));

	/* Exact key hits. */
	entry = nfsd_ffv2_trust_lookup(f.registry, &sid,
				       nfsd_ffv2_test_uuid_a, f.epoch);
	KUNIT_ASSERT_NOT_NULL(test, entry);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_validate(entry, 31,
						 nfsd_ffv2_test_uuid_a,
						 f.epoch,
						 NFSD_FFV2_PROFILE_READ_DATA,
						 NULL));
	/* A profile bit the entry does not carry is refused. */
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_trust_validate(entry, 31,
						 nfsd_ffv2_test_uuid_a,
						 f.epoch,
						 NFSD_FFV2_PROFILE_WRITE_DATA,
						 NULL));
	/* Wrong generation, object, or issuer epoch all fail. */
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_trust_validate(entry, 32,
						 nfsd_ffv2_test_uuid_a,
						 f.epoch,
						 NFSD_FFV2_PROFILE_READ_DATA,
						 NULL));
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_trust_validate(entry, 31,
						 nfsd_ffv2_test_uuid_b,
						 f.epoch,
						 NFSD_FFV2_PROFILE_READ_DATA,
						 NULL));
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_trust_validate(entry, 31,
						 nfsd_ffv2_test_uuid_a,
						 f.epoch + 1,
						 NFSD_FFV2_PROFILE_READ_DATA,
						 NULL));
	nfsd_ffv2_trust_entry_put(entry);

	/* A different seqid is a distinct key, not an update. */
	other = nfsd_ffv2_test_stateid(2, 0x11, 0x22, 0x33);
	KUNIT_EXPECT_NULL(test,
			  nfsd_ffv2_trust_lookup(f.registry, &other,
						 nfsd_ffv2_test_uuid_a,
						 f.epoch));
	/* Wrong object and wrong issuer epoch miss. */
	KUNIT_EXPECT_NULL(test,
			  nfsd_ffv2_trust_lookup(f.registry, &sid,
						 nfsd_ffv2_test_uuid_b,
						 f.epoch));
	KUNIT_EXPECT_NULL(test,
			  nfsd_ffv2_trust_lookup(f.registry, &sid,
						 nfsd_ffv2_test_uuid_a,
						 f.epoch + 1));

	nfsd_ffv2_trust_fixture_exit(test, &f);
}

static void nfsd_ffv2_trust_renewal_test(struct kunit *test)
{
	struct nfsd_ffv2_trust_fixture f = {};
	struct nfsd_ffv2_trust_entry *old, *new;
	struct nfsd_ffv2_trust_request req;
	stateid_t sid;

	KUNIT_ASSERT_TRUE(test, nfsd_ffv2_trust_fixture_init(test, &f, 41));

	sid = nfsd_ffv2_test_stateid(5, 0x1, 0x2, 0x3);
	nfsd_ffv2_test_trust_request(&req, &sid, nfsd_ffv2_test_uuid_a,
				     IOMODE_RW, "nfs@ds.example.net", 3600);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						41, &req));
	KUNIT_EXPECT_EQ(test, strlen("nfs@ds.example.net"),
			nfsd_ffv2_test_trust_bytes(f.registry));

	old = nfsd_ffv2_trust_lookup(f.registry, &sid, nfsd_ffv2_test_uuid_a,
				     f.epoch);
	KUNIT_ASSERT_NOT_NULL(test, old);

	/* Exact renewal: same issuer, target, client id, and iomode. */
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						41, &req));
	KUNIT_EXPECT_EQ(test, 1U, nfsd_ffv2_test_trust_entries(f.registry));

	/* The reader holding the old entry still sees it as replaced. */
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_trust_replaced(old));
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_trust_validate(old, 41,
						 nfsd_ffv2_test_uuid_a,
						 f.epoch,
						 NFSD_FFV2_PROFILE_READ_DATA,
						 "nfs@ds.example.net"));
	/* A new lookup reaches the replacement, which is live. */
	new = nfsd_ffv2_trust_lookup(f.registry, &sid, nfsd_ffv2_test_uuid_a,
				     f.epoch);
	KUNIT_ASSERT_NOT_NULL(test, new);
	KUNIT_EXPECT_PTR_NE(test, old, new);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_validate(new, 41,
						 nfsd_ffv2_test_uuid_a,
						 f.epoch,
						 NFSD_FFV2_PROFILE_READ_DATA,
						 "nfs@ds.example.net"));
	/* A principal mismatch is ACCESS, not BAD_STATEID. */
	KUNIT_EXPECT_EQ(test, nfserr_acces,
			nfsd_ffv2_trust_validate(new, 41,
						 nfsd_ffv2_test_uuid_a,
						 f.epoch,
						 NFSD_FFV2_PROFILE_READ_DATA,
						 "other@ds.example.net"));
	nfsd_ffv2_trust_entry_put(old);
	nfsd_ffv2_trust_entry_put(new);

	/* Changing the iomode is a mismatch, never a silent retarget. */
	nfsd_ffv2_test_trust_request(&req, &sid, nfsd_ffv2_test_uuid_a,
				     IOMODE_READ, "nfs@ds.example.net", 3600);
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						41, &req));
	KUNIT_EXPECT_EQ(test, 1U, nfsd_ffv2_test_trust_entries(f.registry));

	nfsd_ffv2_trust_fixture_exit(test, &f);
}

static void nfsd_ffv2_trust_revoke_test(struct kunit *test)
{
	struct nfsd_ffv2_trust_fixture f = {};
	struct nfsd_ffv2_trust_entry *entry;
	struct nfsd_ffv2_trust_request req;
	clientid_t target;
	stateid_t a, b, c;

	KUNIT_ASSERT_TRUE(test, nfsd_ffv2_trust_fixture_init(test, &f, 51));

	a = nfsd_ffv2_test_stateid(1, 0xaa, 0xbb, 1);
	b = nfsd_ffv2_test_stateid(1, 0xaa, 0xbb, 2);
	c = nfsd_ffv2_test_stateid(1, 0xcc, 0xdd, 3);
	nfsd_ffv2_test_trust_request(&req, &a, nfsd_ffv2_test_uuid_a,
				     IOMODE_RW, NULL, 3600);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						51, &req));
	nfsd_ffv2_test_trust_request(&req, &b, nfsd_ffv2_test_uuid_a,
				     IOMODE_RW, NULL, 3600);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						51, &req));
	nfsd_ffv2_test_trust_request(&req, &c, nfsd_ffv2_test_uuid_a,
				     IOMODE_RW, NULL, 3600);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						51, &req));
	KUNIT_EXPECT_EQ(test, 3U, nfsd_ffv2_test_trust_entries(f.registry));

	/* Revoking one exact entry leaves the others reachable. */
	KUNIT_EXPECT_TRUE(test,
			  nfsd_ffv2_trust_revoke(f.registry, &a,
						 nfsd_ffv2_test_uuid_a,
						 f.epoch));
	KUNIT_EXPECT_EQ(test, 2U, nfsd_ffv2_test_trust_entries(f.registry));
	KUNIT_EXPECT_NULL(test,
			  nfsd_ffv2_trust_lookup(f.registry, &a,
						 nfsd_ffv2_test_uuid_a,
						 f.epoch));
	/* Revoking again, and revoking an unknown key, are both no-ops. */
	KUNIT_EXPECT_FALSE(test,
			   nfsd_ffv2_trust_revoke(f.registry, &a,
						  nfsd_ffv2_test_uuid_a,
						  f.epoch));
	/* A different issuer epoch must not match another issuer's entry. */
	KUNIT_EXPECT_FALSE(test,
			   nfsd_ffv2_trust_revoke(f.registry, &b,
						  nfsd_ffv2_test_uuid_a,
						  f.epoch + 1));
	KUNIT_EXPECT_EQ(test, 2U, nfsd_ffv2_test_trust_entries(f.registry));

	entry = nfsd_ffv2_trust_lookup(f.registry, &b, nfsd_ffv2_test_uuid_a,
				       f.epoch);
	KUNIT_ASSERT_NOT_NULL(test, entry);
	nfsd_ffv2_trust_entry_put(entry);

	/* Bulk revoke for another issuer removes nothing. */
	KUNIT_EXPECT_EQ(test, 0U,
			nfsd_ffv2_trust_bulk_revoke(f.registry, f.epoch + 1,
						    NULL));
	KUNIT_EXPECT_EQ(test, 2U, nfsd_ffv2_test_trust_entries(f.registry));

	/* A selected target removes only that client's entries. */
	target.cl_boot = 0xaa;
	target.cl_id = 0xbb;
	KUNIT_EXPECT_EQ(test, 1U,
			nfsd_ffv2_trust_bulk_revoke(f.registry, f.epoch,
						    &target));
	KUNIT_EXPECT_EQ(test, 1U, nfsd_ffv2_test_trust_entries(f.registry));

	/* A NULL target removes all of this issuer's remaining entries. */
	KUNIT_EXPECT_EQ(test, 1U,
			nfsd_ffv2_trust_bulk_revoke(f.registry, f.epoch, NULL));
	KUNIT_EXPECT_EQ(test, 0U, nfsd_ffv2_test_trust_entries(f.registry));
	KUNIT_EXPECT_EQ(test, 0U, nfsd_ffv2_test_trust_bytes(f.registry));

	nfsd_ffv2_trust_fixture_exit(test, &f);
}

static void nfsd_ffv2_trust_limits_test(struct kunit *test)
{
	struct nfsd_ffv2_trust_fixture f = {};
	struct nfsd_ffv2_trust_request req;
	char *principal;
	stateid_t sid;

	KUNIT_ASSERT_TRUE(test, nfsd_ffv2_trust_fixture_init(test, &f, 61));

	sid = nfsd_ffv2_test_stateid(1, 1, 1, 1);

	/* An over-long principal is refused before any allocation. */
	principal = kunit_kzalloc(test, NFSD_FFV2_TRUST_PRINCIPAL_MAX + 2,
				  GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, principal);
	memset(principal, 'p', NFSD_FFV2_TRUST_PRINCIPAL_MAX + 1);
	nfsd_ffv2_test_trust_request(&req, &sid, nfsd_ffv2_test_uuid_a,
				     IOMODE_RW, principal, 3600);
	KUNIT_EXPECT_EQ(test, nfserr_inval,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						61, &req));
	KUNIT_EXPECT_EQ(test, 0U, nfsd_ffv2_test_trust_entries(f.registry));

	/* Exactly at the bound is accepted. */
	principal[NFSD_FFV2_TRUST_PRINCIPAL_MAX] = '\0';
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						61, &req));
	KUNIT_EXPECT_EQ(test, (size_t)NFSD_FFV2_TRUST_PRINCIPAL_MAX,
			nfsd_ffv2_test_trust_bytes(f.registry));

	/* An invalid iomode, nanoseconds, or profile bit is rejected. */
	nfsd_ffv2_test_trust_request(&req, &sid, nfsd_ffv2_test_uuid_b,
				     0, NULL, 3600);
	KUNIT_EXPECT_EQ(test, nfserr_inval,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						61, &req));
	nfsd_ffv2_test_trust_request(&req, &sid, nfsd_ffv2_test_uuid_b,
				     IOMODE_RW, NULL, 3600);
	req.expires.tv_nsec = NSEC_PER_SEC;
	KUNIT_EXPECT_EQ(test, nfserr_inval,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						61, &req));
	nfsd_ffv2_test_trust_request(&req, &sid, nfsd_ffv2_test_uuid_b,
				     IOMODE_RW, NULL, 3600);
	req.profile_mask = (u32)~NFSD_FFV2_PROFILE_ALL;
	KUNIT_EXPECT_EQ(test, nfserr_inval,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						61, &req));
	KUNIT_EXPECT_EQ(test, 1U, nfsd_ffv2_test_trust_entries(f.registry));

	nfsd_ffv2_trust_fixture_exit(test, &f);
}

static void nfsd_ffv2_trust_expiry_test(struct kunit *test)
{
	struct nfsd_ffv2_trust_fixture f = {};
	struct nfsd_ffv2_trust_entry *entry;
	struct nfsd_ffv2_trust_request req;
	stateid_t sid;

	KUNIT_ASSERT_TRUE(test, nfsd_ffv2_trust_fixture_init(test, &f, 71));

	sid = nfsd_ffv2_test_stateid(9, 3, 4, 5);
	nfsd_ffv2_test_trust_request(&req, &sid, nfsd_ffv2_test_uuid_a,
				     IOMODE_RW, NULL, -3600);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						71, &req));

	/*
	 * An expired entry is still reachable, but expiry is enforced on
	 * every validation rather than depending on a reaper.
	 */
	entry = nfsd_ffv2_trust_lookup(f.registry, &sid,
				       nfsd_ffv2_test_uuid_a, f.epoch);
	KUNIT_ASSERT_NOT_NULL(test, entry);
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_trust_validate(entry, 71,
						 nfsd_ffv2_test_uuid_a,
						 f.epoch,
						 NFSD_FFV2_PROFILE_READ_DATA,
						 NULL));
	nfsd_ffv2_trust_entry_put(entry);

	nfsd_ffv2_trust_fixture_exit(test, &f);
}

static void nfsd_ffv2_trust_retire_test(struct kunit *test)
{
	struct nfsd_ffv2_trust_fixture f = {};
	struct nfsd_ffv2_trust_entry *held;
	struct nfsd_ffv2_trust_request req;
	stateid_t sid;

	KUNIT_ASSERT_TRUE(test, nfsd_ffv2_trust_fixture_init(test, &f, 81));

	sid = nfsd_ffv2_test_stateid(4, 8, 9, 10);
	nfsd_ffv2_test_trust_request(&req, &sid, nfsd_ffv2_test_uuid_a,
				     IOMODE_RW, "svc@ds.example.net", 3600);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						81, &req));

	/* A request already holding a reference survives retirement. */
	held = nfsd_ffv2_trust_lookup(f.registry, &sid, nfsd_ffv2_test_uuid_a,
				      f.epoch);
	KUNIT_ASSERT_NOT_NULL(test, held);

	nfsd_ffv2_trust_retire(f.registry);
	KUNIT_EXPECT_EQ(test, 0U, nfsd_ffv2_test_trust_entries(f.registry));
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_trust_revoked(held));
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_trust_validate(held, 81,
						 nfsd_ffv2_test_uuid_a,
						 f.epoch,
						 NFSD_FFV2_PROFILE_READ_DATA,
						 "svc@ds.example.net"));
	/* New lookups miss immediately. */
	KUNIT_EXPECT_NULL(test,
			  nfsd_ffv2_trust_lookup(f.registry, &sid,
						 nfsd_ffv2_test_uuid_a,
						 f.epoch));
	/* Installing into a retired registry fails closed. */
	KUNIT_EXPECT_EQ(test, nfserr_stale,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						81, &req));
	/* Repeated retirement is a no-op. */
	nfsd_ffv2_trust_retire(f.registry);

	nfsd_ffv2_trust_entry_put(held);
	KUNIT_EXPECT_EQ(test, 0U, nfsd_ffv2_test_trust_bytes(f.registry));

	nfsd_ffv2_trust_fixture_exit(test, &f);
}

static void nfsd_ffv2_trust_dead_authority_test(struct kunit *test)
{
	struct nfsd_ffv2_trust_fixture f = {};
	struct nfsd_ffv2_trust_request req;
	stateid_t sid;

	KUNIT_ASSERT_TRUE(test, nfsd_ffv2_trust_fixture_init(test, &f, 91));

	/* Session death makes the issuer unusable for new registrations. */
	spin_lock(&f.nn->client_lock);
	nfsd_ffv2_session_dead_locked(f.session);
	spin_unlock(&f.nn->client_lock);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_authority_dead(f.authority));

	sid = nfsd_ffv2_test_stateid(1, 5, 5, 5);
	nfsd_ffv2_test_trust_request(&req, &sid, nfsd_ffv2_test_uuid_a,
				     IOMODE_RW, NULL, 3600);
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						91, &req));
	KUNIT_EXPECT_EQ(test, 0U, nfsd_ffv2_test_trust_entries(f.registry));

	nfsd_ffv2_trust_fixture_exit(test, &f);
}

/*
 * Renewal must not disturb a live entry when installation fails.  The
 * replacement itself cannot allocate, so the failure is injected to prove
 * the unwind rather than to model a reachable allocation error.
 */
static void nfsd_ffv2_trust_renewal_failure_test(struct kunit *test)
{
	struct nfsd_ffv2_trust_fixture f = {};
	struct nfsd_ffv2_trust_entry *entry;
	struct nfsd_ffv2_trust_request req;
	stateid_t sid;

	KUNIT_ASSERT_TRUE(test, nfsd_ffv2_trust_fixture_init(test, &f, 101));

	sid = nfsd_ffv2_test_stateid(3, 2, 1, 4);
	nfsd_ffv2_test_trust_request(&req, &sid, nfsd_ffv2_test_uuid_a,
				     IOMODE_RW, "keep@ds.example.net", 3600);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						101, &req));
	KUNIT_EXPECT_EQ(test, 1U, nfsd_ffv2_test_trust_entries(f.registry));

	/* Renewal fails at installation. */
	nfsd_ffv2_test_fault_arm(NFSD_FFV2_FAULT_TRUST_REPLACE);
	KUNIT_EXPECT_EQ(test, nfserr_delay,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						101, &req));

	/* The caller's existing stateid must still be live and usable. */
	KUNIT_EXPECT_EQ(test, 1U, nfsd_ffv2_test_trust_entries(f.registry));
	entry = nfsd_ffv2_trust_lookup(f.registry, &sid,
				       nfsd_ffv2_test_uuid_a, f.epoch);
	KUNIT_ASSERT_NOT_NULL(test, entry);
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_test_trust_replaced(entry));
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_validate(entry, 101,
						 nfsd_ffv2_test_uuid_a,
						 f.epoch,
						 NFSD_FFV2_PROFILE_READ_DATA,
						 "keep@ds.example.net"));
	nfsd_ffv2_trust_entry_put(entry);

	/* The failed attempt returned its own budget and nothing else. */
	KUNIT_EXPECT_EQ(test, strlen("keep@ds.example.net"),
			nfsd_ffv2_test_trust_bytes(f.registry));

	/* A subsequent renewal still succeeds. */
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						101, &req));
	KUNIT_EXPECT_EQ(test, 1U, nfsd_ffv2_test_trust_entries(f.registry));

	nfsd_ffv2_trust_fixture_exit(test, &f);
}

/* Destruction must not complete while a request still holds a reference. */
struct nfsd_ffv2_trust_drain_ctx {
	struct nfsd_ffv2_trust_registry	*registry;
	struct completion		destroy_entered;
	struct completion		destroy_done;
};

static int nfsd_ffv2_trust_drain_thread(void *data)
{
	struct nfsd_ffv2_trust_drain_ctx *ctx = data;

	complete(&ctx->destroy_entered);
	nfsd_ffv2_test_trust_registry_free(ctx->registry);
	complete(&ctx->destroy_done);
	return 0;
}

static void nfsd_ffv2_trust_destroy_drain_test(struct kunit *test)
{
	struct nfsd_ffv2_trust_drain_ctx ctx;
	struct nfsd_ffv2_trust_fixture f = {};
	struct nfsd_ffv2_trust_entry *held;
	struct nfsd_ffv2_trust_request req;
	struct task_struct *task;
	unsigned long left;
	stateid_t sid;

	KUNIT_ASSERT_TRUE(test, nfsd_ffv2_trust_fixture_init(test, &f, 111));

	sid = nfsd_ffv2_test_stateid(6, 7, 8, 9);
	nfsd_ffv2_test_trust_request(&req, &sid, nfsd_ffv2_test_uuid_a,
				     IOMODE_RW, "drain@ds.example.net", 3600);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						111, &req));

	/* A request obtains a reference and has not finished. */
	held = nfsd_ffv2_trust_lookup(f.registry, &sid, nfsd_ffv2_test_uuid_a,
				      f.epoch);
	KUNIT_ASSERT_NOT_NULL(test, held);

	ctx.registry = f.registry;
	init_completion(&ctx.destroy_entered);
	init_completion(&ctx.destroy_done);
	task = kthread_run(nfsd_ffv2_trust_drain_thread, &ctx,
			   "nfsd_ffv2_drain");
	KUNIT_ASSERT_FALSE(test, IS_ERR(task));
	wait_for_completion(&ctx.destroy_entered);

	/* Destruction must block while the reference is outstanding. */
	left = wait_for_completion_timeout(&ctx.destroy_done, HZ / 2);
	KUNIT_EXPECT_EQ(test, 0UL, left);

	/* Releasing the last reference releases destruction. */
	nfsd_ffv2_trust_entry_put(held);
	left = wait_for_completion_timeout(&ctx.destroy_done, 10 * HZ);
	KUNIT_EXPECT_NE(test, 0UL, left);

	/* Freed by the thread; do not free it again during teardown. */
	f.registry = NULL;
	nfsd_ffv2_trust_fixture_exit(test, &f);
}

/*
 * Operation profiles and the ordered validation gate.
 */

static void nfsd_ffv2_op_profile_test(struct kunit *test)
{
	const struct nfsd_ffv2_op_profile *profile;

	/* Reads are data-client operations and accept READ or RW. */
	profile = nfsd_ffv2_op_profile(OP_CHUNK_READ);
	KUNIT_ASSERT_NOT_NULL(test, profile);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_CALLERS(DATA_CLIENT),
			profile->callers);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROFILE_READ_DATA,
			profile->profile_bit);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_IOMODE_READ_OR_RW, profile->iomode);
	KUNIT_EXPECT_FALSE(test, profile->writer_identity);

	profile = nfsd_ffv2_op_profile(OP_CHUNK_HEADER_READ);
	KUNIT_ASSERT_NOT_NULL(test, profile);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROFILE_READ_METADATA,
			profile->profile_bit);

	/* Writes require RW and a writer identity. */
	profile = nfsd_ffv2_op_profile(OP_CHUNK_WRITE);
	KUNIT_ASSERT_NOT_NULL(test, profile);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_IOMODE_RW_ONLY, profile->iomode);
	KUNIT_EXPECT_TRUE(test, profile->writer_identity);

	/* Repair is a distinct caller class from an ordinary writer. */
	profile = nfsd_ffv2_op_profile(OP_CHUNK_WRITE_REPAIR);
	KUNIT_ASSERT_NOT_NULL(test, profile);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_CALLERS(REPAIR_ACTOR),
			profile->callers);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROFILE_REPAIR_WRITE,
			profile->profile_bit);

	/* Control operations are MDS-only and do not consult iomode. */
	profile = nfsd_ffv2_op_profile(OP_TRUST_STATEID);
	KUNIT_ASSERT_NOT_NULL(test, profile);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_CALLERS(MDS_CONTROL),
			profile->callers);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_IOMODE_ANY, profile->iomode);
	KUNIT_EXPECT_EQ(test, 0U, profile->profile_bit);

	/* Every lifecycle operation names the lifecycle profile. */
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROFILE_WRITE_LIFECYCLE,
			nfsd_ffv2_op_profile(OP_CHUNK_COMMIT)->profile_bit);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROFILE_WRITE_LIFECYCLE,
			nfsd_ffv2_op_profile(OP_CHUNK_FINALIZE)->profile_bit);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROFILE_WRITE_LIFECYCLE,
			nfsd_ffv2_op_profile(OP_CHUNK_ROLLBACK)->profile_bit);

	/*
	 * The escrow family and everything outside the frozen range have no
	 * profile, so they cannot be authorized by default.
	 */
	KUNIT_EXPECT_NULL(test, nfsd_ffv2_op_profile(92));
	KUNIT_EXPECT_NULL(test, nfsd_ffv2_op_profile(93));
	KUNIT_EXPECT_NULL(test, nfsd_ffv2_op_profile(94));
	KUNIT_EXPECT_NULL(test, nfsd_ffv2_op_profile(95));
	KUNIT_EXPECT_NULL(test, nfsd_ffv2_op_profile(OP_READ));
	KUNIT_EXPECT_NULL(test, nfsd_ffv2_op_profile(0));
	KUNIT_EXPECT_NULL(test, nfsd_ffv2_op_profile(U32_MAX));
}

static void nfsd_ffv2_validate_order_test(struct kunit *test)
{
	struct svc_rqst *rqstp;
	struct svc_fh *unmapped;
	stateid_t sid;
	u64 before;

	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	unmapped = kunit_kzalloc(test, sizeof(*unmapped), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, rqstp);
	KUNIT_ASSERT_NOT_NULL(test, unmapped);
	sid = nfsd_ffv2_test_stateid(1, 2, 3, 4);

	before = nfsd_ffv2_test_provider_entries();

	/*
	 * An operation with no profile is refused before anything else is
	 * examined, including the escrow range and ordinary NFS operations.
	 */
	KUNIT_EXPECT_EQ(test, nfserr_notsupp,
			nfsd_ffv2_test_validate_operation(rqstp, unmapped,
							  NULL, 92, &sid,
							  NULL, NULL));
	KUNIT_EXPECT_EQ(test, nfserr_notsupp,
			nfsd_ffv2_test_validate_operation(rqstp, unmapped,
							  NULL, OP_READ, &sid,
							  NULL, NULL));

	/*
	 * With a profile but no FFv2 binding, the handle is stale.  This
	 * precedes any authority or stateid work, so an unmapped handle
	 * never reports an authorization error.
	 */
	KUNIT_EXPECT_EQ(test, nfserr_stale,
			nfsd_ffv2_test_validate_operation(rqstp, unmapped,
							  NULL, OP_CHUNK_READ,
							  &sid,
							  NULL, NULL));
	KUNIT_EXPECT_EQ(test, nfserr_stale,
			nfsd_ffv2_test_validate_operation(rqstp, unmapped,
							  NULL,
							  OP_TRUST_STATEID,
							  &sid,
							  NULL, NULL));

	/* No rejection crossed the provider boundary. */
	KUNIT_EXPECT_EQ(test, before, nfsd_ffv2_test_provider_entries());
}

/*
 * Caller class and writer identity are properties of the entry the metadata
 * server installed, not of the operation the client chose to send.
 */
static void nfsd_ffv2_trust_actor_class_test(struct kunit *test)
{
	struct nfsd_ffv2_trust_fixture f = {};
	struct nfsd_ffv2_trust_entry *entry;
	struct nfsd_ffv2_trust_request req;
	stateid_t sid;

	KUNIT_ASSERT_TRUE(test, nfsd_ffv2_trust_fixture_init(test, &f, 121));

	sid = nfsd_ffv2_test_stateid(1, 9, 9, 9);
	nfsd_ffv2_test_trust_request(&req, &sid, nfsd_ffv2_test_uuid_a,
				     IOMODE_RW, NULL, 3600);

	/* An entry with no caller class cannot be installed at all. */
	req.actor = NFSD_FFV2_CALLER_NONE;
	KUNIT_EXPECT_EQ(test, nfserr_inval,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						121, &req));
	/* Nor can a data client be issued MDS control authority this way. */
	req.actor = NFSD_FFV2_CALLER_MDS_CONTROL;
	KUNIT_EXPECT_EQ(test, nfserr_inval,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						121, &req));
	KUNIT_EXPECT_EQ(test, 0U, nfsd_ffv2_test_trust_entries(f.registry));

	/* Install an ordinary data client that also carries repair bits. */
	req.actor = NFSD_FFV2_CALLER_DATA_CLIENT;
	req.profile_mask = NFSD_FFV2_PROFILE_WRITE_DATA |
			   NFSD_FFV2_PROFILE_REPAIR_WRITE;
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						121, &req));

	entry = nfsd_ffv2_trust_lookup(f.registry, &sid,
				       nfsd_ffv2_test_uuid_a, f.epoch);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	/*
	 * Holding the repair profile bit does not make this client a repair
	 * actor: the caller class is checked separately, so a repair
	 * operation is refused even though the bit is present.
	 */
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_CALLER_DATA_CLIENT,
			nfsd_ffv2_test_trust_actor(entry));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_CALLERS(REPAIR_ACTOR),
			nfsd_ffv2_op_profile(OP_CHUNK_WRITE_REPAIR)->callers);
	KUNIT_EXPECT_EQ(test, 0U,
			nfsd_ffv2_op_profile(OP_CHUNK_WRITE_REPAIR)->callers &
			BIT(nfsd_ffv2_test_trust_actor(entry)));
	/* Lock control admits both a data client and a repair actor. */
	KUNIT_EXPECT_NE(test, 0U,
			nfsd_ffv2_op_profile(OP_CHUNK_LOCK)->callers &
			BIT(NFSD_FFV2_CALLER_DATA_CLIENT));
	KUNIT_EXPECT_NE(test, 0U,
			nfsd_ffv2_op_profile(OP_CHUNK_LOCK)->callers &
			BIT(NFSD_FFV2_CALLER_REPAIR_ACTOR));
	KUNIT_EXPECT_NE(test, 0U,
			nfsd_ffv2_op_profile(OP_CHUNK_UNLOCK)->callers &
			BIT(NFSD_FFV2_CALLER_REPAIR_ACTOR));
	nfsd_ffv2_trust_entry_put(entry);

	/* Renewal cannot quietly change the caller class either. */
	req.actor = NFSD_FFV2_CALLER_REPAIR_ACTOR;
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_trust_install(f.registry, f.authority, NULL,
						121, &req));
	KUNIT_EXPECT_EQ(test, 1U, nfsd_ffv2_test_trust_entries(f.registry));
	entry = nfsd_ffv2_trust_lookup(f.registry, &sid,
				       nfsd_ffv2_test_uuid_a, f.epoch);
	KUNIT_ASSERT_NOT_NULL(test, entry);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_CALLER_DATA_CLIENT,
			nfsd_ffv2_test_trust_actor(entry));
	nfsd_ffv2_trust_entry_put(entry);

	nfsd_ffv2_trust_fixture_exit(test, &f);
}

/*
 * A filehandle-less control operation resolves the active generation by
 * reference.  Retirement must not be able to free it while that reference
 * is held, which is what the gate depends on before it dereferences the
 * generation payload.
 */
static void nfsd_ffv2_no_fh_generation_race_test(struct kunit *test)
{
	struct nfsd_ffv2_worker_ctx worker = {};
	struct nfsd_ffv2_generation *held;
	bool worker_installed = false;
	bool service_up = false;
	unsigned int before, after;
	struct nfsd_net *nn;
	struct net *net;
	atomic_t releases;
	u64 generation_id = 0;
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "failed to create test netns: %ld",
			   PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	atomic_set(&releases, 0);
	error = nfsd_ffv2_worker_ctx_install(&worker, net);
	if (error)
		goto out_cleanup;
	worker_installed = true;
	error = nfsd_ffv2_start_test_service(net, &worker);
	if (error)
		goto out_cleanup;
	service_up = true;

	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_test_publish(nn, &releases, nfsd_ffv2_count_release,
				       &generation_id);
	mutex_unlock(&nfsd_mutex);
	if (error)
		goto out_cleanup;

	/* The gate's acquisition must actually take a reference. */
	held = nfsd_ffv2_test_active_generation_get(nn);
	KUNIT_ASSERT_NOT_NULL(test, held);
	before = nfsd_ffv2_test_generation_refcount(held);
	KUNIT_EXPECT_GT(test, before, 1U);

	/* A second acquisition is independent of the first. */
	{
		struct nfsd_ffv2_generation *again;

		again = nfsd_ffv2_test_active_generation_get(nn);
		KUNIT_ASSERT_PTR_EQ(test, held, again);
		after = nfsd_ffv2_test_generation_refcount(again);
		KUNIT_EXPECT_EQ(test, before + 1, after);
		nfsd_ffv2_test_generation_put(again);
		KUNIT_EXPECT_EQ(test, before,
				nfsd_ffv2_test_generation_refcount(held));
	}

	/*
	 * Retire while the reference is held.  The payload is released, but
	 * the generation itself must survive for the holder.
	 */
	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_test_unregister(nn, generation_id);
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, 1, atomic_read(&releases));
	KUNIT_EXPECT_GT(test, nfsd_ffv2_test_generation_refcount(held), 0U);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_generation_retired(held));

	/* A later acquisition finds no active generation. */
	KUNIT_EXPECT_NULL(test, nfsd_ffv2_test_active_generation_get(nn));

	nfsd_ffv2_test_generation_put(held);
	error = 0;

out_cleanup:
	complete_all(&worker.run);
	complete_all(&worker.allow_complete);
	if (service_up)
		nfsd_shutdown_threads(net);
	if (worker_installed)
		nfsd_ffv2_worker_ctx_remove(&worker);
	put_net(net);
	net_ns_barrier();
	if (error)
		KUNIT_FAIL(test, "no-filehandle generation race failed: %d",
			   error);
}

/*
 * Argument-decoder evidence.
 *
 * These build genuine XDR byte streams and run them through the production
 * decoder table, so the wire shape is checked against the aggregate draft
 * rather than against a helper's idea of it.  Field order and widths follow
 * draft-haynes-nfsv4-flexfiles-v2 sections chunk_owner4, chunk_cohort_id4,
 * CHUNK_WRITE4args, CHUNK_UNLOCK4args, and BULK_REVOKE_STATEID4args.
 */

struct nfsd_ffv2_xdr_writer {
	__be32	*p;
	__be32	*base;
};

static void nfsd_ffv2_xdr_u32(struct nfsd_ffv2_xdr_writer *w, u32 v)
{
	*w->p++ = cpu_to_be32(v);
}

static void nfsd_ffv2_xdr_u64(struct nfsd_ffv2_xdr_writer *w, u64 v)
{
	nfsd_ffv2_xdr_u32(w, upper_32_bits(v));
	nfsd_ffv2_xdr_u32(w, lower_32_bits(v));
}

static void nfsd_ffv2_xdr_stateid(struct nfsd_ffv2_xdr_writer *w,
				  const stateid_t *sid)
{
	nfsd_ffv2_xdr_u32(w, sid->si_generation);
	nfsd_ffv2_xdr_u32(w, sid->si_opaque.so_clid.cl_boot);
	nfsd_ffv2_xdr_u32(w, sid->si_opaque.so_clid.cl_id);
	nfsd_ffv2_xdr_u32(w, sid->si_opaque.so_id);
}

static size_t nfsd_ffv2_xdr_len(const struct nfsd_ffv2_xdr_writer *w)
{
	return (w->p - w->base) * XDR_UNIT;
}

/* chunk_owner4: co_cohort_id (64 bits), co_client_id, co_id. */
static void nfsd_ffv2_xdr_owner(struct nfsd_ffv2_xdr_writer *w, u64 cohort,
				u32 client_id, u32 owner_id)
{
	nfsd_ffv2_xdr_u64(w, cohort);
	nfsd_ffv2_xdr_u32(w, client_id);
	nfsd_ffv2_xdr_u32(w, owner_id);
}

static void nfsd_ffv2_decoder_owner_test(struct kunit *test)
{
	struct nfsd_ffv2_xdr_writer w;
	union nfsd4_op_u *u;
	struct svc_rqst *rqstp;
	size_t consumed;
	stateid_t sid;
	__be32 *buf;

	buf = kunit_kzalloc(test, 256, GFP_KERNEL);
	u = kunit_kzalloc(test, sizeof(*u), GFP_KERNEL);
	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	KUNIT_ASSERT_NOT_NULL(test, u);
	KUNIT_ASSERT_NOT_NULL(test, rqstp);

	/* CHUNK_UNLOCK4args: stateid, offset, count, owner. */
	sid = nfsd_ffv2_test_stateid(0x11, 0x22, 0x33, 0x44);
	w.base = buf;
	w.p = buf;
	nfsd_ffv2_xdr_stateid(&w, &sid);
	nfsd_ffv2_xdr_u64(&w, 4096);			/* offset */
	nfsd_ffv2_xdr_u32(&w, 1);			/* count */
	nfsd_ffv2_xdr_owner(&w, 0x0123456789abcdefULL, 0xfeed, 0xbeef);

	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd4_test_decode_op(rqstp, OP_CHUNK_UNLOCK, buf,
					     nfsd_ffv2_xdr_len(&w), u,
					     &consumed));
	/* The whole owner is consumed and retained, all four words. */
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_xdr_len(&w), consumed);
	KUNIT_EXPECT_EQ(test, 0x0123456789abcdefULL, u->ffv2.owner_cohort_id);
	KUNIT_EXPECT_EQ(test, 0xfeedU, u->ffv2.owner_client_id);
	KUNIT_EXPECT_EQ(test, 0xbeefU, u->ffv2.owner_id);
	KUNIT_EXPECT_TRUE(test, u->ffv2.owner_present);
	KUNIT_EXPECT_EQ(test, 0x11U, u->ffv2.stateid.si_generation);
	KUNIT_EXPECT_EQ(test, 4096ULL, u->ffv2.offset);

	/* Truncating the owner by one word must fail closed. */
	memset(u, 0, sizeof(*u));
	KUNIT_EXPECT_NE(test, nfs_ok,
			nfsd4_test_decode_op(rqstp, OP_CHUNK_UNLOCK, buf,
					     nfsd_ffv2_xdr_len(&w) - XDR_UNIT,
					     u, &consumed));
}

static void nfsd_ffv2_decoder_write_test(struct kunit *test)
{
	struct nfsd_ffv2_xdr_writer w;
	union nfsd4_op_u *u;
	struct svc_rqst *rqstp;
	size_t consumed;
	stateid_t sid;
	__be32 *buf;

	buf = kunit_kzalloc(test, 512, GFP_KERNEL);
	u = kunit_kzalloc(test, sizeof(*u), GFP_KERNEL);
	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	KUNIT_ASSERT_NOT_NULL(test, u);
	KUNIT_ASSERT_NOT_NULL(test, rqstp);

	/*
	 * CHUNK_WRITE_REPAIR4args carries a bare cohort and client id, not a
	 * chunk_owner4: stateid, offset, stable, cohort, client, co_ids<>,
	 * payload id, chunk size, checksums<>, chunks<>.
	 */
	sid = nfsd_ffv2_test_stateid(7, 8, 9, 10);
	w.base = buf;
	w.p = buf;
	nfsd_ffv2_xdr_stateid(&w, &sid);
	nfsd_ffv2_xdr_u64(&w, 8192);			/* offset */
	nfsd_ffv2_xdr_u32(&w, 2);			/* stable_how4 */
	nfsd_ffv2_xdr_u64(&w, 0xcafef00dd00dULL);	/* cohort id */
	nfsd_ffv2_xdr_u32(&w, 0x5150);			/* client id */
	nfsd_ffv2_xdr_u32(&w, 2);			/* co_ids<> count */
	nfsd_ffv2_xdr_u32(&w, 11);
	nfsd_ffv2_xdr_u32(&w, 12);
	nfsd_ffv2_xdr_u32(&w, 3);			/* payload id */
	nfsd_ffv2_xdr_u32(&w, 4096);			/* chunk size */
	nfsd_ffv2_xdr_u32(&w, 0);			/* checksums<> */
	nfsd_ffv2_xdr_u32(&w, 0);			/* chunks<> */

	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd4_test_decode_op(rqstp, OP_CHUNK_WRITE_REPAIR, buf,
					     nfsd_ffv2_xdr_len(&w), u,
					     &consumed));
	/*
	 * The writer identity must be the client id at its own position, not
	 * a word of the cohort.  This is the field the authorization gate
	 * compares against the trust entry.
	 */
	KUNIT_EXPECT_EQ(test, 0xcafef00dd00dULL, u->ffv2.owner_cohort_id);
	KUNIT_EXPECT_EQ(test, 0x5150U, u->ffv2.owner_client_id);
	KUNIT_EXPECT_TRUE(test, u->ffv2.owner_present);
	KUNIT_EXPECT_EQ(test, 0U, u->ffv2.owner_id);

	/*
	 * An over-long co_ids array is refused rather than trusted.  The
	 * count is the eleventh word: stateid, offset, stable, cohort,
	 * client, then the array.
	 */
	memset(u, 0, sizeof(*u));
	buf[10] = cpu_to_be32(U32_MAX);
	KUNIT_EXPECT_NE(test, nfs_ok,
			nfsd4_test_decode_op(rqstp, OP_CHUNK_WRITE_REPAIR, buf,
					     nfsd_ffv2_xdr_len(&w), u,
					     &consumed));
}

static void nfsd_ffv2_decoder_bulk_revoke_test(struct kunit *test)
{
	struct nfsd_ffv2_xdr_writer w;
	union nfsd4_op_u *u;
	struct svc_rqst *rqstp;
	size_t consumed;
	__be32 *buf;

	buf = kunit_kzalloc(test, 64, GFP_KERNEL);
	u = kunit_kzalloc(test, sizeof(*u), GFP_KERNEL);
	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	KUNIT_ASSERT_NOT_NULL(test, u);
	KUNIT_ASSERT_NOT_NULL(test, rqstp);

	/* BULK_REVOKE_STATEID4args is one clientid4 and names no file. */
	w.base = buf;
	w.p = buf;
	nfsd_ffv2_xdr_u32(&w, 0xA1A2A3A4);
	nfsd_ffv2_xdr_u32(&w, 0xB1B2B3B4);

	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd4_test_decode_op(rqstp, OP_BULK_REVOKE_STATEID,
					     buf, nfsd_ffv2_xdr_len(&w), u,
					     &consumed));
	KUNIT_EXPECT_EQ(test, 2 * XDR_UNIT, consumed);
	/* The target is retained, and is distinct from any session client. */
	KUNIT_EXPECT_TRUE(test, u->ffv2.target_present);
	KUNIT_EXPECT_EQ(test, 0xA1A2A3A4U, u->ffv2.target_clientid.cl_boot);
	KUNIT_EXPECT_EQ(test, 0xB1B2B3B4U, u->ffv2.target_clientid.cl_id);

	/* A truncated clientid fails closed and retains nothing. */
	memset(u, 0, sizeof(*u));
	KUNIT_EXPECT_NE(test, nfs_ok,
			nfsd4_test_decode_op(rqstp, OP_BULK_REVOKE_STATEID,
					     buf, XDR_UNIT, u, &consumed));
	KUNIT_EXPECT_FALSE(test, u->ffv2.target_present);
}

/*
 * CHUNK_WRITE takes a different path from CHUNK_WRITE_REPAIR: it carries
 * cwa_flags and a discriminated write_chunk_guard4 that the repair form
 * does not.  Both arms of that union are exercised here.
 */
static void nfsd_ffv2_decoder_chunk_write_test(struct kunit *test)
{
	struct nfsd_ffv2_xdr_writer w;
	union nfsd4_op_u *u;
	struct svc_rqst *rqstp;
	size_t consumed, guarded_len;
	stateid_t sid;
	__be32 *buf;

	buf = kunit_kzalloc(test, 512, GFP_KERNEL);
	u = kunit_kzalloc(test, sizeof(*u), GFP_KERNEL);
	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	KUNIT_ASSERT_NOT_NULL(test, u);
	KUNIT_ASSERT_NOT_NULL(test, rqstp);

	sid = nfsd_ffv2_test_stateid(1, 2, 3, 4);

	/* cwg_check FALSE: the guard arm is void. */
	w.base = buf;
	w.p = buf;
	nfsd_ffv2_xdr_stateid(&w, &sid);
	nfsd_ffv2_xdr_u64(&w, 512);			/* offset */
	nfsd_ffv2_xdr_u32(&w, 1);			/* stable_how4 */
	nfsd_ffv2_xdr_u64(&w, 0x1122334455667788ULL);	/* cohort id */
	nfsd_ffv2_xdr_u32(&w, 0x2024);			/* client id */
	nfsd_ffv2_xdr_u32(&w, 0);			/* co_ids<> empty */
	nfsd_ffv2_xdr_u32(&w, 9);			/* payload id */
	nfsd_ffv2_xdr_u32(&w, 0);			/* flags */
	nfsd_ffv2_xdr_u32(&w, 0);			/* cwg_check FALSE */
	nfsd_ffv2_xdr_u32(&w, 4096);			/* chunk size */
	nfsd_ffv2_xdr_u32(&w, 0);			/* checksums<> */
	nfsd_ffv2_xdr_u32(&w, 0);			/* chunks<> */

	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd4_test_decode_op(rqstp, OP_CHUNK_WRITE, buf,
					     nfsd_ffv2_xdr_len(&w), u,
					     &consumed));
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_xdr_len(&w), consumed);
	KUNIT_EXPECT_EQ(test, 0x1122334455667788ULL, u->ffv2.owner_cohort_id);
	KUNIT_EXPECT_EQ(test, 0x2024U, u->ffv2.owner_client_id);
	KUNIT_EXPECT_TRUE(test, u->ffv2.owner_present);

	/* cwg_check TRUE: two further words belong to the guard. */
	memset(u, 0, sizeof(*u));
	w.base = buf;
	w.p = buf;
	nfsd_ffv2_xdr_stateid(&w, &sid);
	nfsd_ffv2_xdr_u64(&w, 512);
	nfsd_ffv2_xdr_u32(&w, 1);
	nfsd_ffv2_xdr_u64(&w, 0x1122334455667788ULL);
	nfsd_ffv2_xdr_u32(&w, 0x2024);
	nfsd_ffv2_xdr_u32(&w, 0);
	nfsd_ffv2_xdr_u32(&w, 9);
	nfsd_ffv2_xdr_u32(&w, 0);
	nfsd_ffv2_xdr_u32(&w, 1);			/* cwg_check TRUE */
	nfsd_ffv2_xdr_u32(&w, 0xaaaa);			/* cg_gen_id */
	nfsd_ffv2_xdr_u32(&w, 0xbbbb);			/* cg_client_id */
	nfsd_ffv2_xdr_u32(&w, 4096);
	nfsd_ffv2_xdr_u32(&w, 0);
	nfsd_ffv2_xdr_u32(&w, 0);
	guarded_len = nfsd_ffv2_xdr_len(&w);

	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd4_test_decode_op(rqstp, OP_CHUNK_WRITE, buf,
					     guarded_len, u, &consumed));
	KUNIT_EXPECT_EQ(test, guarded_len, consumed);
	KUNIT_EXPECT_EQ(test, 0x2024U, u->ffv2.owner_client_id);

	/* A guard discriminant outside the boolean range is refused. */
	memset(u, 0, sizeof(*u));
	buf[13] = cpu_to_be32(2);
	KUNIT_EXPECT_NE(test, nfs_ok,
			nfsd4_test_decode_op(rqstp, OP_CHUNK_WRITE, buf,
					     guarded_len, u, &consumed));
	buf[13] = cpu_to_be32(1);

	/* Claiming a guard and then truncating it fails closed. */
	memset(u, 0, sizeof(*u));
	KUNIT_EXPECT_NE(test, nfs_ok,
			nfsd4_test_decode_op(rqstp, OP_CHUNK_WRITE, buf,
					     14 * XDR_UNIT, u, &consumed));
}

/*
 * CHUNK_COMMIT and CHUNK_FINALIZE both carry a counted array of four-word
 * chunk_owner4 values, which nothing exercised before.
 */
static void nfsd_ffv2_decoder_lifecycle_test(struct kunit *test)
{
	static const u32 ops[] = { OP_CHUNK_COMMIT, OP_CHUNK_FINALIZE };
	struct svc_rqst *rqstp;
	union nfsd4_op_u *u;
	stateid_t sid;
	__be32 *buf;
	unsigned int i;

	buf = kunit_kzalloc(test, 512, GFP_KERNEL);
	u = kunit_kzalloc(test, sizeof(*u), GFP_KERNEL);
	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	KUNIT_ASSERT_NOT_NULL(test, u);
	KUNIT_ASSERT_NOT_NULL(test, rqstp);

	sid = nfsd_ffv2_test_stateid(5, 6, 7, 8);

	for (i = 0; i < ARRAY_SIZE(ops); i++) {
		struct nfsd_ffv2_xdr_writer w;
		size_t consumed, full_len;

		/* Two owners: the array is four words per element. */
		w.base = buf;
		w.p = buf;
		nfsd_ffv2_xdr_stateid(&w, &sid);
		nfsd_ffv2_xdr_u64(&w, 16384);		/* offset */
		nfsd_ffv2_xdr_u32(&w, 2);		/* count */
		nfsd_ffv2_xdr_u32(&w, 2);		/* chunks<> count */
		nfsd_ffv2_xdr_owner(&w, 0xdeadbeefULL, 0x1111, 0x2222);
		nfsd_ffv2_xdr_owner(&w, 0xfeedfaceULL, 0x3333, 0x4444);
		full_len = nfsd_ffv2_xdr_len(&w);

		memset(u, 0, sizeof(*u));
		KUNIT_EXPECT_EQ(test, nfs_ok,
				nfsd4_test_decode_op(rqstp, ops[i], buf,
						     full_len, u, &consumed));
		KUNIT_EXPECT_EQ(test, full_len, consumed);
		KUNIT_EXPECT_EQ(test, 16384ULL, u->ffv2.offset);
		KUNIT_EXPECT_EQ(test, 2U, u->ffv2.count);

		/* An empty array is permitted and consumes only its count. */
		w.base = buf;
		w.p = buf;
		nfsd_ffv2_xdr_stateid(&w, &sid);
		nfsd_ffv2_xdr_u64(&w, 16384);
		nfsd_ffv2_xdr_u32(&w, 0);
		nfsd_ffv2_xdr_u32(&w, 0);		/* chunks<> empty */
		memset(u, 0, sizeof(*u));
		KUNIT_EXPECT_EQ(test, nfs_ok,
				nfsd4_test_decode_op(rqstp, ops[i], buf,
						     nfsd_ffv2_xdr_len(&w), u,
						     &consumed));
		KUNIT_EXPECT_EQ(test, nfsd_ffv2_xdr_len(&w), consumed);

		/* A count larger than the bytes present fails closed. */
		w.base = buf;
		w.p = buf;
		nfsd_ffv2_xdr_stateid(&w, &sid);
		nfsd_ffv2_xdr_u64(&w, 16384);
		nfsd_ffv2_xdr_u32(&w, 2);
		nfsd_ffv2_xdr_u32(&w, 2);
		nfsd_ffv2_xdr_owner(&w, 0xdeadbeefULL, 0x1111, 0x2222);
		memset(u, 0, sizeof(*u));
		KUNIT_EXPECT_NE(test, nfs_ok,
				nfsd4_test_decode_op(rqstp, ops[i], buf,
						     nfsd_ffv2_xdr_len(&w), u,
						     &consumed));

		/* An over-limit count is refused before any allocation. */
		w.base = buf;
		w.p = buf;
		nfsd_ffv2_xdr_stateid(&w, &sid);
		nfsd_ffv2_xdr_u64(&w, 16384);
		nfsd_ffv2_xdr_u32(&w, 2);
		nfsd_ffv2_xdr_u32(&w, U32_MAX);
		memset(u, 0, sizeof(*u));
		KUNIT_EXPECT_NE(test, nfs_ok,
				nfsd4_test_decode_op(rqstp, ops[i], buf,
						     nfsd_ffv2_xdr_len(&w), u,
						     &consumed));
	}
}

/*
 * Read-only provider fixture.
 *
 * Option C of the provider-enablement design gate: a test-only provider
 * that serves CHUNK_READ and CHUNK_HEADER_READ from a synthetic backing
 * object, so the authorized data path and its lifetime gates can be
 * exercised without a metadata server, a KDC, or a real store.  Nothing
 * here is reachable from an ordinary client: the provider exists only in a
 * KUnit build and is installed only by these tests.
 */

#define NFSD_FFV2_RO_CHUNK_SIZE		64
#define NFSD_FFV2_RO_CHUNKS		4

struct nfsd_ffv2_ro_provider {
	/* The object this provider will serve; anything else is stale. */
	const struct nfsd_ffv2_object	*object;
	u8				data[NFSD_FFV2_RO_CHUNKS]
					    [NFSD_FFV2_RO_CHUNK_SIZE];
	struct nfsd_ffv2_read_chunk	chunks[NFSD_FFV2_RO_CHUNKS];
	__be32				status[NFSD_FFV2_RO_CHUNKS];
	u32				locked[NFSD_FFV2_RO_CHUNKS];
	struct nfsd_ffv2_chunk_owner	owners[NFSD_FFV2_RO_CHUNKS];
	struct nfsd_ffv2_chunk_guard	guards[NFSD_FFV2_RO_CHUNKS];
	struct nfsd_ffv2_retained	predecessors[NFSD_FFV2_RO_CHUNKS];
	atomic_t			reads;
	atomic_t			header_reads;
	/* Optional stall, so a test can overlap a read with retirement. */
	struct completion		*enter;
	struct completion		*release;
};

/* Clamp a requested chunk range to what the fixture holds. */
static u32 nfsd_ffv2_ro_range(const struct nfsd_ffv2_chunk_request *request,
			      bool *eof)
{
	u32 avail;

	if (request->offset >= NFSD_FFV2_RO_CHUNKS) {
		*eof = true;
		return 0;
	}
	avail = NFSD_FFV2_RO_CHUNKS - (u32)request->offset;
	if (request->count >= avail) {
		*eof = true;
		return avail;
	}
	*eof = false;
	return request->count;
}

/*
 * Let a test hold a callback inside the provider boundary.  The stall is
 * keyed on the release completion alone: a test that wants to model a
 * callback which never announces itself leaves enter NULL and still gets a
 * held callback.
 */
static void nfsd_ffv2_ro_stall(struct nfsd_ffv2_ro_provider *provider)
{
	if (!provider->release)
		return;
	if (provider->enter)
		complete(provider->enter);
	wait_for_completion(provider->release);
}

static __be32 nfsd_ffv2_ro_chunk_read(void *opaque,
				      const struct nfsd_ffv2_object *object,
				      const struct nfsd_ffv2_chunk_request *req,
				      struct nfsd_ffv2_chunk_result *result)
{
	struct nfsd_ffv2_ro_provider *provider = opaque;

	atomic_inc(&provider->reads);
	if (object != provider->object)
		return nfserr_stale;
	nfsd_ffv2_ro_stall(provider);
	result->count = nfsd_ffv2_ro_range(req, &result->eof);
	if (result->count)
		result->read.chunks = &provider->chunks[req->offset];
	return nfs_ok;
}

static __be32
nfsd_ffv2_ro_chunk_header_read(void *opaque,
			       const struct nfsd_ffv2_object *object,
			       const struct nfsd_ffv2_chunk_request *req,
			       struct nfsd_ffv2_chunk_result *result)
{
	struct nfsd_ffv2_ro_provider *provider = opaque;
	u32 first;

	atomic_inc(&provider->header_reads);
	if (object != provider->object)
		return nfserr_stale;
	nfsd_ffv2_ro_stall(provider);
	result->count = nfsd_ffv2_ro_range(req, &result->eof);
	if (!result->count)
		return nfs_ok;
	first = (u32)req->offset;
	result->header.status = &provider->status[first];
	result->header.locked = &provider->locked[first];
	result->header.owners = &provider->owners[first];
	result->header.guards = &provider->guards[first];
	result->header.predecessors = &provider->predecessors[first];
	return nfs_ok;
}

static const struct nfsd_ffv2_provider_ops nfsd_ffv2_ro_provider_ops = {
	.chunk_read		= nfsd_ffv2_ro_chunk_read,
	.chunk_header_read	= nfsd_ffv2_ro_chunk_header_read,
};

/* Fill the fixture's chunks with values a test can check exactly. */
static void nfsd_ffv2_ro_provider_init(struct nfsd_ffv2_ro_provider *provider)
{
	unsigned int i;

	memset(provider, 0, sizeof(*provider));
	for (i = 0; i < NFSD_FFV2_RO_CHUNKS; i++) {
		memset(provider->data[i], 0x40 + i, NFSD_FFV2_RO_CHUNK_SIZE);
		provider->owners[i].co_cohort_id = 0x1122334400000000ULL + i;
		provider->owners[i].co_client_id = 7;
		provider->owners[i].co_id = 0x900 + i;
		provider->guards[i].cg_gen_id = 3 + i;
		provider->guards[i].cg_client_id = 7;
		provider->locked[i] = i & 1;
		provider->status[i] = nfs_ok;
		provider->predecessors[i].disposition =
			NFSD_FFV2_RETAINED_ABSENT;
		provider->chunks[i].cr_checksum.cs_algorithm = 1;
		provider->chunks[i].cr_checksum.cs_len = 4;
		memset(provider->chunks[i].cr_checksum.cs_value, 0x5a, 4);
		provider->chunks[i].cr_effective_len = NFSD_FFV2_RO_CHUNK_SIZE;
		provider->chunks[i].cr_owner = provider->owners[i];
		provider->chunks[i].cr_guard = provider->guards[i];
		provider->chunks[i].cr_payload_id = 0x100 + i;
		provider->chunks[i].cr_locked = provider->locked[i];
		provider->chunks[i].cr_status = nfs_ok;
		provider->chunks[i].cr_chunk = provider->data[i];
	}
}

/*
 * The environment one authorized read needs: a published generation with a
 * real object and mapped filehandle, the authority that generation was
 * published under, and a live trust entry rooted in that authority's
 * epoch.  Everything is built through the production paths except the
 * session lookup and credential copy, which no KUnit test can supply.
 */
struct nfsd_ffv2_ro_fixture {
	struct net			*net;
	struct nfsd_net			*nn;
	struct nfsd4_session		*session;
	struct auth_domain		*domain;
	struct svc_rqst			*rqstp;
	struct svc_xprt			*xprt;
	struct svc_fh			*mapped;
	struct svc_export		*published;
	struct nfsd_ffv2_binding	*binding;
	struct nfsd_ffv2_object		*object;
	struct nfsd_ffv2_export_update	registration;
	struct nfsd_ffv2_ro_provider	*provider;
	struct path			root;
	struct path			object_path;
	struct dentry			*object_dentry;
	struct knfsd_fh			outer_fh;
	stateid_t			stateid;
	u64				generation_id;
	u8				uuid[16];
	u8				token[32];
	bool				service_up;
	bool				filecache_up;
	bool				registration_open;
	bool				provider_installed;
	bool				root_held;
	/* Set when the publication wait expired; see the init comment. */
	bool				publish_timed_out;
};

/* How long fixture construction waits for publication to complete. */
#define NFSD_FFV2_RO_PUBLISH_WAIT	(10 * HZ)

/*
 * The fixture's publication worker.  @delay_ms exists so a test can make
 * the worker demonstrably still running when construction's wait expires,
 * which is the only way to exercise that timeout deterministically.
 */
struct nfsd_ffv2_ro_publish_ctx {
	struct nfsd_ffv2_transition_publish_ctx	publish;
	unsigned int				delay_ms;
};

static int nfsd_ffv2_ro_publish_thread(void *data)
{
	struct nfsd_ffv2_ro_publish_ctx *ctx = data;

	if (ctx->delay_ms)
		msleep(ctx->delay_ms);
	return nfsd_ffv2_transition_publish_thread(&ctx->publish);
}

/*
 * Run one publication on its own thread and wait it out.  Publication has
 * to run off this thread because it waits for export crossing to drain,
 * and it cannot be cancelled once started: on a timeout the wait is
 * reported and then completed anyway, because returning would leave the
 * worker running against the caller's storage.
 *
 * Return: the publication's own result, or -EIO if the worker never
 * started.  @timed_out, when given, records whether the wait expired.
 */
static int nfsd_ffv2_ro_publish_run(struct kunit *test,
				    struct nfsd_ffv2_ro_publish_ctx *pubctx,
				    unsigned long publish_wait,
				    bool timeout_expected, bool *timed_out)
{
	struct task_struct *publish_task;

	publish_task = kthread_run(nfsd_ffv2_ro_publish_thread, pubctx,
				   "nfsd-ffv2-ro-publish");
	if (IS_ERR(publish_task)) {
		KUNIT_FAIL(test, "failed to start fixture publisher: %ld",
			   PTR_ERR(publish_task));
		return -EIO;
	}
	if (!wait_for_completion_timeout(&pubctx->publish.done, publish_wait)) {
		if (timed_out)
			*timed_out = true;
		if (!timeout_expected)
			KUNIT_FAIL(test,
				   "publication did not complete in %lu jiffies",
				   publish_wait);
		wait_for_completion(&pubctx->publish.done);
	}
	kthread_stop(publish_task);
	return pubctx->publish.result;
}

/*
 * Added to the construction wait to get the worker's delay, so a test that
 * wants the wait to expire gets that on any HZ rather than on the
 * assumption that a jiffy is short.
 */
#define NFSD_FFV2_RO_PUBLISH_DELAY_MS	50

static void nfsd_ffv2_ro_fixture_exit(struct kunit *test,
				      struct nfsd_ffv2_ro_fixture *f)
{
	struct nfsd_ffv2_generation *generation;

	if (f->provider_installed) {
		nfsd_ffv2_test_provider_remove(f->nn);
		f->provider_installed = false;
	}
	if (f->mapped) {
		fh_put(f->mapped);
		f->mapped = NULL;
	}
	if (f->binding) {
		nfsd_ffv2_binding_put(f->binding);
		f->binding = NULL;
	}
	if (f->published) {
		exp_put(f->published);
		f->published = NULL;
	}
	nfsd_ffv2_object_free(f->object);
	f->object = NULL;
	if (f->registration_open) {
		nfsd_ffv2_registration_end(f->nn, &f->registration);
		f->registration_open = false;
	}
	if (f->service_up) {
		mutex_lock(&nfsd_mutex);
		generation = nfsd_ffv2_service_stop_begin(f->nn);
		mutex_unlock(&nfsd_mutex);
		nfsd_ffv2_service_stop_finish(f->nn, generation);
		mutex_lock(&nfsd_mutex);
		nfsd_ffv2_service_down(f->nn);
		mutex_unlock(&nfsd_mutex);
		f->service_up = false;
	}
	if (f->net)
		nfsd_export_flush(f->net);
	if (f->filecache_up) {
		mutex_lock(&nfsd_mutex);
		nfsd_file_cache_shutdown();
		mutex_unlock(&nfsd_mutex);
		f->filecache_up = false;
	}
	if (f->object_dentry) {
		dput(f->object_dentry);
		f->object_dentry = NULL;
	}
	if (f->root_held) {
		path_put(&f->root);
		f->root_held = false;
	}
	if (f->domain) {
		auth_domain_put(f->domain);
		f->domain = NULL;
	}
	if (f->net) {
		put_net(f->net);
		f->net = NULL;
		net_ns_barrier();
	}
}

/*
 * Build the fixture, waiting @publish_wait for the publication worker.
 *
 * A caller that passes a deliberately short wait is exercising the timeout
 * path itself and sets @timeout_expected, which records the timeout in
 * f->publish_timed_out instead of failing the test.  Either way the worker
 * is joined before this returns: it runs against storage owned by this
 * frame, so no exit may leave it alive.
 *
 * Returns false with the failure already reported, so a caller can go
 * straight to teardown.
 */
static bool nfsd_ffv2_ro_fixture_init_wait(struct kunit *test,
					   struct nfsd_ffv2_ro_fixture *f,
					   unsigned long publish_wait,
					   bool timeout_expected)
{
	struct nfsd_ffv2_ro_publish_ctx pubctx = {};
	struct nfsd_ffv2_transition_publish_ctx *publish = &pubctx.publish;
	struct nfsd_ffv2_trust_request trust;
	struct nfsd_ffv2_fh_info decoded;
	struct svc_export *selected;
	struct svc_export *seeded;
	struct inode *object_inode;
	struct svc_export exp;
	const u8 inner[] = { 1, 0, 1, 1, 0xa5, 0xb5, 0xc5, 0xd5 };
	int error;

	memset(f, 0, sizeof(*f));
	memset(f->uuid, 0x2c, sizeof(f->uuid));
	memset(f->token, 0x1c, sizeof(f->token));

	f->rqstp = kunit_kzalloc(test, sizeof(*f->rqstp), GFP_KERNEL);
	f->xprt = kunit_kzalloc(test, sizeof(*f->xprt), GFP_KERNEL);
	f->mapped = kunit_kzalloc(test, sizeof(*f->mapped), GFP_KERNEL);
	f->provider = kunit_kzalloc(test, sizeof(*f->provider), GFP_KERNEL);
	f->session = nfsd_ffv2_test_session(test);
	if (!f->rqstp || !f->xprt || !f->mapped || !f->provider || !f->session) {
		KUNIT_FAIL(test, "failed to allocate read-only fixture");
		return false;
	}
	nfsd_ffv2_ro_provider_init(f->provider);

	f->net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(f->net)) {
		KUNIT_FAIL(test, "failed to create fixture netns: %ld",
			   PTR_ERR(f->net));
		f->net = NULL;
		return false;
	}
	f->nn = net_generic(f->net, nfsd_net_id);
	f->xprt->xpt_net = f->net;
	f->rqstp->rq_xprt = f->xprt;
	/*
	 * nfs4_state_create_net() initialises this lock when the v4 state
	 * machine starts, which the fixture does not do: only the FFv2
	 * service comes up here.  Initialise it so lockdep sees a real key
	 * on the authority path instead of disabling itself for the run.
	 */
	spin_lock_init(&f->nn->client_lock);

	f->domain = unix_domain_find("ffv2-ro-kunit");
	if (!f->domain) {
		KUNIT_FAIL(test, "failed to create fixture auth domain");
		return false;
	}
	get_fs_root(current->fs, &f->root);
	f->root_held = true;

	/*
	 * A regular file under the export root for the object to name.  It
	 * exists only in the dentry cache, which is all the registry needs:
	 * no operation in this fixture reaches the backing filesystem.
	 */
	f->object_dentry = d_alloc_name(f->root.dentry, "ffv2-ro-object");
	if (!f->object_dentry) {
		KUNIT_FAIL(test, "failed to allocate fixture object dentry");
		return false;
	}
	object_inode = new_inode(f->root.mnt->mnt_sb);
	if (!object_inode) {
		KUNIT_FAIL(test, "failed to allocate fixture object inode");
		return false;
	}
	object_inode->i_mode = S_IFREG | 0600;
	object_inode->i_ino = get_next_ino();
	set_nlink(object_inode, 1);
	d_add(f->object_dentry, object_inode);
	f->object_path.mnt = f->root.mnt;
	f->object_path.dentry = f->object_dentry;

	/* Seed the ordinary export the object will be published from. */
	nfsd_ffv2_init_test_export(&exp, f->nn, f->domain, &f->root);
	exp.ex_uuid = kmemdup(f->uuid, sizeof(f->uuid), GFP_KERNEL);
	if (!exp.ex_uuid) {
		KUNIT_FAIL(test, "failed to allocate fixture export UUID");
		return false;
	}
	seeded = nfsd_export_cache_update(&exp);
	if (IS_ERR(seeded)) {
		KUNIT_FAIL(test, "fixture export publication failed: %ld",
			   PTR_ERR(seeded));
		kfree(exp.ex_uuid);
		return false;
	}
	exp_put(seeded);

	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_service_up(f->nn);
	f->service_up = !error;
	if (!error)
		error = nfsd_file_ffv2_test_cache_start();
	f->filecache_up = !error && f->service_up;
	if (!error)
		error = nfsd_ffv2_registration_begin(f->nn, &f->registration);
	f->registration_open = !error;
	mutex_unlock(&nfsd_mutex);
	if (error) {
		KUNIT_FAIL(test, "fixture service start failed: %d", error);
		return false;
	}

	/*
	 * The authority the generation is published under.  Only the session
	 * lookup and credential copy are bypassed; the epoch allocation,
	 * session linkage, and publication are the production paths.
	 */
	f->registration.authority =
		nfsd_ffv2_test_authority_create(f->nn, f->session);
	if (!f->registration.authority) {
		KUNIT_FAIL(test, "fixture authority creation failed");
		return false;
	}

	f->object = nfsd_ffv2_object_alloc();
	if (!f->object) {
		KUNIT_FAIL(test, "failed to allocate fixture object");
		return false;
	}
	error = nfsd_ffv2_test_object_init(f->object, f->domain, &f->root,
					   &f->object_path, inner,
					   sizeof(inner), f->uuid, f->uuid);
	if (error) {
		KUNIT_FAIL(test, "fixture object init failed: %d", error);
		return false;
	}

	selected = nfsd_ffv2_export_lookup(f->nn->svc_export_cache, f->domain,
					   &f->root);
	if (IS_ERR(selected)) {
		KUNIT_FAIL(test, "fixture export lookup failed: %ld",
			   PTR_ERR(selected));
		return false;
	}
	error = nfsd_ffv2_export_transition_exact(selected);
	if (error) {
		KUNIT_FAIL(test, "fixture export transition failed: %d", error);
		exp_put(selected);
		return false;
	}
	error = nfsd_ffv2_export_template_clone(&exp, selected);
	if (error) {
		KUNIT_FAIL(test, "fixture template clone failed: %d", error);
		nfsd_ffv2_export_transition_abort_exact(selected);
		exp_put(selected);
		return false;
	}

	/*
	 * Publication runs on its own thread because it waits for export
	 * crossing to drain, which a caller holding no references still has
	 * to let happen.
	 */
	publish->owner = f->nn;
	publish->registration = &f->registration;
	publish->object = f->object;
	publish->outer_fh = &f->outer_fh;
	publish->template = &exp;
	publish->expected = selected;
	publish->root = &f->root;
	publish->store_uuid = f->uuid;
	publish->binding_token = f->token;
	publish->cred = get_current_cred();
	publish->control_root = 1;
	publish->result = -EINPROGRESS;
	init_completion(&publish->done);
	if (timeout_expected)
		pubctx.delay_ms = jiffies_to_msecs(publish_wait) +
				  NFSD_FFV2_RO_PUBLISH_DELAY_MS;
	error = nfsd_ffv2_ro_publish_run(test, &pubctx, publish_wait,
					 timeout_expected,
					 &f->publish_timed_out);
	if (error == -EIO) {
		put_cred(publish->cred);
		nfsd_ffv2_export_template_free(&exp);
		nfsd_ffv2_export_transition_abort_exact(selected);
		exp_put(selected);
		return false;
	}
	put_cred(publish->cred);
	nfsd_ffv2_export_template_free(&exp);
	exp_put(selected);
	if (error) {
		KUNIT_FAIL(test, "fixture publication failed: %d", error);
		return false;
	}
	/* Publication owns the object from here. */
	f->object = NULL;
	f->generation_id = publish->generation_id;
	mutex_lock(&nfsd_mutex);
	nfsd_ffv2_registration_end(f->nn, &f->registration);
	mutex_unlock(&nfsd_mutex);
	f->registration_open = false;

	if (nfsd_ffv2_fh_parse(&f->outer_fh, &decoded)) {
		KUNIT_FAIL(test, "fixture filehandle did not parse");
		return false;
	}
	f->binding = nfsd_ffv2_test_binding_create(f->nn, &decoded);
	if (IS_ERR(f->binding)) {
		KUNIT_FAIL(test, "fixture binding admission failed: %ld",
			   PTR_ERR(f->binding));
		f->binding = NULL;
		return false;
	}

	nfsd_ffv2_init_test_export(&exp, f->nn, f->domain, &f->root);
	f->published = nfsd_ffv2_test_export_lookup(&exp);
	if (!f->published) {
		KUNIT_FAIL(test, "fixture service export not found");
		return false;
	}

	/* A mapped current filehandle, exactly as PUTFH would leave one. */
	fh_init(f->mapped, NFS4_FHSIZE);
	f->mapped->fh_handle = f->outer_fh;
	f->mapped->fh_export = nfsd_export_get(f->published);
	f->mapped->fh_dentry = dget(f->object_dentry);
	f->mapped->fh_ffv2_binding = f->binding;
	f->binding = NULL;

	/* A live read entry rooted in the published authority's epoch. */
	f->stateid = nfsd_ffv2_test_stateid(1, 0x5e, 0x5f, 0x60);
	nfsd_ffv2_test_trust_request(&trust, &f->stateid, f->uuid, IOMODE_READ,
				     NULL, 3600);
	if (nfsd_ffv2_test_trust_install_active(f->nn, NULL, &trust) != nfs_ok) {
		KUNIT_FAIL(test, "fixture trust installation failed");
		return false;
	}

	f->provider->object = nfsd_ffv2_test_binding_object(f->mapped->fh_ffv2_binding);
	if (nfsd_ffv2_test_provider_install(f->nn, &nfsd_ffv2_ro_provider_ops,
					    f->provider)) {
		KUNIT_FAIL(test, "fixture provider installation failed");
		return false;
	}
	f->provider_installed = true;
	return true;
}

static bool nfsd_ffv2_ro_fixture_init(struct kunit *test,
				      struct nfsd_ffv2_ro_fixture *f)
{
	return nfsd_ffv2_ro_fixture_init_wait(test, f,
					      NFSD_FFV2_RO_PUBLISH_WAIT, false);
}

/*
 * Run one authorized operation the way nfsd4_ffv2_probe() does: the
 * ordered gate, then the provider boundary, then release of the execution
 * admission.  The status and the result are the caller's to check.
 */
static __be32 nfsd_ffv2_ro_operation(struct nfsd_ffv2_ro_fixture *f,
				     u32 opnum, const stateid_t *stateid,
				     const struct nfsd_ffv2_chunk_request *req,
				     struct nfsd_ffv2_chunk_result *result)
{
	struct nfsd_ffv2_admission admission = {};
	__be32 status;

	status = nfsd_ffv2_test_validate_operation(f->rqstp, f->mapped,
						   f->session, opnum, stateid,
						   NULL, &admission);
	if (status)
		return status;
	status = nfsd_ffv2_provider_probe(f->rqstp, f->mapped, opnum, req,
					  result, &admission);
	nfsd_ffv2_complete(&admission);
	return status;
}

/*
 * One authorized CHUNK_READ and one authorized CHUNK_HEADER_READ, checked
 * field by field against what the fixture holds, with exactly one provider
 * callback each.
 */
static void nfsd_ffv2_provider_read_test(struct kunit *test)
{
	const struct nfsd_ffv2_chunk_request req = { .offset = 1, .count = 2 };
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_ffv2_ro_fixture f;
	u64 callbacks;
	unsigned int i;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	callbacks = nfsd_ffv2_test_provider_callbacks();
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &f.stateid,
					       &req, &result));
	KUNIT_EXPECT_EQ(test, callbacks + 1,
			nfsd_ffv2_test_provider_callbacks());
	KUNIT_EXPECT_EQ(test, 1, atomic_read(&f.provider->reads));
	KUNIT_EXPECT_EQ(test, 2U, result.count);
	/* Chunk 3 is still behind this range, so this is not the end. */
	KUNIT_EXPECT_FALSE(test, result.eof);
	if (!result.read.chunks) {
		KUNIT_FAIL(test, "read returned no chunk array");
		goto out;
	}
	for (i = 0; i < result.count; i++) {
		const struct nfsd_ffv2_read_chunk *chunk =
			&result.read.chunks[i];
		unsigned int index = i + 1;

		KUNIT_EXPECT_EQ(test, NFSD_FFV2_RO_CHUNK_SIZE,
				chunk->cr_effective_len);
		KUNIT_EXPECT_EQ(test, 0x100 + index, chunk->cr_payload_id);
		KUNIT_EXPECT_EQ(test, 0x1122334400000000ULL + index,
				chunk->cr_owner.co_cohort_id);
		KUNIT_EXPECT_EQ(test, 7U, chunk->cr_owner.co_client_id);
		KUNIT_EXPECT_EQ(test, 0x900 + index, chunk->cr_owner.co_id);
		KUNIT_EXPECT_EQ(test, 3 + index, chunk->cr_guard.cg_gen_id);
		KUNIT_EXPECT_EQ(test, index & 1, chunk->cr_locked);
		KUNIT_EXPECT_EQ(test, nfs_ok, chunk->cr_status);
		if (!chunk->cr_chunk) {
			KUNIT_FAIL(test, "chunk %u carries no payload", index);
			goto out;
		}
		KUNIT_EXPECT_EQ(test, 0x40 + index, chunk->cr_chunk[0]);
		KUNIT_EXPECT_EQ(test, 0x40 + index,
				chunk->cr_chunk[NFSD_FFV2_RO_CHUNK_SIZE - 1]);
	}

	callbacks = nfsd_ffv2_test_provider_callbacks();
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_HEADER_READ,
					       &f.stateid, &req, &result));
	KUNIT_EXPECT_EQ(test, callbacks + 1,
			nfsd_ffv2_test_provider_callbacks());
	KUNIT_EXPECT_EQ(test, 1, atomic_read(&f.provider->header_reads));
	KUNIT_EXPECT_EQ(test, 2U, result.count);
	KUNIT_EXPECT_FALSE(test, result.eof);
	if (!result.header.owners || !result.header.guards ||
	    !result.header.status || !result.header.locked ||
	    !result.header.predecessors) {
		KUNIT_FAIL(test, "header read returned an incomplete result");
		goto out;
	}
	for (i = 0; i < result.count; i++) {
		unsigned int index = i + 1;

		KUNIT_EXPECT_EQ(test, nfs_ok, result.header.status[i]);
		KUNIT_EXPECT_EQ(test, index & 1, result.header.locked[i]);
		KUNIT_EXPECT_EQ(test, 0x1122334400000000ULL + index,
				result.header.owners[i].co_cohort_id);
		KUNIT_EXPECT_EQ(test, 3 + index,
				result.header.guards[i].cg_gen_id);
		KUNIT_EXPECT_EQ(test, NFSD_FFV2_RETAINED_ABSENT,
				result.header.predecessors[i].disposition);
	}

	/* A range that reaches the last chunk reports EOF with its data. */
	{
		const struct nfsd_ffv2_chunk_request last = { .offset = 2,
							      .count = 2 };

		KUNIT_EXPECT_EQ(test, nfs_ok,
				nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ,
						       &f.stateid, &last,
						       &result));
		KUNIT_EXPECT_EQ(test, 2U, result.count);
		KUNIT_EXPECT_TRUE(test, result.eof);
		if (!result.read.chunks) {
			KUNIT_FAIL(test, "read returned no chunk array");
			goto out;
		}
		KUNIT_EXPECT_EQ(test, 0x102U,
				result.read.chunks[0].cr_payload_id);
		KUNIT_EXPECT_EQ(test, 0x103U,
				result.read.chunks[1].cr_payload_id);
	}

	/* A range past the end succeeds, returns nothing, and reports EOF. */
	{
		const struct nfsd_ffv2_chunk_request past = {
			.offset = NFSD_FFV2_RO_CHUNKS, .count = 1
		};

		KUNIT_EXPECT_EQ(test, nfs_ok,
				nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ,
						       &f.stateid, &past,
						       &result));
		KUNIT_EXPECT_EQ(test, 0U, result.count);
		KUNIT_EXPECT_TRUE(test, result.eof);
	}
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

/*
 * Every rejection the ordered gate is responsible for, each proved to fail
 * before the provider boundary rather than inside it.  The provider
 * callback count must not move across any of them.
 */
static void nfsd_ffv2_provider_negative_test(struct kunit *test)
{
	const struct nfsd_ffv2_chunk_request req = { .offset = 0, .count = 1 };
	struct nfsd_ffv2_authority *other = NULL;
	struct nfsd_ffv2_trust_request trust;
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_ffv2_ro_fixture f;
	struct svc_fh *unmapped;
	struct svc_fh *saved;
	stateid_t sid;
	u64 callbacks;
	u8 wrong_uuid[16];

	unmapped = kunit_kzalloc(test, sizeof(*unmapped), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, unmapped);
	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;
	callbacks = nfsd_ffv2_test_provider_callbacks();

	/* An unmapped current filehandle is stale before anything else. */
	saved = f.mapped;
	f.mapped = unmapped;
	KUNIT_EXPECT_EQ(test, nfserr_stale,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &f.stateid,
					       &req, &result));
	f.mapped = saved;

	/* A stateid that was never installed. */
	sid = nfsd_ffv2_test_stateid(1, 0x11, 0x12, 0x13);
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &sid, &req,
					       &result));

	/* The anonymous stateid is never a data credential. */
	sid = nfsd_ffv2_test_stateid(0, 0, 0, 0);
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &sid, &req,
					       &result));

	/*
	 * An entry rooted in a different issuer epoch.  The bytes are
	 * installed and live, but the gate looks up under the published
	 * authority's epoch, so this entry is not reachable at all.
	 */
	other = nfsd_ffv2_test_authority_create(f.nn, f.session);
	if (!other || !nfsd_ffv2_authority_publish(other, f.generation_id)) {
		KUNIT_FAIL(test, "failed to publish a second authority");
		goto out;
	}
	sid = nfsd_ffv2_test_stateid(1, 0x21, 0x22, 0x23);
	nfsd_ffv2_test_trust_request(&trust, &sid, f.uuid, IOMODE_READ, NULL,
				     3600);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_test_trust_install_active(f.nn, other,
							    &trust));
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &sid, &req,
					       &result));

	/* An entry bound to a different logical object. */
	memset(wrong_uuid, 0x77, sizeof(wrong_uuid));
	sid = nfsd_ffv2_test_stateid(1, 0x31, 0x32, 0x33);
	nfsd_ffv2_test_trust_request(&trust, &sid, wrong_uuid, IOMODE_READ,
				     NULL, 3600);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_test_trust_install_active(f.nn, NULL,
							    &trust));
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &sid, &req,
					       &result));

	/* Live and current, but without the profile bit CHUNK_READ names. */
	sid = nfsd_ffv2_test_stateid(1, 0x41, 0x42, 0x43);
	nfsd_ffv2_test_trust_request(&trust, &sid, f.uuid, IOMODE_RW, NULL,
				     3600);
	trust.profile_mask = NFSD_FFV2_PROFILE_WRITE_DATA;
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_test_trust_install_active(f.nn, NULL,
							    &trust));
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &sid, &req,
					       &result));

	/*
	 * The write profile bit held at read-only iomode.  The profile check
	 * passes and the iomode check is what refuses it, so a read entry
	 * cannot be spent on a write operation.
	 */
	sid = nfsd_ffv2_test_stateid(1, 0x51, 0x52, 0x53);
	nfsd_ffv2_test_trust_request(&trust, &sid, f.uuid, IOMODE_READ, NULL,
				     3600);
	trust.profile_mask = NFSD_FFV2_PROFILE_WRITE_DATA;
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_test_trust_install_active(f.nn, NULL,
							    &trust));
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_WRITE, &sid, &req,
					       &result));

	/* Expired. */
	sid = nfsd_ffv2_test_stateid(1, 0x61, 0x62, 0x63);
	nfsd_ffv2_test_trust_request(&trust, &sid, f.uuid, IOMODE_READ, NULL,
				     -3600);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_test_trust_install_active(f.nn, NULL,
							    &trust));
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &sid, &req,
					       &result));

	/* Revoked after installation. */
	sid = nfsd_ffv2_test_stateid(1, 0x71, 0x72, 0x73);
	nfsd_ffv2_test_trust_request(&trust, &sid, f.uuid, IOMODE_READ, NULL,
				     3600);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_test_trust_install_active(f.nn, NULL,
							    &trust));
	KUNIT_EXPECT_TRUE(test,
			  nfsd_ffv2_test_trust_revoke_active(f.nn, &sid));
	KUNIT_EXPECT_EQ(test, nfserr_bad_stateid,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &sid, &req,
					       &result));

	/* Not one of these reached the provider. */
	KUNIT_EXPECT_EQ(test, callbacks,
			nfsd_ffv2_test_provider_callbacks());
	KUNIT_EXPECT_EQ(test, 0, atomic_read(&f.provider->reads));
	KUNIT_EXPECT_EQ(test, 0, atomic_read(&f.provider->header_reads));

	/* The unmodified entry still works, so nothing above disabled it. */
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &f.stateid,
					       &req, &result));
	KUNIT_EXPECT_EQ(test, callbacks + 1,
			nfsd_ffv2_test_provider_callbacks());
out:
	if (other) {
		nfsd_ffv2_authority_detach(other);
		nfsd_ffv2_authority_put(other);
	}
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

/* Build one SEQUENCE + PUTFH + CHUNK_READ compound at a given offset. */
static size_t nfsd_ffv2_ro_compound(__be32 *request, u32 offset)
{
	__be32 *p = request;
	int i;

	*p++ = cpu_to_be32(0);		/* tag */
	*p++ = cpu_to_be32(2);		/* minorversion */
	*p++ = cpu_to_be32(3);		/* opcount */
	*p++ = cpu_to_be32(OP_SEQUENCE);
	for (i = 0; i < 4; i++)
		*p++ = cpu_to_be32(0);	/* sessionid */
	*p++ = cpu_to_be32(1);		/* sequenceid */
	*p++ = cpu_to_be32(0);		/* slotid */
	*p++ = cpu_to_be32(0);		/* highest slotid */
	*p++ = cpu_to_be32(1);		/* cachethis */
	*p++ = cpu_to_be32(OP_PUTFH);
	*p++ = cpu_to_be32(4);
	*p++ = cpu_to_be32(0x01020304);
	*p++ = cpu_to_be32(OP_CHUNK_READ);
	for (i = 0; i < 4; i++)
		*p++ = cpu_to_be32(i);	/* stateid */
	*p++ = cpu_to_be32(0);		/* offset, high word */
	*p++ = cpu_to_be32(offset);	/* offset, low word */
	*p++ = cpu_to_be32(1);		/* count */
	return (char *)p - (char *)request;
}

/* Decode one such compound and hand back its FFv2 replay digest. */
static bool nfsd_ffv2_ro_digest(struct kunit *test, u32 offset,
				struct nfsd4_compoundargs *args)
{
	struct nfsd_thread_local_info *ntli;
	struct svc_rqst *rqstp;
	struct auth_ops auth = {
		.flavour = RPC_AUTH_NULL,
	};
	struct xdr_stream xdr;
	struct xdr_buf buf;
	__be32 request[32];
	size_t request_len;
	bool decoded;

	ntli = kunit_kzalloc(test, sizeof(*ntli), GFP_KERNEL);
	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	if (!ntli || !rqstp)
		return false;
	request_len = nfsd_ffv2_ro_compound(request, offset);
	xdr_buf_init(&buf, request, request_len);
	buf.len = request_len;
	xdr_init_decode(&xdr, &buf, request, NULL);
	rqstp->rq_argp = args;
	rqstp->rq_private = ntli;
	rqstp->rq_authop = &auth;
	decoded = nfs4svc_decode_compoundargs(rqstp, &xdr);
	if (decoded)
		nfsd4_release_compoundargs(rqstp);
	return decoded;
}

/*
 * Serve one request the way a session slot does: an exact replay returns
 * the retained result and never reaches the operation, anything else is
 * dispatched.  This models the decision nfsd4_sequence() makes from the
 * FFv2 request digest; the slot cache itself needs a live session and a
 * cached reply buffer, which KUnit cannot build.
 */
static __be32 nfsd_ffv2_ro_serve(struct nfsd_ffv2_ro_fixture *f,
				 const struct nfsd4_compoundargs *args,
				 const struct nfsd4_slot *slot,
				 const struct nfsd_ffv2_chunk_request *req,
				 const struct nfsd_ffv2_chunk_result *retained,
				 struct nfsd_ffv2_chunk_result *result,
				 bool *replayed)
{
	if (slot->sl_ffv2_present &&
	    nfsd4_ffv2_replay_identity_match(args, slot)) {
		*replayed = true;
		*result = *retained;
		return nfs_ok;
	}
	*replayed = false;
	return nfsd_ffv2_ro_operation(f, OP_CHUNK_READ, &f->stateid, req,
				      result);
}

/*
 * An identical read is answered from the retained result without entering
 * the provider again; a read whose request identity differs is not, and
 * produces its own result.
 */
static void nfsd_ffv2_provider_replay_test(struct kunit *test)
{
	const struct nfsd_ffv2_chunk_request first = { .offset = 0,
						       .count = 1 };
	const struct nfsd_ffv2_chunk_request second = { .offset = 2,
							.count = 1 };
	struct nfsd_ffv2_chunk_result retained;
	struct nfsd_ffv2_chunk_result result;
	struct nfsd4_compoundargs *args;
	struct nfsd_ffv2_ro_fixture f;
	struct nfsd4_slot *slot;
	bool replayed;
	u64 callbacks;

	args = kunit_kzalloc(test, sizeof(*args), GFP_KERNEL);
	slot = kunit_kzalloc(test, sizeof(*slot), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, args);
	KUNIT_ASSERT_NOT_NULL(test, slot);
	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	/* First request: decoded, dispatched, and its identity retained. */
	if (!nfsd_ffv2_ro_digest(test, 0, args) || !args->ffv2_present ||
	    !args->ffv2_digest_valid) {
		KUNIT_FAIL(test, "failed to digest the first request");
		goto out;
	}
	callbacks = nfsd_ffv2_test_provider_callbacks();
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_ro_serve(&f, args, slot, &first, NULL,
					   &retained, &replayed));
	KUNIT_EXPECT_FALSE(test, replayed);
	KUNIT_EXPECT_EQ(test, callbacks + 1,
			nfsd_ffv2_test_provider_callbacks());
	if (!retained.read.chunks) {
		KUNIT_FAIL(test, "the first read returned no chunk array");
		goto out;
	}
	KUNIT_EXPECT_EQ(test, 0x100U, retained.read.chunks[0].cr_payload_id);
	slot->sl_ffv2_present = true;
	memcpy(slot->sl_ffv2_digest, args->ffv2_digest,
	       sizeof(slot->sl_ffv2_digest));

	/* The same bytes again: retained result, no second callback. */
	memset(args, 0, sizeof(*args));
	if (!nfsd_ffv2_ro_digest(test, 0, args)) {
		KUNIT_FAIL(test, "failed to digest the replayed request");
		goto out;
	}
	callbacks = nfsd_ffv2_test_provider_callbacks();
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_ro_serve(&f, args, slot, &first, &retained,
					   &result, &replayed));
	KUNIT_EXPECT_TRUE(test, replayed);
	KUNIT_EXPECT_EQ(test, callbacks,
			nfsd_ffv2_test_provider_callbacks());
	KUNIT_EXPECT_EQ(test, 1, atomic_read(&f.provider->reads));
	if (!result.read.chunks) {
		KUNIT_FAIL(test, "the replayed read returned no chunk array");
		goto out;
	}
	KUNIT_EXPECT_EQ(test, 0x100U, result.read.chunks[0].cr_payload_id);

	/* A different chunk range is a different request, not a replay. */
	memset(args, 0, sizeof(*args));
	if (!nfsd_ffv2_ro_digest(test, 2, args)) {
		KUNIT_FAIL(test, "failed to digest the second request");
		goto out;
	}
	KUNIT_EXPECT_FALSE(test,
			   nfsd4_ffv2_replay_identity_match(args, slot));
	callbacks = nfsd_ffv2_test_provider_callbacks();
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_ro_serve(&f, args, slot, &second, &retained,
					   &result, &replayed));
	KUNIT_EXPECT_FALSE(test, replayed);
	KUNIT_EXPECT_EQ(test, callbacks + 1,
			nfsd_ffv2_test_provider_callbacks());
	KUNIT_EXPECT_EQ(test, 2, atomic_read(&f.provider->reads));
	if (!result.read.chunks) {
		KUNIT_FAIL(test, "the second read returned no chunk array");
		goto out;
	}
	KUNIT_EXPECT_EQ(test, 0x102U, result.read.chunks[0].cr_payload_id);
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

struct nfsd_ffv2_ro_read_ctx {
	struct nfsd_ffv2_ro_fixture	*f;
	struct nfsd_ffv2_chunk_request	request;
	struct nfsd_ffv2_chunk_result	result;
	__be32				status;
	struct completion		done;
};

static int nfsd_ffv2_ro_read_thread(void *data)
{
	struct nfsd_ffv2_ro_read_ctx *ctx = data;

	ctx->status = nfsd_ffv2_ro_operation(ctx->f, OP_CHUNK_READ,
					     &ctx->f->stateid, &ctx->request,
					     &ctx->result);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

/*
 * Retirement overlapping an admitted read.  The read is held inside the
 * provider, retirement is started, and it must wait: the execution
 * admission the gate took is what it drains.  Exactly one callback runs,
 * both complete, and nothing is left holding the generation.
 */
static void nfsd_ffv2_provider_retire_overlap_test(struct kunit *test)
{
	struct nfsd_ffv2_object_unregister_ctx retire = {};
	struct nfsd_ffv2_ro_read_ctx read = {};
	struct completion enter, release;
	struct task_struct *read_task = NULL;
	struct task_struct *retire_task = NULL;
	struct nfsd_ffv2_ro_fixture f;
	u8 drained[16];
	u64 callbacks;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	init_completion(&enter);
	init_completion(&release);
	f.provider->enter = &enter;
	f.provider->release = &release;

	read.f = &f;
	read.request.offset = 0;
	read.request.count = 1;
	read.status = nfserr_serverfault;
	init_completion(&read.done);
	callbacks = nfsd_ffv2_test_provider_callbacks();
	read_task = kthread_run(nfsd_ffv2_ro_read_thread, &read,
				"nfsd-ffv2-ro-read");
	if (IS_ERR(read_task)) {
		KUNIT_FAIL(test, "failed to start read thread: %ld",
			   PTR_ERR(read_task));
		read_task = NULL;
		goto out_unstall;
	}

	/*
	 * The read is now inside the provider, holding its admission.  A
	 * missed signal must not return from the test function: the read
	 * thread would be left waiting on a completion this frame owns.
	 * Take the recovery path instead.
	 */
	if (!wait_for_completion_timeout(&enter, 5 * HZ)) {
		KUNIT_FAIL(test, "read thread never entered the provider");
		goto out_unstall;
	}

	retire.nn = f.nn;
	retire.generation = f.generation_id;
	memcpy(retire.object_uuid, f.uuid, sizeof(f.uuid));
	retire.result = -EINPROGRESS;
	init_completion(&retire.done);
	retire_task = kthread_run(nfsd_ffv2_object_unregister_thread, &retire,
				  "nfsd-ffv2-ro-retire");
	if (IS_ERR(retire_task)) {
		KUNIT_FAIL(test, "failed to start retirement thread: %ld",
			   PTR_ERR(retire_task));
		retire_task = NULL;
		goto out_unstall;
	}

	/* Retirement cannot finish while the read holds its admission. */
	KUNIT_EXPECT_EQ(test,
			wait_for_completion_timeout(&retire.done, HZ / 2), 0UL);

out_unstall:
	/*
	 * complete_all() rather than complete(): the release must also free
	 * a callback that reaches the stall after this point, so no path out
	 * of this test can leave a thread inside the provider.
	 */
	complete_all(&release);
	if (read_task) {
		KUNIT_EXPECT_NE(test,
				wait_for_completion_timeout(&read.done, 5 * HZ),
				0UL);
		kthread_stop(read_task);
		KUNIT_EXPECT_EQ(test, nfs_ok, read.status);
	}
	f.provider->enter = NULL;
	f.provider->release = NULL;

	/*
	 * The read is done, but the fixture still holds the mapped
	 * filehandle's binding admission and a reference to the published
	 * service export.  Retirement waits for both, so release them here
	 * and only then require it to finish.
	 */
	if (f.mapped) {
		fh_put(f.mapped);
		f.mapped = NULL;
	}
	if (f.published) {
		exp_put(f.published);
		f.published = NULL;
	}
	if (retire_task) {
		KUNIT_EXPECT_NE(test,
				wait_for_completion_timeout(&retire.done,
							    5 * HZ),
				0UL);
		kthread_stop(retire_task);
		KUNIT_EXPECT_EQ(test, 0, retire.result);
		/* Nothing is left holding the retired generation. */
		KUNIT_EXPECT_FALSE(test,
				   nfsd_ffv2_test_active_object_uuid(f.nn,
								     drained));
	}
	if (read_task) {
		KUNIT_EXPECT_EQ(test, callbacks + 1,
				nfsd_ffv2_test_provider_callbacks());
		KUNIT_EXPECT_EQ(test, 1, atomic_read(&f.provider->reads));
	}
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

/*
 * Ordinary NFS operations are unaffected by an installed provider, and the
 * provider is never consulted for them.  The service export still refuses
 * ordinary operations, and an unmapped handle still has nothing to
 * authorize.
 */
static void nfsd_ffv2_provider_ordinary_ops_test(struct kunit *test)
{
	struct nfsd_ffv2_admission admission = {};
	struct nfsd_ffv2_ro_fixture f;
	struct svc_fh *unmapped;
	stateid_t sid;
	u64 callbacks;

	unmapped = kunit_kzalloc(test, sizeof(*unmapped), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, unmapped);
	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	callbacks = nfsd_ffv2_test_provider_callbacks();
	sid = nfsd_ffv2_test_stateid(1, 2, 3, 4);

	/* Handle-positioning operations remain available on the export. */
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd4_ffv2_export_policy_check(f.published, OP_PUTFH));
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd4_ffv2_export_policy_check(f.published,
						       OP_PUTROOTFH));
	/* Ordinary data operations are still refused there. */
	KUNIT_EXPECT_EQ(test, nfserr_notsupp,
			nfsd4_ffv2_export_policy_check(f.published, OP_READ));
	KUNIT_EXPECT_EQ(test, nfserr_notsupp,
			nfsd4_ffv2_export_policy_check(f.published, OP_WRITE));
	KUNIT_EXPECT_EQ(test, nfserr_notsupp,
			nfsd4_ffv2_export_policy_check(f.published, OP_GETATTR));

	/* An ordinary operation has no FFv2 profile at all. */
	KUNIT_EXPECT_EQ(test, nfserr_notsupp,
			nfsd_ffv2_test_validate_operation(f.rqstp, unmapped,
							  f.session, OP_READ,
							  &sid, NULL,
							  &admission));
	/* An FFv2 operation on an unmapped handle stops at the binding. */
	KUNIT_EXPECT_EQ(test, nfserr_stale,
			nfsd_ffv2_test_validate_operation(f.rqstp, unmapped,
							  f.session,
							  OP_CHUNK_READ, &sid,
							  NULL, &admission));

	/* None of that consulted the provider. */
	KUNIT_EXPECT_EQ(test, callbacks,
			nfsd_ffv2_test_provider_callbacks());
	KUNIT_EXPECT_EQ(test, 0, atomic_read(&f.provider->reads));
	KUNIT_EXPECT_EQ(test, 0, atomic_read(&f.provider->header_reads));
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

/*
 * Provider installation is rejected when incomplete or already held, and
 * removing the provider closes the boundary again.  Building and tearing
 * the whole fixture down twice must leave the namespace anchor exactly
 * where it started.
 */
static void nfsd_ffv2_provider_install_cycle_test(struct kunit *test)
{
	static const struct nfsd_ffv2_provider_ops partial = {
		.chunk_read = nfsd_ffv2_ro_chunk_read,
	};
	const struct nfsd_ffv2_provider_ops *ops = &nfsd_ffv2_ro_provider_ops;
	const struct nfsd_ffv2_chunk_request req = { .offset = 0, .count = 1 };
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_ffv2_ro_fixture f;
	unsigned int anchor_before;
	u64 callbacks;
	int pass;

	/* No namespace, no provider. */
	KUNIT_EXPECT_EQ(test, -EINVAL,
			nfsd_ffv2_test_provider_install(NULL, ops, NULL));

	for (pass = 0; pass < 2; pass++) {
		if (!nfsd_ffv2_ro_fixture_init(test, &f)) {
			nfsd_ffv2_ro_fixture_exit(test, &f);
			return;
		}
		anchor_before = nfsd_ffv2_test_anchor_refcount(f.nn);

		/* An incomplete operations vector is never installed. */
		KUNIT_EXPECT_EQ(test, -EINVAL,
				nfsd_ffv2_test_provider_install(f.nn, NULL,
								NULL));
		KUNIT_EXPECT_EQ(test, -EINVAL,
				nfsd_ffv2_test_provider_install(f.nn, &partial,
								NULL));

		/* Only one provider at a time, per namespace. */
		KUNIT_EXPECT_EQ(test, -EBUSY,
				nfsd_ffv2_test_provider_install(f.nn, ops,
								f.provider));

		callbacks = nfsd_ffv2_test_provider_callbacks();
		KUNIT_EXPECT_EQ(test, nfs_ok,
				nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ,
						       &f.stateid, &req,
						       &result));
		KUNIT_EXPECT_EQ(test, callbacks + 1,
				nfsd_ffv2_test_provider_callbacks());

		/* Removed: the boundary is closed again, with no callback. */
		nfsd_ffv2_test_provider_remove(f.nn);
		f.provider_installed = false;
		callbacks = nfsd_ffv2_test_provider_callbacks();
		KUNIT_EXPECT_EQ(test, nfserr_notsupp,
				nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ,
						       &f.stateid, &req,
						       &result));
		KUNIT_EXPECT_EQ(test, callbacks,
				nfsd_ffv2_test_provider_callbacks());

		/* And installable again. */
		KUNIT_EXPECT_EQ(test, 0,
				nfsd_ffv2_test_provider_install(f.nn, ops,
								f.provider));
		f.provider_installed = true;
		KUNIT_EXPECT_EQ(test, nfs_ok,
				nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ,
						       &f.stateid, &req,
						       &result));

		/* The admission taken for each read was released. */
		KUNIT_EXPECT_EQ(test, anchor_before,
				nfsd_ffv2_test_anchor_refcount(f.nn));
		nfsd_ffv2_ro_fixture_exit(test, &f);
	}
}

/*
 * The harness's own recovery path.  A callback that never announces itself
 * must not strand the thread running it: the cleanup path releases the
 * provider unconditionally and joins the thread, so a lost entry signal
 * costs a failed expectation rather than a hung suite and a thread left
 * waiting on completions this stack frame owns.
 */
static void nfsd_ffv2_provider_stall_recovery_test(struct kunit *test)
{
	struct nfsd_ffv2_ro_read_ctx read = {};
	struct completion enter, release;
	struct task_struct *read_task = NULL;
	struct nfsd_ffv2_ro_fixture f;
	u64 callbacks;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	init_completion(&enter);
	init_completion(&release);
	/* Injected fault: the callback stalls but never signals entry. */
	f.provider->enter = NULL;
	f.provider->release = &release;

	read.f = &f;
	read.request.offset = 0;
	read.request.count = 1;
	read.status = nfserr_serverfault;
	init_completion(&read.done);
	callbacks = nfsd_ffv2_test_provider_callbacks();
	read_task = kthread_run(nfsd_ffv2_ro_read_thread, &read,
				"nfsd-ffv2-ro-read");
	if (IS_ERR(read_task)) {
		KUNIT_FAIL(test, "failed to start read thread: %ld",
			   PTR_ERR(read_task));
		read_task = NULL;
		goto out_unstall;
	}

	/* The signal never arrives, exactly as a lost wakeup would look. */
	KUNIT_EXPECT_EQ(test, wait_for_completion_timeout(&enter, HZ / 2), 0UL);

out_unstall:
	complete_all(&release);
	if (read_task) {
		/* Recovered: the held callback returns and the thread joins. */
		KUNIT_EXPECT_NE(test,
				wait_for_completion_timeout(&read.done, 5 * HZ),
				0UL);
		kthread_stop(read_task);
		KUNIT_EXPECT_EQ(test, nfs_ok, read.status);
		KUNIT_EXPECT_EQ(test, callbacks + 1,
				nfsd_ffv2_test_provider_callbacks());
	}
	f.provider->enter = NULL;
	f.provider->release = NULL;
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

struct nfsd_ffv2_ro_remove_ctx {
	struct nfsd_net		*nn;
	struct completion	done;
};

static int nfsd_ffv2_ro_remove_thread(void *data)
{
	struct nfsd_ffv2_ro_remove_ctx *ctx = data;

	nfsd_ffv2_test_provider_remove(ctx->nn);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

/*
 * A provider that owns its operations vector.  A real provider allocates
 * the vector together with its state and frees both once it has been
 * removed, so removal must not return while a callback is still inside
 * them.  The read is held in the callback, removal is started, and it must
 * block until the callback is released; only then are the vector and the
 * state freed.
 */
static void nfsd_ffv2_provider_dynamic_free_test(struct kunit *test)
{
	const struct nfsd_ffv2_chunk_request req = { .offset = 0, .count = 1 };
	struct nfsd_ffv2_ro_provider *dynamic = NULL;
	struct nfsd_ffv2_provider_ops *ops = NULL;
	struct nfsd_ffv2_ro_remove_ctx remove;
	struct nfsd_ffv2_ro_read_ctx read = {};
	struct task_struct *remove_task = NULL;
	struct task_struct *read_task = NULL;
	struct nfsd_ffv2_chunk_result result;
	struct completion enter, release;
	struct nfsd_ffv2_ro_fixture f;
	u64 callbacks;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	ops = kmalloc_obj(*ops, GFP_KERNEL);
	dynamic = kmalloc_obj(*dynamic, GFP_KERNEL);
	if (!ops || !dynamic) {
		KUNIT_FAIL(test, "failed to allocate a dynamic provider");
		goto out_free;
	}
	*ops = nfsd_ffv2_ro_provider_ops;
	nfsd_ffv2_ro_provider_init(dynamic);
	dynamic->object = f.provider->object;

	/* Swap the fixture's static provider for the caller-owned one. */
	nfsd_ffv2_test_provider_remove(f.nn);
	f.provider_installed = false;
	if (nfsd_ffv2_test_provider_install(f.nn, ops, dynamic)) {
		KUNIT_FAIL(test, "failed to install the dynamic provider");
		goto out_free;
	}
	f.provider_installed = true;

	init_completion(&enter);
	init_completion(&release);
	dynamic->enter = &enter;
	dynamic->release = &release;

	read.f = &f;
	read.request.offset = 0;
	read.request.count = 1;
	read.status = nfserr_serverfault;
	init_completion(&read.done);
	callbacks = nfsd_ffv2_test_provider_callbacks();
	read_task = kthread_run(nfsd_ffv2_ro_read_thread, &read,
				"nfsd-ffv2-ro-read");
	if (IS_ERR(read_task)) {
		KUNIT_FAIL(test, "failed to start read thread: %ld",
			   PTR_ERR(read_task));
		read_task = NULL;
		goto out_unstall;
	}
	if (!wait_for_completion_timeout(&enter, 5 * HZ)) {
		KUNIT_FAIL(test, "read thread never entered the provider");
		goto out_unstall;
	}

	remove.nn = f.nn;
	init_completion(&remove.done);
	remove_task = kthread_run(nfsd_ffv2_ro_remove_thread, &remove,
				  "nfsd-ffv2-ro-remove");
	if (IS_ERR(remove_task)) {
		KUNIT_FAIL(test, "failed to start removal thread: %ld",
			   PTR_ERR(remove_task));
		remove_task = NULL;
		goto out_unstall;
	}

	/* Removal cannot return while the callback is inside the vector. */
	KUNIT_EXPECT_EQ(test,
			wait_for_completion_timeout(&remove.done, HZ / 2), 0UL);

out_unstall:
	complete_all(&release);
	if (read_task) {
		KUNIT_EXPECT_NE(test,
				wait_for_completion_timeout(&read.done, 5 * HZ),
				0UL);
		kthread_stop(read_task);
		KUNIT_EXPECT_EQ(test, nfs_ok, read.status);
		KUNIT_EXPECT_EQ(test, callbacks + 1,
				nfsd_ffv2_test_provider_callbacks());
		KUNIT_EXPECT_EQ(test, 1, atomic_read(&dynamic->reads));
	}
	if (remove_task) {
		/* Released, so removal may finish and the vector is idle. */
		KUNIT_EXPECT_NE(test,
				wait_for_completion_timeout(&remove.done,
							    5 * HZ),
				0UL);
		kthread_stop(remove_task);
		f.provider_installed = false;
	}
	if (dynamic) {
		dynamic->enter = NULL;
		dynamic->release = NULL;
	}
out_free:
	/*
	 * Close the boundary before the vector and the state go away: after
	 * this the provider cannot be entered, so freeing them is safe.
	 */
	if (f.provider_installed) {
		nfsd_ffv2_test_provider_remove(f.nn);
		f.provider_installed = false;
	}
	callbacks = nfsd_ffv2_test_provider_callbacks();
	KUNIT_EXPECT_EQ(test, nfserr_notsupp,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &f.stateid,
					       &req, &result));
	KUNIT_EXPECT_EQ(test, callbacks,
			nfsd_ffv2_test_provider_callbacks());
	kfree(dynamic);
	kfree(ops);
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

/*
 * Fixture construction's own timeout path.  Publication is a production
 * transition that cannot be cancelled, so construction must never return
 * while the worker can still reach the storage it was handed.  Force the
 * wait to expire against a worker that is provably still running, and
 * require the fixture to come out whole: the worker joined, the generation
 * it published recorded, and an authorized read still served.
 */
static void nfsd_ffv2_provider_publish_timeout_test(struct kunit *test)
{
	const struct nfsd_ffv2_chunk_request req = { .offset = 0, .count = 1 };
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_ffv2_ro_fixture f;

	/*
	 * One jiffy against a worker that sleeps for longer than that wait
	 * whatever HZ is, so the timeout branch is always the one taken.
	 */
	if (!nfsd_ffv2_ro_fixture_init_wait(test, &f, 1, true))
		goto out;

	KUNIT_EXPECT_TRUE(test, f.publish_timed_out);
	/* Waited out rather than abandoned, so publication still landed. */
	KUNIT_EXPECT_NE(test, 0ULL, f.generation_id);
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &f.stateid,
					       &req, &result));
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

/* A provider that claims more chunks than it was asked for. */
static __be32 nfsd_ffv2_ro_overcount_read(void *opaque,
					  const struct nfsd_ffv2_object *object,
					  const struct nfsd_ffv2_chunk_request *req,
					  struct nfsd_ffv2_chunk_result *result)
{
	struct nfsd_ffv2_ro_provider *provider = opaque;

	atomic_inc(&provider->reads);
	result->count = req->count + 1;
	result->read.chunks = provider->chunks;
	return nfs_ok;
}

/* A provider that reports chunks but hands back no array. */
static __be32 nfsd_ffv2_ro_empty_read(void *opaque,
				      const struct nfsd_ffv2_object *object,
				      const struct nfsd_ffv2_chunk_request *req,
				      struct nfsd_ffv2_chunk_result *result)
{
	struct nfsd_ffv2_ro_provider *provider = opaque;

	atomic_inc(&provider->reads);
	result->count = 1;
	result->read.chunks = NULL;
	return nfs_ok;
}

/* A header read missing one of its five co-indexed arrays. */
static __be32
nfsd_ffv2_ro_partial_header_read(void *opaque,
				 const struct nfsd_ffv2_object *object,
				 const struct nfsd_ffv2_chunk_request *req,
				 struct nfsd_ffv2_chunk_result *result)
{
	struct nfsd_ffv2_ro_provider *provider = opaque;

	atomic_inc(&provider->header_reads);
	result->count = 1;
	result->header.status = provider->status;
	result->header.locked = provider->locked;
	result->header.owners = provider->owners;
	result->header.guards = provider->guards;
	result->header.predecessors = NULL;
	return nfs_ok;
}

/*
 * The boundary's postcondition on provider output.  A result that claims
 * more chunks than were requested, or claims chunks without the arrays an
 * encoder would walk, is refused with NFS4ERR_SERVERFAULT and zeroed, so a
 * later encoder never sees a cardinality it cannot trust.  The callback
 * still ran in each case: this is the boundary rejecting the answer, not
 * the gate refusing the request.
 */
static void nfsd_ffv2_provider_malformed_result_test(struct kunit *test)
{
	static const struct nfsd_ffv2_provider_ops overcount = {
		.chunk_read		= nfsd_ffv2_ro_overcount_read,
		.chunk_header_read	= nfsd_ffv2_ro_chunk_header_read,
	};
	static const struct nfsd_ffv2_provider_ops empty = {
		.chunk_read		= nfsd_ffv2_ro_empty_read,
		.chunk_header_read	= nfsd_ffv2_ro_chunk_header_read,
	};
	static const struct nfsd_ffv2_provider_ops partial = {
		.chunk_read		= nfsd_ffv2_ro_chunk_read,
		.chunk_header_read	= nfsd_ffv2_ro_partial_header_read,
	};
	const struct nfsd_ffv2_chunk_request req = { .offset = 0, .count = 1 };
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_ffv2_ro_fixture f;
	u64 callbacks;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	/* More chunks than asked for. */
	nfsd_ffv2_test_provider_remove(f.nn);
	f.provider_installed = false;
	if (nfsd_ffv2_test_provider_install(f.nn, &overcount, f.provider)) {
		KUNIT_FAIL(test, "failed to install the overcount provider");
		goto out;
	}
	f.provider_installed = true;
	callbacks = nfsd_ffv2_test_provider_callbacks();
	KUNIT_EXPECT_EQ(test, nfserr_serverfault,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &f.stateid,
					       &req, &result));
	KUNIT_EXPECT_EQ(test, callbacks + 1,
			nfsd_ffv2_test_provider_callbacks());
	/* Refused results are zeroed, not passed through. */
	KUNIT_EXPECT_EQ(test, 0U, result.count);
	KUNIT_EXPECT_NULL(test, result.read.chunks);

	/* Chunks claimed with no array behind them. */
	nfsd_ffv2_test_provider_remove(f.nn);
	f.provider_installed = false;
	if (nfsd_ffv2_test_provider_install(f.nn, &empty, f.provider)) {
		KUNIT_FAIL(test, "failed to install the empty provider");
		goto out;
	}
	f.provider_installed = true;
	callbacks = nfsd_ffv2_test_provider_callbacks();
	KUNIT_EXPECT_EQ(test, nfserr_serverfault,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &f.stateid,
					       &req, &result));
	KUNIT_EXPECT_EQ(test, callbacks + 1,
			nfsd_ffv2_test_provider_callbacks());
	KUNIT_EXPECT_EQ(test, 0U, result.count);

	/* A header read missing one of its five arrays. */
	nfsd_ffv2_test_provider_remove(f.nn);
	f.provider_installed = false;
	if (nfsd_ffv2_test_provider_install(f.nn, &partial, f.provider)) {
		KUNIT_FAIL(test, "failed to install the partial provider");
		goto out;
	}
	f.provider_installed = true;
	callbacks = nfsd_ffv2_test_provider_callbacks();
	KUNIT_EXPECT_EQ(test, nfserr_serverfault,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_HEADER_READ,
					       &f.stateid, &req, &result));
	KUNIT_EXPECT_EQ(test, callbacks + 1,
			nfsd_ffv2_test_provider_callbacks());
	KUNIT_EXPECT_EQ(test, 0U, result.count);
	KUNIT_EXPECT_NULL(test, result.header.predecessors);

	/* A well-formed result is still served. */
	nfsd_ffv2_test_provider_remove(f.nn);
	f.provider_installed = false;
	if (nfsd_ffv2_test_provider_install(f.nn, &nfsd_ffv2_ro_provider_ops,
					    f.provider)) {
		KUNIT_FAIL(test, "failed to reinstall the fixture provider");
		goto out;
	}
	f.provider_installed = true;
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &f.stateid,
					       &req, &result));
	KUNIT_EXPECT_EQ(test, 1U, result.count);
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

/*
 * The stale-binding negative, run rather than reasoned about.
 *
 * A namespace holds at most one generation at a time: the generation gate
 * refuses a new one while any is pending, active, or retiring, so a
 * binding can never be caught against a *newer* active generation.  The
 * window where a held binding stops being current is retirement, which
 * clears the active generation and hides the object before it drains the
 * admissions that binding holds.  Read through the binding inside that
 * window: the gate must refuse it as stale, ahead of the boundary, with
 * the provider never entered.
 */
static void nfsd_ffv2_provider_retired_generation_test(struct kunit *test)
{
	const struct nfsd_ffv2_chunk_request req = { .offset = 0, .count = 1 };
	struct nfsd_ffv2_object_unregister_ctx retire = {};
	struct task_struct *retire_task = NULL;
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_ffv2_ro_fixture f;
	u8 drained[16];
	u64 callbacks;
	int waited;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	/* Current, so the read is served. */
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &f.stateid,
					       &req, &result));

	retire.nn = f.nn;
	retire.generation = f.generation_id;
	memcpy(retire.object_uuid, f.uuid, sizeof(f.uuid));
	retire.result = -EINPROGRESS;
	init_completion(&retire.done);
	retire_task = kthread_run(nfsd_ffv2_object_unregister_thread, &retire,
				  "nfsd-ffv2-ro-retire");
	if (IS_ERR(retire_task)) {
		KUNIT_FAIL(test, "failed to start retirement thread: %ld",
			   PTR_ERR(retire_task));
		retire_task = NULL;
		goto out;
	}

	/*
	 * Retirement parks draining the admissions the fixture holds, which
	 * is after it has cleared the active generation.  Wait for that,
	 * rather than for a duration, so the read below lands in the window.
	 */
	for (waited = 0; waited < 250; waited++) {
		if (!nfsd_ffv2_test_active_object_uuid(f.nn, drained))
			break;
		msleep(20);
	}
	if (nfsd_ffv2_test_active_object_uuid(f.nn, drained)) {
		KUNIT_FAIL(test,
			   "retirement never cleared the active generation");
		goto out_drain;
	}

	/* Same handle, same stateid: the generation moved underneath it. */
	callbacks = nfsd_ffv2_test_provider_callbacks();
	KUNIT_EXPECT_EQ(test, nfserr_stale,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &f.stateid,
					       &req, &result));
	KUNIT_EXPECT_EQ(test, nfserr_stale,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_HEADER_READ,
					       &f.stateid, &req, &result));
	KUNIT_EXPECT_EQ(test, callbacks,
			nfsd_ffv2_test_provider_callbacks());

out_drain:
	/* Release what retirement is draining, then require it to finish. */
	if (f.mapped) {
		fh_put(f.mapped);
		f.mapped = NULL;
	}
	if (f.published) {
		exp_put(f.published);
		f.published = NULL;
	}
	KUNIT_EXPECT_NE(test,
			wait_for_completion_timeout(&retire.done, 5 * HZ), 0UL);
	kthread_stop(retire_task);
	KUNIT_EXPECT_EQ(test, 0, retire.result);
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

/*
 * Run one authorized operation but keep the execution admission, so the
 * caller stands where a wire encoder would: holding a result whose arrays
 * are still borrowed from the provider.  The caller must complete the
 * admission.
 */
static __be32 nfsd_ffv2_ro_operation_hold(struct nfsd_ffv2_ro_fixture *f,
					  u32 opnum,
					  const struct nfsd_ffv2_chunk_request *req,
					  struct nfsd_ffv2_chunk_result *result,
					  struct nfsd_ffv2_admission *admission)
{
	__be32 status;

	status = nfsd_ffv2_test_validate_operation(f->rqstp, f->mapped,
						   f->session, opnum,
						   &f->stateid, NULL,
						   admission);
	if (status)
		return status;
	return nfsd_ffv2_provider_probe(f->rqstp, f->mapped, opnum, req,
					result, admission);
}

/*
 * The result-storage contract, held rather than documented.  A result's
 * arrays are borrowed from the provider, and the caller may still be
 * reading them after the callback has returned -- which is exactly where a
 * wire encoder will run.  Removal must therefore block until the execution
 * admission completes, not merely until the callback returns.  The
 * provider here owns its operations vector and state, so if removal
 * returned early the encoder's arrays would be freed underneath it.
 */
static void nfsd_ffv2_provider_result_lifetime_test(struct kunit *test)
{
	const struct nfsd_ffv2_chunk_request req = { .offset = 0, .count = 2 };
	struct nfsd_ffv2_ro_provider *dynamic = NULL;
	struct nfsd_ffv2_provider_ops *ops = NULL;
	struct nfsd_ffv2_admission admission = {};
	struct nfsd_ffv2_ro_remove_ctx remove;
	struct task_struct *remove_task = NULL;
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_ffv2_ro_fixture f;
	bool held = false;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	ops = kmalloc_obj(*ops, GFP_KERNEL);
	dynamic = kmalloc_obj(*dynamic, GFP_KERNEL);
	if (!ops || !dynamic) {
		KUNIT_FAIL(test, "failed to allocate a dynamic provider");
		goto out_free;
	}
	*ops = nfsd_ffv2_ro_provider_ops;
	nfsd_ffv2_ro_provider_init(dynamic);
	dynamic->object = f.provider->object;

	nfsd_ffv2_test_provider_remove(f.nn);
	f.provider_installed = false;
	if (nfsd_ffv2_test_provider_install(f.nn, ops, dynamic)) {
		KUNIT_FAIL(test, "failed to install the dynamic provider");
		goto out_free;
	}
	f.provider_installed = true;

	/* The callback has returned; the admission is still held. */
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_ro_operation_hold(&f, OP_CHUNK_READ, &req,
						    &result, &admission));
	held = true;
	KUNIT_EXPECT_EQ(test, 2U, result.count);
	if (!result.read.chunks) {
		KUNIT_FAIL(test, "read returned no chunk array");
		goto out_complete;
	}

	remove.nn = f.nn;
	init_completion(&remove.done);
	remove_task = kthread_run(nfsd_ffv2_ro_remove_thread, &remove,
				  "nfsd-ffv2-ro-remove");
	if (IS_ERR(remove_task)) {
		KUNIT_FAIL(test, "failed to start removal thread: %ld",
			   PTR_ERR(remove_task));
		remove_task = NULL;
		goto out_complete;
	}

	/* Removal waits for the admission, not just for the callback. */
	KUNIT_EXPECT_EQ(test,
			wait_for_completion_timeout(&remove.done, HZ / 2), 0UL);
	/* And the borrowed arrays are still the provider's, still readable. */
	KUNIT_EXPECT_EQ(test, 0x100U, result.read.chunks[0].cr_payload_id);
	KUNIT_EXPECT_EQ(test, 0x101U, result.read.chunks[1].cr_payload_id);

out_complete:
	if (held) {
		nfsd_ffv2_complete(&admission);
		held = false;
	}
	if (remove_task) {
		/* Completed, so removal may finish and the storage is free. */
		KUNIT_EXPECT_NE(test,
				wait_for_completion_timeout(&remove.done,
							    5 * HZ),
				0UL);
		kthread_stop(remove_task);
		f.provider_installed = false;
	}
out_free:
	if (f.provider_installed) {
		nfsd_ffv2_test_provider_remove(f.nn);
		f.provider_installed = false;
	}
	kfree(dynamic);
	kfree(ops);
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

/*
 * Namespace exit closes the provider boundary itself.  A namespace must
 * not depend on whoever installed a provider to remove it, so the fence in
 * nfsd_ffv2_net_pre_exit() unpublishes, drains, and frees the container.
 * Install a caller-owned provider, deliberately hand the fixture no
 * responsibility for it, and require the fence to have retired it by the
 * time the namespace is gone -- after which freeing the vector is safe.
 */
static void nfsd_ffv2_provider_netns_fence_test(struct kunit *test)
{
	struct nfsd_ffv2_ro_provider *dynamic = NULL;
	struct nfsd_ffv2_provider_ops *ops = NULL;
	struct nfsd_ffv2_ro_fixture f;
	bool abandoned = false;
	u64 fenced = 0;
	int waited;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	ops = kmalloc_obj(*ops, GFP_KERNEL);
	dynamic = kmalloc_obj(*dynamic, GFP_KERNEL);
	if (!ops || !dynamic) {
		KUNIT_FAIL(test, "failed to allocate a dynamic provider");
		goto out;
	}
	*ops = nfsd_ffv2_ro_provider_ops;
	nfsd_ffv2_ro_provider_init(dynamic);
	dynamic->object = f.provider->object;

	nfsd_ffv2_test_provider_remove(f.nn);
	f.provider_installed = false;
	fenced = nfsd_ffv2_test_provider_fenced();
	if (nfsd_ffv2_test_provider_install(f.nn, ops, dynamic)) {
		KUNIT_FAIL(test, "failed to install the dynamic provider");
		goto out;
	}
	/*
	 * Left installed on purpose: provider_installed stays false, so
	 * teardown will not remove it and only the fence can.
	 */
	abandoned = true;

out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
	/*
	 * put_net() queues the namespace's cleanup rather than running it,
	 * and net_ns_barrier() only serialises against a pernet operation
	 * already under way, so wait for the fence's own counter rather than
	 * assuming teardown has happened.  This is also what makes the free
	 * below safe: the fence has drained the container by then.
	 */
	for (waited = 0; abandoned && waited < 250; waited++) {
		if (nfsd_ffv2_test_provider_fenced() > fenced)
			break;
		msleep(20);
	}
	if (abandoned)
		KUNIT_EXPECT_EQ(test, fenced + 1,
				nfsd_ffv2_test_provider_fenced());
	kfree(dynamic);
	kfree(ops);
}

/*
 * One operation that holds its admission open on its own thread, so two
 * can overlap with both results live at once.
 */
struct nfsd_ffv2_ro_hold_ctx {
	struct nfsd_ffv2_ro_fixture	*f;
	struct nfsd_ffv2_chunk_request	request;
	struct nfsd_ffv2_chunk_result	result;
	struct nfsd_ffv2_admission	admission;
	__be32				status;
	u32				expect_payload;
	bool				stable;
	struct completion		ready;
	struct completion		release;
	struct completion		done;
};

static int nfsd_ffv2_ro_hold_thread(void *data)
{
	struct nfsd_ffv2_ro_hold_ctx *ctx = data;

	ctx->status = nfsd_ffv2_ro_operation_hold(ctx->f, OP_CHUNK_READ,
						  &ctx->request, &ctx->result,
						  &ctx->admission);
	complete(&ctx->ready);
	/* Both results are live from here until the test releases us. */
	wait_for_completion(&ctx->release);
	ctx->stable = ctx->status == nfs_ok && ctx->result.read.chunks &&
		      ctx->result.read.chunks[0].cr_payload_id ==
			      ctx->expect_payload;
	nfsd_ffv2_complete(&ctx->admission);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

/*
 * Two successful results live at once.  Holding a reference keeps the
 * provider's storage allocated, but says nothing about whether the
 * provider reused it: a shared scratch array overwritten by the next
 * callback would corrupt a result whose reference is still perfectly
 * valid.  Run two reads for different chunk ranges, keep both admissions
 * open until both callbacks have returned, and require each result to
 * still describe its own range.
 *
 * This demonstrates the property for a provider that honours it -- the
 * fixture's arrays are filled once and never written again.  It is not a
 * check the boundary performs; the contract in ffv2.h is what a provider
 * has to meet, and nfsd cannot verify it without copying.
 */
static void nfsd_ffv2_provider_concurrent_results_test(struct kunit *test)
{
	struct nfsd_ffv2_ro_hold_ctx first = {};
	struct nfsd_ffv2_ro_hold_ctx second = {};
	struct task_struct *first_task = NULL;
	struct task_struct *second_task = NULL;
	struct nfsd_ffv2_ro_fixture f;
	u64 callbacks;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	first.f = &f;
	first.request.offset = 0;
	first.request.count = 1;
	first.expect_payload = 0x100;
	first.status = nfserr_serverfault;
	init_completion(&first.ready);
	init_completion(&first.release);
	init_completion(&first.done);

	second.f = &f;
	second.request.offset = 2;
	second.request.count = 1;
	second.expect_payload = 0x102;
	second.status = nfserr_serverfault;
	init_completion(&second.ready);
	init_completion(&second.release);
	init_completion(&second.done);

	callbacks = nfsd_ffv2_test_provider_callbacks();
	first_task = kthread_run(nfsd_ffv2_ro_hold_thread, &first,
				 "nfsd-ffv2-ro-hold1");
	if (IS_ERR(first_task)) {
		KUNIT_FAIL(test, "failed to start first reader: %ld",
			   PTR_ERR(first_task));
		first_task = NULL;
		goto out_release;
	}
	second_task = kthread_run(nfsd_ffv2_ro_hold_thread, &second,
				  "nfsd-ffv2-ro-hold2");
	if (IS_ERR(second_task)) {
		KUNIT_FAIL(test, "failed to start second reader: %ld",
			   PTR_ERR(second_task));
		second_task = NULL;
		goto out_release;
	}

	/* Both callbacks have returned; neither admission has completed. */
	KUNIT_EXPECT_NE(test,
			wait_for_completion_timeout(&first.ready, 5 * HZ), 0UL);
	KUNIT_EXPECT_NE(test,
			wait_for_completion_timeout(&second.ready, 5 * HZ),
			0UL);

out_release:
	complete_all(&first.release);
	complete_all(&second.release);
	if (first_task) {
		KUNIT_EXPECT_NE(test,
				wait_for_completion_timeout(&first.done,
							    5 * HZ), 0UL);
		kthread_stop(first_task);
		KUNIT_EXPECT_EQ(test, nfs_ok, first.status);
		/* Its arrays still describe chunk 0, not the other range. */
		KUNIT_EXPECT_TRUE(test, first.stable);
	}
	if (second_task) {
		KUNIT_EXPECT_NE(test,
				wait_for_completion_timeout(&second.done,
							    5 * HZ), 0UL);
		kthread_stop(second_task);
		KUNIT_EXPECT_EQ(test, nfs_ok, second.status);
		KUNIT_EXPECT_TRUE(test, second.stable);
	}
	if (first_task && second_task)
		KUNIT_EXPECT_EQ(test, callbacks + 2,
				nfsd_ffv2_test_provider_callbacks());
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

/*
 * Installation and namespace exit are one transaction.  Publication takes
 * the anchor lock and requires NET_LIVE; namespace exit closes that state
 * and only then drains, so there is no window where a provider is
 * published into a namespace that will not fence it.  Drive the real exit
 * path and require both halves: what was published beforehand is drained
 * by the fence, and what is attempted afterwards is refused outright.
 */
static void nfsd_ffv2_provider_install_race_test(struct kunit *test)
{
	struct nfsd_ffv2_ro_provider *dynamic = NULL;
	struct nfsd_ffv2_provider_ops *ops = NULL;
	struct nfsd_ffv2_ro_fixture f;
	u64 fenced;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	ops = kmalloc_obj(*ops, GFP_KERNEL);
	dynamic = kmalloc_obj(*dynamic, GFP_KERNEL);
	if (!ops || !dynamic) {
		KUNIT_FAIL(test, "failed to allocate a dynamic provider");
		goto out;
	}
	*ops = nfsd_ffv2_ro_provider_ops;
	nfsd_ffv2_ro_provider_init(dynamic);
	dynamic->object = f.provider->object;

	nfsd_ffv2_test_provider_remove(f.nn);
	f.provider_installed = false;
	if (nfsd_ffv2_test_provider_install(f.nn, ops, dynamic)) {
		KUNIT_FAIL(test, "failed to install the dynamic provider");
		goto out;
	}

	/*
	 * Exit drains the admissions a mapped handle holds, so release what
	 * this fixture is holding first; the test is about the provider, not
	 * about making retirement wait.
	 */
	if (f.mapped) {
		fh_put(f.mapped);
		f.mapped = NULL;
	}
	if (f.published) {
		exp_put(f.published);
		f.published = NULL;
	}

	fenced = nfsd_ffv2_test_provider_fenced();
	nfsd_ffv2_net_pre_exit(f.nn);
	/*
	 * The namespace has exited; teardown must not stop the service
	 * again, and there is nothing left for it to unregister.
	 */
	f.service_up = false;
	f.registration_open = false;

	/* Published before the close: the fence drained and freed it. */
	KUNIT_EXPECT_EQ(test, fenced + 1, nfsd_ffv2_test_provider_fenced());
	/* Attempted after it: refused, so nothing is left unfenced. */
	KUNIT_EXPECT_EQ(test, -ESHUTDOWN,
			nfsd_ffv2_test_provider_install(f.nn, ops, dynamic));
	KUNIT_EXPECT_EQ(test, fenced + 1, nfsd_ffv2_test_provider_fenced());
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
	/* Drained by the fence and never republished, so this is safe. */
	kfree(dynamic);
	kfree(ops);
}

static struct kunit_case nfsd_ffv2_test_cases[] = {
	KUNIT_CASE(nfsd_ffv2_lifecycle_test),
	KUNIT_CASE(nfsd_ffv2_admission_unregister_test),
	KUNIT_CASE(nfsd_ffv2_zero_threads_test),
	KUNIT_CASE(nfsd_ffv2_generation_boundary_test),
	KUNIT_CASE(nfsd_ffv2_multi_retirement_test),
	KUNIT_CASE(nfsd_ffv2_service_integration_test),
	KUNIT_CASE(nfsd_ffv2_netns_integration_test),
	KUNIT_CASE(nfsd_ffv2_production_netns_integration_test),
	KUNIT_CASE(nfsd_ffv2_production_pre_exit_overlap_test),
	KUNIT_CASE(nfsd_ffv2_shutdown_start_failure_test),
	KUNIT_CASE(nfsd_ffv2_listener_only_integration_test),
	KUNIT_CASE(nfsd_ffv2_partial_start_cleanup_test),
	KUNIT_CASE(nfsd_ffv2_reservation_context_test),
	KUNIT_CASE(nfsd_ffv2_export_update_stop_test),
	KUNIT_CASE(nfsd_ffv2_filehandle_format_test),
	KUNIT_CASE(nfsd_ffv2_filecache_gate_test),
	KUNIT_CASE(nfsd_ffv2_compound_digest_test),
	KUNIT_CASE(nfsd_ffv2_replay_identity_test),
	KUNIT_CASE(nfsd_ffv2_malformed_later_op_test),
	KUNIT_CASE(nfsd_ffv2_authority_qualify_test),
	KUNIT_CASE(nfsd_ffv2_authority_epoch_test),
	KUNIT_CASE(nfsd_ffv2_authority_unknown_locator_test),
	KUNIT_CASE(nfsd_ffv2_authority_publish_test),
	KUNIT_CASE(nfsd_ffv2_authority_death_race_test),
	KUNIT_CASE(nfsd_ffv2_authority_admission_test),
	KUNIT_CASE(nfsd_ffv2_authority_provider_gate_test),
	KUNIT_CASE(nfsd_ffv2_trust_lookup_test),
	KUNIT_CASE(nfsd_ffv2_trust_renewal_test),
	KUNIT_CASE(nfsd_ffv2_trust_revoke_test),
	KUNIT_CASE(nfsd_ffv2_trust_limits_test),
	KUNIT_CASE(nfsd_ffv2_trust_expiry_test),
	KUNIT_CASE(nfsd_ffv2_trust_retire_test),
	KUNIT_CASE(nfsd_ffv2_trust_dead_authority_test),
	KUNIT_CASE(nfsd_ffv2_trust_renewal_failure_test),
	KUNIT_CASE(nfsd_ffv2_trust_destroy_drain_test),
	KUNIT_CASE(nfsd_ffv2_op_profile_test),
	KUNIT_CASE(nfsd_ffv2_validate_order_test),
	KUNIT_CASE(nfsd_ffv2_trust_actor_class_test),
	KUNIT_CASE(nfsd_ffv2_no_fh_generation_race_test),
	KUNIT_CASE(nfsd_ffv2_decoder_owner_test),
	KUNIT_CASE(nfsd_ffv2_decoder_write_test),
	KUNIT_CASE(nfsd_ffv2_decoder_bulk_revoke_test),
	KUNIT_CASE(nfsd_ffv2_decoder_chunk_write_test),
	KUNIT_CASE(nfsd_ffv2_decoder_lifecycle_test),
	KUNIT_CASE(nfsd_ffv2_provider_read_test),
	KUNIT_CASE(nfsd_ffv2_provider_negative_test),
	KUNIT_CASE(nfsd_ffv2_provider_replay_test),
	KUNIT_CASE(nfsd_ffv2_provider_retire_overlap_test),
	KUNIT_CASE(nfsd_ffv2_provider_ordinary_ops_test),
	KUNIT_CASE(nfsd_ffv2_provider_install_cycle_test),
	KUNIT_CASE(nfsd_ffv2_provider_stall_recovery_test),
	KUNIT_CASE(nfsd_ffv2_provider_dynamic_free_test),
	KUNIT_CASE(nfsd_ffv2_provider_publish_timeout_test),
	KUNIT_CASE(nfsd_ffv2_provider_malformed_result_test),
	KUNIT_CASE(nfsd_ffv2_provider_retired_generation_test),
	KUNIT_CASE(nfsd_ffv2_provider_result_lifetime_test),
	KUNIT_CASE(nfsd_ffv2_provider_netns_fence_test),
	KUNIT_CASE(nfsd_ffv2_provider_concurrent_results_test),
	KUNIT_CASE(nfsd_ffv2_provider_install_race_test),
	{}
};

static struct kunit_suite nfsd_ffv2_test_suite = {
	.name = "nfsd_ffv2_lifecycle",
	.test_cases = nfsd_ffv2_test_cases,
};

kunit_test_suite(nfsd_ffv2_test_suite);

MODULE_LICENSE("GPL");
