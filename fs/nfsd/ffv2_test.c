// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>
#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/fs_struct.h>
#include <linux/iopoll.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/sunrpc/svcsock.h>
#include <linux/sunrpc/svc_xprt.h>
#include <net/net_namespace.h>

#include "ffv2.h"
#include "export.h"
#include "nfsd.h"
#include "nfsfh.h"
#include "netns.h"

struct nfsd_ffv2_unregister_ctx {
	struct nfsd_net	*nn;
	u64		generation;
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
	struct nfsd_ffv2_reservation *reservation = NULL;
	struct nfsd_ffv2_generation *generation;
	struct auth_domain *domain;
	struct svc_export *published;
	struct svc_export exp;
	struct nfsd_net *nn;
	struct nfsd_net *nn2;
	struct path nonroot;
	struct path root;
	struct net *net;
	struct net *net2;
	bool service_up = false;
	char domain_name[] = "ffv2-kunit";
	u8 token[32] = { 1 };
	u8 uuid[16] = { 2 };
	u64 generation_id;
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "failed to create reservation test netns: %ld",
			   PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
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

	error = nfsd_ffv2_reservation_claim(nn, &root, uuid, token,
					    &reservation);
	if (!error)
		nfsd_ffv2_reservation_abort(reservation);
	else
		KUNIT_EXPECT_EQ(test, error, -EOPNOTSUPP);

	nfsd_ffv2_init_test_export(&exp, nn, domain, &root);
	published = nfsd_export_cache_update(&exp);
	if (IS_ERR(published)) {
		KUNIT_FAIL(test, "real inventory publication failed: %ld",
			   PTR_ERR(published));
		goto out_root;
	}
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
	nfsd_ffv2_init_test_export(&exp, nn, domain, &root);
	nfsd_ffv2_test_fail_export_alloc(true);
	error = nfsd_ffv2_test_service_export_publish(nn, &exp, &root, uuid,
						      token, current_cred(), 1,
						      &generation_id);
	KUNIT_EXPECT_EQ(test, error, -ENOMEM);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(exp.ex_ffv2_context), NULL);
	KUNIT_EXPECT_TRUE(test, nfsd4_ffv2_mount_crossing_allowed(&root));

	error = nfsd_ffv2_test_service_export_publish(nn, &exp, &root, uuid,
						      token, current_cred(), 1,
						      &generation_id);
	if (error) {
		KUNIT_FAIL(test, "service transaction failed: %d", error);
		goto out_root;
	}
	KUNIT_EXPECT_FALSE(test, nfsd4_ffv2_mount_crossing_allowed(&root));
	published = nfsd_ffv2_test_export_lookup(&exp);
	if (!published) {
		KUNIT_FAIL(test, "published service export not found");
		goto out_root;
	}
	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_export_policy_check(published, OP_GETATTR),
			nfserr_notsupp);
	exp_put(published);

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
	error = nfsd_ffv2_service_generation_retire(nn, generation_id);
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, error, 0);
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
	{}
};

static struct kunit_suite nfsd_ffv2_test_suite = {
	.name = "nfsd_ffv2_lifecycle",
	.test_cases = nfsd_ffv2_test_cases,
};

kunit_test_suite(nfsd_ffv2_test_suite);

MODULE_LICENSE("GPL");
