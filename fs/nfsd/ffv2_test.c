// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>
#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/lockd/bind.h>
#include <linux/mount.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/iopoll.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/shmem_fs.h>
#include <linux/unaligned.h>
#include <linux/sunrpc/svcsock.h>
#include <linux/sunrpc/svcauth.h>
#include <linux/sunrpc/svc_xprt.h>
#include <net/net_namespace.h>

#include "ffv2.h"
#include "ffv2_trust.h"
#include "xdr4.h"
#include "export.h"
#include "nfsd.h"
#include "netns.h"
#include "netlink.h"
#include "nfsfh.h"
#include "filecache.h"
#include "vfs.h"

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

struct nfsd_ffv2_destroy_ctx {
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

static DEFINE_SPINLOCK(nfsd_ffv2_worker_lock);
static struct nfsd_ffv2_worker_ctx *nfsd_ffv2_worker_ctx;

static void nfsd_ffv2_test_thread_park(void);

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
 * Context: sleeps while the fixture holds the admission gate.
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
	int error;

	nn = kunit_kzalloc(test, sizeof(*nn), GFP_KERNEL);
	if (!nn)
		return NULL;
	nfsd_ffv2_net_init(nn);
	error = nfsd_ffv2_participant_register(nn, NULL);
	if (error) {
		nfsd_ffv2_net_pre_exit(nn);
		nfsd_ffv2_net_destroy(nn);
		return NULL;
	}
	return nn;
}

static void nfsd_ffv2_test_net_exit(void *data)
{
	struct nfsd_net *nn = data;

	nfsd_ffv2_net_pre_exit(nn);
	nfsd_ffv2_participant_detach_begin(nn);
	nfsd_ffv2_participant_detach_finish(nn);
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

static int nfsd_ffv2_destroy_thread(void *data)
{
	struct nfsd_ffv2_destroy_ctx *ctx = data;

	nfsd_ffv2_net_destroy(ctx->nn);
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
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, error, -EDEADLK);

	ctx.nn = nn;
	ctx.generation = generation_id;
	ctx.result = -EINPROGRESS;
	init_completion(&ctx.done);
	task = kthread_run(nfsd_ffv2_unregister_thread, &ctx,
			   "nfsd-ffv2-unregister-test");
	if (IS_ERR(task)) {
		nfsd_ffv2_complete(&admission);
		nfsd_ffv2_test_net_destroy(test, nn);
		KUNIT_FAIL(test, "failed to start unregister thread");
		return;
	}

	error = read_poll_timeout(nfsd_ffv2_test_admission_retired,
				  retired, retired,
				  10, USEC_PER_SEC, false, &admission);
	if (error) {
		nfsd_ffv2_complete(&admission);
		wait_for_completion(&ctx.done);
		kthread_stop(task);
		nfsd_ffv2_test_net_destroy(test, nn);
		KUNIT_FAIL(test, "unregister did not retire generation");
		return;
	}
	error = read_poll_timeout(nfsd_ffv2_test_waiters,
				  retired, retired >= 1,
				  10, USEC_PER_SEC, false, &admission);
	if (error) {
		nfsd_ffv2_complete(&admission);
		wait_for_completion(&ctx.done);
		kthread_stop(task);
		nfsd_ffv2_test_net_destroy(test, nn);
		KUNIT_FAIL(test, "unregister did not enter retirement wait");
		return;
	}
	KUNIT_EXPECT_FALSE(test, completion_done(&ctx.done));
	KUNIT_EXPECT_EQ(test, atomic_read(releases), 0);

	nfsd_ffv2_complete(&admission);
	nfsd_ffv2_complete(&admission);
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

static void nfsd_ffv2_destroy_wait_test(struct kunit *test)
{
	struct nfsd_ffv2_destroy_ctx ctx;
	struct completion entered;
	struct task_struct *task;
	struct nfsd_net *nn;
	unsigned long timeout;

	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	KUNIT_ASSERT_TRUE(test, nfsd_ffv2_test_anchor_hold(nn));
	nfsd_ffv2_net_pre_exit(nn);
	nfsd_ffv2_participant_detach_begin(nn);
	nfsd_ffv2_participant_detach_finish(nn);
	ctx.nn = nn;
	init_completion(&ctx.done);
	init_completion(&entered);
	nfsd_ffv2_test_destroy_waiting(nn, &entered);
	task = kthread_run(nfsd_ffv2_destroy_thread, &ctx,
			   "nfsd-ffv2-destroy-test");
	if (IS_ERR(task)) {
		nfsd_ffv2_test_anchor_release(nn);
		nfsd_ffv2_net_destroy(nn);
		KUNIT_FAIL(test, "failed to start destroy thread");
		return;
	}

	timeout = wait_for_completion_timeout(&entered, HZ);
	if (timeout) {
		KUNIT_EXPECT_FALSE(test, completion_done(&ctx.done));
		KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_anchor_refcount(nn), 1U);
	}
	nfsd_ffv2_test_anchor_release(nn);
	wait_for_completion(&ctx.done);
	kthread_stop(task);
	if (!timeout)
		KUNIT_FAIL(test, "destroy did not enter its anchor wait");
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
	unsigned int waiters;
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

	error = read_poll_timeout(nfsd_ffv2_test_waiters,
				  waiters, waiters >= 2,
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
	error = read_poll_timeout(nfsd_ffv2_test_waiters,
				  waiters, waiters >= 3,
				  10, USEC_PER_SEC, false, &admission);
	if (error)
		goto fail;
	error = read_poll_timeout(nfsd_ffv2_test_anchor_refcount,
				  anchor_refs, anchor_refs >= 5,
				  10, USEC_PER_SEC, false, nn);
	if (error)
		goto fail;

	nfsd_ffv2_complete(&admission);
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
		nfsd_ffv2_complete(&admission);
	if (stop_generation)
		nfsd_ffv2_service_stop_finish(nn, stop_generation);
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

static int nfsd_ffv2_threads_set(struct net *net)
{
	struct nlattr *attrs[NFSD_A_SERVER_MAX + 1] = {};
	struct genl_info info = { .attrs = attrs };
	struct sk_buff *skb;
	void *hdr;
	int ret;

	skb = genlmsg_new(nla_total_size(sizeof(u32)), GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	hdr = genlmsg_put(skb, 0, 1, &nfsd_nl_family, 0,
			  NFSD_CMD_THREADS_SET);
	if (!hdr || nla_put_u32(skb, NFSD_A_SERVER_THREADS, 1)) {
		ret = -EMSGSIZE;
		goto out_free;
	}
	genlmsg_end(skb, hdr);
	info.nlhdr = nlmsg_hdr(skb);
	info.genlhdr = nlmsg_data(info.nlhdr);
	attrs[NFSD_A_SERVER_THREADS] = nla_find(genlmsg_data(info.genlhdr),
						genlmsg_len(info.genlhdr),
						NFSD_A_SERVER_THREADS);
	genl_info_net_set(&info, net);
	ret = nfsd_nl_threads_set_doit(skb, &info);
out_free:
	nlmsg_free(skb);
	return ret;
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
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_threads_set(net), -EAGAIN);

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
	if (!error)
		error = read_poll_timeout(nfsd_ffv2_test_waiters,
					  retired, retired >= 1,
					  10, USEC_PER_SEC, false, &admission);
	KUNIT_EXPECT_EQ(test, atomic_read(&releases), 0);
	nfsd_ffv2_complete(&admission);
	net_ns_barrier();
	KUNIT_EXPECT_EQ(test, atomic_read(&releases), 1);
	if (error)
		KUNIT_FAIL(test, "registered netns pre-exit did not retire");
	return;

out_put_net:
	put_net(net);
	net_ns_barrier();
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
	error = read_poll_timeout(nfsd_ffv2_test_waiters,
				  retired, retired >= 1,
				  10, USEC_PER_SEC, false, READ_ONCE(worker.admission));
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
		KUNIT_EXPECT_FALSE(test, test_bit(NFSD_NET_UP, &nn->flags));
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

static void nfsd_ffv2_init_export_test_key(struct svc_export *exp,
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

static void nfsd_ffv2_ordinary_export_update_test(struct kunit *test)
{
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_export_update update;
	struct svc_export key, *published;
	struct auth_domain *domain;
	struct nfsd_net *nn;
	struct path root;
	struct net *net;
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "export test netns: %ld", PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	domain = unix_domain_find("ffv2-export-update-kunit");
	if (!domain) {
		KUNIT_FAIL(test, "export test auth domain allocation failed");
		goto out_net;
	}
	get_fs_root(current->fs, &root);
	nfsd_ffv2_init_export_test_key(&key, nn, domain, &root);
	published = nfsd_export_cache_update(&key);
	if (IS_ERR(published)) {
		KUNIT_FAIL(test, "positive update: %ld", PTR_ERR(published));
		goto out_root;
	}
	KUNIT_EXPECT_EQ(test, nn->ffv2_participant.inventory_count, 1U);
	KUNIT_EXPECT_TRUE(test, published->ex_ffv2_listed);
	exp_put(published);

	nfsd_ffv2_test_fail_export_alloc();
	published = nfsd_export_cache_update(&key);
	KUNIT_EXPECT_TRUE(test, IS_ERR(published));
	if (IS_ERR(published))
		KUNIT_EXPECT_EQ(test, PTR_ERR(published), -ENOMEM);
	else
		exp_put(published);
	KUNIT_EXPECT_EQ(test, nn->ffv2_participant.update_count, 0U);

	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_service_up(nn);
	generation = nfsd_ffv2_service_stop_begin(nn);
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_PTR_EQ(test, generation, NULL);
	set_bit(CACHE_NEGATIVE, &key.h.flags);
	published = nfsd_export_cache_update(&key);
	KUNIT_EXPECT_TRUE(test, IS_ERR(published));
	if (IS_ERR(published))
		KUNIT_EXPECT_EQ(test, PTR_ERR(published), -ESHUTDOWN);
	else
		exp_put(published);
	nfsd_ffv2_service_stop_finish(nn, generation);
	mutex_lock(&nfsd_mutex);
	nfsd_ffv2_service_down(nn);
	mutex_unlock(&nfsd_mutex);
	published = nfsd_export_cache_update(&key);
	KUNIT_EXPECT_FALSE(test, IS_ERR(published));
	if (!IS_ERR(published)) {
		KUNIT_EXPECT_TRUE(test, test_bit(CACHE_NEGATIVE, &published->h.flags));
		KUNIT_EXPECT_FALSE(test, published->ex_ffv2_listed);
		exp_put(published);
	}
	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_service_up(nn);
	generation = nfsd_ffv2_service_stop_begin(nn);
	nfsd_ffv2_service_stop_failed(nn, generation);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_service_up(nn), -EAGAIN);
	nfsd_ffv2_service_down(nn);
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, error, 0);
	clear_bit(CACHE_NEGATIVE, &key.h.flags);
	published = nfsd_export_cache_update(&key);
	KUNIT_EXPECT_FALSE(test, IS_ERR(published));
	if (!IS_ERR(published))
		exp_put(published);

	/* Reopening must not make an update from the prior epoch valid. */
	error = nfsd_ffv2_export_update_begin(&key, &update);
	if (error) {
		KUNIT_FAIL(test, "admit epoch update: %d", error);
		goto out_root;
	}
	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_service_up(nn);
	generation = nfsd_ffv2_service_stop_begin(nn);
	nfsd_ffv2_service_stop_failed(nn, generation);
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_TRUE(test, nn->ffv2_participant.updates_open);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_update_validate(&update),
			-ESHUTDOWN);
	nfsd_ffv2_export_update_abort(&update);

	nfsd_ffv2_net_pre_exit(nn);
	nfsd_ffv2_test_try_reopen_updates(nn);
	KUNIT_EXPECT_FALSE(test, nn->ffv2_participant.updates_open);
	clear_bit(CACHE_NEGATIVE, &key.h.flags);
	published = nfsd_export_cache_update(&key);
	KUNIT_EXPECT_TRUE(test, IS_ERR(published));
	if (IS_ERR(published))
		KUNIT_EXPECT_EQ(test, PTR_ERR(published), -ESHUTDOWN);
	else
		exp_put(published);
	nfsd_export_flush(net);
	KUNIT_EXPECT_EQ(test, nn->ffv2_participant.inventory_count, 0U);
out_root:
	path_put(&root);
	auth_domain_put(domain);
out_net:
	put_net(net);
	net_ns_barrier();
}

struct nfsd_ffv2_cache_update_ctx {
	struct svc_export *key;
	struct svc_export *result;
	struct completion done;
};

static int nfsd_ffv2_cache_update_thread(void *data)
{
	struct nfsd_ffv2_cache_update_ctx *ctx = data;

	ctx->result = nfsd_export_cache_update(ctx->key);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static bool nfsd_ffv2_update_waiting(struct nfsd_net *nn)
{
	/* The token is held until the observer sees the enqueued waiter. */
	return waitqueue_active(&nn->ffv2_participant.update_wait);
}

static void nfsd_ffv2_ordinary_update_drain_test(struct kunit *test)
{
	struct nfsd_ffv2_cache_update_ctx update = {};
	struct nfsd_ffv2_shutdown_ctx shutdown;
	struct task_struct *update_task, *shutdown_task = NULL;
	struct completion validated, proceed;
	struct svc_export key, *published;
	struct auth_domain *domain;
	struct nfsd_net *nn;
	struct path root;
	struct net *net;
	bool waiting;
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "drain test netns: %ld", PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	domain = unix_domain_find("ffv2-export-drain-kunit");
	if (!domain) {
		KUNIT_FAIL(test, "drain auth domain allocation failed");
		goto out_net;
	}
	get_fs_root(current->fs, &root);
	nfsd_ffv2_init_export_test_key(&key, nn, domain, &root);
	error = nfsd_ffv2_start_test_service(net, NULL);
	if (error) {
		KUNIT_FAIL(test, "start ordinary server: %d", error);
		goto out_root;
	}

	init_completion(&validated);
	init_completion(&proceed);
	init_completion(&update.done);
	update.key = &key;
	WRITE_ONCE(nn->ffv2_participant.test_update_validated, &validated);
	WRITE_ONCE(nn->ffv2_participant.test_update_continue, &proceed);
	update_task = kthread_run(nfsd_ffv2_cache_update_thread, &update,
				  "nfsd-ffv2-cache-update-test");
	if (IS_ERR(update_task)) {
		KUNIT_FAIL(test, "start update worker: %ld", PTR_ERR(update_task));
		goto out_service;
	}
	if (!wait_for_completion_timeout(&validated, 5 * HZ)) {
		KUNIT_FAIL(test, "update did not pass validation");
		goto out_update;
	}
	KUNIT_EXPECT_EQ(test, nn->ffv2_participant.update_count, 1U);
	nfsd_ffv2_shutdown_ctx_init(&shutdown, net);
	shutdown_task = nfsd_ffv2_shutdown_thread_start(&shutdown, false);
	if (IS_ERR(shutdown_task)) {
		KUNIT_FAIL(test, "start shutdown worker: %ld", PTR_ERR(shutdown_task));
		shutdown_task = NULL;
		nfsd_ffv2_shutdown_ctx_put(&shutdown);
		goto out_update;
	}
	error = read_poll_timeout(nfsd_ffv2_update_waiting, waiting, waiting,
				  10, USEC_PER_SEC, false, nn);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_FALSE(test, completion_done(&shutdown.done));
	KUNIT_EXPECT_FALSE(test, completion_done(&update.done));
	KUNIT_EXPECT_FALSE(test, nn->ffv2_participant.updates_open);

out_update:
	/* Release and join all users before clearing hooks or fixture storage. */
	complete_all(&proceed);
	wait_for_completion(&update.done);
	kthread_stop(update_task);
	if (!IS_ERR(update.result)) {
		KUNIT_EXPECT_TRUE(test, update.result->ex_ffv2_listed);
		exp_put(update.result);
	} else {
		KUNIT_FAIL(test, "validated cache update: %ld", PTR_ERR(update.result));
	}
	if (shutdown_task) {
		wait_for_completion(&shutdown.done);
		kthread_stop(shutdown_task);
		nfsd_ffv2_shutdown_ctx_put(&shutdown);
		KUNIT_EXPECT_EQ(test, nn->ffv2_participant.update_count, 0U);
		KUNIT_EXPECT_TRUE(test, nn->ffv2_participant.updates_open);
	}
out_service:
	WRITE_ONCE(nn->ffv2_participant.test_update_validated, NULL);
	WRITE_ONCE(nn->ffv2_participant.test_update_continue, NULL);
	nfsd_shutdown_threads(net);
	/* Configuration is accepted after real shutdown and after restart. */
	published = nfsd_export_cache_update(&key);
	KUNIT_EXPECT_FALSE(test, IS_ERR(published));
	if (!IS_ERR(published))
		exp_put(published);
	error = nfsd_ffv2_start_test_service(net, NULL);
	KUNIT_EXPECT_EQ(test, error, 0);
	if (!error) {
		published = nfsd_export_cache_update(&key);
		KUNIT_EXPECT_FALSE(test, IS_ERR(published));
		if (!IS_ERR(published))
			exp_put(published);
		nfsd_shutdown_threads(net);
	}
out_root:
	path_put(&root);
	auth_domain_put(domain);
out_net:
	put_net(net);
	net_ns_barrier();
}

struct nfsd_ffv2_export_detach_ctx {
	struct net *net;
	struct completion done;
};

static int nfsd_ffv2_export_detach_thread(void *data)
{
	struct nfsd_ffv2_export_detach_ctx *ctx = data;

	put_net(ctx->net);
	net_ns_barrier();
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

struct nfsd_ffv2_export_put_ctx {
	struct svc_export *exp;
	struct completion done;
};

static int nfsd_ffv2_export_put_thread(void *data)
{
	struct nfsd_ffv2_export_put_ctx *ctx = data;

	exp_put(ctx->exp);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static void nfsd_ffv2_ordinary_export_detach_test(struct kunit *test)
{
	struct nfsd_ffv2_export_detach_ctx ctx;
	struct nfsd_ffv2_export_put_ctx put_ctx;
	struct svc_export key, *published;
	struct auth_domain *domain;
	struct completion entered, finished, release_zero, release_continue;
	struct completion postwait_entered, postwait_continue, destroy_continue;
	struct completion lock_entered;
	struct task_struct *task, *put_task, *inventory_task = NULL;
	struct nfsd_net *nn;
	struct path root;
	struct net *net;
	unsigned int waiting_count = UINT_MAX;
	unsigned int state;
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "detach test netns: %ld", PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	domain = unix_domain_find("ffv2-export-detach-kunit");
	if (!domain) {
		KUNIT_FAIL(test, "detach auth domain allocation failed");
		goto out_net;
	}
	get_fs_root(current->fs, &root);
	nfsd_ffv2_init_export_test_key(&key, nn, domain, &root);
	published = nfsd_export_cache_update(&key);
	if (IS_ERR(published)) {
		KUNIT_FAIL(test, "detach export update: %ld", PTR_ERR(published));
		goto out_root;
	}
	KUNIT_EXPECT_TRUE(test, published->ex_ffv2_listed);
	KUNIT_EXPECT_EQ(test, nn->ffv2_participant.inventory_count, 1U);
	/* Hold a separate reader reference across cache unregister. */
	exp_get(published);
	init_completion(&entered);
	init_completion(&finished);
	init_completion(&release_zero);
	init_completion(&release_continue);
	init_completion(&postwait_entered);
	init_completion(&postwait_continue);
	init_completion(&destroy_continue);
	init_completion(&lock_entered);
	WRITE_ONCE(nn->ffv2_participant.test_inventory_lock_entered, &lock_entered);
	WRITE_ONCE(nn->ffv2_participant.test_inventory_task, &inventory_task);
	WRITE_ONCE(nn->ffv2_participant.test_inventory_destroy_continue,
		   &destroy_continue);
	init_completion(&ctx.done);
	init_completion(&put_ctx.done);
	put_ctx.exp = published;
	ctx.net = net;
	WRITE_ONCE(nn->ffv2_participant.test_inventory_wait_entered, &entered);
	WRITE_ONCE(nn->ffv2_participant.test_inventory_wait_done, &finished);
	WRITE_ONCE(nn->ffv2_participant.test_inventory_postwait_entered,
		   &postwait_entered);
	WRITE_ONCE(nn->ffv2_participant.test_inventory_postwait_continue,
		   &postwait_continue);
	WRITE_ONCE(nn->ffv2_participant.test_inventory_wait_count,
		   &waiting_count);
	WRITE_ONCE(nn->ffv2_participant.test_release_count_zero,
		   &release_zero);
	WRITE_ONCE(nn->ffv2_participant.test_release_continue,
		   &release_continue);
	task = kthread_run(nfsd_ffv2_export_detach_thread, &ctx,
			   "nfsd-ffv2-export-detach-test");
	if (IS_ERR(task)) {
		KUNIT_FAIL(test, "start detach thread: %ld", PTR_ERR(task));
		WRITE_ONCE(nn->ffv2_participant.test_inventory_wait_entered,
			   NULL);
		WRITE_ONCE(nn->ffv2_participant.test_inventory_wait_done, NULL);
		WRITE_ONCE(nn->ffv2_participant.test_inventory_postwait_entered,
			   NULL);
		WRITE_ONCE(nn->ffv2_participant.test_inventory_postwait_continue,
			   NULL);
		WRITE_ONCE(nn->ffv2_participant.test_inventory_wait_count,
			   NULL);
		WRITE_ONCE(nn->ffv2_participant.test_release_count_zero, NULL);
		WRITE_ONCE(nn->ffv2_participant.test_release_continue, NULL);
		WRITE_ONCE(nn->ffv2_participant.test_inventory_lock_entered, NULL);
		WRITE_ONCE(nn->ffv2_participant.test_inventory_task, NULL);
		WRITE_ONCE(nn->ffv2_participant.test_inventory_destroy_continue, NULL);
		exp_put(published);
		exp_put(published);
		goto out_root;
	}
	/* The worker owns the last netns reference from this point on. */
	if (!wait_for_completion_timeout(&entered, 5 * HZ)) {
		KUNIT_FAIL(test, "detach did not reach inventory wait");
	} else {
		KUNIT_EXPECT_EQ(test, waiting_count, 1U);
		KUNIT_EXPECT_FALSE(test, completion_done(&finished));
	}
	exp_put(published);
	KUNIT_EXPECT_FALSE(test, completion_done(&finished));
	put_task = kthread_run(nfsd_ffv2_export_put_thread, &put_ctx,
			       "nfsd-ffv2-export-put-test");
	if (IS_ERR(put_task)) {
		KUNIT_FAIL(test, "start export put thread: %ld",
			   PTR_ERR(put_task));
		complete_all(&release_continue);
		complete_all(&postwait_continue);
		exp_put(published);
	} else {
		if (!wait_for_completion_timeout(&release_zero, 5 * HZ))
			KUNIT_FAIL(test, "final put did not reach inventory lock");
		else if (!wait_for_completion_timeout(&postwait_entered, 5 * HZ))
			KUNIT_FAIL(test, "detach did not pass inventory wait");
		complete(&postwait_continue);
		if (!wait_for_completion_timeout(&lock_entered, 5 * HZ))
			KUNIT_FAIL(test, "detach did not leave its test gate");
		if (inventory_task) {
			error = read_poll_timeout(READ_ONCE, state,
						  state == TASK_UNINTERRUPTIBLE,
						  10, USEC_PER_SEC, false,
						  inventory_task->__state);
			KUNIT_EXPECT_EQ(test, error, 0);
			/* The only uninterruptible wait now is lock or control gate. */
			KUNIT_EXPECT_FALSE(test, completion_done(&finished));
		} else {
			KUNIT_FAIL(test, "detach task was not captured");
		}
		complete(&release_continue);
		if (!wait_for_completion_timeout(&put_ctx.done, 5 * HZ)) {
			KUNIT_FAIL(test, "export put worker did not finish");
			wait_for_completion(&put_ctx.done);
		}
		kthread_stop(put_task);
	}
	complete_all(&destroy_continue);
	if (!wait_for_completion_timeout(&finished, 5 * HZ)) {
		KUNIT_FAIL(test, "final export put did not release detach");
		wait_for_completion(&finished);
	}
	if (!wait_for_completion_timeout(&ctx.done, 5 * HZ)) {
		KUNIT_FAIL(test, "netns worker did not finish");
		wait_for_completion(&ctx.done);
	}
	kthread_stop(task);
	if (inventory_task)
		put_task_struct(inventory_task);
	path_put(&root);
	auth_domain_put(domain);
	return;
out_root:
	path_put(&root);
	auth_domain_put(domain);
out_net:
	put_net(net);
	net_ns_barrier();
}

struct nfsd_ffv2_access_wait_ctx {
	struct svc_export *exp;
	int result;
	struct completion done;
};

static int nfsd_ffv2_access_wait_thread(void *data)
{
	struct nfsd_ffv2_access_wait_ctx *ctx = data;

	allow_signal(SIGUSR1);
	ctx->result = nfsd_ffv2_export_transition_wait(ctx->exp);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static void nfsd_ffv2_export_access_test(struct kunit *test)
{
	struct nfsd_ffv2_access_wait_ctx ctx;
	struct svc_export key, *exp, *next;
	struct svc_fh first, second;
	struct auth_domain *domain;
	struct task_struct *task;
	struct nfsd_net *nn;
	struct path root;
	struct net *net;
	bool waiting;
	unsigned int refs;
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "access netns: %ld", PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	domain = unix_domain_find("ffv2-access-kunit");
	if (!domain) {
		KUNIT_FAIL(test, "access auth domain allocation");
		goto out_net;
	}
	get_fs_root(current->fs, &root);
	nfsd_ffv2_init_export_test_key(&key, nn, domain, &root);
	key.ex_uuid = kmemdup("export-uuid-test", 16, GFP_KERNEL);
	if (!key.ex_uuid) {
		KUNIT_FAIL(test, "access UUID allocation");
		goto out_root;
	}
	exp = nfsd_export_cache_update(&key);
	kfree(key.ex_uuid);
	key.ex_uuid = NULL;
	if (IS_ERR(exp)) {
		KUNIT_FAIL(test, "access export update: %ld", PTR_ERR(exp));
		goto out_root;
	}
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_export_is_current(exp));
	fh_init(&first, NFS4_FHSIZE);
	fh_init(&second, NFS4_FHSIZE);
	KUNIT_EXPECT_EQ(test, fh_compose(&first, exp, root.dentry, NULL), nfs_ok);
	if (!first.fh_export)
		goto out_exp;
	KUNIT_EXPECT_EQ(test, exp->ex_ffv2_access_count, 1U);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_transition_exact(exp), 0);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_access_get(exp), -ESTALE);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_fh_dup2(&second, &first), nfs_ok);
	KUNIT_EXPECT_EQ(test, exp->ex_ffv2_access_count, 2U);
	ctx.exp = exp;
	init_completion(&ctx.done);
	task = kthread_run(nfsd_ffv2_access_wait_thread, &ctx, "ffv2-access");
	if (IS_ERR(task)) {
		KUNIT_FAIL(test, "access worker: %ld", PTR_ERR(task));
		goto out_handles;
	}
	error = read_poll_timeout(waitqueue_active, waiting, waiting,
				  1000, 1000000, false, &exp->ex_ffv2_access_wait);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_FALSE(test, completion_done(&ctx.done));
	fh_put(&first);
	KUNIT_EXPECT_EQ(test, exp->ex_ffv2_access_count, 1U);
	KUNIT_EXPECT_FALSE(test, completion_done(&ctx.done));
	fh_put(&second);
	wait_for_completion(&ctx.done);
	kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ctx.result, 0);
	KUNIT_EXPECT_EQ(test, exp->ex_ffv2_access_count, 0U);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_access_clone(exp), -ESTALE);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_export_transition_abort_exact(exp));
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_access_get(exp), 0);
	first.fh_export = exp_get(exp);
	first.fh_ffv2_admitted = true;
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_transition_exact(exp), 0);
	init_completion(&ctx.done);
	task = kthread_run(nfsd_ffv2_access_wait_thread, &ctx, "ffv2-cancel");
	if (IS_ERR(task)) {
		KUNIT_FAIL(test, "cancel worker: %ld", PTR_ERR(task));
		goto out_handles;
	}
	error = read_poll_timeout(waitqueue_active, waiting, waiting,
				  1000, 1000000, false, &exp->ex_ffv2_access_wait);
	KUNIT_EXPECT_EQ(test, error, 0);
	send_sig(SIGUSR1, task, 1);
	wait_for_completion(&ctx.done);
	kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ctx.result, -ERESTARTSYS);
	KUNIT_EXPECT_EQ(test, exp->ex_ffv2_access_count, 1U);
	fh_put(&first);
	KUNIT_EXPECT_EQ(test, exp->ex_ffv2_access_count, 0U);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_export_transition_abort_exact(exp));

	nfsd_ffv2_test_fail_export_alloc();
	next = nfsd_ffv2_test_export_update_exact(&key, exp);
	KUNIT_EXPECT_TRUE(test, IS_ERR(next));
	if (IS_ERR(next))
		KUNIT_EXPECT_EQ(test, PTR_ERR(next), -ENOMEM);
	else
		exp_put(next);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_export_is_current(exp));

	/* A retained predecessor cannot substitute for the current cache entry. */
	next = nfsd_ffv2_test_export_update_exact(&key, exp);
	if (IS_ERR(next)) {
		KUNIT_FAIL(test, "access replacement: %ld", PTR_ERR(next));
		goto out_exp;
	}
	KUNIT_EXPECT_TRUE(test, hlist_unhashed(&exp->h.cache_list));
	/* Make expiry unable to hide accidental predecessor hash membership. */
	exp->h.expiry_time = TIME64_MAX;
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_export_is_current(next));
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_export_is_current(exp));
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_transition_exact(exp), -ESTALE);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_transition_exact(next), 0);
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_export_transition_abort_exact(exp));
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_export_is_transitioning(next));
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_export_transition_abort_exact(next));
	exp_put(next);
	set_bit(CACHE_NEGATIVE, &key.h.flags);
	next = nfsd_export_cache_update(&key);
	if (IS_ERR(next)) {
		KUNIT_FAIL(test, "negative current entry: %ld", PTR_ERR(next));
		goto out_exp;
	}
	refs = kref_read(&next->h.ref);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_transition_exact(next), -ENOENT);
	KUNIT_EXPECT_EQ(test, kref_read(&next->h.ref), refs);
	/* Keep a refusal-control's missing caller reference from leaking cleanup. */
	if (kref_read(&next->h.ref) + 1 == refs)
		cache_get(&next->h);
	exp_put(next);
	goto out_exp;
out_handles:
	fh_put(&first);
	fh_put(&second);
	if (nfsd_ffv2_export_is_transitioning(exp))
		nfsd_ffv2_export_transition_abort_exact(exp);
out_exp:
	exp_put(exp);
out_root:
	nfsd_export_flush(net);
	path_put(&root);
	auth_domain_put(domain);
out_net:
	put_net(net);
	net_ns_barrier();
}

struct nfsd_ffv2_file_wait_ctx {
	struct nfsd_file_ffv2_gate *gate;
	int result;
	struct completion done;
};

static int nfsd_ffv2_file_wait_thread(void *data)
{
	struct nfsd_ffv2_file_wait_ctx *ctx = data;

	allow_signal(SIGUSR1);
	ctx->result = nfsd_file_ffv2_gate_wait(ctx->gate);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static void nfsd_ffv2_nlm_open_refusal_test(struct kunit *test)
{
	struct nlmsvc_ffv2_gate gate, probe;
	struct file *files[2], *read_file, *write_file;
	struct nlm_file *owner;
	unsigned int mask, i;
	long baseline[2];
	int error;

	for (i = 0; i < ARRAY_SIZE(files); i++) {
		files[i] = shmem_file_setup("nlm-open-refusal", PAGE_SIZE,
					    mk_vma_flags(VMA_NORESERVE_BIT));
		if (IS_ERR(files[i])) {
			KUNIT_FAIL(test, "NLM slot %u open: %ld", i,
				   PTR_ERR(files[i]));
			while (i)
				fput(files[--i]);
			return;
		}
		baseline[i] = file_count(files[i]);
	}

	for (mask = 1; mask < 4; mask++) {
		read_file = mask & 1 ? files[0] : NULL;
		write_file = mask & 2 ? files[1] : NULL;
		error = nlmsvc_ffv2_gate_begin(&gate, file_inode(files[0])->i_sb);
		KUNIT_EXPECT_EQ(test, error, 0);
		if (error)
			break;
		owner = nlmsvc_ffv2_test_file_insert(read_file, write_file);
		KUNIT_EXPECT_PTR_EQ(test, owner, NULL);
		for (i = 0; i < ARRAY_SIZE(files); i++) {
			KUNIT_EXPECT_EQ_MSG(test, file_count(files[i]), baseline[i],
					    "refused slot %u mask %u owns no file", i, mask);
		}
		nlmsvc_ffv2_gate_end(&gate);
		if (owner)
			nlmsvc_ffv2_test_file_put(owner);
		/* Recover references retained by a missing refusal close. */
		for (i = 0; i < ARRAY_SIZE(files); i++)
			while (file_count(files[i]) > baseline[i])
				fput(files[i]);
		error = nlmsvc_ffv2_gate_begin(&probe, file_inode(files[0])->i_sb);
		KUNIT_EXPECT_EQ_MSG(test, error, 0, "no refused table entry");
		if (!error)
			nlmsvc_ffv2_gate_end(&probe);

		owner = nlmsvc_ffv2_test_file_insert(read_file, write_file);
		KUNIT_EXPECT_NOT_NULL(test, owner);
		if (!owner)
			continue;
		for (i = 0; i < ARRAY_SIZE(files); i++)
			KUNIT_EXPECT_EQ(test, file_count(files[i]),
					baseline[i] + !!(mask & (1U << i)));
		error = nlmsvc_ffv2_gate_begin(&probe, file_inode(files[0])->i_sb);
		KUNIT_EXPECT_EQ_MSG(test, error, -EBUSY, "successful table entry");
		if (!error)
			nlmsvc_ffv2_gate_end(&probe);
		nlmsvc_ffv2_test_file_put(owner);
		for (i = 0; i < ARRAY_SIZE(files); i++)
			KUNIT_EXPECT_EQ_MSG(test, file_count(files[i]), baseline[i],
					    "released slot %u mask %u", i, mask);
		error = nlmsvc_ffv2_gate_begin(&probe, file_inode(files[0])->i_sb);
		KUNIT_EXPECT_EQ(test, error, 0);
		if (!error)
			nlmsvc_ffv2_gate_end(&probe);
	}
	owner = nlmsvc_ffv2_test_file_insert(NULL, NULL);
	KUNIT_EXPECT_PTR_EQ(test, owner, NULL);
	if (owner)
		nlmsvc_ffv2_test_file_put(owner);
	for (i = 0; i < ARRAY_SIZE(files); i++) {
		KUNIT_EXPECT_EQ(test, file_count(files[i]), baseline[i]);
		fput(files[i]);
	}
}

static void nfsd_ffv2_filecache_gate_test(struct kunit *test)
{
	struct nfsd_ffv2_file_wait_ctx ctx;
	struct nfsd_file_ffv2_gate gate, duplicate;
	struct nlmsvc_ffv2_gate nlm_gate, nlm_duplicate;
	struct nfsd_file *nf, *blocked;
	struct task_struct *task;
	struct nlm_file *nlm_file;
	struct file *filp;
	struct path root;
	bool waiting;
	int error;

	mutex_lock(&nfsd_mutex);
	error = nfsd_file_ffv2_test_cache_start();
	mutex_unlock(&nfsd_mutex);
	if (error) {
		KUNIT_FAIL(test, "filecache startup: %d", error);
		return;
	}
	get_fs_root(current->fs, &root);
	nf = nfsd_file_ffv2_test_alloc(d_inode(root.dentry), NFSD_MAY_READ, false);
	if (!nf) {
		KUNIT_FAIL(test, "persistent file allocation");
		goto out_root;
	}
	error = nfsd_file_ffv2_gate_begin(&gate, d_inode(root.dentry));
	KUNIT_EXPECT_EQ(test, error, -EBUSY);
	if (!error)
		nfsd_file_ffv2_gate_end(&gate);
	nfsd_file_put(nf);
	if (error != -EBUSY)
		goto out_root;

	nf = nfsd_file_ffv2_test_alloc(d_inode(root.dentry),
				       NFSD_MAY_READ | NFSD_MAY_LOCALIO, false);
	if (!nf) {
		KUNIT_FAIL(test, "LOCALIO file allocation");
		goto out_root;
	}
	error = nfsd_file_ffv2_gate_begin(&gate, d_inode(root.dentry));
	if (error) {
		KUNIT_FAIL(test, "filecache gate begin: %d", error);
		nfsd_file_put(nf);
		goto out_root;
	}
	KUNIT_EXPECT_EQ(test, gate.live, 1U);
	KUNIT_EXPECT_EQ(test, nf->nf_may,
			(unsigned int)(NFSD_MAY_READ | NFSD_MAY_LOCALIO));
	error = nfsd_file_ffv2_gate_begin(&duplicate, d_inode(root.dentry));
	KUNIT_EXPECT_EQ(test, error, -EBUSY);
	if (!error)
		nfsd_file_ffv2_gate_end(&duplicate);
	blocked = nfsd_file_ffv2_test_alloc(d_inode(root.dentry), NFSD_MAY_READ, false);
	KUNIT_EXPECT_PTR_EQ(test, blocked, NULL);
	if (blocked)
		nfsd_file_put(blocked);
	ctx.gate = &gate;
	init_completion(&ctx.done);
	task = kthread_run(nfsd_ffv2_file_wait_thread, &ctx, "ffv2-file-wait");
	if (IS_ERR(task)) {
		KUNIT_FAIL(test, "filecache wait worker: %ld", PTR_ERR(task));
		goto out_file;
	}
	error = read_poll_timeout(waitqueue_active, waiting, waiting,
				  1000, 1000000, false, &gate.wait);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_FALSE(test, completion_done(&ctx.done));
	send_sig(SIGUSR1, task, 1);
	wait_for_completion(&ctx.done);
	kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ctx.result, -ERESTARTSYS);
	KUNIT_EXPECT_EQ(test, gate.live, 1U);
	blocked = nfsd_file_ffv2_test_alloc(d_inode(root.dentry), NFSD_MAY_READ, false);
	KUNIT_EXPECT_PTR_EQ(test, blocked, NULL);
	if (blocked)
		nfsd_file_put(blocked);
out_file:
	nfsd_file_put(nf);
	if (!list_empty(&gate.list))
		KUNIT_EXPECT_EQ(test, nfsd_file_ffv2_gate_wait(&gate), 0);
	KUNIT_EXPECT_EQ(test, gate.live, 0U);
	nfsd_file_ffv2_gate_end(&gate);
	blocked = nfsd_file_ffv2_test_alloc(d_inode(root.dentry), NFSD_MAY_READ, false);
	KUNIT_EXPECT_NOT_NULL(test, blocked);
	if (blocked)
		nfsd_file_put(blocked);

	filp = dentry_open(&root, O_RDONLY, current_cred());
	if (IS_ERR(filp)) {
		KUNIT_FAIL(test, "NLM file open: %ld", PTR_ERR(filp));
		goto out_root;
	}
	nlm_file = nlmsvc_ffv2_test_file_get(filp);
	fput(filp);
	if (!nlm_file) {
		KUNIT_FAIL(test, "NLM file allocation");
		goto out_root;
	}
	error = nlmsvc_ffv2_gate_begin(&nlm_gate, root.mnt->mnt_sb);
	KUNIT_EXPECT_EQ(test, error, -EBUSY);
	if (!error)
		nlmsvc_ffv2_gate_end(&nlm_gate);
	nlmsvc_ffv2_test_file_put(nlm_file);
	error = nlmsvc_ffv2_gate_begin(&nlm_gate, root.mnt->mnt_sb);
	KUNIT_EXPECT_EQ(test, error, 0);
	if (!error) {
		error = nlmsvc_ffv2_gate_begin(&nlm_duplicate, root.mnt->mnt_sb);
		KUNIT_EXPECT_EQ(test, error, -EBUSY);
		if (!error)
			nlmsvc_ffv2_gate_end(&nlm_duplicate);
		nlmsvc_ffv2_gate_end(&nlm_gate);
		error = nlmsvc_ffv2_gate_begin(&nlm_duplicate, root.mnt->mnt_sb);
		KUNIT_EXPECT_EQ(test, error, 0);
		if (!error)
			nlmsvc_ffv2_gate_end(&nlm_duplicate);
	}
out_root:
	path_put(&root);
	mutex_lock(&nfsd_mutex);
	nfsd_file_cache_shutdown();
	mutex_unlock(&nfsd_mutex);
}

static void nfsd_ffv2_reservation_access_test(struct kunit *test)
{
	struct nfsd_ffv2_reservation *reservation = NULL;
	struct nfsd_ffv2_export_update update;
	struct completion exit_done;
	struct svc_export key, *exp = NULL, *foreign = NULL, *replacement;
	struct svc_export *refused;
	struct auth_domain *domain;
	struct file_system_type *type;
	struct vfsmount *mount;
	struct path root, distinct;
	struct nfsd_net *nn, *other_nn;
	struct net *net, *other_net;
	u8 uuid[16] = { 1 }, token[32] = { 2 };
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "reservation netns: %ld", PTR_ERR(net));
		return;
	}
	other_net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(other_net)) {
		KUNIT_FAIL(test, "foreign netns: %ld", PTR_ERR(other_net));
		goto out_net;
	}
	nn = net_generic(net, nfsd_net_id);
	other_nn = net_generic(other_net, nfsd_net_id);
	domain = unix_domain_find("ffv2-reservation-kunit");
	if (!domain) {
		KUNIT_FAIL(test, "reservation auth domain");
		goto out_other_net;
	}
	get_fs_root(current->fs, &root);
	type = get_fs_type("tmpfs");
	if (!type) {
		KUNIT_FAIL(test, "tmpfs unavailable");
		goto out_root;
	}
	mount = kern_mount(type);
	put_filesystem(type);
	if (IS_ERR(mount)) {
		KUNIT_FAIL(test, "distinct superblock: %ld", PTR_ERR(mount));
		goto out_root;
	}
	distinct.mnt = mount;
	distinct.dentry = mount->mnt_root;
	KUNIT_EXPECT_PTR_NE(test, root.mnt->mnt_sb, distinct.mnt->mnt_sb);

	nfsd_ffv2_init_export_test_key(&key, nn, domain, &root);
	key.ex_uuid = kmemdup(uuid, sizeof(uuid), GFP_KERNEL);
	if (!key.ex_uuid) {
		KUNIT_FAIL(test, "reservation UUID allocation");
		goto out_mount;
	}
	exp = nfsd_export_cache_update(&key);
	kfree(key.ex_uuid);
	key.ex_uuid = NULL;
	if (IS_ERR(exp)) {
		KUNIT_FAIL(test, "reservation export: %ld", PTR_ERR(exp));
		exp = NULL;
		goto out_mount;
	}
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_transition_exact(exp), 0);
	nfsd_ffv2_init_export_test_key(&key, other_nn, domain, &root);
	foreign = nfsd_export_cache_update(&key);
	if (IS_ERR(foreign)) {
		KUNIT_FAIL(test, "foreign export: %ld", PTR_ERR(foreign));
		foreign = NULL;
		goto out_mount;
	}
	error = nfsd_ffv2_test_reservation_claim_expected(nn, &root, uuid, token,
							  exp, &reservation);
	KUNIT_EXPECT_EQ(test, error, -EBUSY);
	if (!error) {
		nfsd_ffv2_reservation_abort(reservation);
		reservation = NULL;
	}
	exp_put(foreign);
	foreign = NULL;
	nfsd_export_flush(other_net);
	nfsd_ffv2_init_export_test_key(&key, other_nn, domain, &distinct);
	foreign = nfsd_export_cache_update(&key);
	if (IS_ERR(foreign)) {
		KUNIT_FAIL(test, "distinct export: %ld", PTR_ERR(foreign));
		foreign = NULL;
		goto out_mount;
	}
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_export_transition_abort_exact(exp));
	nfsd_ffv2_init_export_test_key(&key, nn, domain, &root);
	key.ex_uuid = kmemdup(uuid, sizeof(uuid), GFP_KERNEL);
	if (!key.ex_uuid) {
		KUNIT_FAIL(test, "replacement UUID allocation");
		goto out_mount;
	}
	error = nfsd_ffv2_export_update_begin(&key, &update);
	if (!error)
		error = nfsd_ffv2_export_update_validate(&update);
	if (error) {
		if (update.admitted)
			nfsd_ffv2_export_update_abort(&update);
		kfree(key.ex_uuid);
		key.ex_uuid = NULL;
		KUNIT_FAIL(test, "exact update admission: %d", error);
		goto out_mount;
	}
	replacement = nfsd_ffv2_test_export_update_exact(&key, exp);
	if (IS_ERR(replacement))
		nfsd_ffv2_export_update_abort(&update);
	else
		nfsd_ffv2_export_update_end(replacement, &update);
	kfree(key.ex_uuid);
	key.ex_uuid = NULL;
	if (IS_ERR(replacement)) {
		KUNIT_FAIL(test, "reservation replacement: %ld", PTR_ERR(replacement));
		goto out_mount;
	}
	refused = nfsd_ffv2_test_export_update_exact(&key, exp);
	KUNIT_EXPECT_TRUE(test, IS_ERR(refused));
	if (IS_ERR(refused))
		KUNIT_EXPECT_EQ(test, PTR_ERR(refused), -ESTALE);
	else
		exp_put(refused);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_transition_exact(replacement), 0);
	error = nfsd_ffv2_test_reservation_claim_expected(nn, &root, uuid, token,
							  replacement, &reservation);
	KUNIT_EXPECT_EQ(test, error, -EBUSY);
	if (!error) {
		nfsd_ffv2_reservation_abort(reservation);
		reservation = NULL;
	}
	exp_put(exp);
	exp = replacement;
	nfsd_ffv2_test_fail_reservation_alloc(nn);
	error = nfsd_ffv2_test_reservation_claim_expected(nn, &root, uuid, token,
							  exp, &reservation);
	KUNIT_EXPECT_EQ(test, error, -ENOMEM);
	if (!error) {
		nfsd_ffv2_reservation_abort(reservation);
		reservation = NULL;
	}
	KUNIT_EXPECT_TRUE(test, nfsd4_ffv2_mount_crossing_allowed(&root));
	error = nfsd_ffv2_test_reservation_claim_expected(nn, &root, uuid, token,
							  exp, &reservation);
	if (error) {
		KUNIT_FAIL(test, "distinct-superblock claim: %d", error);
		goto out_mount;
	}
	KUNIT_EXPECT_FALSE(test, nfsd4_ffv2_mount_crossing_allowed(&root));
	KUNIT_EXPECT_TRUE(test, nfsd4_ffv2_mount_crossing_allowed(&distinct));
	replacement = nfsd_export_cache_update(&key);
	KUNIT_EXPECT_TRUE(test, IS_ERR(replacement));
	if (IS_ERR(replacement))
		KUNIT_EXPECT_EQ(test, PTR_ERR(replacement), -EBUSY);
	else
		exp_put(replacement);
	KUNIT_EXPECT_EQ(test, nn->ffv2_participant.update_count, 0U);
	nfsd_ffv2_reservation_abort(reservation);
	reservation = NULL;
	KUNIT_EXPECT_TRUE(test, nfsd4_ffv2_mount_crossing_allowed(&root));
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_export_transition_abort_exact(exp));
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_export_transition_exact(exp), 0);
	error = nfsd_ffv2_test_reservation_claim_expected(nn, &root, uuid, token,
							  exp, &reservation);
	if (error) {
		KUNIT_FAIL(test, "exit reservation: %d", error);
		goto out_mount;
	}
	init_completion(&exit_done);
	WRITE_ONCE(nn->ffv2_participant.test_inventory_wait_done, &exit_done);
	nfsd_ffv2_net_pre_exit(nn);
	replacement = nfsd_export_cache_update(&key);
	KUNIT_EXPECT_TRUE(test, IS_ERR(replacement));
	if (IS_ERR(replacement))
		KUNIT_EXPECT_EQ(test, PTR_ERR(replacement), -ESHUTDOWN);
	else
		exp_put(replacement);
	exp_put(exp);
	exp = NULL;
	nfsd_export_flush(net);
	put_net(net);
	wait_for_completion(&exit_done);
	net_ns_barrier();
	net = NULL;
	KUNIT_EXPECT_TRUE(test, nfsd4_ffv2_mount_crossing_allowed(&root));
	nfsd_ffv2_reservation_abort(reservation);
	reservation = NULL;
out_mount:
	if (reservation)
		nfsd_ffv2_reservation_abort(reservation);
	if (exp)
		exp_put(exp);
	if (foreign)
		exp_put(foreign);
	if (net)
		nfsd_export_flush(net);
	nfsd_export_flush(other_net);
	kern_unmount(mount);
out_root:
	path_put(&root);
	auth_domain_put(domain);
out_other_net:
	put_net(other_net);
	net_ns_barrier();
out_net:
	if (net)
		put_net(net);
	net_ns_barrier();
}

struct nfsd_ffv2_reservation_wait_ctx {
	struct nfsd_ffv2_reservation *reservation;
	int result;
	struct completion done;
};

static int nfsd_ffv2_reservation_wait_thread(void *data)
{
	struct nfsd_ffv2_reservation_wait_ctx *ctx = data;

	allow_signal(SIGUSR1);
	ctx->result = nfsd_ffv2_reservation_gate_io(ctx->reservation);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static void nfsd_ffv2_reservation_io_test(struct kunit *test)
{
	struct nfsd_ffv2_reservation_wait_ctx ctx;
	struct nfsd_ffv2_reservation *reservation = NULL;
	struct nlmsvc_ffv2_gate nlm_gate;
	struct nfsd_file *nf, *probe;
	struct task_struct *task;
	struct nfsd_net *nn;
	struct path root;
	struct net *net;
	u8 uuid[16] = { 3 }, token[32] = { 4 };
	bool waiting;
	int error;

	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(net)) {
		KUNIT_FAIL(test, "gate netns: %ld", PTR_ERR(net));
		return;
	}
	nn = net_generic(net, nfsd_net_id);
	mutex_lock(&nfsd_mutex);
	error = nfsd_file_ffv2_test_cache_start();
	mutex_unlock(&nfsd_mutex);
	if (error) {
		KUNIT_FAIL(test, "gate filecache startup: %d", error);
		goto out_net;
	}
	get_fs_root(current->fs, &root);
	error = nfsd_ffv2_test_reservation_claim(nn, &root, uuid, token, &reservation);
	if (error) {
		KUNIT_FAIL(test, "gate reservation: %d", error);
		goto out_root;
	}
	error = nlmsvc_ffv2_gate_begin(&nlm_gate, root.mnt->mnt_sb);
	KUNIT_EXPECT_EQ(test, error, 0);
	if (!error) {
		KUNIT_EXPECT_EQ(test, nfsd_ffv2_reservation_gate_io(reservation), -EBUSY);
		nlmsvc_ffv2_gate_end(&nlm_gate);
	}
	nf = nfsd_file_ffv2_test_alloc(d_inode(root.dentry), NFSD_MAY_READ, false);
	if (!nf) {
		KUNIT_FAIL(test, "gate persistent file allocation");
		goto out_reservation;
	}
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_reservation_gate_io(reservation), -EBUSY);
	error = nlmsvc_ffv2_gate_begin(&nlm_gate, root.mnt->mnt_sb);
	KUNIT_EXPECT_EQ(test, error, 0);
	if (!error)
		nlmsvc_ffv2_gate_end(&nlm_gate);
	nfsd_file_put(nf);
	nf = nfsd_file_ffv2_test_alloc(d_inode(root.dentry),
				       NFSD_MAY_READ | NFSD_MAY_LOCALIO, false);
	if (!nf) {
		KUNIT_FAIL(test, "gate retained LOCALIO file");
		goto out_reservation;
	}
	ctx.reservation = reservation;
	init_completion(&ctx.done);
	task = kthread_run(nfsd_ffv2_reservation_wait_thread, &ctx, "ffv2-gate-io");
	if (IS_ERR(task)) {
		KUNIT_FAIL(test, "gate I/O worker: %ld", PTR_ERR(task));
		nfsd_file_put(nf);
		goto out_reservation;
	}
	error = read_poll_timeout(nfsd_ffv2_test_reservation_waiting, waiting, waiting,
				  1000, 1000000, false, reservation);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_FALSE(test, completion_done(&ctx.done));
	send_sig(SIGUSR1, task, 1);
	wait_for_completion(&ctx.done);
	kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ctx.result, -ERESTARTSYS);
	error = nlmsvc_ffv2_gate_begin(&nlm_gate, root.mnt->mnt_sb);
	KUNIT_EXPECT_EQ(test, error, 0);
	if (!error)
		nlmsvc_ffv2_gate_end(&nlm_gate);
	probe = nfsd_file_ffv2_test_alloc(d_inode(root.dentry), NFSD_MAY_READ, false);
	KUNIT_EXPECT_NOT_NULL(test, probe);
	if (probe)
		nfsd_file_put(probe);
	nfsd_file_put(nf);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_reservation_gate_io(reservation), 0);
	error = nlmsvc_ffv2_gate_begin(&nlm_gate, root.mnt->mnt_sb);
	KUNIT_EXPECT_EQ(test, error, -EBUSY);
	if (!error)
		nlmsvc_ffv2_gate_end(&nlm_gate);
out_reservation:
	nfsd_ffv2_reservation_abort(reservation);
	KUNIT_EXPECT_TRUE(test, nfsd4_ffv2_mount_crossing_allowed(&root));
	error = nlmsvc_ffv2_gate_begin(&nlm_gate, root.mnt->mnt_sb);
	KUNIT_EXPECT_EQ(test, error, 0);
	if (!error)
		nlmsvc_ffv2_gate_end(&nlm_gate);
out_root:
	path_put(&root);
	mutex_lock(&nfsd_mutex);
	nfsd_file_cache_shutdown();
	mutex_unlock(&nfsd_mutex);
out_net:
	put_net(net);
	net_ns_barrier();
}

static void nfsd_ffv2_codec_test(struct kunit *test)
{
	static const u8 header[] = {
		0xff, 'F', 'F', 'V', '2', 'F', 'H', 0, 1, 0, 0, 56,
		0, 64, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23,
		24, 25, 26, 27, 28, 29, 30, 31,
	};
	struct nfsd_ffv2_fh_info info = { .generation = 0x0102030405060708 };
	struct nfsd_ffv2_fh_info parsed;
	struct knfsd_fh fh, bad;
	u8 inner[NFSD_FFV2_FH_INNER_MAX] = { 1 };
	unsigned int i, len;

	for (i = 0; i < 16; i++) {
		info.object_uuid[i] = i;
		info.export_uuid[i] = i + 16;
	}
	info.inner = inner;
	for (len = 8; len <= sizeof(inner); len += sizeof(inner) - 8) {
		info.inner_len = len;
		KUNIT_ASSERT_EQ(test, nfsd_ffv2_fh_encode(&fh, &info), 0);
		KUNIT_EXPECT_EQ(test, fh.fh_size, 56U + len);
		KUNIT_ASSERT_EQ(test, nfsd_ffv2_fh_parse(&fh, &parsed), 0);
		KUNIT_EXPECT_EQ(test, parsed.generation, info.generation);
		KUNIT_EXPECT_MEMEQ(test, parsed.object_uuid, info.object_uuid, 16);
		KUNIT_EXPECT_MEMEQ(test, parsed.export_uuid, info.export_uuid, 16);
		KUNIT_EXPECT_PTR_EQ(test, parsed.inner, fh.fh_raw + 56);
		KUNIT_EXPECT_EQ(test, parsed.inner_len, len);
		KUNIT_EXPECT_MEMEQ(test, parsed.inner, inner, len);
		if (len == 8)
			KUNIT_EXPECT_MEMEQ(test, fh.fh_raw, header, sizeof(header));
	}

	info.inner_len = 8;
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_fh_encode(&fh, &info), 0);
	for (i = 0; i < 19; i++) {
		bad = fh;
		switch (i) {
		case 0:
			bad.fh_size = 55;
			break;
		case 1:
			bad.fh_size = 129;
			break;
		case 2:
			bad.fh_raw[0] ^= 1;
			break;
		case 3:
			bad.fh_raw[8] = 2;
			break;
		case 4:
			bad.fh_raw[9] = 1;
			break;
		case 5:
			put_unaligned_be16(52, bad.fh_raw + 10);
			put_unaligned_be16(12, bad.fh_raw + 14);
			break;
		case 6:
			put_unaligned_be16(68, bad.fh_raw + 12);
			break;
		case 7:
			put_unaligned_be16(4, bad.fh_raw + 14);
			break;
		case 8:
			put_unaligned_be16(76, bad.fh_raw + 14);
			break;
		case 9:
			put_unaligned_be16(9, bad.fh_raw + 14);
			break;
		case 10:
			put_unaligned_be16(12, bad.fh_raw + 14);
			break;
		case 11:
			bad.fh_raw[56] = 2;
			break;
		case 12:
			memset(bad.fh_raw + 16, 0, 8);
			break;
		case 13:
			bad.fh_size = 60;
			put_unaligned_be16(60, bad.fh_raw + 12);
			put_unaligned_be16(4, bad.fh_raw + 14);
			break;
		case 14:
			bad.fh_size = 65;
			put_unaligned_be16(65, bad.fh_raw + 12);
			put_unaligned_be16(9, bad.fh_raw + 14);
			break;
		default:
			info.inner_len = i == 15 ? 4 : i == 16 ? 76 : 9;
			if (i == 18) {
				info.inner_len = 8;
				info.generation = 0;
			}
			KUNIT_EXPECT_EQ_MSG(test, nfsd_ffv2_fh_encode(&bad, &info),
					    -EINVAL, "encode case %u", i);
			continue;
		}
		KUNIT_EXPECT_EQ_MSG(test, nfsd_ffv2_fh_parse(&bad, &parsed),
				    -EBADMSG, "parse case %u", i);
	}
	info.generation = 1;
	info.inner_len = 8;
	inner[0] = 2;
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_fh_encode(&bad, &info), -EINVAL);
	info.inner = NULL;
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_fh_encode(&bad, &info), -EINVAL);
}

#define FFV2_EXPECT_STATUS(test, actual, expected) \
	KUNIT_EXPECT_EQ(test, be32_to_cpu(actual), be32_to_cpu(expected))
#define FFV2_EXPECT_STATUS_MSG(test, actual, expected, fmt, ...) \
	KUNIT_EXPECT_EQ_MSG(test, be32_to_cpu(actual), be32_to_cpu(expected), \
			    fmt, ##__VA_ARGS__)

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

	KUNIT_EXPECT_EQ(test,
			nfsd4_ffv2_compound_digest(&buf, 4, sizeof(wire), changed),
		-EBADMSG);
	wire[sizeof(wire) - 1] = 1;
	KUNIT_ASSERT_EQ(test,
			nfsd4_ffv2_compound_digest(&buf, 4, sizeof(wire) - 4,
						   changed),
			0);
	KUNIT_EXPECT_MEMNEQ(test, digest, changed, sizeof(digest));
}

static void nfsd_ffv2_test_attach_transport(struct svc_rqst *rqstp)
{
	static struct svc_xprt_class xcl = {
		.xcl_max_payload	= RPCSVC_MAXPAYLOAD_TCP,
	};
	static struct svc_xprt xprt = {
		.xpt_class		= &xcl,
	};
	static struct svc_serv serv = {
		.sv_max_payload		= RPCSVC_MAXPAYLOAD_TCP,
	};

	rqstp->rq_xprt = &xprt;
	rqstp->rq_server = &serv;
}

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

static bool nfsd_ffv2_test_compound_decode(struct kunit *test,
					   struct nfsd4_compoundargs *args,
					   const void *wire, size_t len,
					   size_t head_len, size_t page_len)
{
	struct nfsd_thread_local_info *ntli;
	struct svc_rqst *rqstp;
	struct auth_ops auth = { .flavour = RPC_AUTH_NULL };
	struct xdr_stream xdr;
	struct xdr_buf buf = {};
	struct page *pages[2] = {};
	u8 *scratch;
	bool decoded = false;
	unsigned int i, decoded_opcnt;

	if (head_len + page_len > len || page_len > 2 * PAGE_SIZE)
		return false;
	ntli = kunit_kzalloc(test, sizeof(*ntli), GFP_KERNEL);
	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	scratch = kunit_kmalloc(test, PAGE_SIZE, GFP_KERNEL);
	if (!ntli || !rqstp || !scratch)
		return false;
	for (i = 0; i < DIV_ROUND_UP(page_len, PAGE_SIZE); i++) {
		pages[i] = alloc_page(GFP_KERNEL);
		if (!pages[i])
			goto out_pages;
		memcpy(page_address(pages[i]),
		       (const u8 *)wire + head_len + i * PAGE_SIZE,
		       min_t(size_t, PAGE_SIZE, page_len - i * PAGE_SIZE));
	}
	buf.head[0].iov_base = (void *)wire;
	buf.head[0].iov_len = head_len;
	buf.pages = pages;
	buf.page_len = page_len;
	buf.tail[0].iov_base = (u8 *)wire + head_len + page_len;
	buf.tail[0].iov_len = len - head_len - page_len;
	buf.len = len;
	buf.buflen = len;
	xdr_init_decode(&xdr, &buf, buf.head[0].iov_base, NULL);
	xdr_set_scratch_buffer(&xdr, scratch, PAGE_SIZE);
	rqstp->rq_argp = args;
	rqstp->rq_private = ntli;
	rqstp->rq_authop = &auth;
	nfsd_ffv2_test_attach_transport(rqstp);
	args->opcnt = 0;
	decoded = nfs4svc_decode_compoundargs(rqstp, &xdr);
	decoded_opcnt = args->opcnt;
	nfsd4_release_compoundargs(rqstp);
	/* Only inline operations and copied metadata survive cleanup. */
	args->opcnt = decoded_opcnt;
	xdr_finish_decode(&xdr);
out_pages:
	for (i = 0; i < ARRAY_SIZE(pages); i++)
		if (pages[i])
			__free_page(pages[i]);
	return decoded;
}

static void nfsd_ffv2_selective_digest_test(struct kunit *test)
{
	struct nfsd4_ffv2_digest_test_ctx ctx = {};
	struct nfsd4_compoundargs *args;
	struct xdr_buf baseline;
	__be32 *p;
	u8 *wire;
	u8 expected[NFSD4_FFV2_DIGEST_SIZE];
	u8 zero[NFSD4_FFV2_DIGEST_SIZE] = { 0 };
	size_t len;
	int i;

	args = kunit_kzalloc(test, sizeof(*args), GFP_KERNEL);
	wire = kunit_kzalloc(test, 2 * PAGE_SIZE + 256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, args);
	KUNIT_ASSERT_NOT_NULL(test, wire);
	args->ffv2_digest_test = &ctx;

	p = (__be32 *)wire;
	*p++ = cpu_to_be32(0);
	*p++ = cpu_to_be32(2);
	*p++ = cpu_to_be32(0);
	len = (u8 *)p - wire;
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len, len, 0));
	KUNIT_EXPECT_EQ(test, ctx.calls, 0U);
	KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);
	((__be32 *)wire)[0] = cpu_to_be32(NFSD4_MAX_TAGLEN + 1);
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_test_compound_decode(test, args,
								wire, len, len, 0));
	KUNIT_EXPECT_EQ(test, ctx.calls, 0U);
	((__be32 *)wire)[0] = cpu_to_be32(0);

	p = (__be32 *)(wire + 8);
	*p++ = cpu_to_be32(1);
	*p++ = cpu_to_be32(OP_WRITE);
	for (i = 0; i < 4; i++)
		*p++ = cpu_to_be32(i);
	*p++ = cpu_to_be32(0);
	*p++ = cpu_to_be32(0);
	*p++ = cpu_to_be32(NFS_FILE_SYNC);
	*p++ = cpu_to_be32(2 * PAGE_SIZE);
	memset(p, 0x5a, 2 * PAGE_SIZE);
	len = (u8 *)p - wire + 2 * PAGE_SIZE;
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len,
							 (u8 *)p - wire,
							 2 * PAGE_SIZE));
	KUNIT_EXPECT_EQ(test, ctx.calls, 0U);
	KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);

	len = nfsd_ffv2_ro_compound((__be32 *)wire, 0);
	xdr_buf_init(&baseline, wire, len);
	baseline.len = len;
	KUNIT_ASSERT_EQ(test, nfsd4_ffv2_compound_digest(&baseline, 0, len,
							 expected), 0);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len, 20, 64));
	KUNIT_EXPECT_EQ(test, ctx.calls, 1U);
	KUNIT_EXPECT_TRUE(test, args->ffv2_digest_valid);
	KUNIT_EXPECT_MEMEQ(test, args->ffv2_digest, expected,
			   sizeof(expected));

	ctx.fail = true;
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_test_compound_decode(test, args,
								wire, len, 20, 64));
	KUNIT_EXPECT_EQ(test, ctx.calls, 2U);
	KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);
	KUNIT_EXPECT_MEMEQ(test, args->ffv2_digest,
			   zero, sizeof(expected));
	ctx.fail = false;

	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len - 1, 20, 64));
	KUNIT_EXPECT_EQ(test, ctx.calls, 2U);
	KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);
	KUNIT_EXPECT_EQ(test, args->ffv2_decode_class,
			NFSD4_FFV2_DECODE_BADXDR);
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_test_compound_decode(test, args,
								wire, len + 4, 20, 64));
	KUNIT_EXPECT_EQ(test, ctx.calls, 2U);
	KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);
}

static void nfsd_ffv2_selective_mixed_test(struct kunit *test)
{
	struct nfsd4_ffv2_digest_test_ctx ctx = {};
	struct nfsd4_compoundargs *args;
	struct nfsd4_slot *slot;
	struct xdr_buf baseline;
	__be32 wire[32] = {};
	__be32 reordered[32] = {};
	__be32 *p = wire;
	u8 expected[NFSD4_FFV2_DIGEST_SIZE];
	u8 original[NFSD4_FFV2_DIGEST_SIZE];
	size_t len;
	int i;

	args = kunit_kzalloc(test, sizeof(*args), GFP_KERNEL);
	slot = kunit_kzalloc(test, sizeof(*slot), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, args);
	KUNIT_ASSERT_NOT_NULL(test, slot);
	args->ffv2_digest_test = &ctx;
	*p++ = cpu_to_be32(1);
	*p++ = cpu_to_be32(0x61000000);
	*p++ = cpu_to_be32(2);
	*p++ = cpu_to_be32(2);
	*p++ = cpu_to_be32(OP_WRITE);
	for (i = 0; i < 4; i++)
		*p++ = cpu_to_be32(i);
	*p++ = cpu_to_be32(0);
	*p++ = cpu_to_be32(0);
	*p++ = cpu_to_be32(NFS_FILE_SYNC);
	*p++ = cpu_to_be32(4);
	*p++ = cpu_to_be32(0x10111213);
	*p++ = cpu_to_be32(OP_CHUNK_READ);
	for (i = 0; i < 4; i++)
		*p++ = cpu_to_be32(i);
	*p++ = cpu_to_be32(0);
	*p++ = cpu_to_be32(0);
	*p++ = cpu_to_be32(1);
	len = (u8 *)p - (u8 *)wire;
	xdr_buf_init(&baseline, wire, len);
	baseline.len = len;
	KUNIT_ASSERT_EQ(test, nfsd4_ffv2_compound_digest(&baseline, 0, len,
							 expected), 0);
	KUNIT_ASSERT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len, 8, 48));
	KUNIT_EXPECT_EQ(test, ctx.calls, 1U);
	KUNIT_EXPECT_TRUE(test, args->ffv2_digest_valid);
	KUNIT_EXPECT_MEMEQ(test, args->ffv2_digest, expected,
			   sizeof(expected));
	memcpy(original, args->ffv2_digest, sizeof(original));
	slot->sl_ffv2_present = true;
	memcpy(slot->sl_ffv2_digest, original, sizeof(original));
	KUNIT_EXPECT_TRUE(test, nfsd4_ffv2_replay_identity_match(args, slot));

	((u8 *)wire)[4] = 'b';
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len, 8, 48));
	KUNIT_EXPECT_EQ(test, ctx.calls, 2U);
	KUNIT_EXPECT_MEMNEQ(test, args->ffv2_digest, original,
			    sizeof(original));
	KUNIT_EXPECT_FALSE(test, nfsd4_ffv2_replay_identity_match(args, slot));
	KUNIT_EXPECT_FALSE(test, nfsd4_ffv2_replay_identity_match(args, slot));
	((u8 *)wire)[4] = 'a';

	((u8 *)wire)[7] = 1;
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len, 8, 48));
	KUNIT_EXPECT_EQ(test, ctx.calls, 3U);
	KUNIT_EXPECT_MEMNEQ(test, args->ffv2_digest, original,
			    sizeof(original));
	KUNIT_EXPECT_FALSE(test, nfsd4_ffv2_replay_identity_match(args, slot));
	((u8 *)wire)[7] = 0;

	wire[13] ^= cpu_to_be32(1);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len, 8, 48));
	KUNIT_EXPECT_EQ(test, ctx.calls, 4U);
	KUNIT_EXPECT_MEMNEQ(test, args->ffv2_digest, original,
			    sizeof(original));
	KUNIT_EXPECT_FALSE(test, nfsd4_ffv2_replay_identity_match(args, slot));
	wire[13] ^= cpu_to_be32(1);

	wire[21] = cpu_to_be32(2);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len, 8, 48));
	KUNIT_EXPECT_EQ(test, ctx.calls, 5U);
	KUNIT_EXPECT_MEMNEQ(test, args->ffv2_digest, original,
			    sizeof(original));
	KUNIT_EXPECT_FALSE(test, nfsd4_ffv2_replay_identity_match(args, slot));
	wire[21] = cpu_to_be32(1);
	memcpy(reordered, wire, 4 * sizeof(*wire));
	memcpy(reordered + 4, wire + 14, 8 * sizeof(*wire));
	memcpy(reordered + 12, wire + 4, 10 * sizeof(*wire));
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       reordered, len, 8, 48));
	KUNIT_EXPECT_EQ(test, ctx.calls, 6U);
	KUNIT_EXPECT_MEMNEQ(test, args->ffv2_digest, original,
			    sizeof(original));
	KUNIT_EXPECT_FALSE(test, nfsd4_ffv2_replay_identity_match(args, slot));

	wire[11] = cpu_to_be32(3);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len, 8, 48));
	KUNIT_EXPECT_EQ(test, ctx.calls, 6U);
	KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);
	KUNIT_EXPECT_EQ(test, args->ffv2_decode_class,
			NFSD4_FFV2_DECODE_NONE);
}

static void nfsd_ffv2_selective_errors_test(struct kunit *test)
{
	struct nfsd4_ffv2_digest_test_ctx ctx = {};
	struct nfsd4_compoundargs *args;
	__be32 wire[32] = {};
	size_t len;

	args = kunit_kzalloc(test, sizeof(*args), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, args);
	args->ffv2_digest_test = &ctx;
	len = nfsd_ffv2_ro_compound(wire, 0);

	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_test_compound_decode(test, args,
								wire, 2, 2, 0));
	KUNIT_EXPECT_EQ(test, ctx.calls, 0U);
	KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);

	wire[1] = cpu_to_be32(3);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len, len, 0));
	KUNIT_EXPECT_EQ(test, ctx.calls, 0U);
	KUNIT_EXPECT_FALSE(test, args->ffv2_present);
	wire[1] = cpu_to_be32(2);

	wire[2] = cpu_to_be32(NFSD_MAX_OPS_PER_COMPOUND + 1);
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_test_compound_decode(test, args,
								wire, len, len, 0));
	KUNIT_EXPECT_EQ(test, ctx.calls, 0U);
	KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);
	wire[2] = cpu_to_be32(3);

	wire[15] = cpu_to_be32(OP_CHUNK_COMMIT);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len, len, 0));
	KUNIT_EXPECT_EQ(test, ctx.calls, 0U);
	KUNIT_EXPECT_TRUE(test, args->ffv2_present);
	KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);
	wire[15] = cpu_to_be32(OP_CHUNK_READ);
	wire[1] = cpu_to_be32(1);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len, len, 0));
	KUNIT_EXPECT_EQ(test, ctx.calls, 0U);
	KUNIT_EXPECT_TRUE(test, args->ffv2_present);
	KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);
	KUNIT_EXPECT_EQ(test, args->ffv2_decode_class,
			NFSD4_FFV2_DECODE_NOTSUPP);
	{
		__be32 *capped;
		unsigned int i;

		capped = kunit_kcalloc(test, NFSD_MAX_OPS_PER_COMPOUND + 32,
				       sizeof(*capped), GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, capped);
		len = nfsd_ffv2_ro_compound(capped, 0);
		for (i = 3; i <= NFSD_MAX_OPS_PER_COMPOUND; i++) {
			capped[len / 4] = cpu_to_be32(OP_GETFH);
			len += 4;
		}
		capped[2] = cpu_to_be32(NFSD_MAX_OPS_PER_COMPOUND + 1);
		KUNIT_EXPECT_TRUE(test,
				  nfsd_ffv2_test_compound_decode(test, args, capped, len, len, 0));
		KUNIT_EXPECT_EQ(test, args->opcnt, NFSD_MAX_OPS_PER_COMPOUND);
		KUNIT_EXPECT_EQ(test, ctx.calls, 0U);
		KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);
		capped[2] = cpu_to_be32(NFSD_MAX_OPS_PER_COMPOUND);
		KUNIT_EXPECT_TRUE(test,
				  nfsd_ffv2_test_compound_decode(test, args, capped,
								 len - 4, len - 4, 0));
		KUNIT_EXPECT_EQ(test, ctx.calls, 1U);
		KUNIT_EXPECT_TRUE(test, args->ffv2_digest_valid);
	}
}

static void nfsd_ffv2_slot_replay_test(struct kunit *test)
{
	struct nfsd4_compoundargs *args;
	struct nfsd4_slot *slot;
	struct svc_rqst *rqstp;
	struct nfsd4_sequence seq = { .cachethis = true };
	__be32 wire[32] = {};
	u8 identity[NFSD4_FFV2_DIGEST_SIZE];
	u8 zero[NFSD4_FFV2_DIGEST_SIZE] = {};
	size_t len;
	unsigned int i;

	args = kunit_kzalloc(test, sizeof(*args), GFP_KERNEL);
	slot = kunit_kzalloc(test, sizeof(*slot), GFP_KERNEL);
	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, args);
	KUNIT_ASSERT_NOT_NULL(test, slot);
	KUNIT_ASSERT_NOT_NULL(test, rqstp);
	rqstp->rq_argp = args;
	rqstp->rq_cred.cr_uid = current_uid();
	rqstp->rq_cred.cr_gid = current_gid();
	rqstp->rq_cred.cr_group_info = get_current_groups();
	slot->sl_cred = rqstp->rq_cred;
	slot->sl_flags = NFSD4_SLOT_CACHETHIS;
	len = nfsd_ffv2_ro_compound(wire, 0);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len, len, 0));
	slot->sl_opcnt = args->opcnt;
	nfsd4_test_record_ffv2_identity(slot, args);
	memcpy(identity, slot->sl_ffv2_digest, sizeof(identity));
	KUNIT_EXPECT_TRUE(test, nfsd4_test_replay_matches_cache(rqstp, &seq, slot));
	wire[22] = cpu_to_be32(2);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len, len, 0));
	KUNIT_EXPECT_FALSE(test, nfsd4_test_replay_matches_cache(rqstp, &seq, slot));
	wire[22] = cpu_to_be32(1);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len, len, 0));
	for (i = 0; i < 5; i++) {
		if (i == 0)
			args->ffv2_present = false;
		if (i == 1)
			args->ffv2_digest_valid = false;
		if (i == 2)
			seq.cachethis = false;
		if (i == 3)
			slot->sl_opcnt++;
		if (i == 4)
			slot->sl_cred.cr_uid = make_kuid(&init_user_ns,
							 __kuid_val(current_uid()) + 1);
		KUNIT_EXPECT_FALSE_MSG(test,
				       nfsd4_test_replay_matches_cache(rqstp, &seq, slot),
			"retry mismatch %u", i);
		args->ffv2_present = true;
		args->ffv2_digest_valid = true;
		seq.cachethis = true;
		slot->sl_opcnt = args->opcnt;
		slot->sl_cred.cr_uid = current_uid();
	}
	slot->sl_ffv2_present = false;
	KUNIT_EXPECT_FALSE(test, nfsd4_test_replay_matches_cache(rqstp, &seq, slot));
	slot->sl_ffv2_present = true;
	slot->sl_opcnt--;
	KUNIT_EXPECT_FALSE(test, nfsd4_test_replay_matches_cache(rqstp, &seq, slot));
	slot->sl_status = nfserr_notsupp;
	KUNIT_EXPECT_TRUE(test, nfsd4_test_replay_matches_cache(rqstp, &seq, slot));
	slot->sl_opcnt++;
	slot->sl_status = nfs_ok;
	/* Invalid attempts cannot match or modify a retained valid identity. */
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, len - 1, len - 1, 0));
	KUNIT_EXPECT_FALSE(test, nfsd4_test_replay_matches_cache(rqstp, &seq, slot));
	KUNIT_EXPECT_MEMEQ(test, slot->sl_ffv2_digest, identity, sizeof(identity));
	wire[2] = cpu_to_be32(1);
	wire[3] = cpu_to_be32(OP_GETFH);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args,
							       wire, 16, 16, 0));
	nfsd4_test_record_ffv2_identity(slot, args);
	slot->sl_opcnt = args->opcnt;
	KUNIT_EXPECT_FALSE(test, slot->sl_ffv2_present);
	KUNIT_EXPECT_MEMEQ(test, slot->sl_ffv2_digest, zero, sizeof(zero));
	KUNIT_EXPECT_TRUE(test, nfsd4_test_replay_matches_cache(rqstp, &seq, slot));
	put_group_info(rqstp->rq_cred.cr_group_info);
}

static size_t nfsd_ffv2_wire_op(__be32 *p, u32 op)
{
	__be32 *base = p;
	unsigned int i;

	if (op == OP_BULK_REVOKE_STATEID) {
		*p++ = cpu_to_be32(0x11223344);
		*p++ = cpu_to_be32(0x55667788);
		return (u8 *)p - (u8 *)base;
	}
	for (i = 0; i < 4; i++)
		*p++ = cpu_to_be32(i + 1);
	if (op == OP_REVOKE_STATEID)
		return (u8 *)p - (u8 *)base;
	if (op == OP_TRUST_STATEID) {
		for (i = 0; i < 4; i++)
			*p++ = cpu_to_be32(i + 1);
		*p++ = 0;
		*p++ = cpu_to_be32(30);
		*p++ = 0;
		*p++ = cpu_to_be32(1);
		*p++ = cpu_to_be32(0x61000000);
		return (u8 *)p - (u8 *)base;
	}
	*p++ = 0;
	*p++ = cpu_to_be32(4096);
	if (op == OP_CHUNK_WRITE || op == OP_CHUNK_WRITE_REPAIR) {
		*p++ = cpu_to_be32(NFS_UNSTABLE);
		*p++ = cpu_to_be32(0x01234567);
		*p++ = cpu_to_be32(0x89abcdef);
		*p++ = cpu_to_be32(0x13579bdf);
		*p++ = cpu_to_be32(1);
		*p++ = cpu_to_be32(7);
		*p++ = cpu_to_be32(9);
		if (op == OP_CHUNK_WRITE) {
			*p++ = cpu_to_be32(1);
			*p++ = cpu_to_be32(1);
			*p++ = cpu_to_be32(11);
			*p++ = cpu_to_be32(13);
		}
		*p++ = cpu_to_be32(4096);
		*p++ = cpu_to_be32(1);
		*p++ = cpu_to_be32(1);
		*p++ = cpu_to_be32(1);
		*p++ = cpu_to_be32(0x5a000000);
		*p++ = cpu_to_be32(4);
		*p++ = cpu_to_be32(0xaabbccdd);
		return (u8 *)p - (u8 *)base;
	}
	*p++ = cpu_to_be32(1);
	if (op == OP_CHUNK_READ || op == OP_CHUNK_HEADER_READ)
		return (u8 *)p - (u8 *)base;
	if (op == OP_CHUNK_ERROR)
		*p++ = cpu_to_be32(10001);
	if (op == OP_CHUNK_COMMIT || op == OP_CHUNK_FINALIZE ||
	    op == OP_CHUNK_ROLLBACK)
		*p++ = cpu_to_be32(1);
	if (op == OP_CHUNK_LOCK)
		*p++ = 0;
	*p++ = cpu_to_be32(0x01234567);
	*p++ = cpu_to_be32(0x89abcdef);
	*p++ = cpu_to_be32(0x13579bdf);
	*p++ = cpu_to_be32(7);
	if (op == OP_CHUNK_LOCK)
		*p++ = 0;
	return (u8 *)p - (u8 *)base;
}

static void nfsd_ffv2_wire_profiles_test(struct kunit *test)
{
	struct nfsd4_compoundargs *args;
	struct nfsd4_compound_state *cstate;
	struct svc_rqst *rqstp;
	const struct nfsd_ffv2_op_profile *profile;
	__be32 wire[64] = {};
	size_t len;
	u32 op;

	args = kunit_kzalloc(test, sizeof(*args), GFP_KERNEL);
	cstate = kunit_kzalloc(test, sizeof(*cstate), GFP_KERNEL);
	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, args);
	KUNIT_ASSERT_NOT_NULL(test, cstate);
	KUNIT_ASSERT_NOT_NULL(test, rqstp);
	rqstp->rq_argp = args;
	wire[1] = cpu_to_be32(2);
	wire[2] = cpu_to_be32(1);
	for (op = OP_CHUNK_COMMIT; op <= OP_BULK_REVOKE_STATEID; op++) {
		wire[3] = cpu_to_be32(op);
		len = 16 + nfsd_ffv2_wire_op(wire + 4, op);
		profile = nfsd_ffv2_op_profile(op);
		KUNIT_ASSERT_NOT_NULL(test, profile);
		KUNIT_EXPECT_EQ(test, nfsd_ffv2_op_no_filehandle(op),
				op == OP_BULK_REVOKE_STATEID);
		KUNIT_EXPECT_TRUE_MSG(test,
				      nfsd_ffv2_test_compound_decode(test, args, wire, len, len, 0),
			"linear operation %u", op);
		FFV2_EXPECT_STATUS_MSG(test, args->iops[0].status, nfs_ok,
				       "linear operation %u", op);
		KUNIT_EXPECT_TRUE(test, args->ffv2_digest_valid);
		KUNIT_EXPECT_EQ(test,
				!!(args->iops[0].opdesc->op_flags & ALLOWED_WITHOUT_FH),
			profile->no_filehandle);
		if (op == OP_BULK_REVOKE_STATEID) {
			KUNIT_EXPECT_TRUE(test, args->iops[0].u.ffv2.target_present);
			KUNIT_EXPECT_EQ(test, args->iops[0].u.ffv2.target_clientid.cl_boot,
					0x11223344U);
			KUNIT_EXPECT_EQ(test, args->iops[0].u.ffv2.target_clientid.cl_id,
					0x55667788U);
		} else if (op != OP_CHUNK_READ && op != OP_CHUNK_HEADER_READ) {
			KUNIT_EXPECT_EQ(test, args->iops[0].u.ffv2.stateid.si_generation, 1U);
			if (op != OP_TRUST_STATEID && op != OP_REVOKE_STATEID) {
				KUNIT_EXPECT_TRUE(test, args->iops[0].u.ffv2.owner_present);
				KUNIT_EXPECT_EQ(test, args->iops[0].u.ffv2.owner_cohort_id,
						0x0123456789abcdefULL);
				KUNIT_EXPECT_EQ(test, args->iops[0].u.ffv2.owner_client_id,
						0x13579bdfU);
				KUNIT_EXPECT_EQ(test, args->iops[0].u.ffv2.owner_id, 7U);
			}
		}

		FFV2_EXPECT_STATUS(test, nfsd4_test_ffv2_run_op(rqstp, cstate, op,
								&args->iops[0].u), nfserr_notsupp);
		KUNIT_EXPECT_TRUE(test,
				  nfsd_ffv2_test_compound_decode(test, args, wire,
								 len, 20, len - 20));
		FFV2_EXPECT_STATUS_MSG(test, args->iops[0].status, nfs_ok,
				       "split operation %u", op);
		KUNIT_EXPECT_TRUE(test, args->ffv2_digest_valid);
		KUNIT_EXPECT_TRUE(test,
				  nfsd_ffv2_test_compound_decode(test, args, wire,
								 len - 1, len - 1, 0));
		FFV2_EXPECT_STATUS(test, args->iops[0].status, nfserr_bad_xdr);
		KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);
		FFV2_EXPECT_STATUS(test, nfsd4_test_ffv2_run_op(rqstp, cstate, op,
								&args->iops[0].u), nfserr_bad_xdr);
	}
	KUNIT_EXPECT_PTR_EQ(test, nfsd_ffv2_op_profile(77), NULL);
	KUNIT_EXPECT_PTR_EQ(test, nfsd_ffv2_op_profile(92), NULL);
}

static void nfsd_ffv2_wire_bounds_test(struct kunit *test)
{
	static const struct {
		u32 op, word, value, status;
	} cases[] = {
		{ OP_CHUNK_READ, 6, 4097, NFS4ERR_INVAL },
		{ OP_CHUNK_HEADER_READ, 6, 1025, NFS4ERR_INVAL },
		{ OP_CHUNK_LOCK, 7, 4, NFS4ERR_INVAL },
		{ OP_CHUNK_LOCK, 7, 3, NFS4ERR_INVAL },
		{ OP_CHUNK_LOCK, 7, 1, NFS4ERR_INVAL },
		{ OP_CHUNK_LOCK, 12, 2, NFS4ERR_BADXDR },
		{ OP_CHUNK_WRITE, 6, 3, NFS4ERR_BADXDR },
		{ OP_CHUNK_WRITE, 10, 0, NFS4ERR_NOTSUPP },
		{ OP_CHUNK_WRITE, 10, 4097, NFS4ERR_INVAL },
		{ OP_CHUNK_WRITE, 13, 2, NFS4ERR_INVAL },
		{ OP_CHUNK_WRITE, 14, 2, NFS4ERR_BADXDR },
		{ OP_CHUNK_WRITE, 18, 2, NFS4ERR_NOTSUPP },
		{ OP_CHUNK_WRITE, 18, 4097, NFS4ERR_INVAL },
		{ OP_CHUNK_WRITE, 20, 65, NFS4ERR_BADXDR },
		{ OP_CHUNK_WRITE, 21, 0x5a000001, NFS4ERR_BADXDR },
		{ OP_CHUNK_WRITE, 22, 4 * 1024 * 1024 + 1, NFS4ERR_INVAL },
		{ OP_CHUNK_WRITE_REPAIR, 10, 2, NFS4ERR_NOTSUPP },
		{ OP_CHUNK_WRITE_REPAIR, 14, 0, NFS4ERR_NOTSUPP },
		{ OP_CHUNK_COMMIT, 7, 0, NFS4ERR_NOTSUPP },
		{ OP_CHUNK_FINALIZE, 7, 4097, NFS4ERR_INVAL },
		{ OP_TRUST_STATEID, 11, 1025, NFS4ERR_BADXDR },
		{ OP_TRUST_STATEID, 12, 0x61000001, NFS4ERR_BADXDR },
	};
	struct nfsd4_compoundargs *args;
	struct nfsd4_compound_state *cstate;
	struct svc_rqst *rqstp;
	__be32 wire[64] = {};
	size_t len;
	unsigned int i;

	args = kunit_kzalloc(test, sizeof(*args), GFP_KERNEL);
	cstate = kunit_kzalloc(test, sizeof(*cstate), GFP_KERNEL);
	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, args);
	KUNIT_ASSERT_NOT_NULL(test, cstate);
	KUNIT_ASSERT_NOT_NULL(test, rqstp);
	rqstp->rq_argp = args;
	wire[1] = cpu_to_be32(2);
	wire[2] = cpu_to_be32(1);
	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		wire[3] = cpu_to_be32(cases[i].op);
		len = 16 + nfsd_ffv2_wire_op(wire + 4, cases[i].op);
		wire[4 + cases[i].word] = cpu_to_be32(cases[i].value);
		KUNIT_EXPECT_TRUE(test,
				  nfsd_ffv2_test_compound_decode(test, args, wire, len, len, 0));
		FFV2_EXPECT_STATUS_MSG(test, args->iops[0].status,
				       cpu_to_be32(cases[i].status), "bounds case %u", i);
		KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);
		FFV2_EXPECT_STATUS_MSG(test,
				       nfsd4_test_ffv2_run_op(rqstp, cstate, cases[i].op,
							      &args->iops[0].u),
			cpu_to_be32(cases[i].status), "saved status case %u", i);
	}
	wire[3] = cpu_to_be32(OP_CHUNK_LOCK);
	len = 16 + nfsd_ffv2_wire_op(wire + 4, OP_CHUNK_LOCK);
	wire[11] = cpu_to_be32(1);
	wire[16] = cpu_to_be32(1);
	memset((u8 *)wire + len, 0, 16);
	len += 16;
	KUNIT_EXPECT_TRUE(test,
			  nfsd_ffv2_test_compound_decode(test, args, wire, len, len, 0));
	FFV2_EXPECT_STATUS(test, args->iops[0].status, nfs_ok);
	wire[3] = cpu_to_be32(OP_CHUNK_WRITE);
	len = 16 + nfsd_ffv2_wire_op(wire + 4, OP_CHUNK_WRITE);
	wire[18] = 0;
	memmove(wire + 19, wire + 21, len - 21 * 4);
	len -= 8;
	KUNIT_EXPECT_TRUE(test,
			  nfsd_ffv2_test_compound_decode(test, args, wire, len, len, 0));
	FFV2_EXPECT_STATUS(test, args->iops[0].status, nfs_ok);
	KUNIT_EXPECT_FALSE(test, args->iops[0].u.ffv2.guard_check);
}

static void nfsd_ffv2_later_decode_error_test(struct kunit *test)
{
	struct nfsd4_compoundargs *args;
	struct nfsd4_compound_state *cstate;
	struct svc_rqst *rqstp;
	struct nfsd4_ffv2_digest_test_ctx ctx = {};
	__be32 wire[64] = {};
	size_t len;
	unsigned int i;

	args = kunit_kzalloc(test, sizeof(*args), GFP_KERNEL);
	cstate = kunit_kzalloc(test, sizeof(*cstate), GFP_KERNEL);
	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, args);
	KUNIT_ASSERT_NOT_NULL(test, cstate);
	KUNIT_ASSERT_NOT_NULL(test, rqstp);
	rqstp->rq_argp = args;
	args->ffv2_digest_test = &ctx;
	for (i = 0; i < 3; i++) {
		len = nfsd_ffv2_ro_compound(wire, 0);
		wire[2] = cpu_to_be32(4);
		wire[len / 4] = cpu_to_be32(i == 0 ? OP_GETATTR :
					  i == 1 ? OP_IO_ADVISE : OP_CHUNK_READ);
		len += 4;
		if (i == 2) {
			len += nfsd_ffv2_wire_op(wire + len / 4, OP_CHUNK_READ);
			wire[len / 4 - 1] = cpu_to_be32(4097);
		}
		KUNIT_EXPECT_TRUE(test,
				  nfsd_ffv2_test_compound_decode(test, args, wire,
								 len, 20, len - 20));
		KUNIT_EXPECT_EQ(test, ctx.calls, 0U);
		KUNIT_EXPECT_FALSE(test, args->ffv2_digest_valid);
		FFV2_EXPECT_STATUS(test,
				   nfsd4_test_ffv2_run_op(rqstp, cstate, OP_CHUNK_READ,
							  &args->iops[2].u),
			i == 0 ? nfserr_bad_xdr : i == 1 ? nfserr_notsupp : nfserr_inval);
	}
}

static void nfsd_ffv2_dispatch_precedence_test(struct kunit *test)
{
	struct nfsd4_compoundargs *args;
	struct nfsd4_compoundres *resp;
	struct nfsd_thread_local_info *ntli;
	struct svc_rqst *rqstp;
	struct svc_xprt *xprt;
	struct nfsd_net *nn;
	struct net *net;
	__be32 wire[64] = {};
	void *reply;
	size_t len;
	unsigned int i;

	args = kunit_kzalloc(test, sizeof(*args), GFP_KERNEL);
	resp = kunit_kzalloc(test, sizeof(*resp), GFP_KERNEL);
	ntli = kunit_kzalloc(test, sizeof(*ntli), GFP_KERNEL);
	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	xprt = kunit_kzalloc(test, sizeof(*xprt), GFP_KERNEL);
	reply = kunit_kzalloc(test, 1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, args);
	KUNIT_ASSERT_NOT_NULL(test, resp);
	KUNIT_ASSERT_NOT_NULL(test, ntli);
	KUNIT_ASSERT_NOT_NULL(test, rqstp);
	KUNIT_ASSERT_NOT_NULL(test, xprt);
	KUNIT_ASSERT_NOT_NULL(test, reply);
	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	KUNIT_ASSERT_FALSE(test, IS_ERR(net));
	nn = net_generic(net, nfsd_net_id);
	xprt->xpt_net = net;
	rqstp->rq_argp = args;
	rqstp->rq_resp = resp;
	rqstp->rq_private = ntli;
	rqstp->rq_xprt = xprt;
	for (i = 0; i < 3; i++) {
		memset(resp, 0, sizeof(*resp));
		wire[1] = cpu_to_be32(i == 0 ? 0 : 2);
		wire[2] = cpu_to_be32(1);
		wire[3] = cpu_to_be32(i == 0 ? OP_GETFH : OP_CHUNK_READ);
		len = i == 0 ? 16 : 16 + nfsd_ffv2_wire_op(wire + 4, OP_CHUNK_READ);
		KUNIT_EXPECT_TRUE(test,
				  nfsd_ffv2_test_compound_decode(test, args, wire, len, len, 0));
		if (i == 2)
			nn->nfsd4_minorversions[2] = false;
		xdr_buf_init(&rqstp->rq_res, reply, 1024);
		rqstp->rq_res.head[0].iov_len = 0;
		xdr_init_encode(&rqstp->rq_res_stream, &rqstp->rq_res, reply, NULL);
		nfsd4_test_dispatch_compound(rqstp);
		FFV2_EXPECT_STATUS(test, resp->cstate.status,
				   i == 0 ? nfserr_nofilehandle : i == 1 ?
			nfserr_op_not_in_session : nfserr_minor_vers_mismatch);
	}
	put_net(net);
	net_ns_barrier();
}

static void nfsd_ffv2_single_range_test(struct kunit *test)
{
	static const u32 ops[] = {
		OP_CHUNK_COMMIT, OP_CHUNK_FINALIZE, OP_CHUNK_ROLLBACK,
	};
	struct svc_rqst *rqstp;
	union nfsd4_op_u *u;
	__be32 wire[32];
	unsigned int i, count;
	size_t len, consumed;

	rqstp = kunit_kzalloc(test, sizeof(*rqstp), GFP_KERNEL);
	u = kunit_kzalloc(test, sizeof(*u), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, rqstp);
	KUNIT_ASSERT_NOT_NULL(test, u);
	for (i = 0; i < ARRAY_SIZE(ops); i++) {
		len = nfsd_ffv2_wire_op(wire, ops[i]);
		for (count = 0; count <= 2; count++) {
			wire[6] = cpu_to_be32(count);
			FFV2_EXPECT_STATUS_MSG(test,
					       nfsd4_test_decode_op(rqstp, ops[i], wire,
								    len, u, &consumed),
				count == 1 ? nfs_ok : nfserr_notsupp,
				"operation %u ranges %u", ops[i], count);
			KUNIT_EXPECT_EQ(test, consumed, len);
			if (count == 1) {
				KUNIT_EXPECT_EQ(test, u->ffv2.count, 1U);
				KUNIT_EXPECT_TRUE(test, u->ffv2.owner_present);
				KUNIT_EXPECT_EQ(test, u->ffv2.owner_cohort_id,
						0x0123456789abcdefULL);
				KUNIT_EXPECT_EQ(test, u->ffv2.owner_client_id, 0x13579bdfU);
				KUNIT_EXPECT_EQ(test, u->ffv2.owner_id, 7U);
			}
			FFV2_EXPECT_STATUS(test,
					   nfsd4_test_decode_op(rqstp, ops[i], wire,
								len - 4, u, NULL),
				nfserr_bad_xdr);
		}
		wire[6] = cpu_to_be32(4097);
		FFV2_EXPECT_STATUS(test,
				   nfsd4_test_decode_op(rqstp, ops[i], wire, len, u, NULL),
			nfserr_inval);
		wire[6] = cpu_to_be32(1);
		wire[7] = cpu_to_be32(0);
		FFV2_EXPECT_STATUS(test,
				   nfsd4_test_decode_op(rqstp, ops[i], wire, len, u, NULL),
			nfserr_notsupp);
	}
}

static struct kunit_case nfsd_ffv2_test_cases[] = {
	KUNIT_CASE(nfsd_ffv2_single_range_test),
	KUNIT_CASE(nfsd_ffv2_compound_digest_test),
	KUNIT_CASE(nfsd_ffv2_selective_digest_test),
	KUNIT_CASE(nfsd_ffv2_selective_mixed_test),
	KUNIT_CASE(nfsd_ffv2_selective_errors_test),
	KUNIT_CASE(nfsd_ffv2_slot_replay_test),
	KUNIT_CASE(nfsd_ffv2_wire_profiles_test),
	KUNIT_CASE(nfsd_ffv2_wire_bounds_test),
	KUNIT_CASE(nfsd_ffv2_later_decode_error_test),
	KUNIT_CASE(nfsd_ffv2_dispatch_precedence_test),

	KUNIT_CASE(nfsd_ffv2_codec_test),
	KUNIT_CASE(nfsd_ffv2_reservation_access_test),
	KUNIT_CASE(nfsd_ffv2_reservation_io_test),
	KUNIT_CASE(nfsd_ffv2_filecache_gate_test),
	KUNIT_CASE(nfsd_ffv2_nlm_open_refusal_test),
	KUNIT_CASE(nfsd_ffv2_export_access_test),
	KUNIT_CASE(nfsd_ffv2_lifecycle_test),
	KUNIT_CASE(nfsd_ffv2_admission_unregister_test),
	KUNIT_CASE(nfsd_ffv2_zero_threads_test),
	KUNIT_CASE(nfsd_ffv2_destroy_wait_test),
	KUNIT_CASE(nfsd_ffv2_generation_boundary_test),
	KUNIT_CASE(nfsd_ffv2_multi_retirement_test),
	KUNIT_CASE(nfsd_ffv2_service_integration_test),
	KUNIT_CASE(nfsd_ffv2_netns_integration_test),
	KUNIT_CASE(nfsd_ffv2_production_netns_integration_test),
	KUNIT_CASE(nfsd_ffv2_production_pre_exit_overlap_test),
	KUNIT_CASE(nfsd_ffv2_shutdown_start_failure_test),
	KUNIT_CASE(nfsd_ffv2_listener_only_integration_test),
	KUNIT_CASE(nfsd_ffv2_partial_start_cleanup_test),
	KUNIT_CASE(nfsd_ffv2_ordinary_export_update_test),
	KUNIT_CASE_SLOW(nfsd_ffv2_ordinary_update_drain_test),
	KUNIT_CASE(nfsd_ffv2_ordinary_export_detach_test),
	{}
};

static struct kunit_suite nfsd_ffv2_test_suite = {
	.name = "nfsd_ffv2_lifecycle",
	.test_cases = nfsd_ffv2_test_cases,
};

kunit_test_suite(nfsd_ffv2_test_suite);

MODULE_LICENSE("GPL");
