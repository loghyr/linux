// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>
#include <linux/completion.h>
#include <linux/sunrpc/gss_api.h>
#include <linux/sunrpc/auth_gss.h>
#include <net/sock.h>
#include <linux/cred.h>
#include <linux/crc32.h>
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
#include <linux/namei.h>
#include <linux/unaligned.h>
#include <linux/sunrpc/svcsock.h>
#include <linux/sunrpc/svcauth.h>
#include <linux/sunrpc/svc_xprt.h>
#include <net/net_namespace.h>

#include "ffv2.h"
#include "ffv2_trust.h"
#include "ffv2_store.h"
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
	__be32 expected;
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

		expected = op == OP_BULK_REVOKE_STATEID ? nfserr_stale : nfserr_notsupp;
		FFV2_EXPECT_STATUS(test, nfsd4_test_ffv2_run_op(rqstp, cstate, op,
								&args->iops[0].u), expected);
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

/* Synthetic session-table entries do not authenticate an on-wire client. */
struct nfsd_ffv2_registration_fixture {
	struct net *net;
	struct nfsd_net *nn;
	struct nfs4_client client;
	struct nfsd4_session session;
	struct auth_domain *domain;
	struct path root;
	struct dentry *object;
	struct fs_struct *fs;
	struct socket *reply;
	u32 port;
	u8 uuid[16];
	u8 token[32];
	struct knfsd_fh outer;
	bool service;
	bool hashed;
};

static void nfsd_ffv2_registration_fixture_exit(void *data)
{
	struct nfsd_ffv2_registration_fixture *f = data;

	if (f->reply)
		sock_release(f->reply);
	if (f->hashed)
		nfsd_ffv2_test_session_unhash(f->nn, &f->session, false);
	if (f->service)
		nfsd_shutdown_threads(f->net);
	if (f->net)
		nfsd_export_flush(f->net);
	free_svc_cred(&f->client.cl_cred);
	if (f->domain)
		auth_domain_put(f->domain);
	if (f->object) {
		d_drop(f->object);
		dput(f->object);
	}
	if (f->fs)
		free_fs_struct(f->fs);
	if (f->root.mnt) {
		dput(f->root.dentry);
		mntput(f->root.mnt);
	}
	if (f->net) {
		put_net(f->net);
		net_ns_barrier();
	}
}

static int nfsd_ffv2_registration_seed(struct nfsd_ffv2_registration_fixture *f)
{
	struct svc_export key, *exp;
	unsigned int i;
	int error = -ENOMEM;

	nfsd_ffv2_init_export_test_key(&key, f->nn, f->domain, &f->root);
	key.ex_flags = NFSEXP_NOSUBTREECHECK;
	key.ex_uuid = kmemdup(f->uuid, sizeof(f->uuid), GFP_KERNEL);
	if (!key.ex_uuid)
		return -ENOMEM;
	key.ex_fslocs.locations_count = 2;
	key.ex_fslocs.locations = kcalloc(2, sizeof(*key.ex_fslocs.locations), GFP_KERNEL);
	if (!key.ex_fslocs.locations)
		goto out_free;
	for (i = 0; i < 2; i++) {
		key.ex_fslocs.locations[i].hosts = kstrdup("mds.kunit", GFP_KERNEL);
		key.ex_fslocs.locations[i].path = kstrdup("/export", GFP_KERNEL);
		if (!key.ex_fslocs.locations[i].hosts || !key.ex_fslocs.locations[i].path)
			goto out_free;
	}
	exp = nfsd_export_cache_update(&key);
	error = IS_ERR(exp) ? PTR_ERR(exp) : 0;
	if (!IS_ERR(exp))
		exp_put(exp);
out_free:
	if (key.ex_fslocs.locations) {
		for (i = 0; i < 2; i++) {
			kfree(key.ex_fslocs.locations[i].hosts);
			kfree(key.ex_fslocs.locations[i].path);
		}
		kfree(key.ex_fslocs.locations);
	}
	kfree(key.ex_uuid);
	return error;
}

static struct nfsd_ffv2_registration_fixture *nfsd_ffv2_registration_fixture(struct kunit *test)
{
	struct nfsd_ffv2_registration_fixture *f;
	struct qstr object_name = QSTR_INIT("object", 6);
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	struct file_system_type *type;
	struct fs_struct *fs;
	int error;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return NULL;
	init_svc_cred(&f->client.cl_cred);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_registration_fixture_exit, f);
	if (error)
		return NULL;
	memset(f->uuid, 0x5a, sizeof(f->uuid));
	memset(f->token, 0xa5, sizeof(f->token));
	f->net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(f->net)) {
		f->net = NULL;
		goto fail;
	}
	f->nn = net_generic(f->net, nfsd_net_id);
	error = nfsd_ffv2_start_test_service(f->net, NULL);
	if (error)
		goto fail;
	f->service = true;
	type = get_fs_type("tmpfs");
	if (!type)
		goto fail;
	f->root.mnt = vfs_kern_mount(type, SB_KERNMOUNT, "ffv2-kunit", NULL);
	put_filesystem(type);
	if (IS_ERR(f->root.mnt)) {
		f->root.mnt = NULL;
		goto fail;
	}
	f->root.dentry = dget(f->root.mnt->mnt_root);
	fs = copy_fs_struct(current->fs);
	if (!fs)
		goto fail;
	set_fs_root(fs, &f->root);
	set_fs_pwd(fs, &f->root);
	f->fs = fs;
	error = mnt_want_write(f->root.mnt);
	if (error)
		goto fail;
	inode_lock(d_inode(f->root.dentry));
	f->object = lookup_one(mnt_idmap(f->root.mnt), &object_name, f->root.dentry);
	if (IS_ERR(f->object)) {
		error = PTR_ERR(f->object);
		f->object = NULL;
	} else {
		error = vfs_create(mnt_idmap(f->root.mnt), f->object, 0600, NULL);
	}
	inode_unlock(d_inode(f->root.dentry));
	mnt_drop_write(f->root.mnt);
	if (error)
		goto fail;
	f->domain = unix_domain_find("ffv2-registration-kunit");
	if (!f->domain)
		goto fail;
	error = nfsd_ffv2_registration_seed(f);
	if (error)
		goto fail;
	f->client.net = f->net;
	f->client.cl_minorversion = 2;
	f->client.cl_exchange_flags = EXCHGID4_FLAG_USE_PNFS_MDS;
	f->client.cl_mach_cred = true;
	f->client.cl_time = 1;
	f->client.cl_state = NFSD4_ACTIVE;
	atomic_set(&f->client.cl_rpc_users, 1);
	spin_lock_init(&f->client.cl_lock);
	INIT_LIST_HEAD(&f->client.cl_lru);
	INIT_LIST_HEAD(&f->client.cl_idhash);
	INIT_LIST_HEAD(&f->client.cl_sessions);
	f->client.cl_cred.cr_flavor = RPC_AUTH_GSS_KRB5I;
	f->client.cl_cred.cr_gss_mech = gss_mech_get_by_name("krb5");
	f->client.cl_cred.cr_group_info = groups_alloc(0);
	f->client.cl_cred.cr_principal = kstrdup("nfs/mds@KUNIT", GFP_KERNEL);
	f->client.cl_cred.cr_raw_principal = kstrdup("nfs/mds@KUNIT", GFP_KERNEL);
	f->client.cl_cred.cr_targ_princ = kstrdup("nfs/ds@KUNIT", GFP_KERNEL);
	if (!f->client.cl_cred.cr_gss_mech || !f->client.cl_cred.cr_group_info ||
	    !f->client.cl_cred.cr_principal || !f->client.cl_cred.cr_raw_principal ||
	    !f->client.cl_cred.cr_targ_princ)
		goto fail;
	f->session.se_client = &f->client;
	memset(f->session.se_sessionid.data, 0x73, NFS4_MAX_SESSIONID_LEN);
	put_unaligned_be32(f->net->ns.inum, f->session.se_sessionid.data + 12);
	atomic_set(&f->session.se_ref, 1);
	INIT_LIST_HEAD(&f->session.se_hash);
	INIT_LIST_HEAD(&f->session.se_perclnt);
	INIT_LIST_HEAD(&f->session.se_all_sessions);
	nfsd_ffv2_session_init(&f->session);
	nfsd_ffv2_test_session_hash(f->nn, &f->session);
	f->hashed = true;
	/* A real receiving endpoint lets genlmsg_reply retain its own contract. */
	error = __sock_create(f->net, AF_NETLINK, SOCK_RAW, NETLINK_GENERIC, &f->reply, 0);
	if (error)
		goto fail;
	error = kernel_bind(f->reply, (struct sockaddr_unsized *)&addr, sizeof(addr));
	if (error)
		goto fail;
	error = kernel_getsockname(f->reply, (struct sockaddr *)&addr);
	if (error < 0)
		goto fail;
	f->port = addr.nl_pid;
	return f;
fail:
	KUNIT_FAIL(test, "ordinary registration fixture failed: %d", error);
	return NULL;
}

static int nfsd_ffv2_registration_call(struct nfsd_ffv2_registration_fixture *f, bool unregister,
				       u64 *generation)
{
	struct nlattr *attrs[NFSD_A_FFV2_OBJECT_MAX + 1] = {};
	struct genl_info info = {
		.attrs = attrs, .family = &nfsd_nl_family, .snd_portid = f->port, .snd_seq = 23
	};
	struct msghdr msg = {};
	struct kvec vec;
	struct sk_buff *skb;
	struct fs_struct *saved_fs;
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct nlattr *attr;
	char buffer[512];
	void *header;
	int error, remaining;

	skb = genlmsg_new(512, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;
	header = genlmsg_put(skb, f->port, 23, &nfsd_nl_family, 0,
			     unregister ? NFSD_CMD_FFV2_OBJECT_UNREGISTER :
					  NFSD_CMD_FFV2_OBJECT_REGISTER);
	if (!header) {
		error = -ENOMEM;
		goto out;
	}
	if (nla_put(skb, NFSD_A_FFV2_OBJECT_OBJECT_UUID, 16, f->uuid))
		goto too_big;
	if (unregister) {
		if (nla_put_u64_64bit(skb, NFSD_A_FFV2_OBJECT_GENERATION, *generation, 0))
			goto too_big;
	} else if (nla_put_string(skb, NFSD_A_FFV2_OBJECT_AUTH_DOMAIN, f->domain->name) ||
		   nla_put_string(skb, NFSD_A_FFV2_OBJECT_EXPORT_PATH, "/") ||
		   nla_put_string(skb, NFSD_A_FFV2_OBJECT_OBJECT_PATH, "/object") ||
		   nla_put(skb, NFSD_A_FFV2_OBJECT_STORE_UUID, 16, f->uuid) ||
		   nla_put(skb, NFSD_A_FFV2_OBJECT_BINDING_TOKEN, 32, f->token) ||
		   nla_put_u64_64bit(skb, NFSD_A_FFV2_OBJECT_CONTROL_ROOT, 47, 0) ||
		   nla_put(skb, NFSD_A_FFV2_OBJECT_MDS_SESSIONID, 16,
			   f->session.se_sessionid.data)) {
		goto too_big;
	}
	genlmsg_end(skb, header);
	info.nlhdr = nlmsg_hdr(skb);
	info.genlhdr = nlmsg_data(info.nlhdr);
	genl_info_net_set(&info, f->net);
	nla_for_each_attr(attr, genlmsg_data(info.genlhdr), genlmsg_len(info.genlhdr), remaining)
		if (nla_type(attr) <= NFSD_A_FFV2_OBJECT_MAX)
			attrs[nla_type(attr)] = attr;
	task_lock(current);
	saved_fs = current->fs;
	current->fs = f->fs;
	task_unlock(current);
	error = unregister ? nfsd_nl_ffv2_object_unregister_doit(skb, &info) :
			     nfsd_nl_ffv2_object_register_doit(skb, &info);
	task_lock(current);
	current->fs = saved_fs;
	task_unlock(current);
	if (error || unregister)
		goto out;
	vec.iov_base = buffer;
	vec.iov_len = sizeof(buffer);
	error = kernel_recvmsg(f->reply, &msg, &vec, 1, sizeof(buffer), MSG_DONTWAIT);
	if (error < 0)
		goto out;
	nlh = (struct nlmsghdr *)buffer;
	genl = nlmsg_data(nlh);
	attr = nla_find(genlmsg_data(genl), genlmsg_len(genl), NFSD_A_FFV2_OBJECT_GENERATION);
	if (!attr) {
		error = -EBADMSG;
		goto out;
	}
	*generation = nla_get_u64(attr);
	attr = nla_find(genlmsg_data(genl), genlmsg_len(genl), NFSD_A_FFV2_OBJECT_FILEHANDLE);
	if (!attr || nla_len(attr) < NFSD_FFV2_FH_HEADER_SIZE) {
		error = -EBADMSG;
		goto out;
	}
	f->outer.fh_size = nla_len(attr);
	memcpy(f->outer.fh_raw, nla_data(attr), nla_len(attr));
	error = 0;
	goto out;
too_big:
	error = -EMSGSIZE;
out:
	nlmsg_free(skb);
	return error;
}

static void nfsd_ffv2_ordinary_registration_test(struct kunit *test)
{
	struct nfsd_ffv2_registration_fixture *f;
	struct nfsd_ffv2_export_update second;
	struct svc_export key, *replacement;
	struct nfsd_ffv2_admission admission = {};
	u64 generation = 0, stale;
	int error;

	f = nfsd_ffv2_registration_fixture(test);
	if (!f)
		return;
	error = nfsd_ffv2_registration_call(f, false, &generation);
	KUNIT_ASSERT_EQ(test, error, 0);
	KUNIT_EXPECT_GT(test, generation, 0ULL);
	KUNIT_EXPECT_FALSE(test, f->nn->ffv2.registration_pending);
	KUNIT_EXPECT_PTR_EQ(test, f->nn->ffv2.pending, NULL);
	KUNIT_EXPECT_TRUE(test, f->nn->ffv2.source);
	KUNIT_EXPECT_EQ(test, f->nn->ffv2_participant.update_count, 0U);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->nn->ffv2.test_registration.contexts), 1);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->nn->ffv2.test_registration.authorities), 1);
	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_registration_begin(f->nn, &second);
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, error, -EBUSY);
	nfsd_ffv2_init_export_test_key(&key, f->nn, f->domain, &f->root);
	set_bit(CACHE_NEGATIVE, &key.h.flags);
	replacement = nfsd_export_cache_update(&key);
	error = IS_ERR(replacement) ? PTR_ERR(replacement) : 0;
	if (!IS_ERR(replacement))
		exp_put(replacement);
	KUNIT_ASSERT_EQ(test, error, -EAGAIN);
	stale = generation + 1;
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_registration_call(f, true, &stale), -ENOENT);
	f->uuid[0] ^= 1;
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_registration_call(f, true, &generation), -ENOENT);
	f->uuid[0] ^= 1;
	nfsd_ffv2_test_wrong_unregister_kind(f->nn, true);
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_registration_call(f, true, &generation), -ENOENT);
	nfsd_ffv2_test_wrong_unregister_kind(f->nn, false);
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_test_admit(f->nn, &admission), 0);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_registration_call(f, true, &generation), -EDEADLK);
	nfsd_ffv2_complete(&admission);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_registration_call(f, true, &generation), 0);
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_registration_call(f, true, &generation), -ENOENT);
	KUNIT_EXPECT_FALSE(test, f->nn->ffv2.source);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->nn->ffv2.test_registration.contexts), 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->nn->ffv2.test_registration.authorities), 0);
}

static void
nfsd_ffv2_registration_unwound(struct kunit *test, struct nfsd_ffv2_registration_fixture *f)
{
	KUNIT_EXPECT_FALSE(test, f->nn->ffv2.source);
	KUNIT_EXPECT_FALSE(test, f->nn->ffv2.registration_pending);
	KUNIT_EXPECT_PTR_EQ(test, f->nn->ffv2.pending, NULL);
	KUNIT_EXPECT_PTR_EQ(test, f->nn->ffv2.active, NULL);
	KUNIT_EXPECT_PTR_EQ(test, f->nn->ffv2.retiring, NULL);
	KUNIT_EXPECT_EQ(test, f->nn->ffv2_participant.update_count, 0U);
	KUNIT_EXPECT_TRUE(test, list_empty(&f->session.se_ffv2_authorities));
	KUNIT_EXPECT_TRUE(test, list_empty(&f->nn->ffv2_participant.reservations));
	KUNIT_EXPECT_EQ(test, atomic_read(&f->nn->ffv2.test_registration.contexts), 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->nn->ffv2.test_registration.registries), 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->nn->ffv2.test_registration.authorities), 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->session.se_ref), 1);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->client.cl_rpc_users), 1);
}

static void nfsd_ffv2_registration_faults_test(struct kunit *test)
{
	struct nfsd_ffv2_registration_fixture *f;
	struct nfsd_ffv2_registration_test *trace;
	enum nfsd_ffv2_test_registration_fault phase;
	u64 generation;
	int error;

	f = nfsd_ffv2_registration_fixture(test);
	if (!f)
		return;
	trace = &f->nn->ffv2.test_registration;
	for (phase = NFSD_FFV2_TEST_OBJECT_ALLOC; phase <= NFSD_FFV2_TEST_REPLY_SEND; phase++) {
		generation = 0;
		atomic_set(&trace->fault, phase);
		error = nfsd_ffv2_registration_call(f, false, &generation);
		KUNIT_EXPECT_LT_MSG(test, error, 0, "phase %u", phase);
		KUNIT_EXPECT_EQ_MSG(test, atomic_read(&trace->hit), phase,
				    "phase %u was not reached", phase);
		nfsd_ffv2_registration_unwound(test, f);
		if (phase == NFSD_FFV2_TEST_EXACT_REPLACE)
			KUNIT_EXPECT_EQ(test, atomic_read(&trace->published_refusals), 1);
		if (phase == NFSD_FFV2_TEST_REPLY_SEND)
			KUNIT_EXPECT_EQ(test,
					atomic_read(&trace->reply_consumed),
					1);
		/* The synthetic session remains owned and can be made live again. */
		f->session.se_dead = false;
		if (phase == NFSD_FFV2_TEST_REPLY_BUILD || phase == NFSD_FFV2_TEST_REPLY_SEND)
			KUNIT_ASSERT_EQ(test, nfsd_ffv2_registration_seed(f), 0);
		error = nfsd_ffv2_registration_call(f, false, &generation);
		KUNIT_ASSERT_EQ_MSG(test, error, 0, "phase %u retry", phase);
		KUNIT_ASSERT_EQ(test, nfsd_ffv2_registration_call(f, true, &generation), 0);
		nfsd_ffv2_registration_unwound(test, f);
		KUNIT_ASSERT_EQ(test, nfsd_ffv2_registration_seed(f), 0);
	}
}

static void nfsd_ffv2_registration_authority_test(struct kunit *test)
{
	struct nfsd_ffv2_registration_fixture *f, *other;
	struct nfsd_ffv2_export_update registration;
	struct gss_api_mech *mech;
	char *principal, *raw;
	u8 unknown[16] = {};
	u64 generation = 0;
	int error, i;

	f = nfsd_ffv2_registration_fixture(test);
	if (!f)
		return;
	other = nfsd_ffv2_registration_fixture(test);
	if (!other)
		return;
	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_registration_begin(f->nn, &registration);
	mutex_unlock(&nfsd_mutex);
	KUNIT_ASSERT_EQ(test, error, 0);
	error = nfsd_ffv2_authority_register(f->nn, f->net, unknown,
					     &registration.authority);
	KUNIT_EXPECT_EQ(test, error, -ENOENT);
	error = nfsd_ffv2_authority_register(f->nn, f->net,
					     other->session.se_sessionid.data,
					     &registration.authority);
	KUNIT_EXPECT_EQ(test, error, -ENOENT);
	nfsd_ffv2_registration_end(f->nn, &registration);
	for (i = 0; i < 6; i++) {
		principal = f->client.cl_cred.cr_principal;
		raw = f->client.cl_cred.cr_raw_principal;
		mech = f->client.cl_cred.cr_gss_mech;
		switch (i) {
		case 0:
			f->client.cl_minorversion = 0;
			break;
		case 1:
			f->client.cl_exchange_flags = 0;
			break;
		case 2:
			f->client.cl_mach_cred = false;
			break;
		case 3:
			f->client.cl_cred.cr_gss_mech = NULL;
			break;
		case 4:
			f->client.cl_cred.cr_flavor = RPC_AUTH_GSS_KRB5;
			break;
		case 5:
			f->client.cl_cred.cr_principal = NULL;
			f->client.cl_cred.cr_raw_principal = NULL;
			break;
		}
		KUNIT_EXPECT_EQ_MSG(test, nfsd_ffv2_registration_call(f, false, &generation),
				    -EACCES, "qualification %d", i);
		f->client.cl_minorversion = 2;
		f->client.cl_exchange_flags = EXCHGID4_FLAG_USE_PNFS_MDS;
		f->client.cl_mach_cred = true;
		f->client.cl_cred.cr_gss_mech = mech;
		f->client.cl_cred.cr_flavor = RPC_AUTH_GSS_KRB5I;
		f->client.cl_cred.cr_principal = principal;
		f->client.cl_cred.cr_raw_principal = raw;
		nfsd_ffv2_registration_unwound(test, f);
	}
	f->session.se_dead = true;
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_registration_call(f, false, &generation), -ENOENT);
	f->session.se_dead = false;
	f->nn->ffv2.next_authority_epoch = 0;
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_registration_call(f, false, &generation), -EOVERFLOW);
	f->nn->ffv2.next_authority_epoch = U64_MAX;
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_registration_call(f, false, &generation), -EOVERFLOW);
	nfsd_ffv2_registration_unwound(test, f);
	f->nn->ffv2.next_authority_epoch = U64_MAX - 1;
	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_registration_begin(f->nn, &registration);
	mutex_unlock(&nfsd_mutex);
	KUNIT_ASSERT_EQ(test, error, 0);
	error = nfsd_ffv2_authority_register(f->nn, f->net, f->session.se_sessionid.data,
					     &registration.authority);
	KUNIT_EXPECT_EQ(test, error, 0);
	if (!error) {
		KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_authority_copy(registration.authority,
								      &f->client.cl_cred));
		KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_authority_state(registration.authority), 0);
	}
	nfsd_ffv2_registration_end(f->nn, &registration);
	KUNIT_EXPECT_EQ(test, f->nn->ffv2.next_authority_epoch, U64_MAX);
	nfsd_ffv2_registration_unwound(test, f);
}

struct nfsd_ffv2_object_retire_ctx {
	struct nfsd_ffv2_registration_fixture *fixture;
	u64 generation;
	struct completion done;
	int error;
};

static int nfsd_ffv2_object_retire_thread(void *arg)
{
	struct nfsd_ffv2_object_retire_ctx *ctx = arg;

	ctx->error = nfsd_ffv2_registration_call(ctx->fixture, true, &ctx->generation);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static void nfsd_ffv2_registration_drain_test(struct kunit *test)
{
	struct nfsd_ffv2_registration_fixture *f;
	struct nfsd_ffv2_object_retire_ctx ctx = {};
	struct svc_export *held;
	struct task_struct *task;
	void *entry;
	bool waiting;
	int error;

	f = nfsd_ffv2_registration_fixture(test);
	if (!f)
		return;
	ctx.fixture = f;
	init_completion(&ctx.done);
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_registration_call(f, false, &ctx.generation), 0);
	entry = nfsd_ffv2_test_trust_hold(f->nn);
	KUNIT_ASSERT_NOT_NULL(test, entry);
	held = nfsd_ffv2_export_lookup(f->nn->svc_export_cache, f->domain, &f->root);
	if (IS_ERR(held)) {
		nfsd_ffv2_test_trust_put(entry);
		KUNIT_FAIL(test, "hold published export: %ld", PTR_ERR(held));
		return;
	}
	task = kthread_run(nfsd_ffv2_object_retire_thread, &ctx, "ffv2-object-retire");
	if (IS_ERR(task)) {
		exp_put(held);
		nfsd_ffv2_test_trust_put(entry);
		KUNIT_FAIL(test, "start retirement: %ld", PTR_ERR(task));
		return;
	}
	error = read_poll_timeout(nfsd_ffv2_test_export_waiting, waiting, waiting, 10, USEC_PER_SEC,
				  false, held);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_FALSE(test, completion_done(&ctx.done));
	exp_put(held);
	error = read_poll_timeout(nfsd_ffv2_test_trust_waiting, waiting, waiting, 10, USEC_PER_SEC,
				  false, entry);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_FALSE(test, completion_done(&ctx.done));
	nfsd_ffv2_test_trust_put(entry);
	KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&ctx.done, 5 * HZ), 0UL);
	kthread_stop(task);
	KUNIT_EXPECT_EQ(test, ctx.error, 0);
	nfsd_ffv2_registration_unwound(test, f);
}

static void nfsd_ffv2_export_completion_test(struct kunit *test)
{
	struct svc_export *exp;
	struct completion released;

	exp = kunit_kzalloc(test, sizeof(*exp), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, exp);
	init_completion(&released);
	exp->ex_ffv2_context_released = &released;
	nfsd_ffv2_export_release(exp);
	KUNIT_EXPECT_TRUE(test, completion_done(&released));
}

struct nfsd_ffv2_registration_race {
	struct nfsd_ffv2_registration_fixture *f;
	struct nfsd_ffv2_generation *generation;
	u64 id;
	struct completion done;
	int error;
};

static int nfsd_ffv2_register_thread(void *data)
{
	struct nfsd_ffv2_registration_race *ctx = data;

	ctx->error = nfsd_ffv2_registration_call(ctx->f, false, &ctx->id);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static int nfsd_ffv2_registration_stop_thread(void *data)
{
	struct nfsd_ffv2_registration_race *ctx = data;

	nfsd_ffv2_service_stop_finish(ctx->f->nn, ctx->generation);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static void nfsd_ffv2_registration_overlap_test(struct kunit *test)
{
	struct nfsd_ffv2_registration_fixture *f;
	struct nfsd_ffv2_registration_race reg = {}, stop = {};
	struct task_struct *publisher, *drainer = NULL;
	struct completion entered, resume;
	bool waiting;
	int error;

	f = nfsd_ffv2_registration_fixture(test);
	if (!f)
		return;
	init_completion(&entered);
	init_completion(&resume);
	init_completion(&reg.done);
	init_completion(&stop.done);
	reg.f = f;
	stop.f = f;
	WRITE_ONCE(f->nn->ffv2.test_registration.before_publish, &entered);
	WRITE_ONCE(f->nn->ffv2.test_registration.publish_continue, &resume);
	publisher = kthread_run(nfsd_ffv2_register_thread, &reg, "ffv2-register-race");
	if (IS_ERR(publisher)) {
		KUNIT_FAIL(test, "start publisher: %ld", PTR_ERR(publisher));
		goto out_hooks;
	}
	if (!wait_for_completion_timeout(&entered, 5 * HZ)) {
		KUNIT_FAIL(test, "registration did not reach publication");
		goto out_publisher;
	}
	/* Session death wins before the production publication leaf lock. */
	nfsd_ffv2_test_session_unhash(f->nn, &f->session, false);
	f->hashed = false;
	mutex_lock(&nfsd_mutex);
	stop.generation = nfsd_ffv2_service_stop_begin(f->nn);
	mutex_unlock(&nfsd_mutex);
	drainer = kthread_run(nfsd_ffv2_registration_stop_thread, &stop, "ffv2-registration-drain");
	if (IS_ERR(drainer)) {
		drainer = NULL;
		KUNIT_FAIL(test, "start update drainer");
		goto out_publisher;
	}
	error = read_poll_timeout(nfsd_ffv2_update_waiting, waiting, waiting, 10, USEC_PER_SEC,
				  false, f->nn);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_FALSE(test, completion_done(&stop.done));
out_publisher:
	complete_all(&resume);
	KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&reg.done, 5 * HZ), 0UL);
	kthread_stop(publisher);
	if (drainer) {
		KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&stop.done, 5 * HZ), 0UL);
		kthread_stop(drainer);
		KUNIT_EXPECT_EQ(test, reg.error, -ESHUTDOWN);
	}
	nfsd_ffv2_registration_unwound(test, f);
out_hooks:
	WRITE_ONCE(f->nn->ffv2.test_registration.before_publish, NULL);
	WRITE_ONCE(f->nn->ffv2.test_registration.publish_continue, NULL);
}

static void nfsd_ffv2_registration_close_test(struct kunit *test)
{
	struct nfsd_ffv2_registration_fixture *f;
	struct nfsd_ffv2_registration_race reg;
	struct nfsd_ffv2_exit_ctx exit_ctx;
	struct task_struct *publisher, *exiter;
	struct completion entered, resume;
	bool waiting;
	int error, mode;

	for (mode = 0; mode < 2; mode++) {
		f = nfsd_ffv2_registration_fixture(test);
		if (!f)
			return;
		memset(&reg, 0, sizeof(reg));
		reg.f = f;
		init_completion(&reg.done);
		init_completion(&exit_ctx.done);
		exit_ctx.nn = f->nn;
		init_completion(&entered);
		init_completion(&resume);
		exiter = NULL;
		WRITE_ONCE(f->nn->ffv2.test_registration.before_publish, &entered);
		WRITE_ONCE(f->nn->ffv2.test_registration.publish_continue, &resume);
		publisher = kthread_run(nfsd_ffv2_register_thread, &reg, "ffv2-registration-close");
		if (IS_ERR(publisher)) {
			KUNIT_FAIL(test, "start close-race publisher");
			goto out_hooks;
		}
		if (!wait_for_completion_timeout(&entered, 5 * HZ)) {
			KUNIT_FAIL(test, "close-race publication not reached");
			goto out_publisher;
		}
		if (!mode) {
			nfsd_ffv2_test_session_unhash(f->nn, &f->session, false);
			f->hashed = false;
		} else {
			exiter = kthread_run(nfsd_ffv2_exit_thread, &exit_ctx,
					     "ffv2-registration-exit");
			if (IS_ERR(exiter)) {
				exiter = NULL;
				KUNIT_FAIL(test, "start namespace-exit worker");
				goto out_publisher;
			}
			error = read_poll_timeout(nfsd_ffv2_update_waiting, waiting, waiting, 10,
						  USEC_PER_SEC, false, f->nn);
			KUNIT_EXPECT_EQ(test, error, 0);
			KUNIT_EXPECT_FALSE(test, completion_done(&exit_ctx.done));
		}
out_publisher:
		complete_all(&resume);
		KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&reg.done, 5 * HZ), 0UL);
		kthread_stop(publisher);
		if (exiter) {
			KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&exit_ctx.done, 5 * HZ),
					0UL);
			kthread_stop(exiter);
		}
		KUNIT_EXPECT_EQ(test, reg.error, mode ? -ESHUTDOWN : -ENOENT);
		nfsd_ffv2_registration_unwound(test, f);
out_hooks:
		WRITE_ONCE(f->nn->ffv2.test_registration.before_publish, NULL);
		WRITE_ONCE(f->nn->ffv2.test_registration.publish_continue, NULL);
		kunit_release_action(test, nfsd_ffv2_registration_fixture_exit, f);
	}
}

static void nfsd_ffv2_registration_work_test(struct kunit *test)
{
	struct nfsd_ffv2_registration_fixture *f;
	struct completion entered, resume;
	u64 generation = 0, replacement = 0;
	unsigned int count;
	int error;

	f = nfsd_ffv2_registration_fixture(test);
	if (!f)
		return;
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_registration_call(f, false, &generation), 0);
	init_completion(&entered);
	init_completion(&resume);
	WRITE_ONCE(f->nn->ffv2.test_registration.work_entered, &entered);
	WRITE_ONCE(f->nn->ffv2.test_registration.work_continue, &resume);
	/* The client-expiry route also takes the global session-list lock. */
	nfsd_ffv2_test_session_unhash(f->nn, &f->session, true);
	f->hashed = false;
	if (!wait_for_completion_timeout(&entered, 5 * HZ)) {
		KUNIT_FAIL(test, "session expiry did not queue counted retirement");
		goto out_work;
	}
	KUNIT_EXPECT_EQ(test, f->nn->ffv2.authority_work, 1U);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_registration_call(f, true, &generation), 0);
	KUNIT_EXPECT_FALSE(test, f->nn->ffv2.source);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->nn->ffv2.test_registration.authorities), 1);
	/* The synthetic producer supplies a new live locator and client epoch. */
	f->session.se_dead = false;
	f->session.se_sessionid.data[0]++;
	f->client.cl_time = 1;
	nfsd_ffv2_test_session_hash(f->nn, &f->session);
	f->hashed = true;
	error = nfsd_ffv2_registration_seed(f);
	if (!error)
		error = nfsd_ffv2_registration_call(f, false, &replacement);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_GT(test, replacement, generation);
out_work:
	complete_all(&resume);
	error = read_poll_timeout(READ_ONCE, count, count == 0, 10, USEC_PER_SEC, false,
				  f->nn->ffv2.authority_work);
	KUNIT_EXPECT_EQ(test, error, 0);
	/* Join the worker's final critical section before unarming its storage. */
	nfsd_ffv2_test_work_drain(f->nn);
	WRITE_ONCE(f->nn->ffv2.test_registration.work_entered, NULL);
	WRITE_ONCE(f->nn->ffv2.test_registration.work_continue, NULL);
	if (replacement) {
		KUNIT_EXPECT_PTR_NE(test, f->nn->ffv2.active, NULL);
		KUNIT_EXPECT_EQ(test, nfsd_ffv2_registration_call(f, true, &replacement), 0);
	}
	nfsd_ffv2_registration_unwound(test, f);
}

static void nfsd_ffv2_registration_work_failure_test(struct kunit *test)
{
	struct nfsd_ffv2_registration_fixture *f;
	u64 generation = 0;

	f = nfsd_ffv2_registration_fixture(test);
	if (!f)
		return;
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_registration_call(f, false, &generation), 0);
	atomic_set(&f->nn->ffv2.test_registration.fault, NFSD_FFV2_TEST_WORK_ALLOC);
	nfsd_ffv2_test_session_unhash(f->nn, &f->session, false);
	f->hashed = false;
	KUNIT_EXPECT_EQ(test, atomic_read(&f->nn->ffv2.test_registration.hit),
			NFSD_FFV2_TEST_WORK_ALLOC);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_active_authority_state(f->nn), 2);
	KUNIT_EXPECT_EQ(test, f->nn->ffv2.authority_work, 0U);
	KUNIT_EXPECT_PTR_NE(test, f->nn->ffv2.active, NULL);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_registration_call(f, true, &generation), 0);
	nfsd_ffv2_registration_unwound(test, f);
}

static void nfsd_ffv2_registration_work_exit_test(struct kunit *test)
{
	struct nfsd_ffv2_registration_fixture *f;
	struct nfsd_ffv2_exit_ctx exit_ctx;
	struct completion entered, resume;
	struct task_struct *exiter = NULL;
	u64 generation = 0;
	bool waiting;
	int error;

	f = nfsd_ffv2_registration_fixture(test);
	if (!f)
		return;
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_registration_call(f, false, &generation), 0);
	init_completion(&entered);
	init_completion(&resume);
	init_completion(&exit_ctx.done);
	exit_ctx.nn = f->nn;
	WRITE_ONCE(f->nn->ffv2.test_registration.work_entered, &entered);
	WRITE_ONCE(f->nn->ffv2.test_registration.work_continue, &resume);
	nfsd_ffv2_test_session_unhash(f->nn, &f->session, false);
	f->hashed = false;
	if (!wait_for_completion_timeout(&entered, 5 * HZ)) {
		KUNIT_FAIL(test, "retirement worker did not reach its owned barrier");
		goto out_release;
	}
	exiter = kthread_run(nfsd_ffv2_exit_thread, &exit_ctx, "ffv2-work-net-exit");
	if (IS_ERR(exiter)) {
		exiter = NULL;
		KUNIT_FAIL(test, "start namespace exit with queued work");
		goto out_release;
	}
	error = read_poll_timeout(nfsd_ffv2_test_work_waiting, waiting, waiting,
				  10, USEC_PER_SEC, false, f->nn);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_FALSE(test, completion_done(&exit_ctx.done));
	KUNIT_EXPECT_EQ(test, f->nn->ffv2.authority_work, 1U);
out_release:
	complete_all(&resume);
	nfsd_ffv2_test_work_drain(f->nn);
	if (exiter) {
		KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&exit_ctx.done, 5 * HZ), 0UL);
		kthread_stop(exiter);
	}
	WRITE_ONCE(f->nn->ffv2.test_registration.work_entered, NULL);
	WRITE_ONCE(f->nn->ffv2.test_registration.work_continue, NULL);
	nfsd_ffv2_registration_unwound(test, f);
}

/* Cache/session inputs are fixtures; handle decoding and policy are production. */
struct nfsd_ffv2_mapping_fixture {
	struct nfsd_ffv2_registration_fixture *registration;
	struct svc_rqst rqst;
	struct svc_xprt xprt;
	struct nfsd4_compoundargs args;
	struct nfsd4_compound_state cstate;
	u64 generation;
};

static void nfsd_ffv2_mapping_exit(void *data)
{
	struct nfsd_ffv2_mapping_fixture *m = data;

	fh_put(&m->cstate.current_fh);
	fh_put(&m->cstate.save_fh);
	put_cred(revert_creds(get_cred(current_real_cred())));
}

static int nfsd_ffv2_mapping_key_inner(struct nfsd_ffv2_registration_fixture *f,
				       const struct knfsd_fh *inner)
{
	struct fs_struct *saved;
	char message[256];
	int len, error;

	len = scnprintf(message, sizeof(message), "%s %u \\x%*phN %llu /\n",
			f->domain->name, inner->fh_fsid_type,
			key_len(inner->fh_fsid_type), fh_fsid(inner),
			(unsigned long long)ktime_get_real_seconds() + 3600);
	task_lock(current);
	saved = current->fs;
	current->fs = f->fs;
	task_unlock(current);
	error = f->nn->svc_expkey_cache->cache_parse(f->nn->svc_expkey_cache, message, len);
	task_lock(current);
	current->fs = saved;
	task_unlock(current);
	return error;
}

static int nfsd_ffv2_mapping_key(struct nfsd_ffv2_registration_fixture *f)
{
	struct nfsd_ffv2_fh_info info;
	struct knfsd_fh inner = {};
	int error;

	error = nfsd_ffv2_fh_parse(&f->outer, &info);
	if (error)
		return error;
	inner.fh_size = info.inner_len;
	memcpy(inner.fh_raw, info.inner, info.inner_len);
	return nfsd_ffv2_mapping_key_inner(f, &inner);
}

static struct nfsd_ffv2_mapping_fixture *nfsd_ffv2_mapping_fixture(struct kunit *test)
{
	static struct svc_xprt_class xcl = { .xcl_max_payload = RPCSVC_MAXPAYLOAD_TCP };
	struct nfsd_ffv2_mapping_fixture *m;
	struct nfsd_ffv2_registration_fixture *f;
	int error;

	m = kunit_kzalloc(test, sizeof(*m), GFP_KERNEL);
	if (!m)
		return NULL;
	f = nfsd_ffv2_registration_fixture(test);
	if (!f)
		return NULL;
	m->registration = f;
	if (kunit_add_action_or_reset(test, nfsd_ffv2_mapping_exit, m))
		return NULL;
	error = nfsd_ffv2_registration_call(f, false, &m->generation);
	if (!error)
		error = nfsd_ffv2_mapping_key(f);
	if (error) {
		KUNIT_FAIL(test, "registered mapping inputs: %d", error);
		return NULL;
	}
	m->xprt.xpt_net = f->net;
	m->xprt.xpt_class = &xcl;
	m->rqst.rq_xprt = &m->xprt;
	m->rqst.rq_client = f->domain;
	m->rqst.rq_cred.cr_flavor = RPC_AUTH_UNIX;
	m->rqst.rq_cred.cr_uid = GLOBAL_ROOT_UID;
	m->rqst.rq_cred.cr_gid = GLOBAL_ROOT_GID;
	m->rqst.rq_cred.cr_group_info = f->client.cl_cred.cr_group_info;
	m->rqst.rq_argp = &m->args;
	m->rqst.rq_vers = 4;
	set_bit(RQ_SECURE, &m->rqst.rq_flags);
	m->args.ffv2_digest_valid = true;
	fh_init(&m->cstate.current_fh, NFS4_FHSIZE);
	fh_init(&m->cstate.save_fh, NFS4_FHSIZE);
	return m;
}

static __be32 nfsd_ffv2_mapping_putfh(struct nfsd_ffv2_mapping_fixture *m,
				      const struct knfsd_fh *outer)
{
	union nfsd4_op_u u = {};
	__be32 status;

	u.putfh.pf_fhlen = outer->fh_size;
	u.putfh.pf_fhval = (u8 *)outer->fh_raw;
#ifdef CONFIG_NFSD_V4_2_INTER_SSC
	u.putfh.no_verify = true;
#endif
	status = nfsd4_test_ffv2_run_op(&m->rqst, &m->cstate, OP_PUTFH, &u);
	put_cred(revert_creds(get_cred(current_real_cred())));
	return status;
}

static void nfsd_ffv2_mapped_handle_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct svc_fh *fh;
	struct svc_export *exp;
	unsigned int net_refs;

	if (!m)
		return;
	fh = &m->cstate.current_fh;
	net_refs = ns_ref_read(m->registration->net);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer), nfs_ok);
	KUNIT_EXPECT_NOT_NULL(test, fh->fh_ffv2_binding);
	KUNIT_EXPECT_EQ(test, ns_ref_read(m->registration->net), net_refs + 1);
	KUNIT_EXPECT_PTR_EQ(test, fh->fh_dentry, m->registration->object);
	KUNIT_EXPECT_TRUE(test, fh_match(&fh->fh_handle, &m->registration->outer));
	KUNIT_EXPECT_FALSE(test, fh->fh_ffv2_admitted);
	exp = nfsd_ffv2_export_lookup(m->registration->nn->svc_export_cache,
				      m->registration->domain, &m->registration->root);
	KUNIT_EXPECT_FALSE(test, IS_ERR(exp));
	if (!IS_ERR(exp)) {
		KUNIT_EXPECT_PTR_EQ(test, fh->fh_export, exp);
		KUNIT_EXPECT_TRUE(test, nfsd_ffv2_export_is_service(exp));
		exp_put(exp);
	}
	fh_put(fh);
	fh_put(fh);
	KUNIT_EXPECT_PTR_EQ(test, fh->fh_ffv2_binding, NULL);
	KUNIT_EXPECT_EQ(test, ns_ref_read(m->registration->net), net_refs);
	KUNIT_EXPECT_EQ(test,
			atomic_read(&m->registration->nn->ffv2.test_registration.bindings), 0);
}

static void nfsd_ffv2_mapping_identity_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_registration_test *trace;
	struct knfsd_fh changed;
	struct nfsd_ffv2_registration_fixture *other;
	unsigned int i, anchor_refs;
	__be32 status;

	if (!m)
		return;
	trace = &m->registration->nn->ffv2.test_registration;
	anchor_refs = nfsd_ffv2_test_anchor_refcount(m->registration->nn);
	for (i = 0; i < 7; i++) {
		changed = m->registration->outer;
		switch (i) {
		case 0:
			put_unaligned_be64(m->generation + 1, changed.fh_raw + 16);
			break;
		case 1:
			changed.fh_raw[40] ^= 1;
			break;
		case 2:
			changed.fh_raw[24] ^= 1;
			break;
		case 3:
			changed.fh_size -= 4;
			put_unaligned_be16(changed.fh_size, changed.fh_raw + 12);
			put_unaligned_be16(changed.fh_size - NFSD_FFV2_FH_HEADER_SIZE,
					   changed.fh_raw + 14);
			break;
		case 4:
			changed.fh_raw[changed.fh_size - 1] ^= 1;
			break;
		case 5:
			changed.fh_raw[8]++;
			break;
		case 6:
			changed.fh_size = 1;
			break;
		}
		/* Replacing the old current always puts its owner, even on refusal. */
		FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer),
				   nfs_ok);
		status = nfsd_ffv2_mapping_putfh(m, &changed);
		FFV2_EXPECT_STATUS_MSG(test, status, i < 5 ? nfserr_stale : nfserr_badhandle,
				       "identity %u", i);
		KUNIT_EXPECT_PTR_EQ(test, m->cstate.current_fh.fh_ffv2_binding, NULL);
		fh_put(&m->cstate.current_fh);
		KUNIT_EXPECT_EQ(test,
				atomic_read(&trace->bindings), 0);
		KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_anchor_refcount(m->registration->nn),
				anchor_refs);
	}
	other = nfsd_ffv2_registration_fixture(test);
	if (!other)
		return;
	m->xprt.xpt_net = other->net;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer), nfserr_stale);
	m->xprt.xpt_net = m->registration->net;
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_anchor_refcount(other->nn), 1U);
}

static void nfsd_ffv2_mapping_unwind_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_registration_test *trace;
	unsigned int refs, net_refs;
	unsigned int i;

	if (!m)
		return;
	trace = &m->registration->nn->ffv2.test_registration;
	refs = nfsd_ffv2_test_anchor_refcount(m->registration->nn);
	net_refs = ns_ref_read(m->registration->net);
	for (i = 0; i < 4; i++) {
		if (i < 2)
			atomic_set(&trace->fault,
				   i ? NFSD_FFV2_TEST_MAP_NET : NFSD_FFV2_TEST_MAP_ALLOC);
		else if (i == 2)
			clear_bit(RQ_SECURE, &m->rqst.rq_flags);
		else
			m->rqst.rq_client = NULL;
		FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer),
				   i == 0 ? nfserr_jukebox : i == 2 ? nfserr_perm : nfserr_stale);
		set_bit(RQ_SECURE, &m->rqst.rq_flags);
		m->rqst.rq_client = m->registration->domain;
		KUNIT_EXPECT_PTR_EQ(test, m->cstate.current_fh.fh_ffv2_binding, NULL);
		fh_put(&m->cstate.current_fh);
		KUNIT_EXPECT_EQ(test, atomic_read(&trace->bindings), 0);
		KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_anchor_refcount(m->registration->nn), refs);
		KUNIT_EXPECT_EQ(test, ns_ref_read(m->registration->net), net_refs);
		FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer),
				   nfs_ok);
		fh_put(&m->cstate.current_fh);
	}
}

static void nfsd_ffv2_mapping_clone_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_object_retire_ctx retire = {};
	struct nfsd_ffv2_binding *binding;
	struct task_struct *task;
	union nfsd4_op_u u = {};
	unsigned int net_refs;
	bool waiting;
	int error;

	if (!m)
		return;
	net_refs = ns_ref_read(m->registration->net);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer), nfs_ok);
	KUNIT_EXPECT_EQ(test, ns_ref_read(m->registration->net), net_refs + 1);
	binding = m->cstate.current_fh.fh_ffv2_binding;
	if (!binding)
		return;
	FFV2_EXPECT_STATUS(test, nfsd4_test_ffv2_run_op(&m->rqst, &m->cstate, OP_SAVEFH, &u),
			   nfs_ok);
	KUNIT_EXPECT_EQ(test, ns_ref_read(m->registration->net), net_refs + 1);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_binding_refs(binding), 2U);
	/* A missing clone get must fail safely, before putting a non-owned copy. */
	if (nfsd_ffv2_test_binding_refs(binding) != 2) {
		m->cstate.save_fh.fh_ffv2_binding = NULL;
		return;
	}
	FFV2_EXPECT_STATUS(test, nfsd4_test_ffv2_run_op(&m->rqst, &m->cstate, OP_RESTOREFH, &u),
			   nfs_ok);
	KUNIT_EXPECT_EQ(test, ns_ref_read(m->registration->net), net_refs + 1);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_binding_refs(binding), 2U);
	fh_put(&m->cstate.current_fh);
	KUNIT_EXPECT_EQ(test, ns_ref_read(m->registration->net), net_refs + 1);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_binding_refs(binding), 1U);
	retire.fixture = m->registration;
	retire.generation = m->generation;
	init_completion(&retire.done);
	task = kthread_run(nfsd_ffv2_object_retire_thread, &retire, "ffv2-map-retire");
	if (IS_ERR(task)) {
		KUNIT_FAIL(test, "start mapped retirement: %ld", PTR_ERR(task));
		return;
	}
	error = read_poll_timeout(nfsd_ffv2_test_binding_waiting, waiting, waiting,
				  10, USEC_PER_SEC, false, binding);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_FALSE(test, completion_done(&retire.done));
	KUNIT_EXPECT_TRUE(test, m->registration->nn->ffv2.source);
	KUNIT_EXPECT_EQ(test, atomic_read(&m->registration->nn->ffv2.test_registration.contexts),
			1);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer), nfserr_stale);
	fh_put(&m->cstate.save_fh);
	KUNIT_EXPECT_EQ(test, ns_ref_read(m->registration->net), net_refs);
	KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&retire.done, 5 * HZ), 0UL);
	kthread_stop(task);
	KUNIT_EXPECT_EQ(test, retire.error, 0);
	KUNIT_EXPECT_EQ(test,
			atomic_read(&m->registration->nn->ffv2.test_registration.bindings), 0);
	nfsd_ffv2_registration_unwound(test, m->registration);
}

struct nfsd_ffv2_mapping_race {
	struct nfsd_ffv2_mapping_fixture *m;
	__be32 status;
	struct completion done;
};

static int nfsd_ffv2_mapping_thread(void *data)
{
	struct nfsd_ffv2_mapping_race *race = data;

	race->status = nfsd_ffv2_mapping_putfh(race->m, &race->m->registration->outer);
	complete(&race->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static void nfsd_ffv2_mapping_current_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m;
	struct nfsd_ffv2_mapping_race race;
	struct nfsd_ffv2_object_retire_ctx retire;
	struct nfsd_ffv2_admission held = {};
	struct nfsd_ffv2_registration_test *trace;
	struct task_struct *mapper, *retirer;
	struct completion verified, resume;
	unsigned int waiters;
	int error;

	m = nfsd_ffv2_mapping_fixture(test);
	if (!m)
		return;
	trace = &m->registration->nn->ffv2.test_registration;
	init_completion(&verified);
	init_completion(&resume);
	init_completion(&race.done);
	race.m = m;
	trace->map_verified = &verified;
	trace->map_continue = &resume;
	mapper = kthread_run(nfsd_ffv2_mapping_thread, &race, "ffv2-map-current");
	if (IS_ERR(mapper)) {
		KUNIT_FAIL(test, "start mapper");
		goto out_hooks;
	}
	retirer = NULL;
	if (!wait_for_completion_timeout(&verified, 5 * HZ)) {
		KUNIT_FAIL(test, "mapper did not pass real verifier");
		goto out_mapper;
	}
	/* Own an observer admission until the retirement-wait observation ends. */
	error = nfsd_ffv2_test_admit(m->registration->nn, &held);
	if (error) {
		KUNIT_FAIL(test, "observer admission: %d", error);
		goto out_mapper;
	}
	retire.fixture = m->registration;
	retire.generation = m->generation;
	init_completion(&retire.done);
	retirer = kthread_run(nfsd_ffv2_object_retire_thread, &retire, "ffv2-map-check");
	if (IS_ERR(retirer)) {
		retirer = NULL;
		KUNIT_FAIL(test, "start mapper retirement");
		goto out_mapper;
	}
	error = read_poll_timeout(nfsd_ffv2_test_waiters, waiters, waiters != 0,
				  10, USEC_PER_SEC, false, &held);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_FALSE(test, completion_done(&retire.done));
out_mapper:
	complete_all(&resume);
	KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&race.done, 5 * HZ), 0UL);
	kthread_stop(mapper);
	if (retirer) {
		FFV2_EXPECT_STATUS(test, race.status, nfserr_stale);
		KUNIT_EXPECT_PTR_EQ(test, m->cstate.current_fh.fh_ffv2_binding, NULL);
		/* Also releases a mapping accepted by a broken current check. */
		fh_put(&m->cstate.current_fh);
	}
	nfsd_ffv2_complete(&held);
	if (retirer) {
		KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&retire.done, 5 * HZ), 0UL);
		kthread_stop(retirer);
		KUNIT_EXPECT_EQ(test, retire.error, 0);
		nfsd_ffv2_registration_unwound(test, m->registration);
	}
out_hooks:
	trace->map_verified = NULL;
	trace->map_continue = NULL;
}

static void nfsd_ffv2_service_dispatch_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_registration_test *trace;
	struct nfsd4_op op = { .opnum = OP_GETFH };
	struct nfsd_ffv2_fh_info info;
	struct knfsd_fh inner = {};
	unsigned int i;
	static const struct {
		u32 opnum;
		bool implemented;
	} terminal[] = {
		{ OP_CHUNK_COMMIT, true },
		{ OP_CHUNK_FINALIZE, true },
		{ OP_CHUNK_HEADER_READ, true },
		{ OP_CHUNK_READ, true },
		{ OP_CHUNK_WRITE, true },
		{ OP_TRUST_STATEID, false },
		{ OP_REVOKE_STATEID, false },
		{ OP_BULK_REVOKE_STATEID, false },
		{ OP_CHUNK_ROLLBACK, false },
		{ OP_CHUNK_ERROR, false },
		{ OP_CHUNK_LOCK, false },
		{ OP_CHUNK_UNLOCK, false },
		{ OP_CHUNK_WRITE_REPAIR, false },
		{ OP_CHUNK_REPAIRED, false },
	};

	if (!m)
		return;
	trace = &m->registration->nn->ffv2.test_registration;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer), nfs_ok);
	atomic_set(&trace->dispatch_calls, 0);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_dispatch_op(&m->rqst, &m->cstate, &op),
			   nfserr_notsupp);
	KUNIT_EXPECT_PTR_EQ(test, op.u.getfh, NULL);
	KUNIT_EXPECT_EQ(test, atomic_read(&trace->dispatch_calls), 0);
	for (i = 0; i < ARRAY_SIZE(terminal); i++) {
		atomic_set(&trace->dispatch_calls, 0);
		op.opnum = terminal[i].opnum;
		m->args.ffv2_digest_valid = true;
		FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_dispatch_op(&m->rqst, &m->cstate, &op),
				   terminal[i].implemented ? nfserr_bad_stateid : nfserr_notsupp);
		m->args.ffv2_digest_valid = false;
		m->args.ffv2_decode_class = NFSD4_FFV2_DECODE_ERROR;
		m->args.ffv2_decode_status = nfserr_inval;
		FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_dispatch_op(&m->rqst, &m->cstate, &op),
				   nfserr_inval);
		KUNIT_EXPECT_EQ(test, atomic_read(&trace->dispatch_calls),
				terminal[i].implemented ? 2 : 0);
	}
	fh_put(&m->cstate.current_fh);
	/* The identical inner handle is refused through the ordinary verifier. */
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_fh_parse(&m->registration->outer, &info), 0);
	inner.fh_size = info.inner_len;
	memcpy(inner.fh_raw, info.inner, info.inner_len);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &inner), nfserr_stale);
}

static void nfsd_ffv2_mapping_target_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_registration_test *trace;
	struct nfsd_ffv2_mapping_race race;
	struct completion verified, resume;
	struct svc_export *exp;
	struct task_struct *mapper;
	bool changed = false;

	if (!m)
		return;
	exp = nfsd_ffv2_export_lookup(m->registration->nn->svc_export_cache,
				      m->registration->domain, &m->registration->root);
	KUNIT_ASSERT_FALSE(test, IS_ERR(exp));
	trace = &m->registration->nn->ffv2.test_registration;
	init_completion(&verified);
	init_completion(&resume);
	init_completion(&race.done);
	race.m = m;
	trace->map_verified = &verified;
	trace->map_continue = &resume;
	mapper = kthread_run(nfsd_ffv2_mapping_thread, &race, "ffv2-map-target");
	if (IS_ERR(mapper)) {
		KUNIT_FAIL(test, "start target mapper");
		goto out;
	}
	if (!wait_for_completion_timeout(&verified, 5 * HZ)) {
		KUNIT_FAIL(test, "target mapper did not pass verifier");
	} else {
		/* The mapper is parked after real resolution and before identity checks. */
		exp->ex_uuid[0] ^= 1;
		changed = true;
	}
	complete_all(&resume);
	KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&race.done, 5 * HZ), 0UL);
	kthread_stop(mapper);
	if (changed) {
		exp->ex_uuid[0] ^= 1;
		FFV2_EXPECT_STATUS(test, race.status, nfserr_stale);
		KUNIT_EXPECT_PTR_EQ(test, m->cstate.current_fh.fh_ffv2_binding, NULL);
	}
	fh_put(&m->cstate.current_fh);
	KUNIT_EXPECT_EQ(test, atomic_read(&trace->bindings), 0);
out:
	trace->map_verified = NULL;
	trace->map_continue = NULL;
	exp_put(exp);
}

static void nfsd_ffv2_service_compound_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_registration_test *trace;
	struct nfsd4_compoundres *resp;
	struct nfsd_thread_local_info *ntli;
	struct nfsd4_compoundargs *args;
	__be32 wire[64] = {}, *p;
	void *reply;
	size_t len;

	if (!m)
		return;
	trace = &m->registration->nn->ffv2.test_registration;
	resp = kunit_kzalloc(test, sizeof(*resp), GFP_KERNEL);
	ntli = kunit_kzalloc(test, sizeof(*ntli), GFP_KERNEL);
	reply = kunit_kzalloc(test, 1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, resp);
	KUNIT_ASSERT_NOT_NULL(test, ntli);
	KUNIT_ASSERT_NOT_NULL(test, reply);
	p = wire;
	*p++ = 0;
	*p++ = 0;
	*p++ = cpu_to_be32(4);
	*p++ = cpu_to_be32(OP_PUTFH);
	*p++ = cpu_to_be32(m->registration->outer.fh_size);
	memcpy(p, m->registration->outer.fh_raw, m->registration->outer.fh_size);
	p += XDR_QUADLEN(m->registration->outer.fh_size);
	*p++ = cpu_to_be32(OP_SAVEFH);
	*p++ = cpu_to_be32(OP_RESTOREFH);
	*p++ = cpu_to_be32(OP_GETFH);
	len = (char *)p - (char *)wire;
	args = &m->args;
	KUNIT_ASSERT_TRUE(test, nfsd_ffv2_test_compound_decode(test, args, wire, len, len, 0));
	m->rqst.rq_resp = resp;
	m->rqst.rq_private = ntli;
	m->rqst.rq_server = m->registration->nn->nfsd_serv;
	xdr_buf_init(&m->rqst.rq_res, reply, 1024);
	m->rqst.rq_res.head[0].iov_len = 0;
	xdr_init_encode(&m->rqst.rq_res_stream, &m->rqst.rq_res, reply, NULL);
	atomic_set(&trace->dispatch_calls, 0);
	nfsd4_test_dispatch_compound(&m->rqst);
	put_cred(revert_creds(get_cred(current_real_cred())));
	FFV2_EXPECT_STATUS(test, resp->cstate.status, nfserr_notsupp);
	KUNIT_EXPECT_EQ(test, resp->opcnt, 4U);
	KUNIT_EXPECT_EQ(test,
			atomic_read(&trace->dispatch_calls), 3);
	KUNIT_EXPECT_EQ(test,
			atomic_read(&trace->bindings), 0);
}

static void nfsd_ffv2_mapping_mixed_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_registration_fixture *ordinary;
	struct svc_fh src, bad = {};
	struct svc_export *exp;
	struct nfsd_ffv2_binding *binding;
	struct nfsd4_op getfh = { .opnum = OP_GETFH };
	__be32 status;
	int error;

	if (!m)
		return;
	ordinary = nfsd_ffv2_registration_fixture(test);
	if (!ordinary)
		return;
	exp = nfsd_ffv2_export_lookup(ordinary->nn->svc_export_cache, ordinary->domain,
				      &ordinary->root);
	KUNIT_ASSERT_FALSE(test, IS_ERR(exp));
	fh_init(&src, NFS4_FHSIZE);
	FFV2_EXPECT_STATUS(test, fh_compose(&src, exp, ordinary->object, NULL), nfs_ok);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer), nfs_ok);
	binding = m->cstate.current_fh.fh_ffv2_binding;
	/* Deliberately invalid ordinary source tests the existing clone-refusal branch. */
	bad.fh_export = m->cstate.current_fh.fh_export;
	bad.fh_ffv2_admitted = true;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_fh_dup2(&m->cstate.current_fh, &bad), nfserr_stale);
	KUNIT_EXPECT_PTR_EQ(test, m->cstate.current_fh.fh_ffv2_binding, binding);
	KUNIT_EXPECT_PTR_EQ(test, m->cstate.current_fh.fh_dentry, m->registration->object);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_fh_dup2(&m->cstate.current_fh, &src), nfs_ok);
	KUNIT_EXPECT_PTR_EQ(test, m->cstate.current_fh.fh_ffv2_binding, NULL);
	KUNIT_EXPECT_TRUE(test, m->cstate.current_fh.fh_ffv2_admitted);
	KUNIT_EXPECT_EQ(test, exp->ex_ffv2_access_count, 2U);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_dispatch_op(&m->rqst, &m->cstate, &getfh), nfs_ok);
	KUNIT_EXPECT_PTR_EQ(test, getfh.u.getfh, &m->cstate.current_fh);
	/* Decode the ordinary inner handle through OPEN admission and real checks. */
	error = nfsd_ffv2_mapping_key_inner(ordinary, &src.fh_handle);
	KUNIT_EXPECT_EQ(test, error, 0);
	if (!error) {
		m->xprt.xpt_net = ordinary->net;
		m->rqst.rq_client = ordinary->domain;
		status = nfsd_ffv2_mapping_putfh(m, &src.fh_handle);
		m->xprt.xpt_net = m->registration->net;
		m->rqst.rq_client = m->registration->domain;
		FFV2_EXPECT_STATUS(test, status, nfs_ok);
		KUNIT_EXPECT_PTR_EQ(test, m->cstate.current_fh.fh_dentry, ordinary->object);
		KUNIT_EXPECT_TRUE(test, m->cstate.current_fh.fh_ffv2_admitted);
		KUNIT_EXPECT_PTR_EQ(test, m->cstate.current_fh.fh_ffv2_binding, NULL);
		KUNIT_EXPECT_EQ(test, exp->ex_ffv2_access_count, 2U);
	}
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer), nfs_ok);
	KUNIT_EXPECT_EQ(test, exp->ex_ffv2_access_count, 1U);
	fh_put(&src);
	KUNIT_EXPECT_EQ(test, exp->ex_ffv2_access_count, 0U);
	exp_put(exp);
}

static void nfsd_ffv2_mapping_stop_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_shutdown_ctx stop;
	struct task_struct *task;
	struct nfsd_ffv2_binding *binding;
	bool waiting;
	int error;

	if (!m)
		return;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer), nfs_ok);
	binding = m->cstate.current_fh.fh_ffv2_binding;
	if (!binding)
		return;
	nfsd_ffv2_shutdown_ctx_init(&stop, m->registration->net);
	task = nfsd_ffv2_shutdown_thread_start(&stop, false);
	if (IS_ERR(task)) {
		nfsd_ffv2_shutdown_ctx_put(&stop);
		KUNIT_FAIL(test, "start mapped stop");
		return;
	}
	error = read_poll_timeout(nfsd_ffv2_test_binding_waiting, waiting, waiting,
				  10, USEC_PER_SEC, false, binding);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_FALSE(test, completion_done(&stop.done));
	KUNIT_EXPECT_TRUE(test, check_net(m->registration->net));
	KUNIT_EXPECT_EQ(test, atomic_read(&m->registration->nn->ffv2.test_registration.contexts),
			1);
	fh_put(&m->cstate.current_fh);
	KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&stop.done, 5 * HZ), 0UL);
	kthread_stop(task);
	nfsd_ffv2_shutdown_ctx_put(&stop);
	m->registration->service = false;
	nfsd_ffv2_registration_unwound(test, m->registration);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer), nfserr_stale);
}

static void nfsd_ffv2_service_decode_error_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_registration_test *trace;
	__be32 wire[96] = {};
	__be32 status, expected;
	bool decoded;
	size_t len;
	unsigned int i;

	if (!m)
		return;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer), nfs_ok);
	trace = &m->registration->nn->ffv2.test_registration;
	for (i = 0; i < 3; i++) {
		nfsd_ffv2_ro_compound(wire, 0);
		wire[2] = cpu_to_be32(4);
		wire[15] = cpu_to_be32(OP_CHUNK_LOCK);
		len = 64 + nfsd_ffv2_wire_op(wire + 16, OP_CHUNK_LOCK);
		wire[len / 4] = cpu_to_be32(i == 0 ? OP_GETATTR :
					  i == 1 ? OP_IO_ADVISE : OP_CHUNK_READ);
		len += 4;
		if (i == 2) {
			len += nfsd_ffv2_wire_op(wire + len / 4, OP_CHUNK_READ);
			wire[len / 4 - 1] = cpu_to_be32(4097);
		}
		decoded = nfsd_ffv2_test_compound_decode(test, &m->args, wire, len, len, 0);
		KUNIT_ASSERT_TRUE(test, decoded);
		FFV2_EXPECT_STATUS(test, m->args.iops[2].status, nfs_ok);
		KUNIT_EXPECT_EQ(test, m->args.iops[2].opnum, OP_CHUNK_LOCK);
		atomic_set(&trace->dispatch_calls, 0);
		/* The real call boundary is shared with COMPOUND, after session checks. */
		status = nfsd_ffv2_test_dispatch_op(&m->rqst, &m->cstate, &m->args.iops[2]);
		expected = i == 0 ? nfserr_bad_xdr : i == 1 ? nfserr_notsupp : nfserr_inval;
		FFV2_EXPECT_STATUS(test, status, expected);
		KUNIT_EXPECT_EQ(test, atomic_read(&trace->dispatch_calls), 0);
	}
}

/* Trust producers and sessions below are synthetic, not live provisioning. */
static void nfsd_ffv2_trust_request_init(struct nfsd_ffv2_mapping_fixture *m,
					 struct nfsd_ffv2_trust_request *req)
{
	memset(req, 0, sizeof(*req));
	req->stateid.si_generation = 7;
	req->object_uuid = m->registration->uuid;
	req->actor = NFSD_FFV2_CALLER_DATA_CLIENT;
	req->pnfs_clientid.cl_boot = 0x10203040;
	req->pnfs_clientid.cl_id = 0x50607080;
	req->client_id = 0x12345678;
	req->iomode = IOMODE_RW;
	req->profile_mask = NFSD_FFV2_PROFILE_ALL;
	req->expires.tv_sec = ktime_get_real_seconds() + 3600;
	req->principal = "writer@KUNIT";
	m->rqst.rq_cred.cr_principal = (char *)req->principal;
}

static __be32 nfsd_ffv2_trust_dispatch(struct nfsd_ffv2_mapping_fixture *m, u32 opnum,
				       const struct nfsd_ffv2_trust_request *req)
{
	struct nfsd4_op op = { .opnum = opnum };

	op.u.ffv2.stateid = req->stateid;
	op.u.ffv2.owner_client_id = req->client_id;
	op.u.ffv2.owner_present = true;
	return nfsd_ffv2_test_dispatch_op(&m->rqst, &m->cstate, &op);
}

static __be32 nfsd_ffv2_trust_direct(struct nfsd_ffv2_mapping_fixture *m, u32 opnum,
				     const stateid_t *stateid,
				     const struct nfsd_ffv2_actor_id *actor)
{
	struct nfsd_ffv2_admission admission = {};
	__be32 status;

	status = nfsd_ffv2_validate_operation(&m->rqst, &m->cstate.current_fh, m->cstate.session,
					      opnum, stateid, actor, &admission);
	nfsd_ffv2_complete(&admission);
	return status;
}

static void nfsd_ffv2_trust_policy_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_trust_request req, bad;
	struct nfsd_ffv2_trust_stats stats;
	struct nfs4_client *writer;
	struct nfsd4_session session = {};
	struct nfsd4_op op = { .opnum = OP_CHUNK_WRITE };
	struct nfsd_ffv2_admission observer = {};
	unsigned int i;
	static const u32 allowed[] = { OP_CHUNK_READ, OP_CHUNK_HEADER_READ, OP_CHUNK_WRITE,
				       OP_CHUNK_COMMIT, OP_CHUNK_FINALIZE };

	if (!m)
		return;
	nfsd_ffv2_trust_request_init(m, &req);
	writer = kunit_kzalloc(test, sizeof(*writer), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, writer);
	writer->cl_clientid = req.pnfs_clientid;
	session.se_client = writer;
	m->cstate.session = &session;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer), nfs_ok);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_dispatch(m, OP_CHUNK_READ, &req),
			   nfserr_bad_stateid);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_direct(m, OP_CHUNK_READ, NULL, NULL),
			   nfserr_bad_stateid);
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_test_admit(m->registration->nn, &observer), 0);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &req, false),
			   nfs_ok);
	for (i = 0; i < ARRAY_SIZE(allowed); i++) {
		FFV2_EXPECT_STATUS_MSG(test, nfsd_ffv2_trust_dispatch(m, allowed[i], &req),
				       nfserr_notsupp, "terminal opcode %u", allowed[i]);
		KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_admitted(&observer), 2U);
	}
	bad = req;
	memset(&bad.stateid, 0, sizeof(bad.stateid));
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_dispatch(m, OP_CHUNK_READ, &bad),
			   nfserr_bad_stateid);
	bad.stateid = req.stateid;
	bad.stateid.si_generation ^= 1;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_dispatch(m, OP_CHUNK_READ, &bad),
			   nfserr_bad_stateid);
	m->rqst.rq_cred.cr_principal = NULL;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_dispatch(m, OP_CHUNK_READ, &req), nfserr_acces);
	m->rqst.rq_cred.cr_principal = "other@KUNIT";
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_dispatch(m, OP_CHUNK_READ, &req), nfserr_acces);
	m->rqst.rq_cred.cr_principal = (char *)req.principal;
	bad = req;
	bad.profile_mask = NFSD_FFV2_PROFILE_WRITE_DATA;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &bad, false),
			   nfs_ok);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_dispatch(m, OP_CHUNK_READ, &req),
			   nfserr_bad_stateid);
	bad = req;
	bad.expires.tv_sec = 0;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &bad, false),
			   nfs_ok);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_dispatch(m, OP_CHUNK_READ, &req),
			   nfserr_bad_stateid);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &req, false),
			   nfs_ok);
	op.u.ffv2.stateid = req.stateid;
	op.u.ffv2.owner_present = false;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_dispatch_op(&m->rqst, &m->cstate, &op),
			   nfserr_bad_stateid);
	op.u.ffv2.owner_present = true;
	op.u.ffv2.owner_client_id = req.client_id + 1;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_dispatch_op(&m->rqst, &m->cstate, &op),
			   nfserr_bad_stateid);
	m->cstate.session = NULL;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_dispatch(m, OP_CHUNK_WRITE, &req),
			   nfserr_bad_stateid);
	m->cstate.session = &session;
	writer->cl_clientid.cl_boot ^= 1;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_dispatch(m, OP_CHUNK_WRITE, &req),
			   nfserr_bad_stateid);
	writer->cl_clientid = req.pnfs_clientid;
	writer->cl_clientid.cl_id ^= 1;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_dispatch(m, OP_CHUNK_WRITE, &req),
			   nfserr_bad_stateid);
	writer->cl_clientid = req.pnfs_clientid;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_dispatch(m, OP_CHUNK_WRITE, &req), nfserr_notsupp);
	/* Revoke first: renewal cannot change immutable caller/iomode identity. */
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &req, true),
			   nfs_ok);
	bad = req;
	bad.iomode = IOMODE_READ;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &bad, false),
			   nfs_ok);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_dispatch(m, OP_CHUNK_WRITE, &req),
			   nfserr_bad_stateid);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_dispatch(m, OP_CHUNK_READ, &req), nfserr_notsupp);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &bad, true),
			   nfs_ok);
	bad = req;
	bad.actor = NFSD_FFV2_CALLER_REPAIR_ACTOR;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &bad, false),
			   nfs_ok);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_dispatch(m, OP_CHUNK_WRITE, &req),
			   nfserr_bad_stateid);
	/* SERVICE excludes repair/control before their terminal handler. */
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_dispatch(m, OP_CHUNK_WRITE_REPAIR, &req),
			   nfserr_notsupp);
	{
		struct nfsd_ffv2_actor_id actor = { .present = true, .client_id = req.client_id };

		FFV2_EXPECT_STATUS(test,
				   nfsd_ffv2_trust_direct(m, OP_CHUNK_WRITE_REPAIR, &req.stateid,
							  &actor),
				   nfs_ok);
	}
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_trust_snapshot(m->registration->nn, &stats));
	KUNIT_EXPECT_EQ(test, stats.entries, 1U);
	KUNIT_EXPECT_EQ(test, stats.holds, 1U);
	KUNIT_EXPECT_EQ(test, stats.bytes, strlen(req.principal));
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_admitted(&observer), 2U);
	nfsd_ffv2_complete(&observer);
	m->cstate.session = NULL;
}

static void nfsd_ffv2_trust_entries_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_trust_request req, bad;
	struct nfsd_ffv2_trust_stats stats;
	void *entry;
	u8 other[16] = {};
	unsigned int i;
	static const enum nfsd_ffv2_test_registration_fault faults[] = {
		NFSD_FFV2_TEST_TRUST_ALLOC,
		NFSD_FFV2_TEST_TRUST_PRINCIPAL,
		NFSD_FFV2_TEST_TRUST_REPLACE,
	};

	if (!m)
		return;
	nfsd_ffv2_trust_request_init(m, &req);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &req, false),
			   nfs_ok);
	entry = nfsd_ffv2_test_trust_get(m->registration->nn, &req.stateid);
	KUNIT_ASSERT_NOT_NULL(test, entry);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_trust_snapshot(m->registration->nn, &stats));
	FFV2_EXPECT_STATUS(test,
			   nfsd_ffv2_test_entry_validate(entry, stats.generation, req.object_uuid,
							 stats.epoch, NFSD_FFV2_PROFILE_READ_DATA,
							 req.principal),
			   nfs_ok);
	FFV2_EXPECT_STATUS(test,
			   nfsd_ffv2_test_entry_validate(entry, stats.generation + 1,
							 req.object_uuid, stats.epoch,
							 NFSD_FFV2_PROFILE_READ_DATA, NULL),
			   nfserr_bad_stateid);
	FFV2_EXPECT_STATUS(test,
			   nfsd_ffv2_test_entry_validate(entry, stats.generation, other,
							 stats.epoch, NFSD_FFV2_PROFILE_READ_DATA,
							 NULL),
			   nfserr_bad_stateid);
	FFV2_EXPECT_STATUS(test,
			   nfsd_ffv2_test_entry_validate(entry, stats.generation, req.object_uuid,
							 stats.epoch + 1,
							 NFSD_FFV2_PROFILE_READ_DATA, NULL),
			   nfserr_bad_stateid);
	for (i = 0; i < 2; i++)
		FFV2_EXPECT_STATUS(test,
				   nfsd_ffv2_test_entry_validate(entry, stats.generation,
								 req.object_uuid, stats.epoch,
								 i ? 3 : 0, NULL),
				   nfserr_bad_stateid);
	for (i = 0; i < ARRAY_SIZE(faults); i++) {
		atomic_set(&m->registration->nn->ffv2.test_registration.fault, faults[i]);
		FFV2_EXPECT_STATUS(test,
				   nfsd_ffv2_test_trust_update(m->registration->nn, &req, false),
				   nfserr_delay);
		KUNIT_EXPECT_EQ(test, atomic_read(&m->registration->nn->ffv2.test_registration.hit),
				(int)faults[i]);
		KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_trust_snapshot(m->registration->nn, &stats));
		KUNIT_EXPECT_EQ(test, stats.entries, 1U);
		KUNIT_EXPECT_EQ(test, stats.holds, 1U);
		KUNIT_EXPECT_EQ(test, stats.bytes, strlen(req.principal));
		FFV2_EXPECT_STATUS(test,
				   nfsd_ffv2_test_entry_validate(entry, stats.generation,
								 req.object_uuid, stats.epoch,
								 NFSD_FFV2_PROFILE_READ_DATA,
								 req.principal),
				   nfs_ok);
	}
	bad = req;
	bad.client_id++;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &bad, false),
			   nfserr_bad_stateid);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &req, false),
			   nfs_ok);
	FFV2_EXPECT_STATUS(test,
			   nfsd_ffv2_test_entry_validate(entry, stats.generation, req.object_uuid,
							 stats.epoch, NFSD_FFV2_PROFILE_READ_DATA,
							 req.principal),
			   nfserr_bad_stateid);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_trust_snapshot(m->registration->nn, &stats));
	KUNIT_EXPECT_EQ(test, stats.entries, 1U);
	KUNIT_EXPECT_EQ(test, stats.holds, 2U);
	KUNIT_EXPECT_EQ(test, stats.bytes, 2 * strlen(req.principal));
	nfsd_ffv2_test_trust_put(entry);
	entry = nfsd_ffv2_test_trust_get(m->registration->nn, &req.stateid);
	KUNIT_ASSERT_NOT_NULL(test, entry);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &req, true),
			   nfs_ok);
	FFV2_EXPECT_STATUS(test,
			   nfsd_ffv2_test_entry_validate(entry, stats.generation, req.object_uuid,
							 stats.epoch, NFSD_FFV2_PROFILE_READ_DATA,
							 req.principal),
			   nfserr_bad_stateid);
	KUNIT_EXPECT_PTR_EQ(test, nfsd_ffv2_test_trust_get(m->registration->nn, &req.stateid),
			    NULL);
	nfsd_ffv2_test_trust_put(entry);
	atomic_set(&m->registration->nn->ffv2.test_registration.fault, NFSD_FFV2_TEST_TRUST_INSERT);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &req, false),
			   nfserr_delay);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_trust_snapshot(m->registration->nn, &stats));
	KUNIT_EXPECT_EQ(test, stats.entries, 0U);
	KUNIT_EXPECT_EQ(test, stats.holds, 0U);
	KUNIT_EXPECT_EQ(test, stats.bytes, 0UL);
}

static void nfsd_ffv2_trust_control_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_actor_id actor = { .target_present = true };
	struct nfsd4_session *other;
	stateid_t stateid = { .si_generation = 1 };
	stateid_t anonymous = {};
	struct svc_cred saved;

	if (!m)
		return;
	other = kunit_kzalloc(test, sizeof(*other), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, other);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer), nfs_ok);
	m->cstate.session = &m->registration->session;
	saved = m->rqst.rq_cred;
	m->rqst.rq_cred = m->registration->client.cl_cred;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_direct(m, OP_TRUST_STATEID, &anonymous, NULL),
			   nfserr_inval);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_direct(m, OP_TRUST_STATEID, &stateid, NULL),
			   nfs_ok);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_direct(m, OP_BULK_REVOKE_STATEID, NULL, NULL),
			   nfserr_inval);
	/* Identical credentials and client, but a different session locator. */
	other->se_client = &m->registration->client;
	other->se_sessionid = m->registration->session.se_sessionid;
	other->se_sessionid.data[0] ^= 1;
	m->cstate.session = other;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_direct(m, OP_TRUST_STATEID, &anonymous, NULL),
			   nfserr_perm);
	m->cstate.session = NULL;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_direct(m, OP_TRUST_STATEID, &stateid, NULL),
			   nfserr_perm);
	m->cstate.session = &m->registration->session;
	m->rqst.rq_cred.cr_raw_principal = NULL;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_direct(m, OP_TRUST_STATEID, &stateid, NULL),
			   nfserr_perm);
	m->rqst.rq_cred = m->registration->client.cl_cred;
	m->rqst.rq_cred.cr_raw_principal = "other@KUNIT";
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_direct(m, OP_TRUST_STATEID, &stateid, NULL),
			   nfserr_perm);
	m->rqst.rq_cred = m->registration->client.cl_cred;
	m->registration->client.cl_mach_cred = false;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_direct(m, OP_TRUST_STATEID, &stateid, NULL),
			   nfserr_perm);
	m->registration->client.cl_mach_cred = true;
	fh_put(&m->cstate.current_fh);
	/* Handleless selection uses the actual singleton, not member zero. */
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_trust_direct(m, OP_BULK_REVOKE_STATEID, NULL, &actor),
			   nfs_ok);
	{
		struct nfsd4_op op = { .opnum = OP_BULK_REVOKE_STATEID };

		op.u.ffv2.target_present = true;
		FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_dispatch_op(&m->rqst, &m->cstate, &op),
				   nfserr_notsupp);
	}
	m->rqst.rq_cred = saved;
	m->cstate.session = NULL;
}

struct nfsd_ffv2_policy_race {
	struct nfsd_ffv2_mapping_fixture *m;
	struct nfsd_ffv2_trust_request req;
	struct completion done;
	__be32 status;
	bool install;
	bool handleless;
};

static int nfsd_ffv2_policy_thread(void *data)
{
	struct nfsd_ffv2_policy_race *race = data;
	struct nfsd_ffv2_actor_id actor = { .target_present = true };

	if (race->install)
		race->status =
			nfsd_ffv2_test_trust_update(race->m->registration->nn, &race->req, false);
	else if (race->handleless)
		race->status =
			nfsd_ffv2_trust_direct(race->m, OP_BULK_REVOKE_STATEID, NULL, &actor);
	else
		race->status = nfsd_ffv2_trust_dispatch(race->m, OP_CHUNK_READ, &race->req);
	complete(&race->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

/* An independent admission keeps broken controls from freeing borrowed payload. */
static void nfsd_ffv2_validation_hold(struct kunit *test, bool install)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_registration_test *trace;
	struct nfsd_ffv2_policy_race race = { .install = install, .handleless = true };
	struct nfsd_ffv2_object_retire_ctx retire = {};
	struct nfsd_ffv2_admission observer = {};
	struct completion entered, resume;
	struct task_struct *validator = NULL, *drainer = NULL;
	bool waiting;
	int error;

	if (!m)
		return;
	race.m = m;
	nfsd_ffv2_trust_request_init(m, &race.req);
	m->cstate.session = &m->registration->session;
	m->rqst.rq_cred = m->registration->client.cl_cred;
	trace = &m->registration->nn->ffv2.test_registration;
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_test_admit(m->registration->nn, &observer), 0);
	init_completion(&entered);
	init_completion(&resume);
	init_completion(&race.done);
	init_completion(&retire.done);
	trace->validation_entered = &entered;
	trace->validation_continue = &resume;
	validator = kthread_run(nfsd_ffv2_policy_thread, &race, "ffv2-validation");
	if (IS_ERR(validator)) {
		validator = NULL;
		KUNIT_FAIL(test, "start validation");
		goto out;
	}
	if (!wait_for_completion_timeout(&entered, 5 * HZ)) {
		KUNIT_FAIL(test, "validation did not reach protected payload barrier");
		goto out;
	}
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_admitted(&observer), 2U);
	retire.fixture = m->registration;
	retire.generation = m->generation;
	drainer = kthread_run(nfsd_ffv2_object_retire_thread, &retire, "ffv2-validation-retire");
	if (IS_ERR(drainer)) {
		drainer = NULL;
		KUNIT_FAIL(test, "start validation retirement");
		goto out;
	}
	error = read_poll_timeout(nfsd_ffv2_test_waiters, waiting, waiting, 10, USEC_PER_SEC, false,
				  &observer);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_admission_retired(&observer));
	KUNIT_EXPECT_FALSE(test, completion_done(&retire.done));
	KUNIT_EXPECT_EQ(test, atomic_read(&trace->contexts), 1);
out:
	complete_all(&resume);
	if (validator) {
		KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&race.done, 5 * HZ), 0UL);
		kthread_stop(validator);
		/* Installer owns payload through completion; late execution is fenced. */
		FFV2_EXPECT_STATUS(test, race.status, install ? nfs_ok : nfserr_stale);
	}
	trace->validation_entered = NULL;
	trace->validation_continue = NULL;
	nfsd_ffv2_complete(&observer);
	if (drainer) {
		KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&retire.done, 5 * HZ), 0UL);
		kthread_stop(drainer);
		KUNIT_EXPECT_EQ(test, retire.error, 0);
		nfsd_ffv2_registration_unwound(test, m->registration);
	}
	m->cstate.session = NULL;
}

static void nfsd_ffv2_handleless_hold_test(struct kunit *test)
{
	nfsd_ffv2_validation_hold(test, false);
}

static void nfsd_ffv2_installer_hold_test(struct kunit *test)
{
	nfsd_ffv2_validation_hold(test, true);
}

static void nfsd_ffv2_execution_fence(struct kunit *test, bool authority)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_registration_test *trace;
	struct nfsd_ffv2_policy_race race = {};
	struct nfsd_ffv2_object_retire_ctx retire = {};
	struct completion entered, resume;
	struct task_struct *validator = NULL, *drainer = NULL;
	bool waiting;
	int error;

	if (!m)
		return;
	race.m = m;
	nfsd_ffv2_trust_request_init(m, &race.req);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &race.req, false),
			   nfs_ok);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_mapping_putfh(m, &m->registration->outer), nfs_ok);
	trace = &m->registration->nn->ffv2.test_registration;
	init_completion(&entered);
	init_completion(&resume);
	init_completion(&race.done);
	init_completion(&retire.done);
	trace->execute_entered = &entered;
	trace->execute_continue = &resume;
	validator = kthread_run(nfsd_ffv2_policy_thread, &race, "ffv2-execution");
	if (IS_ERR(validator)) {
		validator = NULL;
		KUNIT_FAIL(test, "start execution fence");
		goto out;
	}
	if (!wait_for_completion_timeout(&entered, 5 * HZ)) {
		KUNIT_FAIL(test, "execution did not reach late admission barrier");
		goto out;
	}
	if (authority) {
		/* Lose prompt worker retirement, retaining DEAD on the active generation. */
		atomic_set(&trace->fault, NFSD_FFV2_TEST_WORK_ALLOC);
		nfsd_ffv2_test_session_unhash(m->registration->nn, &m->registration->session,
					      false);
		m->registration->hashed = false;
		KUNIT_EXPECT_EQ(test, nfsd_ffv2_test_active_authority_state(m->registration->nn),
				2);
	} else {
		retire.fixture = m->registration;
		retire.generation = m->generation;
		drainer = kthread_run(nfsd_ffv2_object_retire_thread, &retire,
				      "ffv2-execution-retire");
		if (IS_ERR(drainer)) {
			drainer = NULL;
			KUNIT_FAIL(test, "start late retirement");
			goto out;
		}
		error = read_poll_timeout(nfsd_ffv2_test_binding_waiting, waiting, waiting, 10,
					  USEC_PER_SEC, false,
					  m->cstate.current_fh.fh_ffv2_binding);
		KUNIT_EXPECT_EQ(test, error, 0);
		KUNIT_EXPECT_FALSE(test, completion_done(&retire.done));
	}
out:
	complete_all(&resume);
	if (validator) {
		KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&race.done, 5 * HZ), 0UL);
		kthread_stop(validator);
		FFV2_EXPECT_STATUS(test, race.status, nfserr_stale);
	}
	trace->execute_entered = NULL;
	trace->execute_continue = NULL;
	fh_put(&m->cstate.current_fh);
	if (drainer) {
		KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&retire.done, 5 * HZ), 0UL);
		kthread_stop(drainer);
		KUNIT_EXPECT_EQ(test, retire.error, 0);
		nfsd_ffv2_registration_unwound(test, m->registration);
	}
}

static void nfsd_ffv2_late_authority_test(struct kunit *test)
{
	nfsd_ffv2_execution_fence(test, true);
}

static void nfsd_ffv2_late_generation_test(struct kunit *test)
{
	nfsd_ffv2_execution_fence(test, false);
}

static void nfsd_ffv2_trust_drain_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_object_retire_ctx retire = {};
	struct nfsd_ffv2_trust_request req;
	struct task_struct *task;
	void *entry;
	bool waiting;
	int error;

	if (!m)
		return;
	nfsd_ffv2_trust_request_init(m, &req);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &req, false),
			   nfs_ok);
	entry = nfsd_ffv2_test_trust_get(m->registration->nn, &req.stateid);
	KUNIT_ASSERT_NOT_NULL(test, entry);
	retire.fixture = m->registration;
	retire.generation = m->generation;
	init_completion(&retire.done);
	task = kthread_run(nfsd_ffv2_object_retire_thread, &retire, "ffv2-trust-retire");
	if (IS_ERR(task)) {
		nfsd_ffv2_test_trust_put(entry);
		KUNIT_FAIL(test, "start real trust retirement");
		return;
	}
	error = read_poll_timeout(nfsd_ffv2_test_trust_waiting, waiting, waiting, 10, USEC_PER_SEC,
				  false, entry);
	KUNIT_EXPECT_EQ(test, error, 0);
	KUNIT_EXPECT_FALSE(test, completion_done(&retire.done));
	KUNIT_EXPECT_EQ(test, atomic_read(&m->registration->nn->ffv2.test_registration.contexts),
			1);
	nfsd_ffv2_test_trust_put(entry);
	KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&retire.done, 5 * HZ), 0UL);
	kthread_stop(task);
	KUNIT_EXPECT_EQ(test, retire.error, 0);
	nfsd_ffv2_registration_unwound(test, m->registration);
}

static void nfsd_ffv2_trust_budget_test(struct kunit *test)
{
	struct nfsd_ffv2_mapping_fixture *m = nfsd_ffv2_mapping_fixture(test);
	struct nfsd_ffv2_trust_request req;
	struct nfsd_ffv2_trust_stats stats;
	char *principal;
	void *held;
	unsigned int i;
	__be32 status;

	if (!m)
		return;
	nfsd_ffv2_trust_request_init(m, &req);
	principal = kunit_kmalloc(test, NFSD_FFV2_TRUST_PRINCIPAL_MAX + 2, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, principal);
	memset(principal, 'p', NFSD_FFV2_TRUST_PRINCIPAL_MAX + 1);
	principal[NFSD_FFV2_TRUST_PRINCIPAL_MAX + 1] = 0;
	req.principal = principal;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &req, false),
			   nfserr_inval);
	principal[NFSD_FFV2_TRUST_PRINCIPAL_MAX] = 0;
	for (i = 0; i < NFSD_FFV2_TRUST_ENTRIES_MAX; i++) {
		req.stateid.si_generation = i + 1;
		status = nfsd_ffv2_test_trust_update(m->registration->nn, &req, false);
		if (status) {
			FFV2_EXPECT_STATUS_MSG(test, status, nfs_ok, "entry %u", i);
			return;
		}
	}
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_test_trust_snapshot(m->registration->nn, &stats));
	KUNIT_EXPECT_EQ(test, stats.entries, NFSD_FFV2_TRUST_ENTRIES_MAX);
	KUNIT_EXPECT_EQ(test, stats.bytes, (size_t)NFSD_FFV2_TRUST_BYTES_MAX);
	req.stateid.si_generation = NFSD_FFV2_TRUST_ENTRIES_MAX + 1;
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &req, false),
			   nfserr_delay);
	req.stateid.si_generation = 1;
	held = nfsd_ffv2_test_trust_get(m->registration->nn, &req.stateid);
	KUNIT_ASSERT_NOT_NULL(test, held);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &req, false),
			   nfserr_delay);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &req, true),
			   nfs_ok);
	/* Unhash frees a slot, but the referenced principal remains charged. */
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &req, false),
			   nfserr_delay);
	nfsd_ffv2_test_trust_put(held);
	FFV2_EXPECT_STATUS(test, nfsd_ffv2_test_trust_update(m->registration->nn, &req, false),
			   nfs_ok);
}

struct ffv2_read_fixture {
	struct nfsd_ffv2_mapping_fixture *mapping;
	struct nfsd_ffv2_trust_request trust;
	struct nfsd4_session session;
	struct nfsd4_slot *slot;
	struct nfsd4_compoundres response;
	struct nfsd_ffv2_admission admission;
	struct nfsd_ffv2_admission *release_probe;
	bool released_with_provider;
	struct nfsd4_op op;
	struct nfsd_ffv2_read_chunk chunks[4];
	__be32 status[4];
	u32 locked[4];
	struct nfsd_ffv2_chunk_owner owners[4];
	struct nfsd_ffv2_chunk_guard guards[4];
	struct nfsd_ffv2_retained predecessors[4];
	u8 bytes[16];
	atomic_t calls;
	atomic_t releases;
	u32 count;
	bool eof;
	unsigned int cleanup;
	unsigned int missing_header;
	__be32 error;
	struct completion *entered;
	struct completion **drain_wait;
};

static void ffv2_read_owner_release(void *data)
{
	struct ffv2_read_fixture *f = data;

	atomic_inc(&f->releases);
	if (f->release_probe)
		f->released_with_provider = !!f->release_probe->provider;
	memset(f->bytes, 0xa5, sizeof(f->bytes));
	memset(f->chunks, 0, sizeof(f->chunks));
	memset(f->status, 0xa5, sizeof(f->status));
	memset(f->owners, 0xa5, sizeof(f->owners));
}

/* The retained admission protects the completion while this predicate runs. */
static bool ffv2_provider_wait_queued(struct completion **waiting)
{
	/* Pairs with the drain observer publication while a ref is held. */
	struct completion *gone = smp_load_acquire(waiting);
	unsigned long flags;
	bool queued;

	if (!gone)
		return false;
	raw_spin_lock_irqsave(&gone->wait.lock, flags);
	queued = swait_active(&gone->wait);
	raw_spin_unlock_irqrestore(&gone->wait.lock, flags);
	return queued;
}

static __be32 ffv2_read_callback(void *data,
				 const struct nfsd_ffv2_object *object,
				 const struct nfsd_ffv2_chunk_request *request,
				 struct nfsd_ffv2_chunk_result *result)
{
	struct ffv2_read_fixture *f = data;

	atomic_inc(&f->calls);
	if (f->entered) {
		bool queued;

		complete(f->entered);

		if (read_poll_timeout(ffv2_provider_wait_queued, queued, queued,
				      1000, 5000000, false, f->drain_wait))
			return nfserr_io;
	}
	result->count = f->count;
	result->eof = f->eof;
	result->read.chunks = f->chunks;
	if (f->cleanup == 1 || f->cleanup == 2)
		result->private = f;
	if (f->cleanup == 1 || f->cleanup == 3)
		result->release = ffv2_read_owner_release;
	return f->error;
}

static __be32
ffv2_header_callback(void *data, const struct nfsd_ffv2_object *object,
		     const struct nfsd_ffv2_chunk_request *request,
		     struct nfsd_ffv2_chunk_result *result)
{
	struct ffv2_read_fixture *f = data;
	__be32 status = ffv2_read_callback(data, object, request, result);

	result->header.status = f->status;
	result->header.locked = f->locked;
	result->header.owners = f->owners;
	result->header.guards = f->guards;
	result->header.predecessors = f->predecessors;
	switch (f->missing_header) {
	case 1:
		result->header.status = NULL;
		break;
	case 2:
		result->header.locked = NULL;
		break;
	case 3:
		result->header.owners = NULL;
		break;
	case 4:
		result->header.guards = NULL;
		break;
	case 5:
		result->header.predecessors = NULL;
		break;
	}
	return status;
}

static const struct nfsd_ffv2_provider_ops ffv2_read_ops = {
	.chunk_read = ffv2_read_callback,
	.chunk_header_read = ffv2_header_callback,
};

static void ffv2_read_reset(struct ffv2_read_fixture *f)
{
	u32 i;

	memset(f->chunks, 0, sizeof(f->chunks));
	memset(f->status, 0, sizeof(f->status));
	memset(f->owners, 0, sizeof(f->owners));
	memset(f->bytes, 0, sizeof(f->bytes));
	f->count = 1;
	f->eof = true;
	f->error = nfs_ok;
	f->cleanup = 0;
	for (i = 0; i < ARRAY_SIZE(f->chunks); i++) {
		f->chunks[i].cr_chunk = f->bytes + 4 * i;
		f->chunks[i].cr_effective_len = 4;
		f->chunks[i].cr_checksum.cs_algorithm =
			NFSD_FFV2_CHECKSUM_ALG_CRC32;
		f->chunks[i].cr_checksum.cs_len = NFSD_FFV2_CHECKSUM_CRC32_LEN;
	}
}

static void ffv2_read_exit(void *data)
{
	struct ffv2_read_fixture *f = data;
	struct nfsd_net *nn = f->mapping->registration->nn;

	nfsd_ffv2_complete(&f->admission);
	nfsd_ffv2_test_release_op(&f->op);
	nfsd_ffv2_test_provider_drain_hook(nn, NULL);
	nfsd_ffv2_provider_remove(nn);
}

static struct ffv2_read_fixture *ffv2_read_fixture(struct kunit *test)
{
	struct ffv2_read_fixture *f;
	struct nfs4_client *writer;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	if (!f)
		return NULL;
	f->mapping = nfsd_ffv2_mapping_fixture(test);
	if (!f->mapping)
		return NULL;
	writer = kunit_kzalloc(test, sizeof(*writer), GFP_KERNEL);
	if (!writer)
		return NULL;
	nfsd_ffv2_trust_request_init(f->mapping, &f->trust);
	writer->cl_clientid = f->trust.pnfs_clientid;
	f->session.se_client = writer;
	f->mapping->cstate.session = &f->session;
	f->response.rqstp = &f->mapping->rqst;
	f->response.cstate.session = &f->session;
	f->slot = kunit_kzalloc(test, sizeof(*f->slot), GFP_KERNEL);
	if (!f->slot)
		return NULL;
	f->response.cstate.slot = f->slot;
	f->response.cstate.minorversion = 2;
	f->mapping->rqst.rq_resp = &f->response;
	f->mapping->rqst.rq_res.buflen = 8192;
	f->mapping->args.opcnt = 1;
	f->response.opcnt = 1;
	if (kunit_add_action_or_reset(test, ffv2_read_exit, f))
		return NULL;
	FFV2_EXPECT_STATUS(test,
			   nfsd_ffv2_mapping_putfh(f->mapping,
						   &f->mapping->registration->outer),
		nfs_ok);
	FFV2_EXPECT_STATUS(test,
			   nfsd_ffv2_test_trust_update(f->mapping->registration->nn,
						       &f->trust, false),
		nfs_ok);
	ffv2_read_reset(f);
	return f;
}

static __be32 ffv2_read_admit(struct ffv2_read_fixture *f)
{
	struct nfsd_ffv2_mapping_fixture *m = f->mapping;

	return nfsd_ffv2_validate_operation(&m->rqst, &m->cstate.current_fh,
					    m->cstate.session, OP_CHUNK_READ,
					    &f->trust.stateid, NULL,
					    &f->admission);
}

static __be32 ffv2_read_probe(struct ffv2_read_fixture *f, u32 opcode,
			      u64 offset, u32 count, u32 available,
			      struct nfsd_ffv2_chunk_result *result)
{
	struct nfsd_ffv2_chunk_request request = { .offset = offset,
						   .count = count };
	struct nfsd_ffv2_mapping_fixture *m = f->mapping;

	return nfsd_ffv2_provider_probe(&m->rqst, &m->cstate.current_fh, opcode,
					&request, result, available,
					&f->admission);
}

static void ffv2_read_bounds_test(struct kunit *test)
{
	struct ffv2_read_fixture *f = ffv2_read_fixture(test);
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_net *nn;

	KUNIT_ASSERT_NOT_NULL(test, f);
	nn = f->mapping->registration->nn;
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_provider_install(nn, &ffv2_read_ops, f, 4096),
			0);
	FFV2_EXPECT_STATUS(test, ffv2_read_admit(f), nfs_ok);
	FFV2_EXPECT_STATUS(test, ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 4096, &result),
			   nfserr_toosmall);
	KUNIT_EXPECT_EQ_MSG(test, atomic_read(&f->calls), 0,
			    "size before callback");
	FFV2_EXPECT_STATUS(test,
			   ffv2_read_probe(f, OP_CHUNK_READ, 0, 4097, U32_MAX,
					   &result),
			   nfserr_inval);
	FFV2_EXPECT_STATUS(test,
			   ffv2_read_probe(f, OP_CHUNK_READ, U64_MAX, 1,
					   U32_MAX, &result),
			   nfserr_inval);
	nfsd_ffv2_test_object_geometry(&f->mapping->cstate.current_fh, 8192);
	FFV2_EXPECT_STATUS(test, ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 16384, &result),
			   nfserr_serverfault);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->calls), 0);
	nfsd_ffv2_test_object_geometry(&f->mapping->cstate.current_fh, 4096);
	f->count = 0;
	FFV2_EXPECT_STATUS(test,
			   ffv2_read_probe(f, OP_CHUNK_READ, 0, 0, 15, &result),
			   nfserr_toosmall);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->calls), 0);
	FFV2_EXPECT_STATUS(test,
			   ffv2_read_probe(f, OP_CHUNK_READ, 0, 0, 16, &result),
			   nfs_ok);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->calls), 1);
	FFV2_EXPECT_STATUS(test,
			   ffv2_read_probe(f, OP_CHUNK_HEADER_READ, 0, 0, 31,
					   &result),
			   nfserr_toosmall);
	FFV2_EXPECT_STATUS(test,
			   ffv2_read_probe(f, OP_CHUNK_HEADER_READ, 0, 0, 32,
					   &result),
			   nfs_ok);
	f->count = 1;
	f->chunks[0].cr_effective_len = 4097;
	FFV2_EXPECT_STATUS(test, ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 8192, &result),
			   nfserr_serverfault);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->calls), 3);
}

static void ffv2_read_ownership_test(struct kunit *test)
{
	struct ffv2_read_fixture *f = ffv2_read_fixture(test);
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_ffv2_provider *pinned;
	struct nfsd_net *nn;

	KUNIT_ASSERT_NOT_NULL(test, f);
	nn = f->mapping->registration->nn;
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_provider_install(nn, &ffv2_read_ops, f, 4096),
			0);
	FFV2_EXPECT_STATUS(test, ffv2_read_admit(f), nfs_ok);
	FFV2_EXPECT_STATUS(test, ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 8192, &result),
			   nfs_ok);
	pinned = f->admission.provider;
	KUNIT_EXPECT_NOT_NULL(test, pinned);
	f->cleanup = 2;
	FFV2_EXPECT_STATUS(test, ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 8192, &result),
			   nfserr_serverfault);
	KUNIT_EXPECT_PTR_EQ_MSG(test, f->admission.provider, pinned,
				"prior provider retention");
	/* Preserve the known outstanding ref if the retention assertion fails. */
	if (!f->admission.provider)
		f->admission.provider = pinned;
	f->cleanup = 3;
	FFV2_EXPECT_STATUS(test, ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 8192, &result),
			   nfserr_serverfault);
	f->cleanup = 0;
	f->error = nfserr_io;
	FFV2_EXPECT_STATUS(test, ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 8192, &result),
			   nfserr_io);
	KUNIT_EXPECT_PTR_EQ(test, f->admission.provider, pinned);
	f->error = nfs_ok;
	f->cleanup = 1;
	f->release_probe = &f->admission;
	f->count = 2;
	/* Valid cleanup is adopted before a count/EOF rejection. */
	FFV2_EXPECT_STATUS(test, ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 8192, &result),
			   nfserr_serverfault);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 0);
	KUNIT_EXPECT_PTR_EQ(test, f->admission.provider_result, f);
	f->count = 1;
	f->error = nfserr_io;
	FFV2_EXPECT_STATUS(test, ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 8192, &result),
			   nfserr_serverfault);
	KUNIT_EXPECT_PTR_EQ(test, f->admission.provider, pinned);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 0);
	nfsd_ffv2_complete(&f->admission);
	nfsd_ffv2_complete(&f->admission);
	KUNIT_EXPECT_EQ_MSG(test, atomic_read(&f->releases), 1,
			    "single result cleanup");
	KUNIT_EXPECT_TRUE_MSG(test, f->released_with_provider,
			      "result release before provider put");
	ffv2_read_reset(f);
	f->cleanup = 1;
	f->error = nfserr_io;
	FFV2_EXPECT_STATUS(test, ffv2_read_admit(f), nfs_ok);
	FFV2_EXPECT_STATUS(test, ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 8192, &result),
			   nfserr_io);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 1);
	nfsd_ffv2_complete(&f->admission);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 2);
}

static __be32 ffv2_read_handle(struct ffv2_read_fixture *f, u32 opcode,
			       u32 count)
{
	memset(&f->op, 0, sizeof(f->op));
	f->op.opnum = opcode;
	/* Both request structures have the same prefix. */
	f->op.u.chunk_read.cra_stateid = f->trust.stateid;
	f->op.u.chunk_read.cra_count = count;
	return nfsd_ffv2_test_dispatch_op(&f->mapping->rqst,
					  &f->mapping->cstate, &f->op);
}

static void ffv2_read_encode(struct ffv2_read_fixture *f, void *bytes,
			     size_t size)
{
	struct svc_rqst *rqstp = &f->mapping->rqst;
	struct xdr_stream xdr = {};

	memset(&rqstp->rq_res, 0, sizeof(rqstp->rq_res));
	rqstp->rq_res.head[0].iov_base = bytes;
	rqstp->rq_res.head[0].iov_len = 0;
	rqstp->rq_res.buflen = size;
	xdr_init_encode(&xdr, &rqstp->rq_res, NULL, NULL);
	f->response.xdr = &xdr;
	f->response.cstate.session = NULL;
	f->response.cstate.slot = NULL;
	nfsd4_encode_operation(&f->response, &f->op);
	nfsd_ffv2_test_release_op(&f->op);
}

static void ffv2_read_copy_encode_test(struct kunit *test)
{
	static const __be32 statuses[] = { nfs_ok, nfserr_noent,
					   nfserr_payload_not_atomic,
					   nfserr_payload_lost };
	struct ffv2_read_fixture *f = ffv2_read_fixture(test);
	__be32 wire[128];
	u32 index, i;
	struct nfsd_net *nn;

	KUNIT_ASSERT_NOT_NULL(test, f);
	nn = f->mapping->registration->nn;
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_provider_install(nn, &ffv2_read_ops, f, 4096),
			0);
	f->count = 4;
	f->cleanup = 1;
	for (i = 0; i < 4; i++) {
		f->chunks[i].cr_status = statuses[i];
		if (i > 1)
			f->chunks[i].cr_effective_len = 0;
	}
	memset(f->bytes, 0x37, 4);
	put_unaligned_be32(crc32_le(~0U, f->bytes + 4, 4) ^ ~0U,
			   f->chunks[1].cr_checksum.cs_value);
	/* Budget covers provider geometry, not just this tiny synthetic payload. */
	f->mapping->rqst.rq_res.buflen = 32768;
	FFV2_EXPECT_STATUS(test, ffv2_read_handle(f, OP_CHUNK_READ, 4), nfs_ok);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 1);
	if (f->op.u.chunk_read.cra_nchunks != 4)
		return;
	KUNIT_EXPECT_EQ_MSG(test, ((u8 *)f->op.u.chunk_read.cra_payload)[0],
			    (u8)0x37,
			    "private payload independent of released result");
	FFV2_EXPECT_STATUS(test, f->op.u.chunk_read.cra_chunks[3].cre_status,
			   nfserr_payload_lost);
	ffv2_read_encode(f, wire, sizeof(wire));
	FFV2_EXPECT_STATUS(test, f->op.status, nfs_ok);
	KUNIT_EXPECT_EQ(test, be32_to_cpu(wire[3]), 4U);
	index = 4;
	for (i = 0; i < 4; i++) {
		FFV2_EXPECT_STATUS_MSG(test, wire[index + 12], statuses[i],
				       "wire status byte order");
		index += 14 + (i < 2 ? 1 : 0);
	}
	KUNIT_EXPECT_PTR_EQ(test, f->op.u.chunk_read.cra_chunks, NULL);
	KUNIT_EXPECT_PTR_EQ(test, f->op.u.chunk_read.cra_payload, NULL);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 1);
}

static void ffv2_header_copy_encode_test(struct kunit *test)
{
	struct ffv2_read_fixture *f = ffv2_read_fixture(test);
	__be32 wire[128];
	u32 i;
	struct nfsd_net *nn;

	KUNIT_ASSERT_NOT_NULL(test, f);
	nn = f->mapping->registration->nn;
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_provider_install(nn, &ffv2_read_ops, f, 4096),
			0);
	f->count = 4;
	f->cleanup = 1;
	f->status[1] = nfserr_noent;
	f->status[2] = nfserr_payload_not_atomic;
	f->status[3] = nfserr_payload_lost;
	f->owners[0].co_id = 77;
	FFV2_EXPECT_STATUS(test, ffv2_read_handle(f, OP_CHUNK_HEADER_READ, 4),
			   nfs_ok);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 1);
	if (f->op.u.chunk_header_read.chrr_nents != 4)
		return;
	KUNIT_EXPECT_EQ_MSG(test, f->op.u.chunk_header_read.chrr_ents[0].che_owner.co_id,
			    77U, "private header independent of released result");
	ffv2_read_encode(f, wire, sizeof(wire));
	FFV2_EXPECT_STATUS(test, f->op.status, nfs_ok);
	FFV2_EXPECT_STATUS(test, wire[4], nfs_ok);
	FFV2_EXPECT_STATUS(test, wire[5], nfserr_noent);
	FFV2_EXPECT_STATUS(test, wire[6], nfserr_payload_not_atomic);
	FFV2_EXPECT_STATUS(test, wire[7], nfserr_payload_lost);
	/* Five arrays have the same count. */
	for (i = 0; i < 5; i++) {
		static const unsigned int counts[] = { 3, 8, 13, 30, 39 };

		KUNIT_EXPECT_EQ(test, be32_to_cpu(wire[counts[i]]), 4U);
	}
	KUNIT_EXPECT_PTR_EQ(test, f->op.u.chunk_header_read.chrr_ents, NULL);
}

static void ffv2_read_failures_test(struct kunit *test)
{
	struct ffv2_read_fixture *f = ffv2_read_fixture(test);
	struct nfsd_net *nn;
	__be32 wire[16];
	unsigned int i;

	KUNIT_ASSERT_NOT_NULL(test, f);
	nn = f->mapping->registration->nn;
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_provider_install(nn, &ffv2_read_ops, f, 4096),
			0);
	for (i = 1; i <= 2; i++) {
		ffv2_read_reset(f);
		f->cleanup = 1;
		nfsd_ffv2_test_read_copy_fault(nn, i);
		FFV2_EXPECT_STATUS(test, ffv2_read_handle(f, OP_CHUNK_READ, 1),
				   nfserr_jukebox);
		KUNIT_EXPECT_PTR_EQ(test, f->op.u.chunk_read.cra_chunks, NULL);
		KUNIT_EXPECT_PTR_EQ(test, f->op.u.chunk_read.cra_payload, NULL);
		KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), (int)i);
	}
	ffv2_read_reset(f);
	f->cleanup = 1;
	FFV2_EXPECT_STATUS(test, ffv2_read_handle(f, OP_CHUNK_READ, 1), nfs_ok);
	ffv2_read_encode(f, wire, sizeof(wire));
	FFV2_EXPECT_STATUS(test, f->op.status, nfserr_resource);
	KUNIT_EXPECT_EQ(test, f->mapping->rqst.rq_res.len, 8U);
	KUNIT_EXPECT_PTR_EQ(test, f->op.u.chunk_read.cra_chunks, NULL);
	KUNIT_EXPECT_PTR_EQ(test, f->op.u.chunk_read.cra_payload, NULL);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 3);
	ffv2_read_reset(f);
	f->cleanup = 1;
	f->mapping->rqst.rq_res.len = 0;
	f->mapping->rqst.rq_res.buflen = 8192;
	nfsd_ffv2_test_read_copy_fault(nn, 1);
	FFV2_EXPECT_STATUS(test, ffv2_read_handle(f, OP_CHUNK_HEADER_READ, 1),
			   nfserr_jukebox);
	KUNIT_EXPECT_PTR_EQ(test, f->op.u.chunk_header_read.chrr_ents, NULL);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 4);
	ffv2_read_reset(f);
	f->cleanup = 1;
	FFV2_EXPECT_STATUS(test, ffv2_read_handle(f, OP_CHUNK_HEADER_READ, 1),
			   nfs_ok);
	ffv2_read_encode(f, wire, sizeof(wire));
	FFV2_EXPECT_STATUS(test, f->op.status, nfserr_resource);
	KUNIT_EXPECT_EQ(test, f->mapping->rqst.rq_res.len, 8U);
	KUNIT_EXPECT_PTR_EQ(test, f->op.u.chunk_header_read.chrr_ents, NULL);
}

static void ffv2_read_validation_test(struct kunit *test)
{
	struct ffv2_read_fixture *f = ffv2_read_fixture(test);
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_net *nn;
	unsigned int i;

	KUNIT_ASSERT_NOT_NULL(test, f);
	nn = f->mapping->registration->nn;
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_provider_install(nn, &ffv2_read_ops, f, 4096),
			0);
	FFV2_EXPECT_STATUS(test, ffv2_read_admit(f), nfs_ok);
	for (i = 0; i < 6; i++) {
		ffv2_read_reset(f);
		switch (i) {
		case 0:
			f->chunks[0].cr_status = nfserr_io;
			f->chunks[0].cr_effective_len = 0;
			break;
		case 1:
			f->chunks[0].cr_checksum.cs_len = 3;
			break;
		case 2:
			f->chunks[0].cr_checksum.cs_algorithm =
				NFSD_FFV2_CHECKSUM_ALG_NONE;
			break;
		case 3:
			f->count = 0;
			f->eof = false;
			break;
		case 4:
			f->chunks[0].cr_status = nfserr_payload_lost;
			break;
		case 5:
			f->chunks[0].cr_status = nfserr_noent;
			f->bytes[0] = 1;
			break;
		}
		FFV2_EXPECT_STATUS(test,
				   ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 8192,
						   &result),
				   nfserr_serverfault);
	}
	for (i = 1; i <= 5; i++) {
		ffv2_read_reset(f);
		f->missing_header = i;
		FFV2_EXPECT_STATUS(test, ffv2_read_probe(f, OP_CHUNK_HEADER_READ,
							 0, 1, 8192, &result), nfserr_serverfault);
	}
	f->missing_header = 0;
	ffv2_read_reset(f);
	f->status[0] = nfserr_io;
	FFV2_EXPECT_STATUS(test,
			   ffv2_read_probe(f, OP_CHUNK_HEADER_READ, 0, 1, 8192,
					   &result),
			   nfserr_serverfault);
	f->status[0] = nfserr_noent;
	f->guards[0].cg_gen_id = 1;
	FFV2_EXPECT_STATUS(test,
			   ffv2_read_probe(f, OP_CHUNK_HEADER_READ, 0, 1, 8192,
					   &result),
			   nfserr_serverfault);
	f->guards[0].cg_gen_id = 0;
	f->predecessors[0].disposition = 99;
	FFV2_EXPECT_STATUS(test,
			   ffv2_read_probe(f, OP_CHUNK_HEADER_READ, 0, 1, 8192,
					   &result),
			   nfserr_serverfault);
}

/* The worker owns its namespace and context through its last instruction. */
struct ffv2_provider_drain {
	struct net *net;
	struct nfsd_net *nn;
	refcount_t refs;
	struct completion go;
	struct completion *waiting;
	struct completion done;
	bool net_exit;
};

static void ffv2_provider_drain_put(struct ffv2_provider_drain *d)
{
	if (refcount_dec_and_test(&d->refs)) {
		put_net(d->net);
		kfree(d);
	}
}

static int ffv2_provider_drain_thread(void *data)
{
	struct ffv2_provider_drain *d = data;

	if (wait_for_completion_timeout(&d->go, 5 * HZ)) {
		if (d->net_exit)
			nfsd_ffv2_net_pre_exit(d->nn);
		else
			nfsd_ffv2_provider_remove(d->nn);
	}
	complete(&d->done);
	ffv2_provider_drain_put(d);
	return 0;
}

static void ffv2_provider_drain_check(struct kunit *test, bool callback,
				      bool net_exit)
{
	struct ffv2_read_fixture *f = ffv2_read_fixture(test);
	struct nfsd_ffv2_chunk_result result;
	struct ffv2_provider_drain *d;
	struct task_struct *task;
	unsigned long finished;

	KUNIT_ASSERT_NOT_NULL(test, f);
	d = kzalloc_obj(*d);
	KUNIT_ASSERT_NOT_NULL(test, d);
	d->net = get_net(f->mapping->registration->net);
	d->nn = f->mapping->registration->nn;
	d->net_exit = net_exit;
	refcount_set(&d->refs, 1);
	init_completion(&d->go);
	init_completion(&d->done);
	if (nfsd_ffv2_provider_install(d->nn, &ffv2_read_ops, f, 4096)) {
		KUNIT_FAIL(test, "install drain provider");
		goto out;
	}
	f->cleanup = 1;
	FFV2_EXPECT_STATUS(test, ffv2_read_admit(f), nfs_ok);
	if (!callback)
		FFV2_EXPECT_STATUS(test,
				   ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 8192,
						   &result),
				   nfs_ok);
	task = kthread_create(ffv2_provider_drain_thread, d,
			      "ffv2-provider-drain");
	if (IS_ERR(task)) {
		KUNIT_FAIL(test, "create drain worker");
		goto out;
	}
	get_task_struct(task);
	refcount_inc(&d->refs);
	nfsd_ffv2_test_provider_drain_hook(d->nn, &d->waiting);
	wake_up_process(task);
	if (callback) {
		f->entered = &d->go;
		f->drain_wait = &d->waiting;
		/* The callback resumes only after the remover has queued a waiter. */
		FFV2_EXPECT_STATUS(test,
				   ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 8192,
						   &result),
				   nfs_ok);
		f->entered = NULL;
		f->drain_wait = NULL;
	} else {
		complete(&d->go);
		bool queued;

		KUNIT_EXPECT_EQ_MSG(test,
				    read_poll_timeout(ffv2_provider_wait_queued,
						      queued, queued, 1000,
						      5000000, false,
						      &d->waiting),
				    0, "remover reached provider owner wait");
	}
	KUNIT_EXPECT_FALSE_MSG(test, completion_done(&d->done),
			       "result holds provider drain");
	nfsd_ffv2_complete(&f->admission);
	if (net_exit) {
		fh_put(&f->mapping->cstate.current_fh);
		fh_put(&f->mapping->cstate.save_fh);
	}
	finished = wait_for_completion_timeout(&d->done, 5 * HZ);
	KUNIT_EXPECT_NE_MSG(test, finished, 0UL,
			    "owners released before drain returns");
	KUNIT_EXPECT_EQ(test, atomic_read(&f->releases), 1);
	nfsd_ffv2_test_provider_drain_hook(d->nn, NULL);
	put_task_struct(task);
out:
	ffv2_provider_drain_put(d);
}

static void ffv2_provider_callback_remove_test(struct kunit *test)
{
	ffv2_provider_drain_check(test, true, false);
}

static void ffv2_provider_result_remove_test(struct kunit *test)
{
	ffv2_provider_drain_check(test, false, false);
}

static void ffv2_provider_callback_net_exit_test(struct kunit *test)
{
	ffv2_provider_drain_check(test, true, true);
}

static void ffv2_provider_result_net_exit_test(struct kunit *test)
{
	ffv2_provider_drain_check(test, false, true);
}

static void ffv2_provider_replacement_test(struct kunit *test)
{
	struct ffv2_read_fixture *f = ffv2_read_fixture(test);
	struct ffv2_read_fixture *other;
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_net *nn;

	KUNIT_ASSERT_NOT_NULL(test, f);
	other = kunit_kzalloc(test, sizeof(*other), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, other);
	ffv2_read_reset(other);
	nn = f->mapping->registration->nn;
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_provider_install(nn, &ffv2_read_ops, f, 4096),
			0);
	KUNIT_EXPECT_EQ(test,
			nfsd_ffv2_provider_install(nn, &ffv2_read_ops, other,
						   4096),
			-EBUSY);
	FFV2_EXPECT_STATUS(test, ffv2_read_admit(f), nfs_ok);
	FFV2_EXPECT_STATUS(test, ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 8192, &result),
			   nfs_ok);
	nfsd_ffv2_complete(&f->admission);
	nfsd_ffv2_provider_remove(nn);
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_provider_install(nn, &ffv2_read_ops, other, 4096), 0);
	FFV2_EXPECT_STATUS(test, ffv2_read_admit(f), nfs_ok);
	FFV2_EXPECT_STATUS(test, ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 8192, &result),
			   nfs_ok);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->calls), 1);
	KUNIT_EXPECT_EQ(test, atomic_read(&other->calls), 1);
	nfsd_ffv2_complete(&f->admission);
	/* The synthetic provider has no adapter-owned allocation to retire. */
	nfsd_ffv2_provider_remove(nn);
	other = ffv2_read_fixture(test);
	KUNIT_ASSERT_NOT_NULL(test, other);
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_provider_install(other->mapping->registration->nn,
						   &ffv2_read_ops, other, 4096),
		0);
	FFV2_EXPECT_STATUS(test, ffv2_read_admit(f), nfs_ok);
	FFV2_EXPECT_STATUS(test, ffv2_read_probe(f, OP_CHUNK_READ, 0, 1, 8192, &result),
			   nfserr_notsupp);
	KUNIT_EXPECT_EQ(test, atomic_read(&other->calls), 0);
}

static void ffv2_header_bounds_test(struct kunit *test)
{
	struct ffv2_read_fixture *f = ffv2_read_fixture(test);
	struct nfsd_net *nn;
	__be32 wire[64];

	KUNIT_ASSERT_NOT_NULL(test, f);
	nn = f->mapping->registration->nn;
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_provider_install(nn, &ffv2_read_ops, f, 4096),
			0);
	f->count = 2;
	f->predecessors[0].disposition = NFSD_FFV2_RETAINED_PRESENT;
	f->predecessors[0].rp_owner.co_id = 19;
	f->predecessors[1].disposition = NFSD_FFV2_RETAINED_ERRORED;
	f->mapping->rqst.rq_res.buflen = 120;
	FFV2_EXPECT_STATUS(test, ffv2_read_handle(f, OP_CHUNK_HEADER_READ, 2),
			   nfs_ok);
	KUNIT_EXPECT_EQ(test, f->op.u.chunk_header_read.chrr_nents, 1U);
	KUNIT_EXPECT_FALSE(test, f->op.u.chunk_header_read.chrr_eof);
	KUNIT_EXPECT_EQ(test,
			f->op.u.chunk_header_read.chrr_ents[0]
				.che_predecessor.rp_owner.co_id,
			19U);
	ffv2_read_encode(f, wire, sizeof(wire));
	FFV2_EXPECT_STATUS(test, f->op.status, nfs_ok);
	KUNIT_EXPECT_EQ(test, be32_to_cpu(wire[3]), 1U);
	f->response.cstate.slot = f->slot;
	f->slot->sl_flags = NFSD4_SLOT_CACHETHIS;
	f->mapping->rqst.rq_res.len = 0;
	f->mapping->rqst.rq_res.buflen = 31;
	FFV2_EXPECT_STATUS(test, ffv2_read_handle(f, OP_CHUNK_HEADER_READ, 0),
			   nfserr_rep_too_big_to_cache);
	KUNIT_EXPECT_EQ_MSG(test, atomic_read(&f->calls), 1,
			    "header size before callback");
}

static void ffv2_read_authority_test(struct kunit *test)
{
	struct ffv2_read_fixture *f = ffv2_read_fixture(test);
	struct nfsd_net *nn;

	KUNIT_ASSERT_NOT_NULL(test, f);
	nn = f->mapping->registration->nn;
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_provider_install(nn, &ffv2_read_ops, f, 4096),
			0);
	f->mapping->args.ffv2_digest_valid = false;
	f->mapping->args.ffv2_decode_class = NFSD4_FFV2_DECODE_BADXDR;
	FFV2_EXPECT_STATUS(test, ffv2_read_handle(f, OP_CHUNK_READ, 1),
			   nfserr_bad_xdr);
	f->mapping->args.ffv2_digest_valid = true;
	f->trust.stateid.si_generation++;
	FFV2_EXPECT_STATUS(test, ffv2_read_handle(f, OP_CHUNK_READ, 1),
			   nfserr_bad_stateid);
	f->trust.stateid.si_generation--;
	f->mapping->rqst.rq_cred.cr_principal = "other@KUNIT";
	FFV2_EXPECT_STATUS(test, ffv2_read_handle(f, OP_CHUNK_READ, 1),
			   nfserr_acces);
	f->mapping->rqst.rq_cred.cr_principal = (char *)f->trust.principal;
	KUNIT_EXPECT_EQ_MSG(test, atomic_read(&f->calls), 0,
			    "authority before provider dispatch");
	FFV2_EXPECT_STATUS(test, ffv2_read_handle(f, OP_CHUNK_READ, 1), nfs_ok);
	KUNIT_EXPECT_EQ(test, atomic_read(&f->calls), 1);
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
struct ffv2_proto_fixture;
static int ffv2_proto_race_hook(struct ffv2_proto_fixture *f,
				enum nfsd_ffv2_prototype_test_site site);
/* Only handle resolution and provisioned files are synthetic. */
struct ffv2_proto_fixture {
	struct nfsd_ffv2_registration_fixture *ordinary;
	struct ffv2_proto_closer *closer;
	int drain_site;
	bool observed_wait;
	struct nfsd_ffv2_mapping_fixture *mapping;
	struct nfsd_ffv2_prototype_test hooks;
	struct nfsd_ffv2_recovery_input input;
	struct nfsd_ffv2_prototype_request request;
	struct nfsd_ffv2_prototype_bundle bundle;
	struct dentry *second;
	struct knfsd_fh inner[2];
	u8 persisted[2][32];
	u8 nonce[32];
	u32 calls[2];
	int fail_site;
	u32 fail_member;
	int pause_site;
	struct completion entered;
	struct completion resume;
	atomic_t hook_timeout;
	unsigned int open_admissions;
	unsigned int releases;
	struct nfsd_ffv2_admission *release_probe;
	bool release_pinned;
	bool stop_ready;
	struct nfsd_ffv2_generation *stopped;
	bool busy_check;
	int busy_result;
	int challenge_result;
};

static int ffv2_proto_event(void *data, enum nfsd_ffv2_prototype_test_site site, u32 member)
{
	struct ffv2_proto_fixture *f = data;

	if (site == NFSD_FFV2_TEST_PROTO_STORE_OPEN)
		f->open_admissions = nfsd_ffv2_test_active_admissions(f->ordinary->nn);
	if (ffv2_proto_race_hook(f, site))
		return -ETIMEDOUT;
	if (site == NFSD_FFV2_TEST_PROTO_RELEASE) {
		f->releases++;
		if (f->release_probe)
			f->release_pinned = !!f->release_probe->provider;
	}
	if (site == NFSD_FFV2_TEST_PROTO_STORE_OPEN && f->busy_check) {
		struct nfsd_ffv2_prototype_bundle *bundle = kzalloc_obj(*bundle, GFP_KERNEL);
		u8 nonce[32];
		u64 expires;

		f->busy_check = false;
		nfsd_ffv2_prototype_test_age(f->ordinary->nn, f->nonce);
		f->challenge_result = nfsd_ffv2_prototype_challenge(f->ordinary->nn,
								    f->ordinary->net, nonce,
								    &expires);
		if (bundle) {
			f->busy_result = nfsd_ffv2_prototype_register(f->ordinary->nn,
								      f->ordinary->net, &f->request,
								      bundle);
			kfree(bundle);
		}
	}

	if (site == NFSD_FFV2_TEST_PROTO_READY && f->stop_ready) {
		f->stop_ready = false;
		mutex_lock(&nfsd_mutex);
		f->stopped = nfsd_ffv2_service_stop_begin(f->ordinary->nn);
		mutex_unlock(&nfsd_mutex);
	}
	if (READ_ONCE(f->pause_site) == site) {
		complete(&f->entered);
		if (!wait_for_completion_timeout(&f->resume, 5 * HZ)) {
			atomic_inc(&f->hook_timeout);
			return -ETIMEDOUT;
		}
	}
	if (f->fail_site == site && f->fail_member == member) {
		f->fail_site = -1;
		return -EIO;
	}
	return 0;
}

static int ffv2_proto_resolve(void *data, const u8 *handle, u32 len, struct svc_fh *fhp)
{
	struct ffv2_proto_fixture *f = data;
	struct nfsd_ffv2_registration_fixture *o = f->ordinary;
	struct svc_export *exp;
	__be32 status;
	u32 member;
	int error;

	for (member = 0; member < 2; member++)
		if (len == f->inner[member].fh_size &&
		    !memcmp(handle, f->inner[member].fh_raw, len))
			break;
	if (member == 2)
		return -ESTALE;
	/* Each retry resolves the current cache export; no arming pins its predecessor. */
	exp = nfsd_ffv2_export_lookup(o->nn->svc_export_cache, o->domain, &o->root);
	if (IS_ERR(exp))
		return PTR_ERR(exp);
	fh_init(fhp, NFS4_FHSIZE);
	status = fh_compose(fhp, exp, member ? f->second : o->object, NULL);
	error = status ? -ESTALE : 0;
	if (!error) {
		fhp->fh_ffv2_admitted = true;
		f->calls[member]++;
	}
	exp_put(exp);
	if (error)
		fh_put(fhp);
	return error;
}

static void ffv2_proto_exit(void *data)
{
	struct ffv2_proto_fixture *f = data;

	complete_all(&f->resume);
	if (f->mapping)
		nfsd_ffv2_mapping_exit(f->mapping);
	nfsd_ffv2_prototype_net_pre_exit(f->ordinary->nn);
	WRITE_ONCE(f->ordinary->nn->ffv2.test_prototype, NULL);
	if (f->second) {
		d_drop(f->second);
		dput(f->second);
	}
}

static struct ffv2_proto_fixture *ffv2_proto_fixture(struct kunit *test)
{
	struct ffv2_proto_fixture *f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	struct nfsd_ffv2_registration_fixture *o;
	struct qstr name = QSTR_INIT("member1", 7);
	struct svc_export *exp;
	struct svc_fh fh;
	u32 i;
	u64 expires;
	int error;

	if (!f)
		return NULL;
	o = nfsd_ffv2_registration_fixture(test);
	if (!o)
		return NULL;
	f->ordinary = o;
	nfsd_ffv2_store_test_provision(test, &f->input, f->persisted, o->uuid, o->token);
	if (!f->input.files[0])
		return NULL;
	init_completion(&f->entered);
	init_completion(&f->resume);
	f->pause_site = -1;
	f->fail_site = -1;
	if (kunit_add_action_or_reset(test, ffv2_proto_exit, f))
		return NULL;
	inode_lock(d_inode(o->root.dentry));
	f->second = lookup_one(mnt_idmap(o->root.mnt), &name, o->root.dentry);
	if (IS_ERR(f->second)) {
		error = PTR_ERR(f->second);
		f->second = NULL;
	} else {
		error = vfs_create(mnt_idmap(o->root.mnt), f->second, 0600, NULL);
	}
	inode_unlock(d_inode(o->root.dentry));
	if (error)
		goto fail;
	exp = nfsd_ffv2_export_lookup(o->nn->svc_export_cache, o->domain, &o->root);
	if (IS_ERR(exp)) {
		error = PTR_ERR(exp);
		goto fail;
	}
	for (i = 0; i < 2; i++) {
		fh_init(&fh, NFS4_FHSIZE);
		if (fh_compose(&fh, exp, i ? f->second : o->object, NULL)) {
			fh_put(&fh);
			exp_put(exp);
			goto fail;
		}
		f->inner[i] = fh.fh_handle;
		fh_put(&fh);
	}
	exp_put(exp);
	f->hooks.event = ffv2_proto_event;
	f->hooks.resolve = ffv2_proto_resolve;
	f->hooks.data = f;
	f->hooks.input = &f->input;
	WRITE_ONCE(o->nn->ffv2.test_prototype, &f->hooks);
	error = nfsd_ffv2_prototype_enable(o->nn, o->net);
	if (error)
		goto fail;
	error = nfsd_ffv2_prototype_challenge(o->nn, o->net, f->nonce, &expires);
	if (error)
		goto fail;
	f->request.nonce = f->nonce;
	f->request.auth_domain = o->domain->name;
	f->request.chunk_size = 4096;
	f->request.data_count = 1;
	f->request.parity_count = 1;
	f->request.object_count = 2;
	f->request.store_uuid = f->input.store_uuid;
	f->request.binding_token = f->input.binding_token;
	f->request.writer_id = 17;
	f->request.pnfs_clientid = 0x0123456789abcdefULL;
	for (i = 0; i < 2; i++) {
		f->request.objects[i].handle = f->inner[i].fh_raw;
		f->request.objects[i].handle_len = f->inner[i].fh_size;
		f->request.objects[i].persisted_handle = f->persisted[i];
	}
	return f;
fail:
	KUNIT_FAIL(test, "prototype fixture failed: %d", error);
	return NULL;
}

static int ffv2_proto_register(struct ffv2_proto_fixture *f)
{
	return nfsd_ffv2_prototype_register(f->ordinary->nn, f->ordinary->net, &f->request,
					    &f->bundle);
}

static void ffv2_proto_constructor_test(struct kunit *test)
{
	struct ffv2_proto_fixture *f = ffv2_proto_fixture(test);
	struct nfsd_ffv2_prototype_bundle *saved;
	struct nfsd_ffv2_export_update registration;
	struct nfsd_ffv2_registration_fixture *o;
	u32 i;
	int error;

	KUNIT_ASSERT_NOT_NULL(test, f);
	o = f->ordinary;
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_prototype_ds_role(o->nn));
	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_registration_begin(o->nn, &registration);
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, error, -EBUSY);
	KUNIT_ASSERT_EQ(test, ffv2_proto_register(f), 0);
	KUNIT_EXPECT_EQ_MSG(test, f->open_admissions, 1U, "store open validation admission");
	KUNIT_EXPECT_EQ(test, f->bundle.object_count, 2U);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_prototype_state_get(o->nn), NFSD_FFV2_PROTOTYPE_READY);
	KUNIT_EXPECT_NE(test,
			memcmp(f->bundle.objects[0].stateid, f->bundle.objects[1].stateid, 16), 0);
	for (i = 0; i < 2; i++) {
		struct nfsd_ffv2_fh_info info;
		struct knfsd_fh outer = {};

		outer.fh_size = f->bundle.objects[i].handle_len;
		memcpy(outer.fh_raw, f->bundle.objects[i].handle, outer.fh_size);
		KUNIT_ASSERT_EQ(test, nfsd_ffv2_fh_parse(&outer, &info), 0);
		KUNIT_EXPECT_MEMEQ(test, info.object_uuid, f->persisted[i] + 16, 16);
	}
	saved = kunit_kzalloc(test, sizeof(*saved), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, saved);
	memcpy(saved, &f->bundle, sizeof(*saved));
	KUNIT_EXPECT_EQ_MSG(test, ffv2_proto_register(f), 0, "exact retry");
	KUNIT_EXPECT_MEMEQ(test, &f->bundle, saved, sizeof(*saved));
	f->request.writer_id++;
	KUNIT_EXPECT_EQ_MSG(test, ffv2_proto_register(f), -EEXIST, "changed writer");
	f->request.writer_id--;
	f->request.pnfs_clientid++;
	KUNIT_EXPECT_EQ_MSG(test, ffv2_proto_register(f), -EEXIST, "changed native clientid");
	f->request.pnfs_clientid--;
	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_object_unregister(o->nn, f->bundle.generation, f->bundle.source_uuid);
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ_MSG(test, error, -ENOENT, "immutable unregister kind");
	KUNIT_EXPECT_EQ(test, ffv2_proto_register(f), 0);
	KUNIT_EXPECT_EQ(test,
			nfsd_ffv2_prototype_unregister(o->nn, o->net, f->bundle.source_uuid,
						       f->bundle.generation),
			0);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_source_get(o->nn), NFSD_FFV2_SOURCE_NONE);
	KUNIT_EXPECT_FALSE(test, nfsd_ffv2_prototype_ds_role(o->nn));
}

static int ffv2_proto_seed(struct nfsd_ffv2_registration_fixture *o)
{
	struct svc_export *exp =
		nfsd_ffv2_export_lookup(o->nn->svc_export_cache, o->domain, &o->root);

	if (IS_ERR(exp))
		return nfsd_ffv2_registration_seed(o);
	exp_put(exp);
	return 0;
}

static void ffv2_proto_failure_test(struct kunit *test)
{
	static const enum nfsd_ffv2_prototype_test_site sites[] = {
		NFSD_FFV2_TEST_PROTO_WORK_ALLOC,   NFSD_FFV2_TEST_PROTO_RESOLVE,
		NFSD_FFV2_TEST_PROTO_AUTH_ALLOC,   NFSD_FFV2_TEST_PROTO_OBJECT_ALLOC,
		NFSD_FFV2_TEST_PROTO_PUBLISHED,	   NFSD_FFV2_TEST_PROTO_PROVIDER_ALLOC,
		NFSD_FFV2_TEST_PROTO_STORE_OPEN,   NFSD_FFV2_TEST_PROTO_STORE_ALLOC,
		NFSD_FFV2_TEST_PROTO_SUPER_FILE,   NFSD_FFV2_TEST_PROTO_WAL_FILE,
		NFSD_FFV2_TEST_PROTO_PAYLOAD_FILE, NFSD_FFV2_TEST_PROTO_FILE_LOOKUP,
		NFSD_FFV2_TEST_PROTO_ADMITTED,	   NFSD_FFV2_TEST_PROTO_PROVIDER,
		NFSD_FFV2_TEST_PROTO_TRUST,	   NFSD_FFV2_TEST_PROTO_READY,
	};
	u32 i, j;

	for (i = 0; i < ARRAY_SIZE(sites); i++) {
		struct ffv2_proto_fixture *f = ffv2_proto_fixture(test);
		struct nfsd_ffv2_registration_fixture *o;
		unsigned long refs[3];

		KUNIT_ASSERT_NOT_NULL(test, f);
		o = f->ordinary;
		for (j = 0; j < 3; j++)
			refs[j] = file_count(f->input.files[j]);
		f->fail_site = sites[i];
		f->fail_member = sites[i] == NFSD_FFV2_TEST_PROTO_TRUST ||
						 sites[i] == NFSD_FFV2_TEST_PROTO_OBJECT_ALLOC ?
					 1 :
					 0;
		KUNIT_EXPECT_LT_MSG(test, ffv2_proto_register(f), 0, "stage %u", sites[i]);
		KUNIT_EXPECT_EQ(test, f->fail_site, -1);
		for (j = 0; j < 3; j++)
			KUNIT_EXPECT_EQ_MSG(test, file_count(f->input.files[j]), refs[j],
					    "partial file unwind %u/%u", sites[i], j);
		KUNIT_EXPECT_PTR_EQ(test, o->nn->ffv2.active, NULL);
		KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(o->nn->ffv2.provider), NULL);
		KUNIT_EXPECT_EQ(test, o->nn->ffv2.prototype.users, 0U);
		KUNIT_EXPECT_EQ(test, atomic_read(&o->nn->ffv2.test_registration.contexts), 0);
		KUNIT_EXPECT_EQ(test, atomic_read(&o->nn->ffv2.test_registration.authorities), 0);
		KUNIT_ASSERT_EQ(test, ffv2_proto_seed(o), 0);
		KUNIT_ASSERT_EQ_MSG(test, ffv2_proto_register(f), 0, "same nonce retry stage %u",
				    sites[i]);
		KUNIT_EXPECT_EQ(test, f->bundle.object_count, 2U);
		KUNIT_EXPECT_GE_MSG(test, f->calls[1], 1U,
				    "current export selected after rollback");
		if (sites[i] == NFSD_FFV2_TEST_PROTO_TRUST)
			KUNIT_EXPECT_GT_MSG(test,
					    get_unaligned_be64(f->bundle.objects[0].stateid + 8),
					    2ULL,
					    "failed registration did not erase durable admissions");
		KUNIT_EXPECT_EQ(test, nfsd_ffv2_prototype_disable(o->nn, o->net), 0);
		for (j = 0; j < 3; j++)
			KUNIT_EXPECT_EQ(test, file_count(f->input.files[j]), refs[j]);
		kunit_release_action(test, ffv2_proto_exit, f);
		kunit_release_action(test, nfsd_ffv2_registration_fixture_exit, o);
	}
}

static void ffv2_proto_identity_test(struct kunit *test)
{
	struct ffv2_proto_fixture *f = ffv2_proto_fixture(test);
	struct nfsd_ffv2_prototype_request changed;

	KUNIT_ASSERT_NOT_NULL(test, f);
	changed = f->request;
	f->request.objects[1] = f->request.objects[0];
	KUNIT_EXPECT_EQ(test, ffv2_proto_register(f), -EEXIST);
	KUNIT_EXPECT_PTR_EQ(test, f->ordinary->nn->ffv2.active, NULL);
	f->request = changed;
	f->request.data_count = U32_MAX;
	KUNIT_EXPECT_EQ(test, ffv2_proto_register(f), -EINVAL);
	f->request = changed;
	f->persisted[1][0] ^= 1;
	KUNIT_EXPECT_EQ(test, ffv2_proto_register(f), -EXDEV);
	f->persisted[1][0] ^= 1;
	KUNIT_EXPECT_EQ_MSG(test, ffv2_proto_register(f), 0, "identity refusals preserve nonce");
}

static struct nfsd_ffv2_mapping_fixture *ffv2_proto_mapping(struct kunit *test,
							    struct ffv2_proto_fixture *f)
{
	static struct svc_xprt_class xcl = { .xcl_max_payload = RPCSVC_MAXPAYLOAD_TCP };
	struct nfsd_ffv2_mapping_fixture *m = kunit_kzalloc(test, sizeof(*m), GFP_KERNEL);

	if (!m)
		return NULL;
	m->registration = f->ordinary;
	m->xprt.xpt_net = f->ordinary->net;
	m->xprt.xpt_class = &xcl;
	m->rqst.rq_xprt = &m->xprt;
	m->rqst.rq_client = f->ordinary->domain;
	m->rqst.rq_cred.cr_flavor = RPC_AUTH_UNIX;
	m->rqst.rq_cred.cr_uid = GLOBAL_ROOT_UID;
	m->rqst.rq_cred.cr_gid = GLOBAL_ROOT_GID;
	m->rqst.rq_cred.cr_group_info = f->ordinary->client.cl_cred.cr_group_info;
	m->rqst.rq_argp = &m->args;
	m->rqst.rq_vers = 4;
	set_bit(RQ_SECURE, &m->rqst.rq_flags);
	m->args.ffv2_digest_valid = true;
	m->cstate.session = &f->ordinary->session;
	fh_init(&m->cstate.current_fh, NFS4_FHSIZE);
	fh_init(&m->cstate.save_fh, NFS4_FHSIZE);
	f->mapping = m;
	return m;
}

static __be32 ffv2_proto_probe(struct ffv2_proto_fixture *f, u32 member, u64 offset, u32 count,
			       struct nfsd_ffv2_chunk_result *result,
			       struct nfsd_ffv2_admission *admission)
{
	struct nfsd_ffv2_chunk_request request = { .offset = offset, .count = count };
	struct nfsd_ffv2_mapping_fixture *m = f->mapping;
	struct knfsd_fh fh = {};
	stateid_t stateid;
	__be32 status;

	fh.fh_size = f->bundle.objects[member].handle_len;
	memcpy(fh.fh_raw, f->bundle.objects[member].handle, fh.fh_size);
	status = nfsd_ffv2_mapping_putfh(m, &fh);
	if (status)
		return status;
	memcpy(&stateid, f->bundle.objects[member].stateid, sizeof(stateid));
	status = nfsd_ffv2_validate_operation(&m->rqst, &m->cstate.current_fh, m->cstate.session,
					      OP_CHUNK_READ, &stateid, NULL, admission);
	if (status)
		return status;
	return nfsd_ffv2_provider_probe(&m->rqst, &m->cstate.current_fh, OP_CHUNK_READ, &request,
					result, NFSD_FFV2_MAX_PAYLOAD_BYTES, admission);
}

static void ffv2_proto_write_input(struct nfsd_ffv2_store_write *request, const u8 *bytes, u32 len,
				   u32 sequence, u64 index)
{
	memset(request, 0, sizeof(*request));
	memset(request->operation.session, 0x77, 16);
	memset(request->operation.request_digest, sequence, 32);
	request->operation.sequence = sequence;
	request->chunk_index = index;
	request->stability = 2;
	request->owner_client_id = 17;
	request->owner_co_id = sequence;
	request->writer_payload_id = 500 + sequence;
	request->guard_check = true;
	request->guard_never_written = true;
	request->activate_if_empty = true;
	request->content = bytes;
	request->content_len = len;
}

static void ffv2_proto_read_test(struct kunit *test)
{
	struct ffv2_proto_fixture *f = ffv2_proto_fixture(test);
	struct nfsd_ffv2_store_write *request;
	struct nfsd_ffv2_store_mutation_result write_result;
	struct nfsd_ffv2_chunk_result result = {};
	struct nfsd_ffv2_admission admission = {};
	u8 *bytes;
	u32 member;
	stateid_t wrong;

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_EQ(test, ffv2_proto_register(f), 0);
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_mapping_key_inner(f->ordinary, &f->inner[0]), 0);
	KUNIT_ASSERT_NOT_NULL(test, ffv2_proto_mapping(test, f));
	bytes = kunit_kmalloc(test, 4096, GFP_KERNEL);
	request = kunit_kzalloc(test, sizeof(*request), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, bytes);
	KUNIT_ASSERT_NOT_NULL(test, request);
	for (member = 0; member < 2; member++) {
		memset(bytes, 0x30 + member, 4096);
		ffv2_proto_write_input(request, bytes, 4096, 1 + member, 0);
		KUNIT_ASSERT_EQ(test,
				nfsd_ffv2_prototype_test_write(f->ordinary->nn, member, request,
							       &write_result),
				0);
		FFV2_EXPECT_STATUS(test, ffv2_proto_probe(f, member, 0, 1, &result, &admission),
				   nfs_ok);
		if (result.count == 1 && result.read.chunks) {
			KUNIT_EXPECT_EQ(test, result.read.chunks[0].cr_payload_id, 501 + member);
			KUNIT_EXPECT_EQ(test, result.read.chunks[0].cr_chunk[0],
					(u8)(0x30 + member));
			KUNIT_EXPECT_EQ_MSG(test, result.read.chunks[0].cr_effective_len, 4096U,
					    "current EOF after registration");
			KUNIT_EXPECT_TRUE(test, result.eof);
			KUNIT_EXPECT_NOT_NULL(test, result.private);
			KUNIT_EXPECT_NOT_NULL(test, result.release);
		} else {
			KUNIT_FAIL(test, "missing member payload");
		}
		nfsd_ffv2_complete(&admission);
		nfsd_ffv2_complete(&admission);
	}
	memcpy(&wrong, f->bundle.objects[0].stateid, sizeof(wrong));
	FFV2_EXPECT_STATUS(test,
			   nfsd_ffv2_validate_operation(&f->mapping->rqst,
							&f->mapping->cstate.current_fh,
							f->mapping->cstate.session, OP_CHUNK_READ,
							&wrong, NULL, &admission),
			   nfserr_bad_stateid);
	nfsd_ffv2_complete(&admission);
	/* Extend only member 1, leaving one sparse chunk between visible writes. */
	memset(bytes, 0x51, 32);
	ffv2_proto_write_input(request, bytes, 32, 3, 2);
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_prototype_test_write(f->ordinary->nn, 1, request, &write_result),
			0);
	FFV2_EXPECT_STATUS(test, ffv2_proto_probe(f, 1, 1, 2, &result, &admission), nfs_ok);
	if (result.count == 2 && result.read.chunks) {
		FFV2_EXPECT_STATUS(test, result.read.chunks[0].cr_status, nfserr_noent);
		KUNIT_EXPECT_EQ(test, result.read.chunks[0].cr_chunk[0], (u8)0);
		KUNIT_EXPECT_EQ(test, result.read.chunks[1].cr_effective_len, 32U);
		KUNIT_EXPECT_EQ(test, result.read.chunks[1].cr_chunk[0], (u8)0x51);
		KUNIT_EXPECT_TRUE(test, result.eof);
	} else {
		KUNIT_FAIL(test, "missing sparse/extended view");
	}
	nfsd_ffv2_complete(&admission);
}

static void ffv2_proto_checksum_test(struct kunit *test)
{
	struct ffv2_proto_fixture *f = ffv2_proto_fixture(test);
	struct nfsd_ffv2_store_write *request;
	struct nfsd_ffv2_store_mutation_result write_result;
	struct nfsd_ffv2_chunk_result result = {};
	struct nfsd_ffv2_admission admission = {};
	u8 bytes[32], bad = 0xff;
	loff_t pos = NFSD_FFV2_PAYLOAD_ALIGN + NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE;

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_EQ(test, ffv2_proto_register(f), 0);
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_mapping_key_inner(f->ordinary, &f->inner[0]), 0);
	KUNIT_ASSERT_NOT_NULL(test, ffv2_proto_mapping(test, f));
	request = kunit_kzalloc(test, sizeof(*request), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, request);
	memset(bytes, 0x31, sizeof(bytes));
	ffv2_proto_write_input(request, bytes, sizeof(bytes), 1, 0);
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_prototype_test_write(f->ordinary->nn, 0, request, &write_result),
			0);
	FFV2_EXPECT_STATUS(test, ffv2_proto_probe(f, 0, 0, 1, &result, &admission), nfs_ok);
	nfsd_ffv2_complete(&admission);
	KUNIT_ASSERT_EQ(test, kernel_write(f->input.files[NFSD_FFV2_IO_PAYLOAD], &bad, 1, &pos),
			(ssize_t)1);
	FFV2_EXPECT_STATUS(test, ffv2_proto_probe(f, 0, 0, 1, &result, &admission), nfserr_io);
	nfsd_ffv2_complete(&admission);
}

/* The closer owns its namespace and context until its final instruction. */
struct ffv2_proto_closer {
	struct net *net;
	struct nfsd_net *nn;
	refcount_t refs;
	struct completion go;
	struct completion done;
	struct completion *waiting;
	bool net_exit;
	int result;
	int expected;
};

static void ffv2_proto_closer_put(struct ffv2_proto_closer *d)
{
	if (refcount_dec_and_test(&d->refs)) {
		put_net(d->net);
		kfree(d);
	}
}

static int ffv2_proto_close_thread(void *data)
{
	struct ffv2_proto_closer *d = data;

	d->result = -ETIMEDOUT;
	if (wait_for_completion_timeout(&d->go, 5 * HZ)) {
		if (d->net_exit) {
			nfsd_ffv2_net_pre_exit(d->nn);
			d->result = 0;
		} else {
			d->result = nfsd_ffv2_prototype_disable(d->nn, d->net);
		}
	}
	complete(&d->done);
	ffv2_proto_closer_put(d);
	return 0;
}

static struct ffv2_proto_closer *ffv2_proto_close_start(struct kunit *test,
							struct ffv2_proto_fixture *f, bool net_exit,
							struct task_struct **task)
{
	struct ffv2_proto_closer *d = kzalloc_obj(*d, GFP_KERNEL);

	if (!d)
		return NULL;
	d->net = get_net(f->ordinary->net);
	d->nn = f->ordinary->nn;
	d->net_exit = net_exit;
	refcount_set(&d->refs, 1);
	init_completion(&d->go);
	init_completion(&d->done);
	*task = kthread_create(ffv2_proto_close_thread, d, "ffv2-prototype-close");
	if (IS_ERR(*task)) {
		ffv2_proto_closer_put(d);
		KUNIT_FAIL(test, "create closer");
		return NULL;
	}
	get_task_struct(*task);
	refcount_inc(&d->refs);
	nfsd_ffv2_test_provider_drain_hook(d->nn, &d->waiting);
	wake_up_process(*task);
	return d;
}

static void ffv2_proto_close_join(struct kunit *test, struct ffv2_proto_closer *d,
				  struct task_struct *task)
{
	unsigned long finished = wait_for_completion_timeout(&d->done, 8 * HZ);

	KUNIT_EXPECT_NE_MSG(test, finished, 0UL, "closer joined after releasing all owners");
	if (finished)
		KUNIT_EXPECT_EQ(test, d->result, d->expected);
	nfsd_ffv2_test_provider_drain_hook(d->nn, NULL);
	put_task_struct(task);
	ffv2_proto_closer_put(d);
}

static bool ffv2_proto_users_waiting(struct nfsd_net *nn)
{
	/* The closer and the fixture retain the namespace throughout observation. */
	return waitqueue_active(&nn->ffv2.prototype.users_wait);
}

static int ffv2_proto_race_hook(struct ffv2_proto_fixture *f,
				enum nfsd_ffv2_prototype_test_site site)
{
	struct ffv2_proto_closer *d = f->closer;
	bool queued;
	int error;

	if (!d || site != f->drain_site)
		return 0;
	if (site == NFSD_FFV2_TEST_PROTO_RESULT) {
		fh_put(&f->mapping->cstate.current_fh);
		fh_put(&f->mapping->cstate.save_fh);
	}
	complete(&d->go);
	if (site == NFSD_FFV2_TEST_PROTO_SETUP) {
		struct completion *waiting = &d->nn->ffv2.prototype.setup_done;

		error = read_poll_timeout(ffv2_provider_wait_queued, queued, queued, 1000, 5000000,
					  false, &waiting);
	} else if (site == NFSD_FFV2_TEST_PROTO_RESULT) {
		error = read_poll_timeout(ffv2_provider_wait_queued, queued, queued, 1000, 5000000,
					  false, &d->waiting);
	} else {
		error = read_poll_timeout(ffv2_proto_users_waiting, queued, queued, 1000, 5000000,
					  false, d->nn);
	}
	if (error)
		atomic_inc(&f->hook_timeout);
	else
		f->observed_wait = true;
	return error;
}

static void ffv2_proto_setup_close_test(struct kunit *test)
{
	struct ffv2_proto_fixture *f = ffv2_proto_fixture(test);
	struct ffv2_proto_closer *d;
	struct task_struct *task;

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_prototype_disable(f->ordinary->nn, f->ordinary->net), 0);
	d = ffv2_proto_close_start(test, f, false, &task);
	KUNIT_ASSERT_NOT_NULL(test, d);
	f->closer = d;
	f->drain_site = NFSD_FFV2_TEST_PROTO_SETUP;
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_prototype_enable(f->ordinary->nn, f->ordinary->net),
			-EBUSY);
	KUNIT_EXPECT_TRUE_MSG(test, f->observed_wait, "close waited for actual setup completion");
	complete(&d->go);
	ffv2_proto_close_join(test, d, task);
	f->closer = NULL;
	KUNIT_EXPECT_EQ(test, atomic_read(&f->hook_timeout), 0);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_source_get(f->ordinary->nn), NFSD_FFV2_SOURCE_NONE);
}

static void ffv2_proto_registration_close_test(struct kunit *test)
{
	struct ffv2_proto_fixture *f = ffv2_proto_fixture(test);
	struct ffv2_proto_closer *d;
	struct task_struct *task;

	KUNIT_ASSERT_NOT_NULL(test, f);
	d = ffv2_proto_close_start(test, f, false, &task);
	KUNIT_ASSERT_NOT_NULL(test, d);
	f->closer = d;
	f->drain_site = NFSD_FFV2_TEST_PROTO_READY;
	KUNIT_EXPECT_EQ_MSG(test, ffv2_proto_register(f), -EBUSY, "close won before READY commit");
	KUNIT_EXPECT_TRUE_MSG(test, f->observed_wait, "close waited for registration user");
	complete(&d->go);
	ffv2_proto_close_join(test, d, task);
	f->closer = NULL;
	KUNIT_EXPECT_EQ(test, atomic_read(&f->hook_timeout), 0);
	KUNIT_EXPECT_EQ(test, f->bundle.generation, 0ULL);
	KUNIT_EXPECT_PTR_EQ(test, f->ordinary->nn->ffv2.active, NULL);
}

static void ffv2_proto_drain_check(struct kunit *test, bool callback, bool net_exit)
{
	struct ffv2_proto_fixture *f = ffv2_proto_fixture(test);
	struct nfsd_ffv2_store_write *request;
	struct nfsd_ffv2_store_mutation_result write_result;
	struct nfsd_ffv2_chunk_result result = {};
	struct nfsd_ffv2_admission admission = {};
	struct ffv2_proto_closer *d, *second = NULL;
	struct task_struct *task, *second_task = NULL;
	u8 bytes[32];
	bool queued;

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_EQ(test, ffv2_proto_register(f), 0);
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_mapping_key_inner(f->ordinary, &f->inner[0]), 0);
	KUNIT_ASSERT_NOT_NULL(test, ffv2_proto_mapping(test, f));
	request = kunit_kzalloc(test, sizeof(*request), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, request);
	memset(bytes, 0x61, sizeof(bytes));
	ffv2_proto_write_input(request, bytes, sizeof(bytes), 1, 0);
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_prototype_test_write(f->ordinary->nn, 0, request, &write_result),
			0);
	d = ffv2_proto_close_start(test, f, net_exit, &task);
	KUNIT_ASSERT_NOT_NULL(test, d);
	f->closer = d;
	f->drain_site = callback ? NFSD_FFV2_TEST_PROTO_RESULT : -1;
	FFV2_EXPECT_STATUS(test, ffv2_proto_probe(f, 0, 0, 1, &result, &admission), nfs_ok);
	if (!callback) {
		fh_put(&f->mapping->cstate.current_fh);
		fh_put(&f->mapping->cstate.save_fh);
		complete(&d->go);
		KUNIT_EXPECT_EQ_MSG(test,
				    read_poll_timeout(ffv2_provider_wait_queued, queued, queued,
						      1000, 5000000, false, &d->waiting),
				    0, "real adapter result drain");
	} else {
		KUNIT_EXPECT_TRUE_MSG(test, f->observed_wait, "real adapter callback drain");
	}
	if (!callback && !net_exit) {
		struct completion *waiting = &d->nn->ffv2.prototype.close_done;

		second = ffv2_proto_close_start(test, f, false, &second_task);
		if (second) {
			second->expected = -EBUSY;
			complete(&second->go);
			KUNIT_EXPECT_EQ_MSG(test,
					    read_poll_timeout(ffv2_provider_wait_queued, queued,
							      queued, 1000, 5000000, false,
							      &waiting),
					    0, "second closer joined actual close wait");
		}
	}
	if (result.count && result.read.chunks)
		KUNIT_EXPECT_EQ(test, result.read.chunks[0].cr_chunk[0], (u8)0x61);
	else
		KUNIT_FAIL(test, "result lost while close waits");
	KUNIT_EXPECT_FALSE(test, completion_done(&d->done));
	nfsd_ffv2_complete(&admission);
	nfsd_ffv2_complete(&admission);
	complete(&d->go);
	ffv2_proto_close_join(test, d, task);
	if (second)
		ffv2_proto_close_join(test, second, second_task);
	f->closer = NULL;
	KUNIT_EXPECT_EQ(test, atomic_read(&f->hook_timeout), 0);
	KUNIT_EXPECT_PTR_EQ(test, f->ordinary->nn->ffv2.active, NULL);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(f->ordinary->nn->ffv2.provider), NULL);
	if (net_exit)
		KUNIT_EXPECT_EQ(test, nfsd_ffv2_prototype_enable(f->ordinary->nn, f->ordinary->net),
				-ESHUTDOWN);
}

static void ffv2_proto_callback_close_test(struct kunit *test)
{
	ffv2_proto_drain_check(test, true, false);
}

static void ffv2_proto_result_close_test(struct kunit *test)
{
	ffv2_proto_drain_check(test, false, false);
}

static void ffv2_proto_callback_exit_test(struct kunit *test)
{
	ffv2_proto_drain_check(test, true, true);
}

static void ffv2_proto_result_exit_test(struct kunit *test)
{
	ffv2_proto_drain_check(test, false, true);
}

static void ffv2_proto_nonce_test(struct kunit *test)
{
	struct ffv2_proto_fixture *f = ffv2_proto_fixture(test);

	KUNIT_ASSERT_NOT_NULL(test, f);
	f->busy_check = true;
	KUNIT_ASSERT_EQ(test, ffv2_proto_register(f), 0);
	KUNIT_EXPECT_EQ_MSG(test, f->busy_result, -EBUSY,
			    "claimed nonce survives reaper and refuses reuse");
	KUNIT_EXPECT_EQ_MSG(test, f->challenge_result, 0, "challenge reaped beside busy nonce");
	KUNIT_EXPECT_EQ(test, ffv2_proto_register(f), 0);
}

static void ffv2_proto_owner_test(struct kunit *test)
{
	struct ffv2_proto_fixture *f = ffv2_proto_fixture(test);
	struct nfsd_ffv2_registration_fixture *o;
	const struct cred *saved;
	struct cred *cred;
	u8 nonce[32];
	u64 expires;
	u32 roles;
	int error;

	KUNIT_ASSERT_NOT_NULL(test, f);
	o = f->ordinary;
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_prototype_challenge(o->nn, &init_net, nonce, &expires),
			-EPERM);
	roles = nfsd4_test_ffv2_roles(o->nn, EXCHGID4_FLAG_USE_PNFS_MDS);
	KUNIT_EXPECT_EQ_MSG(test, roles & EXCHGID4_FLAG_MASK_PNFS,
			    EXCHGID4_FLAG_USE_NON_PNFS | EXCHGID4_FLAG_USE_PNFS_DS,
			    "prototype DS role only");
	cred = prepare_creds();
	KUNIT_ASSERT_NOT_NULL(test, cred);
	cred->uid = make_kuid(current_user_ns(), 99);
	saved = override_creds(cred);
	error = nfsd_ffv2_prototype_disable(o->nn, o->net);
	revert_creds(saved);
	put_cred(cred);
	KUNIT_EXPECT_EQ(test, error, -EPERM);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_prototype_state_get(o->nn), NFSD_FFV2_PROTOTYPE_OPEN);
	KUNIT_ASSERT_EQ(test, ffv2_proto_register(f), 0);
}

static void ffv2_proto_geometry_test(struct kunit *test)
{
	struct ffv2_proto_fixture *f = ffv2_proto_fixture(test);
	u8 *record;
	u32 i, crc;
	loff_t pos;

	KUNIT_ASSERT_NOT_NULL(test, f);
	record = kunit_kmalloc(test, NFSD_FFV2_FILE_REGISTER_RECORD_SIZE, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, record);
	for (i = 0; i < 2; i++) {
		pos = NFSD_FFV2_START_RECORD_SIZE + i * NFSD_FFV2_FILE_REGISTER_RECORD_SIZE;
		KUNIT_ASSERT_EQ(test,
				kernel_read(f->input.files[NFSD_FFV2_IO_WAL], record,
					    NFSD_FFV2_FILE_REGISTER_RECORD_SIZE, &pos),
				(ssize_t)NFSD_FFV2_FILE_REGISTER_RECORD_SIZE);
		put_unaligned_be32(65536, record + 372);
		crc = crc32c(~0U, "FFV2-D2-WAL-v1", sizeof("FFV2-D2-WAL-v1") - 1);
		put_unaligned_be32(~crc32c(crc, record, NFSD_FFV2_FILE_REGISTER_RECORD_SIZE - 4),
				   record + NFSD_FFV2_FILE_REGISTER_RECORD_SIZE - 4);
		pos = NFSD_FFV2_START_RECORD_SIZE + i * NFSD_FFV2_FILE_REGISTER_RECORD_SIZE;
		KUNIT_ASSERT_EQ(test,
				kernel_write(f->input.files[NFSD_FFV2_IO_WAL], record,
					     NFSD_FFV2_FILE_REGISTER_RECORD_SIZE, &pos),
				(ssize_t)NFSD_FFV2_FILE_REGISTER_RECORD_SIZE);
	}
	f->request.chunk_size = 65536;
	KUNIT_EXPECT_EQ_MSG(test, ffv2_proto_register(f), -E2BIG, "total member reply capacity");
}

static void ffv2_proto_allocation_test(struct kunit *test)
{
	struct ffv2_proto_fixture *f = ffv2_proto_fixture(test);
	struct nfsd_ffv2_store_write *request;
	struct nfsd_ffv2_store_mutation_result write_result;
	struct nfsd_ffv2_chunk_result result = {};
	struct nfsd_ffv2_admission admission = {};
	struct nfsd_ffv2_chunk_request header = { .count = 1 };
	u8 bytes[32];
	u32 i, before;

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_EQ(test, ffv2_proto_register(f), 0);
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_mapping_key_inner(f->ordinary, &f->inner[0]), 0);
	KUNIT_ASSERT_NOT_NULL(test, ffv2_proto_mapping(test, f));
	request = kunit_kzalloc(test, sizeof(*request), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, request);
	memset(bytes, 0x31, sizeof(bytes));
	ffv2_proto_write_input(request, bytes, sizeof(bytes), 1, 0);
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_prototype_test_write(f->ordinary->nn, 0, request, &write_result),
			0);
	for (i = 0; i < 4; i++) {
		f->fail_site = NFSD_FFV2_TEST_PROTO_READ_ALLOC;
		f->fail_member = i;
		FFV2_EXPECT_STATUS(test, ffv2_proto_probe(f, 0, 0, 1, &result, &admission),
				   nfserr_jukebox);
		KUNIT_EXPECT_EQ_MSG(test, f->fail_site, -1, "read allocation stage %u", i);
		nfsd_ffv2_complete(&admission);
	}
	before = f->releases;
	f->release_probe = &admission;
	FFV2_EXPECT_STATUS(test, ffv2_proto_probe(f, 0, 0, 1, &result, &admission), nfs_ok);
	FFV2_EXPECT_STATUS(test,
			   nfsd_ffv2_provider_probe(&f->mapping->rqst,
						    &f->mapping->cstate.current_fh,
						    OP_CHUNK_HEADER_READ, &header, &result, 8192,
						    &admission),
			   nfserr_notsupp);
	nfsd_ffv2_complete(&admission);
	nfsd_ffv2_complete(&admission);
	f->release_probe = NULL;
	KUNIT_EXPECT_EQ_MSG(test, f->releases, before + 1, "one adopted real result cleanup");
	KUNIT_EXPECT_TRUE_MSG(test, f->release_pinned, "adapter release retains provider");
}

static int ffv2_proto_netlink(struct ffv2_proto_fixture *f)
{
	struct nfsd_ffv2_registration_fixture *o = f->ordinary;
	struct nlattr *attrs[NFSD_A_FFV2_PROTOTYPE_MAX + 1] = {};
	struct genl_info info = { .attrs = attrs,
				  .family = &nfsd_nl_family,
				  .snd_portid = o->port,
				  .snd_seq = 23 };
	struct sk_buff *skb = genlmsg_new(4096, GFP_KERNEL);
	struct nlattr *objects, *child, *attr;
	void *hdr;
	u32 i;
	int error, remaining;

	if (!skb)
		return -ENOMEM;
	hdr = genlmsg_put(skb, o->port, 23, &nfsd_nl_family, 0, NFSD_CMD_FFV2_PROTOTYPE_REGISTER);
	if (!hdr || nla_put(skb, NFSD_A_FFV2_PROTOTYPE_NONCE, 32, f->nonce) ||
	    nla_put_string(skb, NFSD_A_FFV2_PROTOTYPE_AUTH_DOMAIN, o->domain->name) ||
	    nla_put_u32(skb, NFSD_A_FFV2_PROTOTYPE_CHUNK_SIZE, f->request.chunk_size) ||
	    nla_put_u32(skb, NFSD_A_FFV2_PROTOTYPE_DATA_COUNT, 1) ||
	    nla_put_u32(skb, NFSD_A_FFV2_PROTOTYPE_PARITY_COUNT, 1) ||
	    nla_put(skb, NFSD_A_FFV2_PROTOTYPE_STORE_UUID, 16, f->input.store_uuid) ||
	    nla_put(skb, NFSD_A_FFV2_PROTOTYPE_BINDING_TOKEN, 32, f->input.binding_token) ||
	    nla_put_u32(skb, NFSD_A_FFV2_PROTOTYPE_WRITER_ID, f->request.writer_id) ||
	    nla_put_u64_64bit(skb, NFSD_A_FFV2_PROTOTYPE_PNFS_CLIENTID, f->request.pnfs_clientid,
			      0))
		goto too_big;
	objects = nla_nest_start(skb, NFSD_A_FFV2_PROTOTYPE_OBJECTS);
	if (!objects)
		goto too_big;
	for (i = 0; i < 2; i++) {
		child = nla_nest_start(skb, i);
		if (!child ||
		    nla_put(skb, NFSD_A_FFV2_PROTOTYPE_OBJECT_ORDINARY_HANDLE, f->inner[i].fh_size,
			    f->inner[i].fh_raw) ||
		    nla_put(skb, NFSD_A_FFV2_PROTOTYPE_OBJECT_PERSISTED_HANDLE, 32,
			    f->persisted[i]))
			goto too_big;
		nla_nest_end(skb, child);
	}
	nla_nest_end(skb, objects);
	genlmsg_end(skb, hdr);
	info.nlhdr = nlmsg_hdr(skb);
	info.genlhdr = nlmsg_data(info.nlhdr);
	genl_info_net_set(&info, o->net);
	nla_for_each_attr(attr, genlmsg_data(info.genlhdr), genlmsg_len(info.genlhdr), remaining)
		if (nla_type(attr) <= NFSD_A_FFV2_PROTOTYPE_MAX)
			attrs[nla_type(attr)] = attr;
	error = nfsd_nl_ffv2_prototype_register_doit(skb, &info);
	nlmsg_free(skb);
	return error;
too_big:
	nlmsg_free(skb);
	return -EMSGSIZE;
}

static void ffv2_proto_reply_test(struct kunit *test)
{
	struct ffv2_proto_fixture *f = ffv2_proto_fixture(test);
	struct nfsd_ffv2_prototype_bundle *saved;

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_EXPECT_EQ(test, NFSD_CMD_SERVER_STATS_GET, 19);
	KUNIT_EXPECT_EQ(test, NFSD_CMD_FFV2_OBJECT_REGISTER, 20);
	KUNIT_EXPECT_EQ(test, NFSD_CMD_FFV2_OBJECT_UNREGISTER, 21);
	KUNIT_EXPECT_EQ(test, NFSD_CMD_FFV2_PROTOTYPE_ENABLE, 22);
	KUNIT_EXPECT_EQ(test, NFSD_CMD_FFV2_PROTOTYPE_UNREGISTER, 26);
	atomic_set(&f->ordinary->nn->ffv2.test_registration.fault, NFSD_FFV2_TEST_REPLY_ALLOC);
	KUNIT_EXPECT_EQ(test, ffv2_proto_netlink(f), -ENOMEM);
	KUNIT_EXPECT_EQ_MSG(test, nfsd_ffv2_prototype_state_get(f->ordinary->nn),
			    NFSD_FFV2_PROTOTYPE_READY, "prototype reply loss retains READY");
	KUNIT_ASSERT_EQ(test, ffv2_proto_register(f), 0);
	saved = kunit_kzalloc(test, sizeof(*saved), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, saved);
	memcpy(saved, &f->bundle, sizeof(*saved));
	atomic_set(&f->ordinary->nn->ffv2.test_registration.fault, NFSD_FFV2_TEST_REPLY_SEND);
	KUNIT_EXPECT_EQ(test, ffv2_proto_netlink(f), -ECONNREFUSED);
	KUNIT_EXPECT_EQ(test, ffv2_proto_register(f), 0);
	KUNIT_EXPECT_MEMEQ(test, &f->bundle, saved, sizeof(*saved));
	KUNIT_EXPECT_EQ(test, ffv2_proto_netlink(f), 0);
}

static void ffv2_proto_stop_ready_test(struct kunit *test)
{
	struct ffv2_proto_fixture *f = ffv2_proto_fixture(test);

	KUNIT_ASSERT_NOT_NULL(test, f);
	f->stop_ready = true;
	KUNIT_EXPECT_EQ_MSG(test, ffv2_proto_register(f), -EBUSY, "service stop won before READY");
	nfsd_ffv2_service_stop_finish(f->ordinary->nn, f->stopped);
	f->stopped = NULL;
	KUNIT_EXPECT_PTR_EQ(test, f->ordinary->nn->ffv2.active, NULL);
	KUNIT_EXPECT_PTR_EQ(test, rcu_access_pointer(f->ordinary->nn->ffv2.provider), NULL);
}

static void ffv2_proto_setup_failure_test(struct kunit *test)
{
	struct ffv2_proto_fixture *f = ffv2_proto_fixture(test);

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_EQ(test, nfsd_ffv2_prototype_disable(f->ordinary->nn, f->ordinary->net), 0);
	f->fail_site = NFSD_FFV2_TEST_PROTO_SETUP;
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_prototype_enable(f->ordinary->nn, f->ordinary->net),
			-ENOMEM);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_prototype_state_get(f->ordinary->nn),
			NFSD_FFV2_PROTOTYPE_OFF);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_source_get(f->ordinary->nn), NFSD_FFV2_SOURCE_NONE);
	KUNIT_EXPECT_PTR_EQ(test, f->ordinary->nn->ffv2.prototype.ctx, NULL);
	KUNIT_EXPECT_EQ(test, nfsd_ffv2_prototype_enable(f->ordinary->nn, f->ordinary->net), 0);
}

/* Synthetic authority and shmem files feed the production mutation path. */
struct ffv2_mutation_fixture {
	struct ffv2_proto_fixture *proto;
	struct nfsd4_compoundres response;
	struct nfsd4_slot *slot;
	struct nfsd4_op op;
	u8 *wire;
	u32 len;
};

static struct ffv2_mutation_fixture *ffv2_mutation_fixture(struct kunit *test)
{
	struct ffv2_mutation_fixture *f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	struct nfsd_ffv2_mapping_fixture *m;
	u32 i;

	if (!f)
		return NULL;
	f->proto = ffv2_proto_fixture(test);
	f->slot = kunit_kzalloc(test, sizeof(*f->slot), GFP_KERNEL);
	f->wire = kunit_kzalloc(test, 2 * (4096 + 256), GFP_KERNEL);
	if (!f->proto || !f->slot || !f->wire || ffv2_proto_register(f->proto))
		return NULL;
	for (i = 0; i < 2; i++)
		if (nfsd_ffv2_mapping_key_inner(f->proto->ordinary, &f->proto->inner[i]))
			return NULL;
	m = ffv2_proto_mapping(test, f->proto);
	if (!m)
		return NULL;
	memcpy(&f->proto->ordinary->client.cl_clientid, &f->proto->request.pnfs_clientid,
	       sizeof(clientid_t));
	memset(&m->cstate.session->se_sessionid, 0x57, 16);
	m->cstate.slot = f->slot;
	f->slot->sl_index = 3;
	f->slot->sl_seqid = 1;
	m->rqst.rq_resp = &f->response;
	m->rqst.rq_res.buflen = 65536;
	f->response.rqstp = &m->rqst;
	f->response.opcnt = 1;
	return f;
}

static int ffv2_mutation_map(struct ffv2_mutation_fixture *f, u32 member)
{
	struct knfsd_fh fh = {};

	fh.fh_size = f->proto->bundle.objects[member].handle_len;
	memcpy(fh.fh_raw, f->proto->bundle.objects[member].handle, fh.fh_size);
	return nfsd_ffv2_mapping_putfh(f->proto->mapping, &fh) == nfs_ok ? 0 : -ESTALE;
}

static __be32 *ffv2_mutation_wire(struct ffv2_mutation_fixture *f, __be32 *p, u32 member, u32 op,
				  u64 index, u32 len, u32 stable, u32 owner)
{
	*p++ = cpu_to_be32(op);
	memcpy(p, f->proto->bundle.objects[member].stateid, sizeof(stateid_t));
	*p = cpu_to_be32(((stateid_t *)f->proto->bundle.objects[member].stateid)->si_generation);
	p += 4;
	*p++ = cpu_to_be32(index >> 32);
	*p++ = cpu_to_be32(index);
	if (op == OP_CHUNK_WRITE) {
		*p++ = cpu_to_be32(stable);
	} else {
		*p++ = cpu_to_be32(1);
		*p++ = cpu_to_be32(1);
	}
	*p++ = 0;
	*p++ = 0;
	*p++ = cpu_to_be32(17);
	if (op == OP_CHUNK_WRITE)
		*p++ = cpu_to_be32(1);
	*p++ = cpu_to_be32(owner);
	if (op != OP_CHUNK_WRITE)
		return p;
	*p++ = cpu_to_be32(700 + owner);
	*p++ = cpu_to_be32(1);
	*p++ = cpu_to_be32(1);
	*p++ = 0;
	*p++ = 0;
	*p++ = cpu_to_be32(4096);
	*p++ = cpu_to_be32(1);
	*p++ = 0;
	*p++ = 0;
	*p++ = cpu_to_be32(len);
	memset(p, 0x30 + member, len);
	return p + XDR_QUADLEN(len);
}

static bool ffv2_mutation_decode(struct kunit *test, struct ffv2_mutation_fixture *f, u32 member,
				 u32 op, u32 sequence, u64 index, u32 len, u32 stable, u32 owner)
{
	struct nfsd_ffv2_mapping_fixture *m = f->proto->mapping;
	__be32 *p = (__be32 *)f->wire;

	if (ffv2_mutation_map(f, member))
		return false;
	*p++ = 0;
	*p++ = cpu_to_be32(2);
	*p++ = cpu_to_be32(1);
	p = ffv2_mutation_wire(f, p, member, op, index, len, stable, owner);
	f->len = (u8 *)p - f->wire;
	if (!nfsd_ffv2_test_compound_decode(test, &m->args, f->wire, f->len, f->len, 0))
		return false;
	f->slot->sl_seqid = sequence;
	f->response.opcnt = 1;
	f->op = m->args.ops[0];
	return f->op.status == nfs_ok && m->args.ffv2_digest_valid;
}

static __be32 ffv2_mutation_handle(struct ffv2_mutation_fixture *f)
{
	struct nfsd_ffv2_mapping_fixture *m = f->proto->mapping;

	f->op.status = nfsd4_test_ffv2_run_op(&m->rqst, &m->cstate, f->op.opnum, &f->op.u);
	return f->op.status;
}

static void ffv2_mutation_encode(struct ffv2_mutation_fixture *f, void *wire, u32 size)
{
	struct svc_rqst *rqstp = &f->proto->mapping->rqst;
	struct xdr_stream xdr;

	memset(&rqstp->rq_res, 0, sizeof(rqstp->rq_res));
	rqstp->rq_res.head[0].iov_base = wire;
	rqstp->rq_res.buflen = size;
	xdr_init_encode(&xdr, &rqstp->rq_res, NULL, NULL);
	f->response.xdr = &xdr;
	if (size < 13 * XDR_UNIT)
		f->op.status = nfsd4_test_encode_ffv2_mutation(&xdr, f->op.opnum, &f->op.u);
	else
		nfsd4_encode_operation(&f->response, &f->op);
	nfsd_ffv2_test_release_op(&f->op);
	rqstp->rq_res.buflen = 65536;
}

static void
ffv2_mutation_state(struct ffv2_mutation_fixture *f, struct nfsd_ffv2_recovery_state *state)
{
	nfsd_ffv2_prototype_test_store_state(f->proto->ordinary->nn, state);
}

static void ffv2_mutation_members_test(struct kunit *test)
{
	struct ffv2_mutation_fixture *f = ffv2_mutation_fixture(test);
	struct nfsd_ffv2_recovery_state state, before, after;
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_ffv2_admission admission = {};
	__be32 wire[32];
	u32 member, op, sequence = 1;

	KUNIT_ASSERT_NOT_NULL(test, f);
	/* Bind the higher admission first, then the lower admission. */
	for (member = 2; member-- > 0;) {
		KUNIT_ASSERT_TRUE(test,
				  ffv2_mutation_decode(test, f, member, OP_CHUNK_WRITE, sequence++,
						       0, 32, NFS_UNSTABLE, member + 1));
		FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
		FFV2_EXPECT_STATUS(test, f->op.u.ffv2.result_status, nfs_ok);
		KUNIT_EXPECT_FALSE(test, f->op.u.ffv2.result_activated);
		KUNIT_EXPECT_EQ(test, f->op.u.ffv2.result_bytes, 32U);
		ffv2_mutation_encode(f, wire, sizeof(wire));
		KUNIT_EXPECT_EQ_MSG(test, be32_to_cpu(wire[2]), 1U, "accepted chunks, not bytes");
		for (op = OP_CHUNK_FINALIZE;; op = OP_CHUNK_COMMIT) {
			KUNIT_ASSERT_TRUE(test,
					  ffv2_mutation_decode(test, f, member, op, sequence++, 0,
							       0, 0, member + 1));
			FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
			FFV2_EXPECT_STATUS(test, f->op.u.ffv2.result_status, nfs_ok);
			ffv2_mutation_state(f, &before);
			FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
			ffv2_mutation_state(f, &after);
			KUNIT_EXPECT_MEMEQ(test, &before, &after, sizeof(before));
			ffv2_mutation_encode(f, wire, sizeof(wire));
			KUNIT_EXPECT_EQ(test, be32_to_cpu(wire[4]), 1U);
			FFV2_EXPECT_STATUS(test, wire[5], nfs_ok);
			if (op == OP_CHUNK_COMMIT)
				break;
		}
		FFV2_EXPECT_STATUS(test,
				   ffv2_proto_probe(f->proto, member, 0, 1, &result, &admission),
				   nfs_ok);
		if (result.count == 1 && result.read.chunks) {
			KUNIT_EXPECT_EQ(test, result.read.chunks[0].cr_effective_len, 32U);
			KUNIT_EXPECT_EQ(test, result.read.chunks[0].cr_payload_id, 701U + member);
			KUNIT_EXPECT_EQ(test, result.read.chunks[0].cr_chunk[0],
					(u8)(0x30 + member));
		} else {
			KUNIT_FAIL(test, "missing committed member data");
		}
		nfsd_ffv2_complete(&admission);
	}
	ffv2_mutation_state(f, &state);
	KUNIT_EXPECT_EQ(test, state.transactions, 2U);
	KUNIT_EXPECT_EQ(test, state.receipts, 6U);
}

static void ffv2_mutation_replay_test(struct kunit *test)
{
	struct ffv2_mutation_fixture *f = ffv2_mutation_fixture(test);
	struct nfsd_ffv2_recovery_state before, after;
	struct nfsd4_ffv2 frozen;

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_TRUE(test, ffv2_mutation_decode(test, f, 1, OP_CHUNK_WRITE, 9, 0, 32,
						     NFS_FILE_SYNC, 8));
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
	frozen = f->op.u.ffv2;
	KUNIT_EXPECT_TRUE(test, frozen.result_activated);
	ffv2_mutation_state(f, &before);
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
	KUNIT_EXPECT_MEMEQ(test, f->op.u.ffv2.result_verifier.data, frozen.result_verifier.data, 8);
	KUNIT_EXPECT_EQ(test, f->op.u.ffv2.result_activated, frozen.result_activated);
	ffv2_mutation_state(f, &after);
	KUNIT_EXPECT_MEMEQ(test, &before, &after, sizeof(before));
	/* Change a tag byte through the complete compound decoder. */
	put_unaligned_be32(1, f->wire);
	memmove(f->wire + 8, f->wire + 4, f->len - 4);
	memset(f->wire + 4, 0, 4);
	f->wire[4] = 'x';
	f->len += 4;
	KUNIT_ASSERT_TRUE(test, nfsd_ffv2_test_compound_decode(test, &f->proto->mapping->args,
							       f->wire, f->len, f->len, 0));
	f->op = f->proto->mapping->args.ops[0];
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
	FFV2_EXPECT_STATUS_MSG(test, f->op.u.ffv2.result_status, nfserr_seq_false_retry,
			       "full transcript participates in durable receipt identity");
	ffv2_mutation_state(f, &after);
	KUNIT_EXPECT_MEMEQ(test, &before, &after, sizeof(before));
}

static void ffv2_mutation_ordinal_test(struct kunit *test)
{
	struct ffv2_mutation_fixture *f = ffv2_mutation_fixture(test);
	struct nfsd_ffv2_recovery_state state;
	struct nfsd_ffv2_mapping_fixture *m;
	__be32 *p;
	u32 i;

	KUNIT_ASSERT_NOT_NULL(test, f);
	m = f->proto->mapping;
	KUNIT_ASSERT_EQ(test, ffv2_mutation_map(f, 0), 0);
	p = (__be32 *)f->wire;
	*p++ = 0;
	*p++ = cpu_to_be32(2);
	*p++ = cpu_to_be32(2);
	p = ffv2_mutation_wire(f, p, 0, OP_CHUNK_WRITE, 0, 4096, NFS_FILE_SYNC, 20);
	p = ffv2_mutation_wire(f, p, 0, OP_CHUNK_WRITE, 1, 32, NFS_FILE_SYNC, 21);
	f->len = (u8 *)p - f->wire;
	KUNIT_ASSERT_TRUE(test, nfsd_ffv2_test_compound_decode(test, &m->args, f->wire, f->len,
							       f->len, 0));
	for (i = 0; i < 2; i++) {
		f->op = m->args.ops[i];
		f->response.opcnt = i + 1;
		FFV2_EXPECT_STATUS_MSG(test, ffv2_mutation_handle(f), nfs_ok,
				       "distinct compound ordinal reaches its own mutation");
		KUNIT_EXPECT_EQ(test, f->op.u.ffv2.result_owner_id, 20U + i);
	}
	ffv2_mutation_state(f, &state);
	KUNIT_EXPECT_EQ_MSG(test, state.transactions, 2U, "two durable operations in one compound");
}

static void ffv2_mutation_guards_test(struct kunit *test)
{
	struct ffv2_mutation_fixture *f = ffv2_mutation_fixture(test);
	struct nfsd_ffv2_recovery_state before, after;
	__be32 wire[32];

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_TRUE(test, ffv2_mutation_decode(test, f, 0, OP_CHUNK_WRITE, 1, 0, 32,
						     NFS_FILE_SYNC, 1));
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
	ffv2_mutation_state(f, &before);
	KUNIT_ASSERT_TRUE(test, ffv2_mutation_decode(test, f, 0, OP_CHUNK_WRITE, 2, 0, 32,
						     NFS_UNSTABLE, 2));
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
	FFV2_EXPECT_STATUS_MSG(test, f->op.u.ffv2.result_status, nfserr_chunk_guarded,
			       "occupied chunk refuses the never-written guard");
	KUNIT_EXPECT_FALSE(test, f->op.u.ffv2.result_activated);
	ffv2_mutation_encode(f, wire, sizeof(wire));
	KUNIT_EXPECT_EQ_MSG(test, be32_to_cpu(wire[2]), 0U, "rejected block accepts zero chunks");
	ffv2_mutation_state(f, &after);
	KUNIT_EXPECT_MEMEQ(test, &before, &after, sizeof(before));
	f->op.u.ffv2.guard_never_written = false;
	f->op.u.ffv2.guard_generation = 0;
	f->op.u.ffv2.guard_writer = 17;
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
	FFV2_EXPECT_STATUS(test, f->op.u.ffv2.result_status, nfs_ok);
	KUNIT_ASSERT_TRUE(test, ffv2_mutation_decode(test, f, 0, OP_CHUNK_WRITE, 3, 0, 32,
						     NFS_UNSTABLE, 3));
	f->op.u.ffv2.guard_check = false;
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
	FFV2_EXPECT_STATUS(test, f->op.u.ffv2.result_status, nfserr_chunk_guarded);
	KUNIT_ASSERT_TRUE(test, ffv2_mutation_decode(test, f, 0, OP_CHUNK_COMMIT, 4, 0, 0, 0, 2));
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
	FFV2_EXPECT_STATUS(test, f->op.u.ffv2.result_status, nfserr_inval);
}

static void ffv2_mutation_identity_test(struct kunit *test)
{
	struct ffv2_mutation_fixture *f = ffv2_mutation_fixture(test);
	struct nfsd_ffv2_recovery_state before, after;
	struct nfsd_ffv2_mapping_fixture *m;

	KUNIT_ASSERT_NOT_NULL(test, f);
	m = f->proto->mapping;
	KUNIT_ASSERT_TRUE(test, ffv2_mutation_decode(test, f, 1, OP_CHUNK_WRITE, 1, 0, 32,
						     NFS_FILE_SYNC, 1));
	ffv2_mutation_state(f, &before);
	memcpy(&f->op.u.ffv2.stateid, f->proto->bundle.objects[0].stateid, sizeof(stateid_t));
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfserr_bad_stateid);
	m->args.ffv2_decode_status = nfserr_bad_xdr;
	m->args.ffv2_digest_valid = false;
	m->args.ffv2_decode_class = NFSD4_FFV2_DECODE_BADXDR;
	FFV2_EXPECT_STATUS_MSG(test, ffv2_mutation_handle(f), nfserr_bad_xdr,
			       "saved decode error precedes identity and provider");
	m->args.ffv2_decode_status = nfs_ok;
	m->args.ffv2_digest_valid = true;
	m->args.ffv2_decode_class = NFSD4_FFV2_DECODE_NONE;
	memcpy(&f->op.u.ffv2.stateid, f->proto->bundle.objects[1].stateid, sizeof(stateid_t));
	f->op.u.ffv2.owner_client_id = 18;
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfserr_bad_stateid);
	f->op.u.ffv2.owner_client_id = 17;
	m->args.ffv2_digest_valid = false;
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfserr_notsupp);
	m->args.ffv2_digest_valid = true;
	m->cstate.slot = NULL;
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfserr_serverfault);
	m->cstate.slot = f->slot;
	ffv2_mutation_state(f, &after);
	KUNIT_EXPECT_MEMEQ(test, &before, &after, sizeof(before));
}

static void ffv2_mutation_copy_encode_test(struct kunit *test)
{
	struct ffv2_mutation_fixture *f = ffv2_mutation_fixture(test);
	struct nfsd_ffv2_recovery_state before, after;
	struct nfsd_net *nn;
	__be32 wire[32];
	u32 stage;

	KUNIT_ASSERT_NOT_NULL(test, f);
	nn = f->proto->ordinary->nn;
	KUNIT_ASSERT_TRUE(test, ffv2_mutation_decode(test, f, 0, OP_CHUNK_WRITE, 1, 0, 32,
						     NFS_FILE_SYNC, 1));
	ffv2_mutation_state(f, &before);
	for (stage = 3; stage <= 4; stage++) {
		nn->ffv2.test_registration.read_copy_fault = stage;
		FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f),
				   stage == 3 ? nfserr_jukebox : nfserr_bad_xdr);
		ffv2_mutation_state(f, &after);
		KUNIT_EXPECT_MEMEQ(test, &before, &after, sizeof(before));
	}
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
	ffv2_mutation_state(f, &before);
	ffv2_mutation_encode(f, wire, 5 * XDR_UNIT);
	FFV2_EXPECT_STATUS(test, f->op.status, nfserr_resource);
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
	ffv2_mutation_state(f, &after);
	KUNIT_EXPECT_MEMEQ_MSG(test, &before, &after, sizeof(before),
			       "failed reply preserves exact successful receipt");
	ffv2_mutation_encode(f, wire, sizeof(wire));
	FFV2_EXPECT_STATUS(test, f->op.status, nfs_ok);
	KUNIT_EXPECT_EQ(test, be32_to_cpu(wire[2]), 1U);
}

static void ffv2_mutation_store_failure_test(struct kunit *test)
{
	struct ffv2_mutation_fixture *f = ffv2_mutation_fixture(test);
	struct nfsd_ffv2_recovery_state before, after;
	u8 byte = 1;
	loff_t pos;

	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_TRUE(test, ffv2_mutation_decode(test, f, 0, OP_CHUNK_WRITE, 1, 0, 32,
						     NFS_FILE_SYNC, 1));
	ffv2_mutation_state(f, &before);
	pos = before.wal_cursor;
	KUNIT_ASSERT_EQ(test, kernel_write(f->proto->input.files[NFSD_FFV2_IO_WAL], &byte, 1, &pos),
			(ssize_t)1);
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
	FFV2_EXPECT_STATUS(test, f->op.u.ffv2.result_status, nfserr_io);
	KUNIT_EXPECT_FALSE(test, f->op.u.ffv2.result_activated);
	ffv2_mutation_state(f, &after);
	KUNIT_EXPECT_TRUE(test, after.failed);
	KUNIT_EXPECT_EQ(test, after.transactions, before.transactions);
	KUNIT_EXPECT_EQ(test, after.receipts, before.receipts);
}

/* This provider only tests malformed results and callback/result ownership. */
struct ffv2_mutation_provider {
	struct ffv2_mutation_fixture *fixture;
	struct nfsd_ffv2_admission admission;
	struct ffv2_provider_drain *drain;
	u32 mode;
	u32 releases;
	bool pinned_at_release;
};

static void ffv2_mutation_result_release(void *data)
{
	struct ffv2_mutation_provider *p = data;

	p->releases++;
	p->pinned_at_release = !!p->admission.provider;
}

static __be32 ffv2_mutation_provider_read(void *data, const struct nfsd_ffv2_object *object,
					  const struct nfsd_ffv2_chunk_request *request,
					  struct nfsd_ffv2_chunk_result *result)
{
	return nfserr_notsupp;
}

static __be32 ffv2_mutation_provider_write(void *data, const struct nfsd_ffv2_object *object,
					   const struct nfsd_ffv2_write_request *request,
					   struct nfsd_ffv2_mutation_result *result)
{
	struct ffv2_mutation_provider *p = data;
	bool queued;

	result->count = 1;
	result->bytes = request->payload_len;
	result->stability = request->stability;
	result->owner = request->owner;
	result->private = p;
	result->release = ffv2_mutation_result_release;
	if (p->drain) {
		complete(&p->drain->go);
		if (read_poll_timeout(ffv2_provider_wait_queued, queued, queued, 1000, 5000000,
				      false, &p->drain->waiting))
			return nfserr_io;
	}
	switch (p->mode) {
	case 1:
		result->count = 2;
		break;
	case 2:
		result->bytes--;
		break;
	case 3:
		result->stability = 3;
		break;
	case 4:
		result->owner.co_id++;
		break;
	case 5:
		result->status = cpu_to_be32(0x7fffffff);
		break;
	case 6:
		result->status = nfserr_io;
		result->activated = true;
		break;
	case 7:
		return nfserr_io;
	case 8:
		result->release = NULL;
		break;
	}
	return nfs_ok;
}

static const struct nfsd_ffv2_provider_ops ffv2_mutation_test_ops = {
	.chunk_read = ffv2_mutation_provider_read,
	.chunk_header_read = ffv2_mutation_provider_read,
	.chunk_write = ffv2_mutation_provider_write,
};

static __be32 ffv2_mutation_provider_call(struct ffv2_mutation_provider *p,
					  struct nfsd_ffv2_mutation_result *result)
{
	struct nfsd_ffv2_mapping_fixture *m = p->fixture->proto->mapping;
	struct nfsd_ffv2_write_request request = {
		.payload_len = 32,
		.stability = NFS_FILE_SYNC,
		.owner = { .co_client_id = 17, .co_id = 1 },
	};

	return nfsd_ffv2_provider_mutate(&m->rqst, &m->cstate.current_fh, OP_CHUNK_WRITE, &request,
					 result, &p->admission);
}

static bool ffv2_mutation_provider_admit(struct ffv2_mutation_provider *p)
{
	struct nfsd_ffv2_mapping_fixture *m = p->fixture->proto->mapping;
	struct nfsd_ffv2_actor_id actor = { .client_id = 17, .present = true };

	return nfsd_ffv2_validate_operation(&m->rqst, &m->cstate.current_fh, m->cstate.session,
					    OP_CHUNK_WRITE, &p->fixture->op.u.ffv2.stateid, &actor,
					    &p->admission) == nfs_ok;
}

static void ffv2_mutation_results_test(struct kunit *test)
{
	struct ffv2_mutation_fixture *f = ffv2_mutation_fixture(test);
	struct ffv2_mutation_provider *p;
	struct nfsd_ffv2_mutation_result result;
	u32 mode;

	KUNIT_ASSERT_NOT_NULL(test, f);
	p = kunit_kzalloc(test, sizeof(*p), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, p);
	p->fixture = f;
	KUNIT_ASSERT_TRUE(test, ffv2_mutation_decode(test, f, 0, OP_CHUNK_WRITE, 1, 0, 32,
						     NFS_FILE_SYNC, 1));
	nfsd_ffv2_provider_remove(f->proto->ordinary->nn);
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_provider_install(f->proto->ordinary->nn, &ffv2_mutation_test_ops,
						   p, 4096),
			0);
	for (mode = 0; mode <= 8; mode++) {
		p->mode = mode;
		KUNIT_ASSERT_TRUE(test, ffv2_mutation_provider_admit(p));
		FFV2_EXPECT_STATUS_MSG(test, ffv2_mutation_provider_call(p, &result),
				       mode == 0 ? nfs_ok :
				       mode == 7 ? nfserr_io :
						   nfserr_serverfault,
				       "malformed result mode %u", mode);
		KUNIT_EXPECT_NOT_NULL_MSG(test, p->admission.provider,
					  "refused results retain their provider");
		nfsd_ffv2_complete(&p->admission);
		KUNIT_EXPECT_EQ(test, p->releases, min(mode + 1, 8U));
	}
	KUNIT_EXPECT_TRUE(test, p->pinned_at_release);
}

static void ffv2_mutation_drain_check(struct kunit *test, bool callback)
{
	struct ffv2_mutation_fixture *f = ffv2_mutation_fixture(test);
	struct ffv2_mutation_provider *p;
	struct nfsd_ffv2_mutation_result result;
	struct ffv2_provider_drain *d;
	struct task_struct *task;
	bool queued;

	KUNIT_ASSERT_NOT_NULL(test, f);
	p = kunit_kzalloc(test, sizeof(*p), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, p);
	p->fixture = f;
	KUNIT_ASSERT_TRUE(test, ffv2_mutation_decode(test, f, 0, OP_CHUNK_WRITE, 1, 0, 32,
						     NFS_FILE_SYNC, 1));
	nfsd_ffv2_provider_remove(f->proto->ordinary->nn);
	KUNIT_ASSERT_EQ(test,
			nfsd_ffv2_provider_install(f->proto->ordinary->nn, &ffv2_mutation_test_ops,
						   p, 4096),
			0);
	KUNIT_ASSERT_TRUE(test, ffv2_mutation_provider_admit(p));
	if (!callback) {
		FFV2_EXPECT_STATUS(test, ffv2_mutation_provider_call(p, &result), nfs_ok);
		p->mode = 1;
		FFV2_EXPECT_STATUS_MSG(test, ffv2_mutation_provider_call(p, &result),
				       nfserr_serverfault, "earlier owner survives");
	}
	d = kzalloc_obj(*d, GFP_KERNEL);
	if (!d) {
		nfsd_ffv2_complete(&p->admission);
		KUNIT_FAIL(test, "allocate drain observer");
		return;
	}
	d->net = get_net(f->proto->ordinary->net);
	d->nn = f->proto->ordinary->nn;
	refcount_set(&d->refs, 1);
	init_completion(&d->go);
	init_completion(&d->done);
	task = kthread_create(ffv2_provider_drain_thread, d, "ffv2-mutation-drain");
	if (IS_ERR(task)) {
		nfsd_ffv2_complete(&p->admission);
		ffv2_provider_drain_put(d);
		KUNIT_FAIL(test, "start mutation drain");
		return;
	}
	get_task_struct(task);
	refcount_inc(&d->refs);
	nfsd_ffv2_test_provider_drain_hook(d->nn, &d->waiting);
	wake_up_process(task);
	if (callback) {
		p->drain = d;
		FFV2_EXPECT_STATUS(test, ffv2_mutation_provider_call(p, &result), nfs_ok);
		p->drain = NULL;
	} else {
		complete(&d->go);
	}
	KUNIT_EXPECT_EQ_MSG(test,
			    read_poll_timeout(ffv2_provider_wait_queued, queued, queued, 1000,
					      5000000, false, &d->waiting),
			    0, "mutation result holds actual provider drain wait");
	KUNIT_EXPECT_FALSE(test, completion_done(&d->done));
	nfsd_ffv2_complete(&p->admission);
	KUNIT_EXPECT_EQ(test, p->releases, 1U);
	KUNIT_EXPECT_TRUE(test, p->pinned_at_release);
	KUNIT_EXPECT_NE(test, wait_for_completion_timeout(&d->done, 5 * HZ), 0UL);
	nfsd_ffv2_test_provider_drain_hook(d->nn, NULL);
	put_task_struct(task);
	ffv2_provider_drain_put(d);
}

static void ffv2_mutation_result_drain_test(struct kunit *test)
{
	ffv2_mutation_drain_check(test, false);
}

static void ffv2_mutation_callback_drain_test(struct kunit *test)
{
	ffv2_mutation_drain_check(test, true);
}

static void ffv2_mutation_geometry_test(struct kunit *test)
{
	struct ffv2_mutation_fixture *f = ffv2_mutation_fixture(test);
	struct nfsd_ffv2_recovery_state before, after;
	u32 op;

	KUNIT_ASSERT_NOT_NULL(test, f);
	ffv2_mutation_state(f, &before);
	for (op = OP_CHUNK_COMMIT; op <= OP_CHUNK_WRITE; op++) {
		if (op != OP_CHUNK_COMMIT && op != OP_CHUNK_FINALIZE && op != OP_CHUNK_WRITE)
			continue;
		KUNIT_ASSERT_TRUE(test, ffv2_mutation_decode(test, f, 1, op, op, U64_MAX, 32,
							     NFS_FILE_SYNC, op));
		FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
		FFV2_EXPECT_STATUS_MSG(test, f->op.u.ffv2.result_status, nfserr_inval,
				       "member geometry rejects before indexing store state");
	}
	KUNIT_ASSERT_TRUE(test, ffv2_mutation_decode(test, f, 1, OP_CHUNK_WRITE, 1, 0, 32,
						     NFS_FILE_SYNC, 1));
	f->proto->mapping->rqst.rq_res.buflen = 0;
	FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfserr_resource);
	ffv2_mutation_state(f, &after);
	KUNIT_EXPECT_MEMEQ(test, &before, &after, sizeof(before));
}

static void ffv2_mutation_session_test(struct kunit *test)
{
	struct ffv2_mutation_fixture *f = ffv2_mutation_fixture(test);
	struct nfsd_ffv2_recovery_state state;
	u32 i;

	KUNIT_ASSERT_NOT_NULL(test, f);
	for (i = 0; i < 3; i++) {
		KUNIT_ASSERT_TRUE(test, ffv2_mutation_decode(test, f, 1, OP_CHUNK_WRITE, 1, i, 4096,
							     NFS_FILE_SYNC, i + 1));
		if (i == 1)
			f->slot->sl_index++;
		if (i == 2)
			((u8 *)&f->proto->mapping->cstate.session->se_sessionid)[0]++;
		FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
		FFV2_EXPECT_STATUS_MSG(test, f->op.u.ffv2.result_status, nfs_ok,
				       "session and slot distinguish equal sequence numbers");
	}
	ffv2_mutation_state(f, &state);
	KUNIT_EXPECT_EQ(test, state.receipts, 3U);
}

static void ffv2_mutation_read_handler_test(struct kunit *test)
{
	struct ffv2_mutation_fixture *f = ffv2_mutation_fixture(test);
	struct nfsd4_chunk_read *read;
	u32 member;

	KUNIT_ASSERT_NOT_NULL(test, f);
	for (member = 0; member < 2; member++) {
		KUNIT_ASSERT_TRUE(test,
				  ffv2_mutation_decode(test, f, member, OP_CHUNK_WRITE, member + 1,
						       2, 32, NFS_FILE_SYNC, member + 1));
		FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
		memset(&f->op, 0, sizeof(f->op));
		f->op.opnum = OP_CHUNK_READ;
		read = &f->op.u.chunk_read;
		memcpy(&read->cra_stateid, f->proto->bundle.objects[member].stateid,
		       sizeof(stateid_t));
		read->cra_count = 3;
		FFV2_EXPECT_STATUS(test, ffv2_mutation_handle(f), nfs_ok);
		if (read->cra_nchunks == 3 && read->cra_chunks && read->cra_payload) {
			KUNIT_EXPECT_TRUE(test, read->cra_eof);
			FFV2_EXPECT_STATUS(test, read->cra_chunks[0].cre_status, nfserr_noent);
			FFV2_EXPECT_STATUS(test, read->cra_chunks[2].cre_status, nfs_ok);
			KUNIT_EXPECT_EQ(test, read->cra_chunks[2].cre_effective_len, 32U);
			KUNIT_EXPECT_EQ(test, read->cra_chunks[2].cre_payload_id, 701U + member);
			KUNIT_EXPECT_EQ(test, ((u8 *)read->cra_payload)[8192], (u8)(0x30 + member));
		} else {
			KUNIT_FAIL(test, "missing sparse or partial handler data");
		}
		nfsd_ffv2_test_release_op(&f->op);
	}
}

#endif

static struct kunit_case nfsd_ffv2_test_cases[] = {
#if IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
	KUNIT_CASE(ffv2_mutation_results_test),
	KUNIT_CASE(ffv2_mutation_result_drain_test),
	KUNIT_CASE(ffv2_mutation_callback_drain_test),
	KUNIT_CASE(ffv2_mutation_geometry_test),
	KUNIT_CASE(ffv2_mutation_session_test),
	KUNIT_CASE(ffv2_mutation_read_handler_test),
	KUNIT_CASE(ffv2_mutation_members_test),
	KUNIT_CASE(ffv2_mutation_replay_test),
	KUNIT_CASE(ffv2_mutation_ordinal_test),
	KUNIT_CASE(ffv2_mutation_guards_test),
	KUNIT_CASE(ffv2_mutation_identity_test),
	KUNIT_CASE(ffv2_mutation_copy_encode_test),
	KUNIT_CASE(ffv2_mutation_store_failure_test),

	KUNIT_CASE(ffv2_proto_constructor_test),
	KUNIT_CASE_SLOW(ffv2_proto_failure_test),
	KUNIT_CASE(ffv2_proto_identity_test),
	KUNIT_CASE(ffv2_proto_read_test),
	KUNIT_CASE(ffv2_proto_checksum_test),
	KUNIT_CASE(ffv2_proto_setup_close_test),
	KUNIT_CASE(ffv2_proto_registration_close_test),
	KUNIT_CASE(ffv2_proto_callback_close_test),
	KUNIT_CASE(ffv2_proto_result_close_test),
	KUNIT_CASE(ffv2_proto_callback_exit_test),
	KUNIT_CASE(ffv2_proto_result_exit_test),
	KUNIT_CASE(ffv2_proto_nonce_test),
	KUNIT_CASE(ffv2_proto_owner_test),
	KUNIT_CASE(ffv2_proto_geometry_test),
	KUNIT_CASE(ffv2_proto_allocation_test),
	KUNIT_CASE(ffv2_proto_reply_test),
	KUNIT_CASE(ffv2_proto_stop_ready_test),
	KUNIT_CASE(ffv2_proto_setup_failure_test),
#endif
	KUNIT_CASE(ffv2_header_bounds_test),
	KUNIT_CASE(ffv2_read_authority_test),
	KUNIT_CASE(ffv2_provider_callback_remove_test),
	KUNIT_CASE(ffv2_provider_result_remove_test),
	KUNIT_CASE(ffv2_provider_callback_net_exit_test),
	KUNIT_CASE(ffv2_provider_result_net_exit_test),
	KUNIT_CASE_SLOW(ffv2_provider_replacement_test),

	KUNIT_CASE(ffv2_read_bounds_test),
	KUNIT_CASE(ffv2_read_ownership_test),
	KUNIT_CASE(ffv2_read_copy_encode_test),
	KUNIT_CASE(ffv2_header_copy_encode_test),
	KUNIT_CASE(ffv2_read_failures_test),
	KUNIT_CASE(ffv2_read_validation_test),

	KUNIT_CASE(nfsd_ffv2_trust_drain_test),
	KUNIT_CASE_SLOW(nfsd_ffv2_trust_budget_test),
	KUNIT_CASE(nfsd_ffv2_trust_policy_test),
	KUNIT_CASE(nfsd_ffv2_trust_entries_test),
	KUNIT_CASE(nfsd_ffv2_trust_control_test),
	KUNIT_CASE(nfsd_ffv2_handleless_hold_test),
	KUNIT_CASE(nfsd_ffv2_installer_hold_test),
	KUNIT_CASE(nfsd_ffv2_late_authority_test),
	KUNIT_CASE(nfsd_ffv2_late_generation_test),

	KUNIT_CASE(nfsd_ffv2_service_decode_error_test),
	KUNIT_CASE(nfsd_ffv2_mapping_stop_test),
	KUNIT_CASE_SLOW(nfsd_ffv2_mapping_mixed_test),
	KUNIT_CASE(nfsd_ffv2_service_compound_test),
	KUNIT_CASE(nfsd_ffv2_mapping_target_test),
	KUNIT_CASE(nfsd_ffv2_service_dispatch_test),
	KUNIT_CASE(nfsd_ffv2_mapping_current_test),
	KUNIT_CASE(nfsd_ffv2_mapping_clone_test),
	KUNIT_CASE(nfsd_ffv2_mapping_unwind_test),
	KUNIT_CASE_SLOW(nfsd_ffv2_mapping_identity_test),
	KUNIT_CASE(nfsd_ffv2_mapped_handle_test),
	KUNIT_CASE(nfsd_ffv2_ordinary_registration_test),
	KUNIT_CASE_SLOW(nfsd_ffv2_registration_faults_test),
	KUNIT_CASE_SLOW(nfsd_ffv2_registration_authority_test),
	KUNIT_CASE(nfsd_ffv2_registration_drain_test),
	KUNIT_CASE(nfsd_ffv2_export_completion_test),
	KUNIT_CASE(nfsd_ffv2_registration_overlap_test),
	KUNIT_CASE_SLOW(nfsd_ffv2_registration_close_test),
	KUNIT_CASE(nfsd_ffv2_registration_work_test),
	KUNIT_CASE(nfsd_ffv2_registration_work_failure_test),
	KUNIT_CASE(nfsd_ffv2_registration_work_exit_test),
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
