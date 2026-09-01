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
#include <linux/sunrpc/gss_api.h>
#include <linux/sunrpc/svcsock.h>
#include <linux/sunrpc/svc_xprt.h>
#include <net/net_namespace.h>

#include "ffv2.h"
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
	KUNIT_EXPECT_EQ(test,
			nfsd_ffv2_provider_probe(rqstp, mapped, OP_CHUNK_READ),
			nfserr_notsupp);
	KUNIT_EXPECT_EQ(test,
			nfsd_ffv2_provider_probe(rqstp, mapped,
						 OP_CHUNK_HEADER_READ),
			nfserr_notsupp);
	KUNIT_EXPECT_EQ(test,
			nfsd_ffv2_provider_probe(rqstp, ordinary,
						 OP_CHUNK_READ),
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
	/* The authority paths nest ->client_lock outside the leaf lock. */
	spin_lock_init(&nn->client_lock);
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
	{}
};

static struct kunit_suite nfsd_ffv2_test_suite = {
	.name = "nfsd_ffv2_lifecycle",
	.test_cases = nfsd_ffv2_test_cases,
};

kunit_test_suite(nfsd_ffv2_test_suite);

MODULE_LICENSE("GPL");
