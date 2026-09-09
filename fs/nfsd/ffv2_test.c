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

#include <linux/rtnetlink.h>
#include <linux/net.h>
#include <net/sock.h>
#include <net/genetlink.h>
#include <uapi/linux/nfsd_netlink.h>
#include <uapi/linux/sunrpc_netlink.h>
#include "ffv2.h"
#include "ffv2_prototype.h"
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
			     struct nfsd_ffv2_worker_ctx *worker,
			     int *startup_error)
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
	/*
	 * What the service itself said, kept before the cleanup below can
	 * replace it: a cleanup status describes the cleanup, not the reason
	 * the start failed.
	 */
	if (startup_error)
		*startup_error = error == 1 ? 0 : error;
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

	error = nfsd_ffv2_start_test_service(net, &worker, NULL);
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

	error = nfsd_ffv2_start_test_service(net, &worker, NULL);
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
	error = nfsd_ffv2_start_test_service(net, &worker, NULL);
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
	error = nfsd_ffv2_start_test_service(net, &worker, NULL);
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
	error = nfsd_ffv2_start_test_service(net, NULL, NULL);
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
	error = nfsd_ffv2_start_test_service(net, NULL, NULL);
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
	u64 unadmitted;

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
	 * The boundary requires a *live* admission, and this context has no
	 * generation to take one against, so a zeroed one is refused before
	 * anything else is decided -- ahead of the missing provider and
	 * ahead of the stale binding.  The refusal is counted rather than
	 * warned.  What the refused paths would otherwise report is covered
	 * by the read-only fixture tests, which hold real admissions.
	 */
	unadmitted = nfsd_ffv2_test_provider_unadmitted();
	KUNIT_EXPECT_EQ(test,
			nfsd_ffv2_provider_probe(rqstp, mapped, OP_CHUNK_READ,
						 &chunks, &chunk_result,
						 U32_MAX, &probe_admission),
			nfserr_serverfault);
	KUNIT_EXPECT_EQ(test,
			nfsd_ffv2_provider_probe(rqstp, mapped,
						 OP_CHUNK_HEADER_READ,
						 &chunks, &chunk_result,
						 U32_MAX, &probe_admission),
			nfserr_serverfault);
	KUNIT_EXPECT_EQ(test,
			nfsd_ffv2_provider_probe(rqstp, ordinary,
						 OP_CHUNK_READ,
						 &chunks, &chunk_result,
						 U32_MAX, &probe_admission),
			nfserr_serverfault);
	KUNIT_EXPECT_EQ(test, unadmitted + 3,
			nfsd_ffv2_test_provider_unadmitted());

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

/*
 * A decoded compound asks each operation for its maximum reply size, and
 * the FFv2 read operations answer from the transport's payload limit.  A
 * synthetic request therefore needs enough of a transport and server to be
 * asked, even when the test only cares about decoding.
 */
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
	nfsd_ffv2_test_attach_transport(rqstp);
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
	error = nfsd_ffv2_start_test_service(net, &worker, NULL);
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
	error = nfsd_ffv2_start_test_service(net, &worker, NULL);
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
struct nfsd_ffv2_nl;
static int nfsd_ffv2_nl_flush(struct nfsd_ffv2_nl *nl, u32 mask);
static void nfsd_ffv2_nl_close(struct nfsd_ffv2_nl *nl);

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
	/*
	 * A netlink sender the test handed over, if any.  The fixture owns it
	 * from that point: the phase-four flush needs a live sender after the
	 * threads have stopped, and nothing else may still be sending then.
	 */
	struct nfsd_ffv2_nl		*nl;
	/* The phase-four flush's own result, for the test to assert on. */
	int				nl_flush_error;
	/* Set when the fixture also runs a real service with a listener. */
	struct nfsd_ffv2_worker_ctx	worker;
	bool				worker_installed;
	/* Set once a service may exist, whether or not the start succeeded. */
	bool				service_attempted;
	/* The start's own error, kept apart from any cleanup error. */
	int				service_error;
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

	/*
	 * Teardown in four phases, because the order is not free: stopping
	 * the last nfsd thread drives this namespace's nfsd teardown, and
	 * that waits on FFv2 state.  So the FFv2 side stops first, the
	 * threads join second, and everything the fixture still owns is
	 * released only after both -- while it is all still valid for
	 * whatever is shutting down to look at.
	 */

	/* One: the worker hook stops gating anything. */
	if (f->worker_installed) {
		complete_all(&f->worker.run);
		complete_all(&f->worker.allow_complete);
	}

	/*
	 * Two: admissions stop and the generation and provider retire, with
	 * the export, dentry, root and cache still in place.
	 */
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
	/*
	 * The fixture's own object and its reference to the published export
	 * go here too, before the retirement rather than after it: retiring
	 * the generation waits for them, so releasing them later would be
	 * waiting on something still held.  The export cache itself, the
	 * dentry, the root and the file cache all stay until phase four.
	 */
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

	/*
	 * Three: the threads join, so the per-net shutdown they drive finds
	 * no live generation and does ordinary teardown.  Ownership does not
	 * depend on the start having succeeded: a failed start can still
	 * have left a service and a thread behind.
	 */
	if (f->service_attempted || (f->nn && f->nn->nfsd_serv)) {
		nfsd_shutdown_threads(f->net);
		f->service_attempted = false;
	}

	/*
	 * Four: what the fixture still holds, and the namespace last.
	 *
	 * The authentication caches are emptied here, after the threads have
	 * joined in phase three and before the namespace is dropped below.
	 * The order matters in both directions: removing an entry can revisit
	 * a request that was deferred on it, so no transport may still be
	 * able to take one, and the flush needs a live namespace to reach.
	 */
	if (f->nl) {
		f->nl_flush_error = nfsd_ffv2_nl_flush(f->nl, 0);
		nfsd_ffv2_nl_close(f->nl);
		f->nl = NULL;
	}
	if (f->worker_installed) {
		nfsd_ffv2_worker_ctx_remove(&f->worker);
		f->worker_installed = false;
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
					   bool timeout_expected,
					   bool with_transport)
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
	/*
	 * Only a fixture without a real service brings the global file cache
	 * up itself.  A wired fixture's nfsd_svc() brings it up through
	 * nfsd_users, the count that keeps it up while any other service is
	 * still live; a fixture that raised it here as well would hold an
	 * ownership the count knows nothing about.  What is recorded is the
	 * transition this caller actually performed, not whether the service
	 * started.
	 */
	if (!error && !with_transport) {
		error = nfsd_file_ffv2_test_cache_start();
		f->filecache_up = !error;
	}
	if (!error)
		error = nfsd_ffv2_registration_begin(f->nn, &f->registration);
	f->registration_open = !error;
	mutex_unlock(&nfsd_mutex);
	if (error) {
		KUNIT_FAIL(test, "fixture service start failed: %d", error);
		return false;
	}

	/*
	 * A fixture that will be reached over the wire runs a real service
	 * and listener too.  It comes after the fixture's own service state
	 * and export are up, because the service needs them, and before
	 * anything is published, which is the order the other tests in this
	 * file establish.  The service brings the file cache up itself.
	 */
	if (with_transport) {
		int wire_error;

		wire_error = nfsd_ffv2_worker_ctx_install(&f->worker, f->net);
		if (wire_error) {
			KUNIT_FAIL(test, "fixture worker install failed: %d",
				   wire_error);
			return false;
		}
		f->worker_installed = true;
		/*
		 * From here a service may exist even if the start reports a
		 * failure, so teardown owns it before the result is known.
		 */
		f->service_attempted = true;
		wire_error = nfsd_ffv2_start_test_service(f->net,
							  &f->worker,
							  &f->service_error);
		if (wire_error) {
			KUNIT_FAIL(test,
				   "fixture listener start failed: %d (cleanup %d)",
				   f->service_error, wire_error);
			return false;
		}
		complete(&f->worker.run);
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
					    f->provider,
					    NFSD_FFV2_RO_CHUNK_SIZE)) {
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
					      NFSD_FFV2_RO_PUBLISH_WAIT, false,
					      false);
}

/* The same fixture, also running a real service with a loopback listener. */
static bool nfsd_ffv2_ro_fixture_init_wired(struct kunit *test,
					    struct nfsd_ffv2_ro_fixture *f)
{
	return nfsd_ffv2_ro_fixture_init_wait(test, f,
					      NFSD_FFV2_RO_PUBLISH_WAIT, false,
					      true);
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
					  result, U32_MAX, &admission);
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
	nfsd_ffv2_test_attach_transport(rqstp);
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
			nfsd_ffv2_test_provider_install(NULL, ops, NULL,
							NFSD_FFV2_RO_CHUNK_SIZE));

	for (pass = 0; pass < 2; pass++) {
		if (!nfsd_ffv2_ro_fixture_init(test, &f)) {
			nfsd_ffv2_ro_fixture_exit(test, &f);
			return;
		}
		anchor_before = nfsd_ffv2_test_anchor_refcount(f.nn);

		/* An incomplete operations vector is never installed. */
		KUNIT_EXPECT_EQ(test, -EINVAL,
				nfsd_ffv2_test_provider_install(f.nn, NULL,
								NULL,
								NFSD_FFV2_RO_CHUNK_SIZE));
		KUNIT_EXPECT_EQ(test, -EINVAL,
				nfsd_ffv2_test_provider_install(f.nn, &partial,
								NULL,
								NFSD_FFV2_RO_CHUNK_SIZE));

		/* Only one provider at a time, per namespace. */
		KUNIT_EXPECT_EQ(test, -EBUSY,
				nfsd_ffv2_test_provider_install(f.nn, ops,
								f.provider,
								NFSD_FFV2_RO_CHUNK_SIZE));

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
								f.provider,
								NFSD_FFV2_RO_CHUNK_SIZE));
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
	if (nfsd_ffv2_test_provider_install(f.nn, ops, dynamic,
					    NFSD_FFV2_RO_CHUNK_SIZE)) {
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
	if (!nfsd_ffv2_ro_fixture_init_wait(test, &f, 1, true, false))
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
/*
 * Every per-chunk rule the boundary enforces, exercised one at a time from
 * a well-formed result: a rule that is only checked in combination is not
 * checked at all.  The fixture's own arrays are edited between calls, so
 * each case differs from a served result by exactly one field.
 */
/* Encode one reply into a private buffer and hand back its length. */
static int nfsd_ffv2_ro_encode(struct kunit *test, union nfsd4_op_u *u,
			       bool header, __be32 **out)
{
	struct xdr_stream xdr;
	struct xdr_buf buf;
	__be32 *page;
	__be32 status;

	page = kunit_kzalloc(test, PAGE_SIZE, GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	/*
	 * Poison the buffer first.  Zeroed memory would let an encoder that
	 * never wrote a pad byte pass a test that the padding is zero.
	 */
	memset(page, 0xa5, PAGE_SIZE);
	/* An empty head the stream will fill, not a buffer already holding. */
	memset(&buf, 0, sizeof(buf));
	buf.head[0].iov_base = page;
	buf.head[0].iov_len = 0;
	buf.buflen = PAGE_SIZE;
	xdr_init_encode(&xdr, &buf, page, NULL);
	status = header ? nfsd_ffv2_test_encode_chunk_header_read(&xdr, u) :
			  nfsd_ffv2_test_encode_chunk_read(&xdr, u);
	if (status != nfs_ok)
		return -EIO;
	*out = page;
	return buf.len;
}

/*
 * The encoded shape of a read reply.  A reply can be structurally right and
 * still wrong on the wire, so this checks the bytes: that each payload is
 * padded on its own rather than the concatenation being padded once, that
 * the padding is zeroed, and that an entirely empty result encodes without
 * a payload block to point into.
 */
static void nfsd_ffv2_encode_read_test(struct kunit *test)
{
	static const u32 lens[] = { 1, 2, 3, 4 };
	struct nfsd4_chunk_read_ent ents[ARRAY_SIZE(lens)] = {};
	u8 payload[ARRAY_SIZE(lens) * 4];
	union nfsd4_op_u u = {};
	u32 expect, off = 0;
	__be32 *p;
	int len;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(lens); i++) {
		memset(payload + off, 0xc0 + i, lens[i]);
		ents[i].cre_checksum.cs_algorithm = NFSD_FFV2_CHECKSUM_ALG_CRC32;
		ents[i].cre_checksum.cs_len = NFSD_FFV2_CHECKSUM_CRC32_LEN;
		ents[i].cre_effective_len = lens[i];
		ents[i].cre_payload_off = off;
		ents[i].cre_status = nfs_ok;
		off += lens[i];
	}
	u.chunk_read.cra_eof = true;
	u.chunk_read.cra_nchunks = ARRAY_SIZE(lens);
	u.chunk_read.cra_chunks = ents;
	u.chunk_read.cra_payload = payload;
	u.chunk_read.cra_payload_len = off;

	len = nfsd_ffv2_ro_encode(test, &u, false, &p);
	KUNIT_ASSERT_GT(test, len, 0);

	/*
	 * eof, the outer count, then each entry: fourteen words of metadata
	 * and a payload padded to a four-byte boundary by itself.  Ten bytes
	 * of payload become sixteen, not twelve.
	 */
	expect = 2 * XDR_UNIT;
	for (i = 0; i < ARRAY_SIZE(lens); i++)
		expect += NFSD4_FFV2_TEST_READ_ENT_WORDS * XDR_UNIT +
			  xdr_align_size(lens[i]);
	KUNIT_EXPECT_EQ(test, expect, (u32)len);

	KUNIT_EXPECT_EQ(test, 1U, be32_to_cpu(p[0]));	/* crr_eof */
	KUNIT_EXPECT_EQ(test, ARRAY_SIZE(lens), be32_to_cpu(p[1]));

	/* Walk the entries and check each payload's length, bytes and pad. */
	p += 2;
	for (i = 0; i < ARRAY_SIZE(lens); i++) {
		const u8 *bytes;
		u32 pad;

		/* checksum algorithm, checksum length, checksum value word */
		KUNIT_EXPECT_EQ(test, NFSD_FFV2_CHECKSUM_ALG_CRC32,
				be32_to_cpu(p[0]));
		KUNIT_EXPECT_EQ(test, NFSD_FFV2_CHECKSUM_CRC32_LEN,
				be32_to_cpu(p[1]));
		p += NFSD4_FFV2_TEST_READ_ENT_WORDS - 1;
		KUNIT_EXPECT_EQ(test, lens[i], be32_to_cpu(p[0]));
		bytes = (const u8 *)&p[1];
		KUNIT_EXPECT_EQ(test, 0xc0 + i, bytes[0]);
		for (pad = lens[i]; pad < xdr_align_size(lens[i]); pad++)
			KUNIT_EXPECT_EQ(test, 0, bytes[pad]);
		p += 1 + xdr_align_size(lens[i]) / XDR_UNIT;
	}

	/* A result of nothing but empty chunks allocates no payload block. */
	memset(ents, 0, sizeof(ents));
	ents[0].cre_status = nfserr_payload_lost;
	ents[0].cre_checksum.cs_algorithm = NFSD_FFV2_CHECKSUM_ALG_CRC32;
	ents[0].cre_checksum.cs_len = NFSD_FFV2_CHECKSUM_CRC32_LEN;
	u.chunk_read.cra_nchunks = 1;
	u.chunk_read.cra_payload = NULL;
	u.chunk_read.cra_payload_len = 0;
	len = nfsd_ffv2_ro_encode(test, &u, false, &p);
	KUNIT_ASSERT_GT(test, len, 0);
	KUNIT_EXPECT_EQ(test,
			2 * XDR_UNIT + NFSD4_FFV2_TEST_READ_ENT_WORDS * XDR_UNIT,
			(u32)len);
	KUNIT_EXPECT_EQ(test, 0U,
			be32_to_cpu(p[2 + NFSD4_FFV2_TEST_READ_ENT_WORDS - 1]));
}

/*
 * The encoded shape of a header reply: five arrays, each carrying its own
 * count, and an absent predecessor encoding its discriminant alone.
 */
static void nfsd_ffv2_encode_header_test(struct kunit *test)
{
	struct nfsd4_chunk_header_ent ents[2] = {};
	union nfsd4_op_u u = {};
	__be32 *base, *p;
	int len;

	ents[0].che_status = nfs_ok;
	ents[0].che_predecessor.disposition = NFSD_FFV2_RETAINED_ABSENT;
	ents[1].che_status = nfserr_payload_lost;
	ents[1].che_predecessor.disposition = NFSD_FFV2_RETAINED_PRESENT;
	ents[1].che_predecessor.rp_owner.co_client_id = 5;
	u.chunk_header_read.chrr_eof = false;
	u.chunk_header_read.chrr_nents = ARRAY_SIZE(ents);
	u.chunk_header_read.chrr_ents = ents;

	len = nfsd_ffv2_ro_encode(test, &u, true, &p);
	KUNIT_ASSERT_GT(test, len, 0);
	base = p;

	/*
	 * Walk the reply array by array rather than checking a total, so the
	 * shape is asserted where it is emitted: eof, then five arrays each
	 * introduced by its own count, and a predecessor arm that carries an
	 * owner only when one is retained.
	 */
	KUNIT_EXPECT_EQ(test, 0U, be32_to_cpu(p[0]));		/* chrr_eof */
	p += 1;

	KUNIT_EXPECT_EQ(test, ARRAY_SIZE(ents), be32_to_cpu(p[0]));
	KUNIT_EXPECT_EQ(test, nfs_ok, (__force __be32)p[1]);
	KUNIT_EXPECT_EQ(test, nfserr_payload_lost, (__force __be32)p[2]);
	p += 1 + ARRAY_SIZE(ents);				/* chrr_status */

	KUNIT_EXPECT_EQ(test, ARRAY_SIZE(ents), be32_to_cpu(p[0]));
	p += 1 + ARRAY_SIZE(ents);				/* chrr_locked */

	KUNIT_EXPECT_EQ(test, ARRAY_SIZE(ents), be32_to_cpu(p[0]));
	p += 1 + ARRAY_SIZE(ents) * 4;				/* chrr_owners */

	KUNIT_EXPECT_EQ(test, ARRAY_SIZE(ents), be32_to_cpu(p[0]));
	p += 1 + ARRAY_SIZE(ents) * 2;				/* chrr_guards */

	/* chrr_predecessors: absent is one word, present carries an owner. */
	KUNIT_EXPECT_EQ(test, ARRAY_SIZE(ents), be32_to_cpu(p[0]));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_RETAINED_ABSENT, be32_to_cpu(p[1]));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_RETAINED_PRESENT, be32_to_cpu(p[2]));
	KUNIT_EXPECT_EQ(test, 5U, be32_to_cpu(p[5]));		/* co_client_id */
	p += 1 + 1 + 1 + 4;

	/* The walk consumed exactly the reply, and nothing followed it. */
	KUNIT_EXPECT_EQ(test, (u32)len, (u32)((char *)p - (char *)base));
}

/*
 * Run one operation the way a compound would, with a response buffer of a
 * chosen size, so the capacity decision, the short form and the cleanup are
 * the production handler's rather than a reimplementation of them.
 */
static __be32 nfsd_ffv2_ro_compound_op(struct kunit *test,
				       struct nfsd_ffv2_ro_fixture *f,
				       u32 opnum, u32 budget,
				       bool cachethis, union nfsd4_op_u *u)
{
	struct nfsd4_compound_state cstate = {};
	struct nfsd4_compoundargs *args;
	struct nfsd4_compoundres *resp;
	struct nfsd4_slot *slot;
	struct xdr_stream *xdr;
	__be32 *page;

	args = kunit_kzalloc(test, sizeof(*args), GFP_KERNEL);
	resp = kunit_kzalloc(test, sizeof(*resp), GFP_KERNEL);
	slot = kunit_kzalloc(test, sizeof(*slot), GFP_KERNEL);
	xdr = kunit_kzalloc(test, sizeof(*xdr), GFP_KERNEL);
	page = kunit_kzalloc(test, PAGE_SIZE, GFP_KERNEL);
	if (!args || !resp || !slot || !xdr || !page)
		return nfserr_jukebox;

	args->ffv2_digest_valid = true;
	args->opcnt = 1;
	resp->opcnt = 1;		/* the last operation, so no slack */
	resp->xdr = xdr;
	resp->rqstp = f->rqstp;
	resp->cstate.slot = slot;
	if (cachethis)
		slot->sl_flags |= NFSD4_SLOT_CACHETHIS;

	/*
	 * The buffer must never claim more room than it has: a handler that
	 * believed otherwise would be invited to write past the end of it.
	 */
	if (budget > PAGE_SIZE)
		return nfserr_jukebox;
	f->rqstp->rq_argp = args;
	f->rqstp->rq_resp = resp;
	f->rqstp->rq_res.head[0].iov_base = page;
	f->rqstp->rq_res.head[0].iov_len = 0;
	f->rqstp->rq_res.len = 0;
	f->rqstp->rq_res.buflen = budget;

	cstate.session = f->session;
	cstate.slot = slot;
	cstate.current_fh = *f->mapped;
	return nfsd_ffv2_test_run_op(f->rqstp, &cstate, opnum, u);
}

/*
 * The capacity decisions a header read makes, taken through the production
 * handler: a reply that fits whole, one this server shortened, one that
 * cannot carry a single entry, and an empty request that is not a capacity
 * failure at all.
 */
static void nfsd_ffv2_compound_header_capacity_test(struct kunit *test)
{
	/*
	 * The fixture's entries hold no retained predecessor, so each costs
	 * the absent-arm minimum: the discriminant alone rather than an owner
	 * triple after it.  That is also the cost the count is chosen from
	 * before the provider runs.
	 */
	static const u32 fixed = (2 + 1 + 5) * XDR_UNIT;
	static const u32 entry = 9 * XDR_UNIT;
	struct nfsd_ffv2_ro_fixture f;
	union nfsd4_op_u u;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

#define HEADER_OP(budget, count, cache)					\
	({								\
		memset(&u, 0, sizeof(u));				\
		u.chunk_header_read.chra_stateid = f.stateid;		\
		u.chunk_header_read.chra_offset = 0;			\
		u.chunk_header_read.chra_count = (count);		\
		nfsd_ffv2_ro_compound_op(test, &f, OP_CHUNK_HEADER_READ, \
					 (budget), (cache), &u);	\
	})

	/* Room for both entries: neither the server nor the provider trims. */
	KUNIT_EXPECT_EQ(test, nfs_ok, HEADER_OP(fixed + 2 * entry, 2, false));
	KUNIT_EXPECT_EQ(test, 2U, u.chunk_header_read.chrr_nents);
	nfsd_ffv2_test_release_op(OP_CHUNK_HEADER_READ, &u);
	KUNIT_EXPECT_NULL(test, u.chunk_header_read.chrr_ents);
	/* Releasing twice is safe; a compound may unwind after an error. */
	nfsd_ffv2_test_release_op(OP_CHUNK_HEADER_READ, &u);

	/*
	 * Room for one entry only.  The reply is short and says so: the
	 * chunks left out still exist, so end of file must not be claimed.
	 */
	KUNIT_EXPECT_EQ(test, nfs_ok, HEADER_OP(fixed + entry, 2, false));
	KUNIT_EXPECT_EQ(test, 1U, u.chunk_header_read.chrr_nents);
	KUNIT_EXPECT_FALSE(test, u.chunk_header_read.chrr_eof);
	nfsd_ffv2_test_release_op(OP_CHUNK_HEADER_READ, &u);

	/* Not even one entry fits, and a short reply of nothing is not one. */
	KUNIT_EXPECT_EQ(test, nfserr_rep_too_big,
			HEADER_OP(fixed + entry - XDR_UNIT, 2, false));
	KUNIT_EXPECT_EQ(test, 0U, u.chunk_header_read.chrr_nents);

	/* The same shortfall, but the client asked for its reply to be cached. */
	KUNIT_EXPECT_EQ(test, nfserr_rep_too_big_to_cache,
			HEADER_OP(fixed + entry - XDR_UNIT, 2, true));

	/* Asking for nothing succeeds whenever the empty reply itself fits. */
	KUNIT_EXPECT_EQ(test, nfs_ok, HEADER_OP(fixed + entry, 0, false));
	KUNIT_EXPECT_EQ(test, 0U, u.chunk_header_read.chrr_nents);
	nfsd_ffv2_test_release_op(OP_CHUNK_HEADER_READ, &u);

#undef HEADER_OP
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

/*
 * A chunk read admits the whole payload limit before the provider runs,
 * because nothing at this boundary bounds a chunk's size.  An ordinary
 * response budget therefore cannot satisfy one, and the refusal happens
 * before dispatch rather than after bytes have been built.
 */
static void nfsd_ffv2_compound_read_capacity_test(struct kunit *test)
{
	struct nfsd_ffv2_ro_fixture f;
	union nfsd4_op_u u = {};
	u64 callbacks;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	/*
	 * One chunk of the size this provider declared costs its metadata,
	 * its bytes and its padding; a buffer smaller than that cannot hold
	 * the reply and the request is refused before the provider is asked.
	 */
	u.chunk_read.cra_stateid = f.stateid;
	u.chunk_read.cra_count = 1;
	callbacks = nfsd_ffv2_test_provider_callbacks();
	KUNIT_EXPECT_EQ(test, nfserr_toosmall,
			nfsd_ffv2_ro_compound_op(test, &f, OP_CHUNK_READ,
						 2 * XDR_UNIT, false, &u));
	/* Refused before dispatch: the provider was never asked. */
	KUNIT_EXPECT_EQ(test, callbacks,
			nfsd_ffv2_test_provider_callbacks());
	KUNIT_EXPECT_EQ(test, 0U, u.chunk_read.cra_nchunks);
	KUNIT_EXPECT_NULL(test, u.chunk_read.cra_payload);

	/*
	 * A budget that can hold it is served, and an ordinary session is
	 * now large enough: the bound is the chunk size the provider
	 * declared, not the whole payload the protocol allows.
	 */
	memset(&u, 0, sizeof(u));
	u.chunk_read.cra_stateid = f.stateid;
	u.chunk_read.cra_count = 1;
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_ro_compound_op(test, &f, OP_CHUNK_READ,
						 PAGE_SIZE, false, &u));
	KUNIT_EXPECT_EQ(test, 1U, u.chunk_read.cra_nchunks);
	nfsd_ffv2_test_release_op(OP_CHUNK_READ, &u);
	KUNIT_EXPECT_NULL(test, u.chunk_read.cra_chunks);
	KUNIT_EXPECT_NULL(test, u.chunk_read.cra_payload);

out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

/* The service's own listener, so a client can find it. */
static int nfsd_ffv2_ro_listener_port(struct nfsd_net *nn)
{
	struct svc_serv *serv = nn->nfsd_serv;
	struct svc_xprt *xprt;
	int port = -ENOENT;

	if (!serv)
		return -ENOENT;
	spin_lock_bh(&serv->sv_lock);
	list_for_each_entry(xprt, &serv->sv_permsocks, xpt_list) {
		port = svc_xprt_local_port(xprt);
		break;
	}
	spin_unlock_bh(&serv->sv_lock);
	return port;
}

/*
 * Read exactly @len bytes, or give up.  The socket carries a receive
 * deadline, so a service that stops answering ends the read rather than the
 * test case.
 */
static int nfsd_ffv2_ro_recvfull(struct socket *sock, void *buf, size_t len)
{
	unsigned long deadline = jiffies + 5 * HZ;
	size_t have = 0;

	while (have < len) {
		struct msghdr msg = {};
		struct kvec iov = {
			.iov_base	= (char *)buf + have,
			.iov_len	= len - have,
		};
		int got;

		got = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len,
				     MSG_DONTWAIT);
		if (got == -EAGAIN) {
			if (time_after(jiffies, deadline))
				return -ETIMEDOUT;
			msleep(20);
			continue;
		}
		if (got <= 0)
			return got ? got : -ECONNRESET;
		have += got;
	}
	return 0;
}

/* Nothing in a fresh namespace can be reached until loopback is up. */
static int nfsd_ffv2_ro_loopback_up(struct net *net)
{
	int error;

	rtnl_lock();
	error = dev_change_flags(net->loopback_dev,
				 net->loopback_dev->flags | IFF_UP, NULL);
	rtnl_unlock();
	return error;
}

/*
 * One real request, arriving the way requests arrive.
 *
 * This is the smallest exchange that proves the whole path: the fixture's
 * service, its listener, a client that reaches it, and a reply built by the
 * server for a request the server received.  Everything a later encoder
 * test needs -- the page array, the head and page split, the cursor, the
 * buffer length -- is established by that path rather than by a test, which
 * is the point of arriving this way.
 */

/*
 * P0 authentication-cache netlink probe helpers.
 *
 * These drive the existing per-net SunRPC generic-netlink provisioning API
 * from a kernel socket in the fixture's own network namespace.  No production
 * code is involved: this is a test client for a UAPI the kernel already
 * exports.  Ownership is local -- the sender is created by
 * nfsd_ffv2_nl_open(), used only from the owning test, and released by
 * nfsd_ffv2_nl_close() before the namespace is dropped.
 */
struct nfsd_ffv2_nl {
	struct socket	*sock;
	u32		portid;
	u16		family;
	u32		seq;
};

#define NFSD_FFV2_NL_BUF	512

/* Reserve one attribute, leaving the padding zeroed.  NULL if it will not fit. */
static struct nlattr *nfsd_ffv2_nl_reserve(void *buf, size_t cap, size_t *off,
					   u16 type, u16 payload)
{
	size_t total = NLA_ALIGN(NLA_HDRLEN + payload);
	struct nlattr *nla;

	if (*off + total > cap)
		return NULL;
	nla = (struct nlattr *)((char *)buf + *off);
	nla->nla_type = type;
	nla->nla_len = NLA_HDRLEN + payload;
	memset((char *)nla + NLA_HDRLEN, 0, total - NLA_HDRLEN);
	*off += total;
	return nla;
}

static int nfsd_ffv2_nl_put(void *buf, size_t cap, size_t *off, u16 type,
			    const void *data, u16 len)
{
	struct nlattr *nla = nfsd_ffv2_nl_reserve(buf, cap, off, type, len);

	if (!nla)
		return -EMSGSIZE;
	memcpy(nla_data(nla), data, len);
	return 0;
}

static int nfsd_ffv2_nl_put_str(void *buf, size_t cap, size_t *off, u16 type,
				const char *str)
{
	return nfsd_ffv2_nl_put(buf, cap, off, type, str, strlen(str) + 1);
}

static int nfsd_ffv2_nl_put_u64(void *buf, size_t cap, size_t *off, u16 type,
				u64 val)
{
	return nfsd_ffv2_nl_put(buf, cap, off, type, &val, sizeof(val));
}

static int nfsd_ffv2_nl_put_u32(void *buf, size_t cap, size_t *off, u16 type,
				u32 val)
{
	return nfsd_ffv2_nl_put(buf, cap, off, type, &val, sizeof(val));
}

/*
 * Start a request.  The destination is always explicit: sock_create_kern()
 * leaves sock->file NULL, and __netlink_ns_capable() only skips the
 * file_ns_capable() half when NETLINK_SKB_DST is set, which netlink_sendmsg()
 * sets only for a message that carries a destination address.  Sending with
 * msg_name == NULL would dereference that NULL file.
 */
static size_t nfsd_ffv2_nl_begin(void *buf, u16 type, u8 cmd, u32 seq,
				 u16 flags)
{
	struct nlmsghdr *nlh = buf;
	struct genlmsghdr *gnlh;

	memset(buf, 0, NLMSG_HDRLEN + GENL_HDRLEN);
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST | flags;
	nlh->nlmsg_seq = seq;
	nlh->nlmsg_pid = 0;
	gnlh = nlmsg_data(nlh);
	gnlh->cmd = cmd;
	gnlh->version = SUNRPC_FAMILY_VERSION;
	return NLMSG_HDRLEN + GENL_HDRLEN;
}

static int nfsd_ffv2_nl_send(struct nfsd_ffv2_nl *nl, void *buf, size_t len)
{
	struct sockaddr_nl dst = {
		.nl_family	= AF_NETLINK,
		.nl_pid		= 0,		/* the kernel */
		.nl_groups	= 0,
	};
	struct nlmsghdr *nlh = buf;
	struct msghdr msg = {
		.msg_name	= &dst,
		.msg_namelen	= sizeof(dst),
	};
	struct kvec iov = { .iov_base = buf, .iov_len = len };

	nlh->nlmsg_len = len;
	return kernel_sendmsg(nl->sock, &msg, &iov, 1, len);
}

/* One bounded receive.  Returns the byte count, or a negative errno. */
static int nfsd_ffv2_nl_recv(struct nfsd_ffv2_nl *nl, void *buf, size_t cap)
{
	unsigned long deadline = jiffies + 5 * HZ;

	for (;;) {
		struct msghdr msg = {};
		struct kvec iov = { .iov_base = buf, .iov_len = cap };
		int got;

		got = kernel_recvmsg(nl->sock, &msg, &iov, 1, cap,
				     MSG_DONTWAIT);
		if (got == -EAGAIN) {
			if (time_after(jiffies, deadline))
				return -ETIMEDOUT;
			msleep(20);
			continue;
		}
		return got ? got : -ECONNRESET;
	}
}

/*
 * Consume the acknowledgment for the request just sent.  A successful
 * kernel_sendmsg() proves delivery, not that the handler ran: the handler's
 * status arrives here as NLMSG_ERROR with error == 0 for success.
 */
/*
 * Everything a reply must satisfy before any of it is read: it has to be a
 * whole message, addressed to this socket, and answering the request that is
 * outstanding.  A reply that fails any of these is rejected rather than
 * partially believed.
 */
static int nfsd_ffv2_nl_check(struct nfsd_ffv2_nl *nl, const struct nlmsghdr *nlh,
			      unsigned int len)
{
	if (len < NLMSG_HDRLEN || !NLMSG_OK(nlh, len))
		return -EBADMSG;
	if (nlh->nlmsg_pid != nl->portid)
		return -EBADMSG;
	if (nlh->nlmsg_seq != nl->seq)
		return -EBADMSG;
	return 0;
}

/*
 * Read the result out of an acknowledgment, having first established that it
 * is one, that it answers the outstanding request, and that it is the whole
 * datagram.  The checks come before the error is taken, so an error belonging
 * to another exchange cannot be returned as this one's.
 *
 * The request is echoed back only when it was not capped.  When it was, what
 * follows the echoed header is extended-acknowledgment data, which must not
 * be read as a generic-netlink header; the flag says which case this is, and
 * the length alone cannot.
 */
static int nfsd_ffv2_nl_parse_ack(struct nfsd_ffv2_nl *nl, const void *buf,
				  unsigned int len, u16 type, u8 cmd,
				  u8 version)
{
	const struct nlmsghdr *nlh = buf;
	const struct nlmsgerr *e;
	int error;

	error = nfsd_ffv2_nl_check(nl, nlh, len);
	if (error)
		return error;
	if (nlh->nlmsg_type != NLMSG_ERROR)
		return -EPROTO;
	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*e)))
		return -EBADMSG;
	/* Nothing may follow: a single request is answered by one message. */
	if (len != NLMSG_ALIGN(nlh->nlmsg_len))
		return -EBADMSG;

	e = nlmsg_data(nlh);
	if (e->msg.nlmsg_seq != nl->seq || e->msg.nlmsg_type != type)
		return -EBADMSG;

	if (!(nlh->nlmsg_flags & NLM_F_CAPPED)) {
		unsigned int echoed_at, available;
		const struct genlmsghdr *gnlh;

		/*
		 * The echoed message declares its own length, and a length
		 * larger than what arrived would send the read past the end
		 * of the datagram.  What it claims is checked against what is
		 * physically there before any of it is read.
		 */
		echoed_at = NLMSG_HDRLEN + offsetof(struct nlmsgerr, msg);
		if (nlh->nlmsg_len <= echoed_at)
			return -EBADMSG;
		available = nlh->nlmsg_len - echoed_at;
		if (e->msg.nlmsg_len < NLMSG_LENGTH(GENL_HDRLEN))
			return -EBADMSG;
		/*
		 * The echoed length is whatever arrived, so it is checked
		 * before it is rounded: NLMSG_ALIGN() of a value near the
		 * top of the range wraps to a small one, and a wrapped
		 * length would pass the fit test it was meant to fail.
		 */
		if (e->msg.nlmsg_len > UINT_MAX - (NLMSG_ALIGNTO - 1))
			return -EBADMSG;
		if (NLMSG_ALIGN(e->msg.nlmsg_len) > available)
			return -EBADMSG;
		gnlh = (const struct genlmsghdr *)((const char *)&e->msg +
						   NLMSG_HDRLEN);
		if (gnlh->cmd != cmd || gnlh->version != version)
			return -EPROTO;
	}
	return e->error;
}

/*
 * A generic-netlink payload must be the command and version that was asked
 * for; a reply carrying someone else's command is not this reply.
 */
static int nfsd_ffv2_nl_check_genl(const struct nlmsghdr *nlh, u8 cmd, u8 version)
{
	const struct genlmsghdr *gnlh;

	if (nlh->nlmsg_len < NLMSG_LENGTH(GENL_HDRLEN))
		return -EBADMSG;
	gnlh = nlmsg_data(nlh);
	if (gnlh->cmd != cmd || gnlh->version != version)
		return -EPROTO;
	return 0;
}

static noinline int nfsd_ffv2_nl_ack(struct nfsd_ffv2_nl *nl, u8 cmd)
{
	char buf[NFSD_FFV2_NL_BUF];
	int got;

	got = nfsd_ffv2_nl_recv(nl, buf, sizeof(buf));
	if (got < 0)
		return got;
	return nfsd_ffv2_nl_parse_ack(nl, buf, (unsigned int)got, nl->family,
				      cmd, SUNRPC_FAMILY_VERSION);
}

/* Resolve the runtime family id; the UAPI name is not an nlmsg_type. */
/*
 * Take the family identifier out of a controller reply.  The whole attribute
 * stream is walked before the answer is used: a message that carries the
 * wanted attribute and then trails malformed bytes is not well formed, and
 * stopping at the first match would accept it.
 */
static int nfsd_ffv2_nl_parse_family(struct nfsd_ffv2_nl *nl, const void *buf,
				     unsigned int len, u16 *family)
{
	const struct nlmsghdr *nlh = buf;
	const struct nlattr *nla;
	bool have_family = false;
	int nrem, error;
	u16 found = 0;

	error = nfsd_ffv2_nl_check(nl, nlh, len);
	if (error)
		return error;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		error = nfsd_ffv2_nl_parse_ack(nl, buf, len, GENL_ID_CTRL,
					       CTRL_CMD_GETFAMILY, 1);
		return error ? error : -ENOENT;
	}
	if (nlh->nlmsg_type != GENL_ID_CTRL)
		return -EPROTO;
	if (nlh->nlmsg_len < NLMSG_LENGTH(GENL_HDRLEN))
		return -EBADMSG;
	error = nfsd_ffv2_nl_check_genl(nlh, CTRL_CMD_NEWFAMILY, 2);
	if (error)
		return error;

	/* One reply answers one request; nothing may follow it. */
	if (len != NLMSG_ALIGN(nlh->nlmsg_len))
		return -EBADMSG;

	nlmsg_for_each_attr(nla, nlh, GENL_HDRLEN, nrem) {
		if (nla_type(nla) != CTRL_ATTR_FAMILY_ID)
			continue;
		/* A family identifier is a scalar, not a nest. */
		if (nla->nla_type & NLA_F_NESTED)
			return -EBADMSG;
		/* Exactly the width it is defined to have, no more. */
		if (nla_len(nla) != (int)sizeof(u16))
			return -EBADMSG;
		/*
		 * Two identifiers for one family is a contradiction, not a
		 * choice: taking either would be a guess.  Presence is
		 * tracked separately from the value, so a first identifier
		 * of zero is still a first identifier.
		 */
		if (have_family)
			return -EBADMSG;
		have_family = true;
		found = nla_get_u16(nla);
	}
	if (nrem)
		return -EBADMSG;
	if (!have_family || !found)
		return -ENOENT;
	*family = found;
	return 0;
}

/*
 * The controller's answer carries the family's whole operation and
 * attribute inventory, which for a family the size of nfsd does not fit in
 * a request-sized buffer.  A truncated datagram is not a short read to be
 * retried; it is a message that fails its own length check, so the receive
 * has to be large enough for the answer in the first place.
 */
#define NFSD_FFV2_NL_FAMILY_BUF		16384

static noinline int nfsd_ffv2_nl_resolve(struct nfsd_ffv2_nl *nl,
					 const char *family_name)
{
	struct nlmsghdr *nlh;
	size_t off;
	int got, error;
	u16 family;
	char *buf;

	buf = kzalloc(NFSD_FFV2_NL_FAMILY_BUF, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	nlh = (struct nlmsghdr *)buf;
	off = nfsd_ffv2_nl_begin(buf, GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
				 ++nl->seq, 0);
	((struct genlmsghdr *)nlmsg_data(nlh))->version = 1;
	error = nfsd_ffv2_nl_put_str(buf, NFSD_FFV2_NL_FAMILY_BUF, &off,
				     CTRL_ATTR_FAMILY_NAME, family_name);
	if (error)
		goto out_free;
	error = nfsd_ffv2_nl_send(nl, buf, off);
	if (error < 0)
		goto out_free;

	got = nfsd_ffv2_nl_recv(nl, buf, NFSD_FFV2_NL_FAMILY_BUF);
	if (got < 0) {
		error = got;
		goto out_free;
	}
	error = nfsd_ffv2_nl_parse_family(nl, buf, (unsigned int)got, &family);
	if (!error)
		nl->family = family;
out_free:
	kfree(buf);
	return error;
}

static int nfsd_ffv2_nl_open_named(struct net *net, struct nfsd_ffv2_nl *nl,
				   const char *family_name)
{
	struct sockaddr_nl bind_addr = { .nl_family = AF_NETLINK };
	int error;

	memset(nl, 0, sizeof(*nl));
	error = sock_create_kern(net, AF_NETLINK, SOCK_RAW, NETLINK_GENERIC,
				 &nl->sock);
	if (error)
		return error;
	/*
	 * Bind before sending, so the port the kernel assigns is known and
	 * every reply can be required to carry it.
	 */
	error = kernel_bind(nl->sock, (struct sockaddr_unsized *)&bind_addr,
			    sizeof(bind_addr));
	if (!error)
		error = kernel_getsockname(nl->sock,
					   (struct sockaddr *)&bind_addr);
	if (error < 0)
		goto out_release;
	nl->portid = bind_addr.nl_pid;

	error = nfsd_ffv2_nl_resolve(nl, family_name);
	if (error)
		goto out_release;
	return 0;

out_release:
	sock_release(nl->sock);
	nl->sock = NULL;
	return error;
}

static int nfsd_ffv2_nl_open(struct net *net, struct nfsd_ffv2_nl *nl)
{
	return nfsd_ffv2_nl_open_named(net, nl, SUNRPC_FAMILY_NAME);
}

/*
 * Send one request and take the whole reply.
 *
 * A command that answers with attributes answers with a message of its
 * own, not with an acknowledgment, so the caller gets the bytes back and
 * walks them.  A command that fails answers with an acknowledgment
 * carrying its status either way, which is returned as a negative errno.
 *
 * Return: the reply length, 0 for a command that succeeded with no reply,
 * or a negative errno.
 */
/* Consume the acknowledgment that follows a reply, and nothing else. */
static noinline int nfsd_ffv2_nl_ack_only(struct nfsd_ffv2_nl *nl, u8 cmd)
{
	char buf[NFSD_FFV2_NL_BUF];
	int got;

	got = nfsd_ffv2_nl_recv(nl, buf, sizeof(buf));
	if (got < 0)
		return got;
	return nfsd_ffv2_nl_parse_ack(nl, buf, (unsigned int)got, nl->family,
				      cmd, NFSD_FAMILY_VERSION);
}

static noinline int nfsd_ffv2_nl_call(struct nfsd_ffv2_nl *nl, u8 cmd,
				      void *request, size_t len, void *reply,
				      size_t reply_cap)
{
	const struct nlmsghdr *nlh;
	int got, error;

	error = nfsd_ffv2_nl_send(nl, request, len);
	if (error < 0)
		return error;
	got = nfsd_ffv2_nl_recv(nl, reply, reply_cap);
	if (got < 0)
		return got;
	nlh = reply;
	error = nfsd_ffv2_nl_check(nl, nlh, (unsigned int)got);
	if (error)
		return error;
	if (nlh->nlmsg_type == NLMSG_ERROR)
		return nfsd_ffv2_nl_parse_ack(nl, reply, (unsigned int)got,
					      nl->family, cmd,
					      NFSD_FAMILY_VERSION);
	if (nlh->nlmsg_type != nl->family)
		return -EPROTO;
	error = nfsd_ffv2_nl_check_genl(nlh, cmd, NFSD_FAMILY_VERSION);
	if (error)
		return error;
	if ((unsigned int)got != NLMSG_ALIGN(nlh->nlmsg_len))
		return -EBADMSG;
	/*
	 * A request that asked to be acknowledged is acknowledged as well as
	 * answered, and the acknowledgment is a second datagram.  Take it
	 * here: leaving it queued would make it the answer to whatever is
	 * asked next.
	 */
	error = nfsd_ffv2_nl_ack_only(nl, cmd);
	if (error)
		return error;
	return got;
}

/* One attribute out of a reply, by type, with its length checked. */
static const struct nlattr *nfsd_ffv2_nl_find(const void *reply,
					      unsigned int len, u16 type,
					      int expected_len)
{
	const struct nlmsghdr *nlh = reply;
	const struct nlattr *nla;
	int nrem;

	nlmsg_for_each_attr(nla, nlh, GENL_HDRLEN, nrem) {
		if (nla_type(nla) != type)
			continue;
		if (expected_len >= 0 && nla_len(nla) != expected_len)
			return NULL;
		return nla;
	}
	return NULL;
}

static void nfsd_ffv2_nl_close(struct nfsd_ffv2_nl *nl)
{
	if (nl->sock) {
		sock_release(nl->sock);
		nl->sock = NULL;
	}
}

/* Seed one positive auth.unix.ip entry for the given address. */
static noinline int nfsd_ffv2_nl_seed_ip(struct nfsd_ffv2_nl *nl,
					 const char *class, const char *addr,
					 const char *domain, u64 expiry)
{
	char buf[NFSD_FFV2_NL_BUF];
	struct nlattr *nest;
	size_t off, nest_at;
	int error;

	off = nfsd_ffv2_nl_begin(buf, nl->family, SUNRPC_CMD_IP_MAP_SET_REQS,
				 ++nl->seq, NLM_F_ACK);
	nest_at = off;
	nest = nfsd_ffv2_nl_reserve(buf, sizeof(buf), &off,
				    SUNRPC_A_IP_MAP_REQS_REQUESTS |
				    NLA_F_NESTED, 0);
	if (!nest)
		return -EMSGSIZE;
	error = nfsd_ffv2_nl_put_str(buf, sizeof(buf), &off,
				     SUNRPC_A_IP_MAP_CLASS, class);
	if (!error)
		error = nfsd_ffv2_nl_put_str(buf, sizeof(buf), &off,
					     SUNRPC_A_IP_MAP_ADDR, addr);
	if (!error && domain)
		error = nfsd_ffv2_nl_put_str(buf, sizeof(buf), &off,
					     SUNRPC_A_IP_MAP_DOMAIN, domain);
	if (!error)
		error = nfsd_ffv2_nl_put_u64(buf, sizeof(buf), &off,
					     SUNRPC_A_IP_MAP_EXPIRY, expiry);
	if (error)
		return error;
	nest->nla_len = off - nest_at;

	error = nfsd_ffv2_nl_send(nl, buf, off);
	if (error < 0)
		return error;
	return nfsd_ffv2_nl_ack(nl, SUNRPC_CMD_IP_MAP_SET_REQS);
}

/*
 * Seed one auth.unix.gid entry with an empty group list.  At this tip the
 * attribute spelled NEGATIVE does not set CACHE_NEGATIVE: both it and an
 * empty GIDS list produce a valid positive entry holding groups_alloc(0).
 * The empty-GIDS spelling is used so the name cannot mislead a later reader.
 */
static noinline int nfsd_ffv2_nl_seed_gid_raw(struct nfsd_ffv2_nl *nl, u32 uid,
					      u64 expiry, bool with_uid)
{
	char buf[NFSD_FFV2_NL_BUF];
	struct nlattr *nest;
	size_t off, nest_at;
	int error;

	off = nfsd_ffv2_nl_begin(buf, nl->family, SUNRPC_CMD_UNIX_GID_SET_REQS,
				 ++nl->seq, NLM_F_ACK);
	nest_at = off;
	nest = nfsd_ffv2_nl_reserve(buf, sizeof(buf), &off,
				    SUNRPC_A_UNIX_GID_REQS_REQUESTS |
				    NLA_F_NESTED, 0);
	if (!nest)
		return -EMSGSIZE;
	error = 0;
	if (with_uid)
		error = nfsd_ffv2_nl_put_u32(buf, sizeof(buf), &off,
					     SUNRPC_A_UNIX_GID_UID, uid);
	if (!error)
		error = nfsd_ffv2_nl_put_u64(buf, sizeof(buf), &off,
					     SUNRPC_A_UNIX_GID_EXPIRY, expiry);
	if (error)
		return error;
	nest->nla_len = off - nest_at;

	error = nfsd_ffv2_nl_send(nl, buf, off);
	if (error < 0)
		return error;
	return nfsd_ffv2_nl_ack(nl, SUNRPC_CMD_UNIX_GID_SET_REQS);
}

/*
 * GET_REQS is a pending-request dump, not entry readback: it walks the
 * cache's outstanding upcalls.  A resolved entry has no pending request, so a
 * successful seed makes this count zero.  It proves the absence of a
 * deferral; it never proves an entry exists.  Multipart is terminated on
 * NLMSG_DONE, with a bounded message budget.
 */
/*
 * Scan one datagram of a dump, adding to @count and reporting through @done
 * whether the completion was seen.  Kept apart from the receive so the shapes
 * a socket will not readily produce can be handed to it directly.
 */
static int nfsd_ffv2_nl_parse_dump(struct nfsd_ffv2_nl *nl, const void *buf,
				   unsigned int len, u8 cmd, u16 nest_type,
				   int *count, bool *done)
{
	const struct nlmsghdr *nlh = buf;
	bool multipart = false;
	unsigned int rem = len;
	int error;

	*done = false;
	for (; NLMSG_OK(nlh, rem); nlh = NLMSG_NEXT(nlh, rem)) {
		const struct nlattr *nla;
		int nrem;

		error = nfsd_ffv2_nl_check(nl, nlh, rem);
		if (error)
			return error;
		/*
		 * Whether the dump continues belongs to the message being
		 * read, so it is taken before the walk moves on.
		 */
		multipart = nlh->nlmsg_flags & NLM_F_MULTI;
		if (nlh->nlmsg_type == NLMSG_DONE) {
			/* A completion ends the dump; nothing follows it. */
			if (rem != NLMSG_ALIGN(nlh->nlmsg_len))
				return -EBADMSG;
			*done = true;
			return 0;
		}
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			error = nfsd_ffv2_nl_parse_ack(nl, nlh, rem, nl->family,
						       cmd,
						       SUNRPC_FAMILY_VERSION);
			return error ? error : -EBADMSG;
		}
		if (nlh->nlmsg_type != nl->family)
			return -EPROTO;
		error = nfsd_ffv2_nl_check_genl(nlh, cmd, SUNRPC_FAMILY_VERSION);
		if (error)
			return error;
		nlmsg_for_each_attr(nla, nlh, GENL_HDRLEN, nrem)
			if (nla_type(nla) == nest_type)
				(*count)++;
		if (nrem)
			return -EBADMSG;		/* malformed residue */
	}
	if (rem)
		return -EBADMSG;		/* trailing partial header */
	if (!multipart)
		return -EBADMSG;		/* no completion will come */
	return 0;
}

static noinline int nfsd_ffv2_nl_pending(struct nfsd_ffv2_nl *nl, u8 cmd,
					 u16 nest_type, int *count)
{
	char buf[NFSD_FFV2_NL_BUF];
	int budget = 16;
	size_t off;
	int error;

	*count = 0;
	off = nfsd_ffv2_nl_begin(buf, nl->family, cmd, ++nl->seq, NLM_F_DUMP);
	error = nfsd_ffv2_nl_send(nl, buf, off);
	if (error < 0)
		return error;

	while (budget--) {
		int got = nfsd_ffv2_nl_recv(nl, buf, sizeof(buf));
		bool done;

		if (got < 0)
			return got;
		error = nfsd_ffv2_nl_parse_dump(nl, buf, (unsigned int)got, cmd,
						nest_type, count, &done);
		if (error)
			return error;
		if (done)
			return 0;
	}
	return -EMSGSIZE;		/* dump did not terminate */
}

static int nfsd_ffv2_nl_seed_gid(struct nfsd_ffv2_nl *nl, u32 uid, u64 expiry)
{
	return nfsd_ffv2_nl_seed_gid_raw(nl, uid, expiry, true);
}

/* Flush by mask; zero means the handler's default, which is both caches. */
static int nfsd_ffv2_nl_flush(struct nfsd_ffv2_nl *nl, u32 mask)
{
	char buf[NFSD_FFV2_NL_BUF];
	size_t off;
	int error;

	off = nfsd_ffv2_nl_begin(buf, nl->family, SUNRPC_CMD_CACHE_FLUSH,
				 ++nl->seq, NLM_F_ACK);
	if (mask) {
		error = nfsd_ffv2_nl_put_u32(buf, sizeof(buf), &off,
					     SUNRPC_A_CACHE_FLUSH_MASK, mask);
		if (error)
			return error;
	}
	error = nfsd_ffv2_nl_send(nl, buf, off);
	if (error < 0)
		return error;
	return nfsd_ffv2_nl_ack(nl, SUNRPC_CMD_CACHE_FLUSH);
}

/*
 * P0: the authentication-cache netlink probe.
 *
 * This is a transport gate, not a session test.  It answers one question the
 * design could not: whether a kernel generic-netlink socket in the fixture's
 * own namespace can drive the per-net SunRPC auth-cache provisioning API at
 * all.  Everything it touches is per-net and is flushed before the namespace
 * is dropped.  No session is established, no session operation is
 * sent, and no provider is enabled.
 */

/*
 * Drive one real AUTH_SYS admission and report whether nfsd dispatched it.
 *
 * The carrier is an NFSv4 COMPOUND holding no operations.  Procedure zero is
 * exempt from the export-authentication callback, so a non-zero procedure is
 * the only way to reach svc_set_client(), and COMPOUND is the only non-zero
 * procedure version four defines.  An empty operation array establishes no
 * session, asks for no state, and names no file: it exists solely to carry a
 * credential far enough for authentication to decide.  A fresh connection is
 * used for every call because a transport that has already authenticated
 * keeps its own resolved entry in xpt_auth_cache, which a cache flush does
 * not invalidate.
 *
 * Returns 0 when the request reached nfsd, -ETIMEDOUT when authentication
 * dropped it (a dropped request is answered with silence), or another
 * negative errno for a setup failure.
 */
static noinline int nfsd_ffv2_admit_authsys(struct net *net, struct nfsd_net *nn,
					    u32 uid)
{
	struct sockaddr_in addr = {};
	struct socket *sock = NULL;
	struct msghdr msg = {};
	__be32 call[32];
	__be32 reply[16];
	struct kvec iov;
	__be32 marker;
	int port, error;
	u32 frame;
	u32 words;

	port = nfsd_ffv2_ro_listener_port(nn);
	if (port <= 0)
		return port ? port : -ENOTCONN;

	error = sock_create_kern(net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (error)
		return error;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(port);
	error = kernel_connect(sock, (struct sockaddr_unsized *)&addr,
			       sizeof(addr), 0);
	if (error)
		goto out;

	words = 0;
	call[++words] = cpu_to_be32(0x46465641);	/* transaction id */
	call[++words] = cpu_to_be32(0);			/* CALL */
	call[++words] = cpu_to_be32(2);			/* RPC version */
	call[++words] = cpu_to_be32(100003);		/* NFS */
	call[++words] = cpu_to_be32(4);			/* version four */
	call[++words] = cpu_to_be32(1);			/* COMPOUND */
	call[++words] = cpu_to_be32(RPC_AUTH_UNIX);
	/*
	 * The body below is five words: stamp, machine name length, uid, gid
	 * and the group count.  The length must name exactly those, whether
	 * or not a particular parser reads it.
	 */
	call[++words] = cpu_to_be32(5 * XDR_UNIT);
	call[++words] = cpu_to_be32(0);			/* stamp */
	call[++words] = cpu_to_be32(0);			/* machine name */
	call[++words] = cpu_to_be32(uid);
	call[++words] = cpu_to_be32(uid);		/* gid */
	call[++words] = cpu_to_be32(0);			/* no aux groups */
	call[++words] = cpu_to_be32(0);			/* verifier flavour */
	call[++words] = cpu_to_be32(0);			/* verifier length */
	call[++words] = cpu_to_be32(0);			/* tag length */
	call[++words] = cpu_to_be32(1);			/* minorversion */
	call[++words] = cpu_to_be32(0);			/* no operations */
	call[0] = cpu_to_be32(0x80000000 | (words * XDR_UNIT));

	iov.iov_base = call;
	iov.iov_len = (words + 1) * XDR_UNIT;
	error = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
	if (error != (int)iov.iov_len) {
		error = error < 0 ? error : -EIO;
		goto out;
	}

	/*
	 * A reply means the request was admitted and answered; the reply is
	 * checked rather than merely counted, so that four arbitrary bytes
	 * cannot pass for one.  Silence until the deadline means the request
	 * was never answered, which is what authentication's drop looks like
	 * on the wire: svc_process() sends nothing at all.
	 */
	error = nfsd_ffv2_ro_recvfull(sock, &marker, XDR_UNIT);
	if (error)
		goto out;
	frame = be32_to_cpu(marker);
	if (!(frame & 0x80000000)) {
		error = -EBADMSG;		/* fragmented, unexpected here */
		goto out;
	}
	frame &= 0x7fffffff;
	if (frame < 4 * XDR_UNIT || frame > sizeof(reply)) {
		error = -EBADMSG;
		goto out;
	}
	error = nfsd_ffv2_ro_recvfull(sock, reply, frame);
	if (error)
		goto out;
	if (reply[0] != call[1]) {		/* the transaction it answers */
		error = -EBADMSG;
		goto out;
	}
	if (be32_to_cpu(reply[1]) != 1) {	/* REPLY */
		error = -EBADMSG;
		goto out;
	}
out:
	sock_release(sock);
	return error;
}

/*
 * P0: the authentication-cache provisioning probe.
 *
 * Seeds the two per-net caches nfsd's export authentication needs, then
 * proves by admission -- not by acknowledgment -- that a real AUTH_SYS
 * request is accepted with the expected domain and an empty supplementary
 * group set, and that it stops being accepted once the caches are flushed.
 *
 * Every prerequisite fails closed: a step that cannot be established jumps
 * to the single cleanup path rather than letting a later phase report a
 * success it did not earn.
 */
/*
 * The reply parser, exercised against replies a socket will not readily
 * produce: a capped acknowledgment carrying extended-acknowledgment data, an
 * echoed command that was never sent, an echoed length larger than what
 * arrived, errors and completions with other messages behind them, and family
 * identifiers that are nested, mis-sized, or given twice.
 *
 * Most must be refused.  Three must not, and are checked here for that
 * reason: a capped acknowledgment, an echoed acknowledgment claiming exactly
 * what arrived, and a lone dump completion are all ordinary, and a parser
 * that rejected any of them would be wrong in the other direction.
 */
static void nfsd_ffv2_auth_cache_nl_parser_test(struct kunit *test)
{
	struct nfsd_ffv2_nl nl = { .portid = 0x2a, .family = 23, .seq = 7 };
	char buf[256];
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	struct nlmsgerr *e;
	struct nlattr *nla;
	size_t len;
	u16 family;

	/*
	 * A capped acknowledgment: the request was not echoed, so what sits
	 * behind the echoed header is extended-acknowledgment data.  Reading
	 * it as a generic-netlink header would find a command of zero and
	 * reject a reply that is perfectly good, so the capped flag decides.
	 */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = NLMSG_ERROR;
	nlh->nlmsg_flags = NLM_F_CAPPED | NLM_F_ACK_TLVS;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	e = nlmsg_data(nlh);
	e->error = 0;
	e->msg.nlmsg_type = nl.family;
	e->msg.nlmsg_seq = nl.seq;
	e->msg.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	len = NLMSG_HDRLEN + sizeof(*e);
	nla = (struct nlattr *)(buf + NLMSG_ALIGN(len));
	nla->nla_type = NLMSGERR_ATTR_MSG;
	nla->nla_len = NLA_HDRLEN + 4;
	memcpy(nla_data(nla), "abc", 4);
	len = NLMSG_ALIGN(len) + NLA_ALIGN(nla->nla_len);
	nlh->nlmsg_len = len;
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_nl_parse_ack(&nl, buf, len, nl.family,
					       SUNRPC_CMD_IP_MAP_SET_REQS,
					       SUNRPC_FAMILY_VERSION));

	/* The same reply, with a command that is not the one asked for. */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = NLMSG_ERROR;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	e = nlmsg_data(nlh);
	e->error = 0;
	e->msg.nlmsg_type = nl.family;
	e->msg.nlmsg_seq = nl.seq;
	e->msg.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	((struct genlmsghdr *)((char *)&e->msg + NLMSG_HDRLEN))->cmd =
		SUNRPC_CMD_CACHE_FLUSH;
	((struct genlmsghdr *)((char *)&e->msg + NLMSG_HDRLEN))->version =
		SUNRPC_FAMILY_VERSION;
	len = NLMSG_LENGTH(sizeof(*e) + GENL_HDRLEN);
	nlh->nlmsg_len = len;
	KUNIT_EXPECT_EQ(test, -EPROTO,
			nfsd_ffv2_nl_parse_ack(&nl, buf, NLMSG_ALIGN(len),
					       nl.family,
					       SUNRPC_CMD_IP_MAP_SET_REQS,
					       SUNRPC_FAMILY_VERSION));

	/*
	 * A negative acknowledgment with another message behind it.  The
	 * error must not be returned: a datagram carrying more than the one
	 * answer is not the answer to one request.
	 */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = NLMSG_ERROR;
	nlh->nlmsg_flags = NLM_F_CAPPED;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*e));
	e = nlmsg_data(nlh);
	e->error = -EINVAL;
	e->msg.nlmsg_type = nl.family;
	e->msg.nlmsg_seq = nl.seq;
	e->msg.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	len = NLMSG_ALIGN(nlh->nlmsg_len) + NLMSG_HDRLEN;
	KUNIT_EXPECT_EQ(test, -EBADMSG,
			nfsd_ffv2_nl_parse_ack(&nl, buf, len, nl.family,
					       SUNRPC_CMD_IP_MAP_SET_REQS,
					       SUNRPC_FAMILY_VERSION));

	/*
	 * A controller reply whose family identifier is valid but which then
	 * trails bytes too short to be an attribute.  Stopping at the first
	 * match would return the identifier and never see them.
	 */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	((struct genlmsghdr *)nlmsg_data(nlh))->cmd = CTRL_CMD_NEWFAMILY;
	((struct genlmsghdr *)nlmsg_data(nlh))->version = 2;
	len = NLMSG_HDRLEN + GENL_HDRLEN;
	nla = (struct nlattr *)(buf + len);
	nla->nla_type = CTRL_ATTR_FAMILY_ID;
	nla->nla_len = NLA_HDRLEN + sizeof(u16);
	*(u16 *)nla_data(nla) = 23;
	len += NLA_ALIGN(nla->nla_len);
	len += NLA_HDRLEN / 2;			/* not a whole attribute */
	nlh->nlmsg_len = len;
	family = 0;
	KUNIT_EXPECT_EQ(test, -EBADMSG,
			nfsd_ffv2_nl_parse_family(&nl, buf,
						  NLMSG_ALIGN(len), &family));
	KUNIT_EXPECT_EQ(test, 0, (int)family);

	/* A reply for someone else's request is refused before anything else. */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = NLMSG_ERROR;
	nlh->nlmsg_flags = NLM_F_CAPPED;
	nlh->nlmsg_seq = nl.seq + 1;
	nlh->nlmsg_pid = nl.portid;
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*e));
	KUNIT_EXPECT_EQ(test, -EBADMSG,
			nfsd_ffv2_nl_parse_ack(&nl, buf,
					       NLMSG_ALIGN(nlh->nlmsg_len),
					       nl.family,
					       SUNRPC_CMD_IP_MAP_SET_REQS,
					       SUNRPC_FAMILY_VERSION));

	/*
	 * An acknowledgment whose echoed message claims more than arrived.
	 * Believing that length would read the command from past the end of
	 * the datagram.
	 */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = NLMSG_ERROR;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	e = nlmsg_data(nlh);
	e->error = 0;
	e->msg.nlmsg_type = nl.family;
	e->msg.nlmsg_seq = nl.seq;
	e->msg.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN) + 64;	/* over-claimed */
	len = NLMSG_LENGTH(sizeof(*e) + GENL_HDRLEN);
	nlh->nlmsg_len = len;
	KUNIT_EXPECT_EQ(test, -EBADMSG,
			nfsd_ffv2_nl_parse_ack(&nl, buf, NLMSG_ALIGN(len),
					       nl.family,
					       SUNRPC_CMD_IP_MAP_SET_REQS,
					       SUNRPC_FAMILY_VERSION));

	/* A positive family reply with a complete message behind it. */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	((struct genlmsghdr *)nlmsg_data(nlh))->cmd = CTRL_CMD_NEWFAMILY;
	((struct genlmsghdr *)nlmsg_data(nlh))->version = 2;
	len = NLMSG_HDRLEN + GENL_HDRLEN;
	nla = (struct nlattr *)(buf + len);
	nla->nla_type = CTRL_ATTR_FAMILY_ID;
	nla->nla_len = NLA_HDRLEN + sizeof(u16);
	*(u16 *)nla_data(nla) = 23;
	len += NLA_ALIGN(nla->nla_len);
	nlh->nlmsg_len = len;
	{
		struct nlmsghdr *second = (struct nlmsghdr *)(buf +
							      NLMSG_ALIGN(len));

		second->nlmsg_len = NLMSG_HDRLEN;
		second->nlmsg_type = NLMSG_DONE;
		second->nlmsg_seq = nl.seq;
		second->nlmsg_pid = nl.portid;
	}
	family = 0;
	KUNIT_EXPECT_EQ(test, -EBADMSG,
			nfsd_ffv2_nl_parse_family(&nl, buf,
						  NLMSG_ALIGN(len) + NLMSG_HDRLEN,
						  &family));
	KUNIT_EXPECT_EQ(test, 0, (int)family);

	/* Two family identifiers is a contradiction, not a choice. */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	((struct genlmsghdr *)nlmsg_data(nlh))->cmd = CTRL_CMD_NEWFAMILY;
	((struct genlmsghdr *)nlmsg_data(nlh))->version = 2;
	len = NLMSG_HDRLEN + GENL_HDRLEN;
	nla = (struct nlattr *)(buf + len);
	nla->nla_type = CTRL_ATTR_FAMILY_ID;
	nla->nla_len = NLA_HDRLEN + sizeof(u16);
	*(u16 *)nla_data(nla) = 23;
	len += NLA_ALIGN(nla->nla_len);
	nla = (struct nlattr *)(buf + len);
	nla->nla_type = CTRL_ATTR_FAMILY_ID;
	nla->nla_len = NLA_HDRLEN + sizeof(u16);
	*(u16 *)nla_data(nla) = 24;
	len += NLA_ALIGN(nla->nla_len);
	nlh->nlmsg_len = len;
	family = 0;
	KUNIT_EXPECT_EQ(test, -EBADMSG,
			nfsd_ffv2_nl_parse_family(&nl, buf, NLMSG_ALIGN(len),
						  &family));
	KUNIT_EXPECT_EQ(test, 0, (int)family);

	/* A well-formed single identifier is still accepted. */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	((struct genlmsghdr *)nlmsg_data(nlh))->cmd = CTRL_CMD_NEWFAMILY;
	((struct genlmsghdr *)nlmsg_data(nlh))->version = 2;
	len = NLMSG_HDRLEN + GENL_HDRLEN;
	nla = (struct nlattr *)(buf + len);
	nla->nla_type = CTRL_ATTR_FAMILY_ID;
	nla->nla_len = NLA_HDRLEN + sizeof(u16);
	*(u16 *)nla_data(nla) = 23;
	len += NLA_ALIGN(nla->nla_len);
	nlh->nlmsg_len = len;
	family = 0;
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_nl_parse_family(&nl, buf, NLMSG_ALIGN(len),
						  &family));
	KUNIT_EXPECT_EQ(test, 23, (int)family);

	/* A dump completion with anything behind it ends nothing cleanly. */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = NLMSG_DONE;
	nlh->nlmsg_flags = NLM_F_MULTI;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	nlh->nlmsg_len = NLMSG_HDRLEN;
	{
		struct nlmsghdr *second = (struct nlmsghdr *)(buf +
							      NLMSG_HDRLEN);
		int count = 0;
		bool done = true;

		second->nlmsg_len = NLMSG_HDRLEN;
		second->nlmsg_type = NLMSG_DONE;
		second->nlmsg_seq = nl.seq;
		second->nlmsg_pid = nl.portid;
		KUNIT_EXPECT_EQ(test, -EBADMSG,
				nfsd_ffv2_nl_parse_dump(&nl, buf,
							2 * NLMSG_HDRLEN,
							SUNRPC_CMD_IP_MAP_GET_REQS,
							SUNRPC_A_IP_MAP_REQS_REQUESTS,
							&count, &done));
		KUNIT_EXPECT_FALSE(test, done);
	}

	/* A lone completion is the ordinary end of a dump. */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = NLMSG_DONE;
	nlh->nlmsg_flags = NLM_F_MULTI;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	nlh->nlmsg_len = NLMSG_HDRLEN;
	{
		int count = 0;
		bool done = false;

		KUNIT_EXPECT_EQ(test, 0,
				nfsd_ffv2_nl_parse_dump(&nl, buf, NLMSG_HDRLEN,
							SUNRPC_CMD_IP_MAP_GET_REQS,
							SUNRPC_A_IP_MAP_REQS_REQUESTS,
							&count, &done));
		KUNIT_EXPECT_TRUE(test, done);
		KUNIT_EXPECT_EQ(test, 0, count);
	}

	/* A dump that ends without a completion and without multipart. */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = nl.family;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	((struct genlmsghdr *)nlmsg_data(nlh))->cmd =
		SUNRPC_CMD_IP_MAP_GET_REQS;
	((struct genlmsghdr *)nlmsg_data(nlh))->version = SUNRPC_FAMILY_VERSION;
	nlh->nlmsg_len = NLMSG_HDRLEN + GENL_HDRLEN;
	{
		int count = 0;
		bool done = true;

		KUNIT_EXPECT_EQ(test, -EBADMSG,
				nfsd_ffv2_nl_parse_dump(&nl, buf,
							NLMSG_ALIGN(nlh->nlmsg_len),
							SUNRPC_CMD_IP_MAP_GET_REQS,
							SUNRPC_A_IP_MAP_REQS_REQUESTS,
							&count, &done));
		KUNIT_EXPECT_FALSE(test, done);
	}

	/*
	 * An echoed length near the top of the range.  Rounding it up before
	 * checking it wraps to a small number, and the fit test then passes.
	 *
	 * Everything else about this reply is well formed, including the
	 * embedded command and version, so the only thing that can reject it
	 * is the bound on the length itself.  Without that bound the reply is
	 * accepted outright.
	 */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = NLMSG_ERROR;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	e = nlmsg_data(nlh);
	e->error = 0;
	e->msg.nlmsg_type = nl.family;
	e->msg.nlmsg_seq = nl.seq;
	e->msg.nlmsg_len = UINT_MAX - 1;
	((struct genlmsghdr *)((char *)&e->msg + NLMSG_HDRLEN))->cmd =
		SUNRPC_CMD_IP_MAP_SET_REQS;
	((struct genlmsghdr *)((char *)&e->msg + NLMSG_HDRLEN))->version =
		SUNRPC_FAMILY_VERSION;
	len = NLMSG_LENGTH(sizeof(*e) + GENL_HDRLEN);
	nlh->nlmsg_len = len;
	KUNIT_EXPECT_EQ(test, -EBADMSG,
			nfsd_ffv2_nl_parse_ack(&nl, buf, NLMSG_ALIGN(len),
					       nl.family,
					       SUNRPC_CMD_IP_MAP_SET_REQS,
					       SUNRPC_FAMILY_VERSION));

	/* An echo claiming exactly what arrived is not over-claiming. */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = NLMSG_ERROR;
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	e = nlmsg_data(nlh);
	e->error = 0;
	e->msg.nlmsg_type = nl.family;
	e->msg.nlmsg_seq = nl.seq;
	e->msg.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	((struct genlmsghdr *)((char *)&e->msg + NLMSG_HDRLEN))->cmd =
		SUNRPC_CMD_IP_MAP_SET_REQS;
	((struct genlmsghdr *)((char *)&e->msg + NLMSG_HDRLEN))->version =
		SUNRPC_FAMILY_VERSION;
	len = NLMSG_LENGTH(sizeof(*e) + GENL_HDRLEN);
	nlh->nlmsg_len = len;
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_nl_parse_ack(&nl, buf, NLMSG_ALIGN(len),
					       nl.family,
					       SUNRPC_CMD_IP_MAP_SET_REQS,
					       SUNRPC_FAMILY_VERSION));

	/* A family identifier is a scalar; a nest in its place is refused. */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	((struct genlmsghdr *)nlmsg_data(nlh))->cmd = CTRL_CMD_NEWFAMILY;
	((struct genlmsghdr *)nlmsg_data(nlh))->version = 2;
	len = NLMSG_HDRLEN + GENL_HDRLEN;
	nla = (struct nlattr *)(buf + len);
	nla->nla_type = CTRL_ATTR_FAMILY_ID | NLA_F_NESTED;
	nla->nla_len = NLA_HDRLEN + sizeof(u16);
	*(u16 *)nla_data(nla) = 23;
	len += NLA_ALIGN(nla->nla_len);
	nlh->nlmsg_len = len;
	family = 0;
	KUNIT_EXPECT_EQ(test, -EBADMSG,
			nfsd_ffv2_nl_parse_family(&nl, buf, NLMSG_ALIGN(len),
						  &family));
	KUNIT_EXPECT_EQ(test, 0, (int)family);

	/* Wider than the scalar it is defined to be. */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	((struct genlmsghdr *)nlmsg_data(nlh))->cmd = CTRL_CMD_NEWFAMILY;
	((struct genlmsghdr *)nlmsg_data(nlh))->version = 2;
	len = NLMSG_HDRLEN + GENL_HDRLEN;
	nla = (struct nlattr *)(buf + len);
	nla->nla_type = CTRL_ATTR_FAMILY_ID;
	nla->nla_len = NLA_HDRLEN + sizeof(u32);
	*(u32 *)nla_data(nla) = 23;
	len += NLA_ALIGN(nla->nla_len);
	nlh->nlmsg_len = len;
	family = 0;
	KUNIT_EXPECT_EQ(test, -EBADMSG,
			nfsd_ffv2_nl_parse_family(&nl, buf, NLMSG_ALIGN(len),
						  &family));
	KUNIT_EXPECT_EQ(test, 0, (int)family);

	/*
	 * A first identifier of zero followed by a second.  Tracking presence
	 * by the value alone would miss this, and take the second as if it
	 * were the only one.
	 */
	memset(buf, 0, sizeof(buf));
	nlh->nlmsg_type = GENL_ID_CTRL;
	nlh->nlmsg_seq = nl.seq;
	nlh->nlmsg_pid = nl.portid;
	((struct genlmsghdr *)nlmsg_data(nlh))->cmd = CTRL_CMD_NEWFAMILY;
	((struct genlmsghdr *)nlmsg_data(nlh))->version = 2;
	len = NLMSG_HDRLEN + GENL_HDRLEN;
	nla = (struct nlattr *)(buf + len);
	nla->nla_type = CTRL_ATTR_FAMILY_ID;
	nla->nla_len = NLA_HDRLEN + sizeof(u16);
	*(u16 *)nla_data(nla) = 0;
	len += NLA_ALIGN(nla->nla_len);
	nla = (struct nlattr *)(buf + len);
	nla->nla_type = CTRL_ATTR_FAMILY_ID;
	nla->nla_len = NLA_HDRLEN + sizeof(u16);
	*(u16 *)nla_data(nla) = 23;
	len += NLA_ALIGN(nla->nla_len);
	nlh->nlmsg_len = len;
	family = 0;
	KUNIT_EXPECT_EQ(test, -EBADMSG,
			nfsd_ffv2_nl_parse_family(&nl, buf, NLMSG_ALIGN(len),
						  &family));
	KUNIT_EXPECT_EQ(test, 0, (int)family);
}

static void nfsd_ffv2_auth_cache_p0_probe_test(struct kunit *test)
{
	static const char domain[] = "ffv2-p0-test-domain";
	const u32 uid = 4242;
	struct nfsd_ffv2_auth_record rec;
	struct nfsd_ffv2_ro_fixture f;
	struct nfsd_ffv2_nl other_nl = {};
	struct nfsd_ffv2_nl nl = {};
	struct net *other = NULL;
	bool other_open = false;
	bool seeded = false;
	int cleanup_error = 0;
	int pending;
	u64 expiry;
	int error;

	if (!nfsd_ffv2_ro_fixture_init_wired(test, &f))
		goto out;
	if (nfsd_ffv2_ro_loopback_up(f.net)) {
		KUNIT_FAIL(test, "could not bring the namespace loopback up");
		goto out;
	}

	/* The sender is owned by the fixture from here to its teardown. */
	error = nfsd_ffv2_nl_open(f.net, &nl);
	if (error) {
		KUNIT_FAIL(test,
			   "generic netlink is not reachable from a kernel socket: %d",
			   error);
		goto out;
	}
	f.nl = &nl;
	pr_info("FFV2P0: family=%u cap_net_admin=%d\n", nl.family,
		ns_capable(&init_user_ns, CAP_NET_ADMIN));

	/*
	 * Cold, before any seeding: authentication must refuse.  This is the
	 * baseline the later admissions are measured against, so a reply here
	 * would mean the rest of the test proves nothing.
	 */
	nfsd_ffv2_test_auth_record_reset();
	error = nfsd_ffv2_admit_authsys(f.net, f.nn, uid);
	pr_info("FFV2P0: cold admit=%d\n", error);
	if (error != -ETIMEDOUT) {
		KUNIT_FAIL(test, "an unseeded cache admitted a request: %d",
			   error);
		goto out;
	}
	nfsd_ffv2_test_auth_record(&rec);
	KUNIT_EXPECT_FALSE(test, rec.valid);

	expiry = ktime_get_real_seconds() + 300;

	/*
	 * Isolation, measured rather than assumed.  A second namespace is
	 * seeded with exactly the parameters this one will use, and this
	 * namespace must still refuse: the handlers select their cache from
	 * the sending socket's namespace, so nothing seeded there can admit
	 * here.  Admitting *in* the second namespace would need a second
	 * nfsd service, which the shared file cache does not currently allow
	 * to run alongside this one, so that direction is not claimed.
	 */
	other = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(other)) {
		KUNIT_FAIL(test, "a second namespace was unavailable: %ld",
			   PTR_ERR(other));
		other = NULL;
		goto out;
	}
	error = nfsd_ffv2_nl_open(other, &other_nl);
	if (error) {
		KUNIT_FAIL(test, "no sender in the second namespace: %d",
			   error);
		goto out;
	}
	other_open = true;
	error = nfsd_ffv2_nl_seed_ip(&other_nl, "nfsd", "127.0.0.1", domain,
				     expiry);
	if (!error)
		error = nfsd_ffv2_nl_seed_gid(&other_nl, uid, expiry);
	if (error) {
		KUNIT_FAIL(test, "the second namespace refused a seed: %d",
			   error);
		goto out;
	}
	nfsd_ffv2_test_auth_record_reset();
	error = nfsd_ffv2_admit_authsys(f.net, f.nn, uid);
	pr_info("FFV2P0: admit after seeding only the other net=%d\n", error);
	if (error != -ETIMEDOUT) {
		KUNIT_FAIL(test,
			   "another namespace's seed admitted a request here: %d",
			   error);
		goto out;
	}

	error = nfsd_ffv2_nl_seed_ip(&nl, "nfsd", "127.0.0.1", domain, expiry);
	if (error) {
		KUNIT_FAIL(test, "the ip_map seed was refused: %d", error);
		goto out;
	}
	seeded = true;
	error = nfsd_ffv2_nl_seed_gid(&nl, uid, expiry);
	if (error) {
		KUNIT_FAIL(test, "the unix_gid seed was refused: %d", error);
		goto out;
	}

	/* Pending drain only: this says nothing about the entries existing. */
	error = nfsd_ffv2_nl_pending(&nl, SUNRPC_CMD_IP_MAP_GET_REQS,
				     SUNRPC_A_IP_MAP_REQS_REQUESTS, &pending);
	if (error) {
		KUNIT_FAIL(test, "the ip_map dump did not complete: %d", error);
		goto out;
	}
	KUNIT_EXPECT_EQ(test, 0, pending);
	error = nfsd_ffv2_nl_pending(&nl, SUNRPC_CMD_UNIX_GID_GET_REQS,
				     SUNRPC_A_UNIX_GID_REQS_REQUESTS, &pending);
	if (error) {
		KUNIT_FAIL(test, "the unix_gid dump did not complete: %d",
			   error);
		goto out;
	}
	KUNIT_EXPECT_EQ(test, 0, pending);

	/* The gate: a real AUTH_SYS request is now admitted and dispatched. */
	nfsd_ffv2_test_auth_record_reset();
	error = nfsd_ffv2_admit_authsys(f.net, f.nn, uid);
	pr_info("FFV2P0: seeded admit=%d\n", error);
	if (error) {
		KUNIT_FAIL(test, "a seeded cache did not admit: %d", error);
		goto out;
	}
	nfsd_ffv2_test_auth_record(&rec);
	KUNIT_EXPECT_TRUE(test, rec.valid);
	KUNIT_EXPECT_TRUE(test, rec.have_client);
	KUNIT_EXPECT_STREQ(test, rec.domain, domain);
	KUNIT_EXPECT_EQ(test, 4U, rec.vers);
	KUNIT_EXPECT_EQ(test, 1U, rec.proc);
	/*
	 * The seeded gid entry is positive and empty, so set_client replaces
	 * the credential's groups with it.  Asserted, not inferred from the
	 * attribute's name.
	 */
	KUNIT_EXPECT_EQ(test, 0U, rec.ngroups);
	pr_info("FFV2P0: admitted domain=%s ngroups=%u\n", rec.domain,
		rec.ngroups);

	/*
	 * The other namespace's flush must not reach this one either, so the
	 * isolation is checked in both operations, not only in seeding.
	 */
	error = nfsd_ffv2_nl_flush(&other_nl, 0);
	if (error) {
		KUNIT_FAIL(test, "the second namespace refused a flush: %d",
			   error);
		goto out;
	}
	nfsd_ffv2_test_auth_record_reset();
	error = nfsd_ffv2_admit_authsys(f.net, f.nn, uid);
	pr_info("FFV2P0: admit after flushing only the other net=%d\n", error);
	if (error) {
		KUNIT_FAIL(test,
			   "another namespace's flush stopped admission here: %d",
			   error);
		goto out;
	}

	/* Flushed: a fresh connection must stop being admitted. */
	error = nfsd_ffv2_nl_flush(&nl, 0);
	if (error) {
		KUNIT_FAIL(test, "the flush was refused: %d", error);
		goto out;
	}
	seeded = false;
	nfsd_ffv2_test_auth_record_reset();
	error = nfsd_ffv2_admit_authsys(f.net, f.nn, uid);
	pr_info("FFV2P0: post-flush admit=%d\n", error);
	KUNIT_EXPECT_EQ(test, -ETIMEDOUT, error);
	nfsd_ffv2_test_auth_record(&rec);
	KUNIT_EXPECT_FALSE(test, rec.valid);

	/*
	 * Partial seed: an accepted ip_map followed by a gid the parser
	 * rejects.  The uid is required, so omitting it is a genuine refusal
	 * rather than a value the parser happens to accept.  Rollback runs on
	 * the live sender, and is proved by admission failing afterwards.
	 */
	error = nfsd_ffv2_nl_seed_ip(&nl, "nfsd", "127.0.0.1", domain, expiry);
	if (error) {
		KUNIT_FAIL(test, "the rollback case could not be set up: %d",
			   error);
		goto out;
	}
	seeded = true;
	error = nfsd_ffv2_nl_seed_gid_raw(&nl, uid, expiry, false);
	pr_info("FFV2P0: partial-seed gid=%d\n", error);
	if (error >= 0) {
		/*
		 * The rollback below is only meaningful if this seed really
		 * failed.  If the parser accepted a request with no uid, the
		 * case proves nothing and must not continue as though it did.
		 */
		KUNIT_FAIL(test,
			   "a gid seed with no uid was accepted: %d", error);
		goto out;
	}

	error = nfsd_ffv2_nl_flush(&nl, 0);
	if (error) {
		KUNIT_FAIL(test, "the rollback flush was refused: %d", error);
		goto out;
	}
	seeded = false;
	nfsd_ffv2_test_auth_record_reset();
	error = nfsd_ffv2_admit_authsys(f.net, f.nn, uid);
	pr_info("FFV2P0: post-rollback admit=%d\n", error);
	KUNIT_EXPECT_EQ(test, -ETIMEDOUT, error);

	/* The handlers' error paths reject and insert nothing. */
	KUNIT_EXPECT_LT(test,
			nfsd_ffv2_nl_seed_ip(&nl, "nfsd", "not-an-address",
					     domain, expiry), 0);
	KUNIT_EXPECT_LT(test,
			nfsd_ffv2_nl_seed_ip(&nl, "this-class-is-far-too-long",
					     "127.0.0.1", domain, expiry), 0);
	KUNIT_EXPECT_LT(test,
			nfsd_ffv2_nl_seed_ip(&nl, "nfsd", "127.0.0.1", NULL,
					     expiry), 0);

	/* Each mask reaches its own cache; zero means the handler's default. */
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_nl_flush(&nl, SUNRPC_CACHE_TYPE_IP_MAP));
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_nl_flush(&nl, SUNRPC_CACHE_TYPE_UNIX_GID));

out:
	/*
	 * Anything still seeded is removed here rather than left for the
	 * namespace to collect, so a failed run does not hand the next test a
	 * populated cache.  The phase-four flush and the sender's release
	 * belong to the fixture teardown, which runs them after the service
	 * stops and before the namespace is dropped.
	 */
	/*
	 * Cleanup is best effort after an earlier failure, but it is never
	 * silent: each step's result is kept and asserted below, so a run
	 * cannot report the gate as passed while leaving state behind.
	 */
	if (seeded && f.nl) {
		error = nfsd_ffv2_nl_flush(&nl, 0);
		if (error)
			cleanup_error = error;
	}
	if (other_open) {
		error = nfsd_ffv2_nl_flush(&other_nl, 0);
		if (error)
			cleanup_error = error;
		nfsd_ffv2_nl_close(&other_nl);
	}
	if (other)
		put_net(other);
	/*
	 * This test sends real compounds, so it clears the reply record it
	 * filled: a later test asks whether any compound was recorded, and
	 * that question is only about its own traffic.
	 */
	nfsd_ffv2_test_reply_shape_reset();
	nfsd_ffv2_test_auth_record_reset();
	nfsd_ffv2_ro_fixture_exit(test, &f);

	/*
	 * The teardown flush runs inside the fixture exit, after the threads
	 * have joined.  Its result is asserted here rather than discarded:
	 * a purge that failed then would leave entries for the next test.
	 */
	KUNIT_EXPECT_EQ(test, 0, cleanup_error);
	KUNIT_EXPECT_EQ(test, 0, f.nl_flush_error);
}

/*
 * The other half of isolation, as far as one file cache allows.
 *
 * Admitting inside a second namespace needs a second nfsd service, and two
 * cannot run at once: the file cache is global and holds a single up/down
 * bit, so whichever fixture tears down first dismantles the other's cache.
 * What can be done is to run the second namespace after the first has been
 * released, which is what this case does: a namespace that never saw the
 * first one's seeding starts cold, and admits only once it has been seeded
 * in its own right.
 *
 * This is deliberately not the full gate.  Proving that flushing one live
 * namespace leaves another live namespace admitting still needs the two to
 * exist together, and that remains blocked.
 */
static void nfsd_ffv2_auth_cache_second_net_test(struct kunit *test)
{
	static const char domain[] = "ffv2-p0-second-net-domain";
	const u32 uid = 4243;
	struct nfsd_ffv2_auth_record rec;
	struct nfsd_ffv2_ro_fixture f;
	struct nfsd_ffv2_nl nl = {};
	int cleanup_error = 0;
	bool seeded = false;
	u64 expiry;
	int error;

	if (!nfsd_ffv2_ro_fixture_init_wired(test, &f))
		goto out;
	if (nfsd_ffv2_ro_loopback_up(f.net)) {
		KUNIT_FAIL(test, "could not bring the namespace loopback up");
		goto out;
	}
	error = nfsd_ffv2_nl_open(f.net, &nl);
	if (error) {
		KUNIT_FAIL(test, "no sender in this namespace: %d", error);
		goto out;
	}
	f.nl = &nl;

	/* Cold: nothing this namespace has done can admit yet. */
	nfsd_ffv2_test_auth_record_reset();
	error = nfsd_ffv2_admit_authsys(f.net, f.nn, uid);
	pr_info("FFV2P0B: cold admit=%d\n", error);
	if (error != -ETIMEDOUT) {
		KUNIT_FAIL(test, "an unseeded namespace admitted: %d", error);
		goto out;
	}

	expiry = ktime_get_real_seconds() + 300;
	error = nfsd_ffv2_nl_seed_ip(&nl, "nfsd", "127.0.0.1", domain, expiry);
	if (!error) {
		seeded = true;
		error = nfsd_ffv2_nl_seed_gid(&nl, uid, expiry);
	}
	if (error) {
		KUNIT_FAIL(test, "this namespace refused a seed: %d", error);
		goto out;
	}

	/* Seeded in its own right: it admits, with its own domain. */
	nfsd_ffv2_test_auth_record_reset();
	error = nfsd_ffv2_admit_authsys(f.net, f.nn, uid);
	pr_info("FFV2P0B: seeded admit=%d\n", error);
	if (error) {
		KUNIT_FAIL(test, "a seeded namespace did not admit: %d", error);
		goto out;
	}
	nfsd_ffv2_test_auth_record(&rec);
	KUNIT_EXPECT_TRUE(test, rec.have_client);
	KUNIT_EXPECT_STREQ(test, rec.domain, domain);
	KUNIT_EXPECT_EQ(test, 0U, rec.ngroups);
	pr_info("FFV2P0B: admitted domain=%s ngroups=%u\n", rec.domain,
		rec.ngroups);

out:
	if (seeded && f.nl) {
		error = nfsd_ffv2_nl_flush(&nl, 0);
		if (error)
			cleanup_error = error;
	}
	nfsd_ffv2_test_reply_shape_reset();
	nfsd_ffv2_test_auth_record_reset();
	nfsd_ffv2_ro_fixture_exit(test, &f);
	KUNIT_EXPECT_EQ(test, 0, cleanup_error);
	KUNIT_EXPECT_EQ(test, 0, f.nl_flush_error);
}

/*
 * One namespace running a real service with a loopback listener and a
 * netlink sender, and nothing else.
 *
 * The read-only fixture cannot be used for two live namespaces: it publishes
 * an FFv2 export, and an FFv2 reservation is held per superblock across the
 * whole machine rather than per namespace, so a second fixture rooted in the
 * same filesystem is refused.  This gate does not need an FFv2 export.  An
 * AUTH_SYS admission is decided before any operation is dispatched, and the
 * COMPOUND used here carries none, so a service, a listener and the two
 * authentication caches are the whole requirement.
 */
struct nfsd_ffv2_auth_service {
	struct net		*net;
	struct nfsd_net		*nn;
	struct nfsd_ffv2_nl	nl;
	/*
	 * @service_up is cleared by a normal stop, so it cannot say whether
	 * the namespace ever had a service.  @started can: the per-net
	 * disposal lock and list are initialised by the service start and by
	 * nothing else, so only a namespace that started one may be looked at
	 * afterwards.
	 */
	bool			service_up;
	bool			started;
	bool			nl_open;
	int			flush_error;
};

/*
 * Where a deliberately failed start gives up.  Everything before the chosen
 * point runs for real, so the teardown being tested is the teardown that a
 * genuine failure at that point would leave behind.
 */
enum nfsd_ffv2_auth_fail {
	NFSD_FFV2_AUTH_FAIL_NONE = 0,
	NFSD_FFV2_AUTH_FAIL_BEFORE_SERVICE,
	NFSD_FFV2_AUTH_FAIL_AFTER_SERVICE,
	NFSD_FFV2_AUTH_FAIL_AFTER_LOOPBACK,
};

static bool nfsd_ffv2_auth_service_start_fail(struct kunit *test,
					      struct nfsd_ffv2_auth_service *s,
					      const char *side,
					      enum nfsd_ffv2_auth_fail fail)
{
	int error;

	memset(s, 0, sizeof(*s));
	s->net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(s->net)) {
		KUNIT_FAIL(test, "%s: no namespace: %ld", side, PTR_ERR(s->net));
		s->net = NULL;
		return false;
	}
	s->nn = net_generic(s->net, nfsd_net_id);
	if (fail == NFSD_FFV2_AUTH_FAIL_BEFORE_SERVICE)
		return false;

	error = nfsd_ffv2_start_test_service(s->net, NULL, NULL);
	if (error) {
		KUNIT_FAIL(test, "%s: service start failed: %d", side, error);
		return false;
	}
	s->service_up = true;
	s->started = true;
	if (fail == NFSD_FFV2_AUTH_FAIL_AFTER_SERVICE)
		return false;

	if (nfsd_ffv2_ro_loopback_up(s->net)) {
		KUNIT_FAIL(test, "%s: could not bring the loopback up", side);
		return false;
	}
	if (fail == NFSD_FFV2_AUTH_FAIL_AFTER_LOOPBACK)
		return false;

	error = nfsd_ffv2_nl_open(s->net, &s->nl);
	if (error) {
		KUNIT_FAIL(test, "%s: no sender: %d", side, error);
		return false;
	}
	s->nl_open = true;
	return true;
}

static bool nfsd_ffv2_auth_service_start(struct kunit *test,
					 struct nfsd_ffv2_auth_service *s,
					 const char *side)
{
	return nfsd_ffv2_auth_service_start_fail(test, s, side,
						 NFSD_FFV2_AUTH_FAIL_NONE);
}

/*
 * Stop the service, then empty the caches, in that order and for the same
 * reason the read-only fixture uses it: removing an entry can revisit a
 * request deferred on it, so no transport may still be able to take one, and
 * the flush needs a namespace that is still there to reach.  The namespace
 * reference is the caller's to drop, so it can still look at what the
 * shutdown left behind.
 *
 * Safe on a half-built service and safe to repeat: a start that fails after
 * the service is up leaves one running, and this is what stops it.
 */
static void nfsd_ffv2_auth_service_stop(struct nfsd_ffv2_auth_service *s)
{
	if (s->service_up) {
		nfsd_shutdown_threads(s->net);
		s->service_up = false;
	}
	if (s->nl_open) {
		s->flush_error = nfsd_ffv2_nl_flush(&s->nl, 0);
		nfsd_ffv2_nl_close(&s->nl);
		s->nl_open = false;
	}
}

static void nfsd_ffv2_auth_service_put(struct nfsd_ffv2_auth_service *s)
{
	if (s->net) {
		put_net(s->net);
		s->net = NULL;
		net_ns_barrier();
	}
}

/*
 * True when a namespace's delayed disposal list has drained.  Read under
 * that namespace's own lock, on a net the caller still holds a reference to:
 * the list is inline in struct nfsd_net, so a per-net shutdown leaves nothing
 * here for this to chase.
 */
static bool nfsd_ffv2_dispose_list_empty(struct net *net)
{
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	bool empty;

	spin_lock(&nn->fcache_dispose_lock);
	empty = list_empty(&nn->fcache_dispose_list);
	spin_unlock(&nn->fcache_dispose_lock);
	return empty;
}

/* One per producer cycle; the repetition schedule needs the most. */
#define NFSD_FFV2_DP_MAX_FILES		4
/* The directory those files live in, exported on its own. */
#define NFSD_FFV2_DP_ROOT_NAME		"ffv2-dp-root"
/* How long a released worker is given to reach its request loop. */
#define NFSD_FFV2_DP_WORKER_WAIT	HZ
/* How long the nfsd thread is given to drain what a producer published. */
#define NFSD_FFV2_DP_DRAIN_WAIT		(15 * HZ)

/* A real regular file under the exported directory, owned by the service. */
struct nfsd_ffv2_dp_file {
	struct path	path;
	bool		created;
};

/*
 * A service for the delayed-producer schedules: one namespace, one nfsd
 * thread parked before its request loop, one ordinary export, and the files
 * it serves.  Nothing FFv2 is published here.  Publication is what would
 * leave the export in the service state, which refuses ordinary access, and
 * what would claim the superblock, which would refuse a second export on it.
 */
struct nfsd_ffv2_dp_service {
	struct net			*net;
	struct nfsd_net			*nn;
	struct svc_rqst			*rqstp;
	struct svc_xprt			*xprt;
	struct auth_domain		*domain;
	struct path			root;
	struct path			export_root;
	struct svc_export		*export;
	struct nfsd_ffv2_worker_ctx	worker;
	struct nfsd_ffv2_dp_file	files[NFSD_FFV2_DP_MAX_FILES];
	unsigned int			file_count;
	bool				root_held;
	bool				export_root_held;
	bool				worker_installed;
	bool				worker_released;
	bool				service_up;
};

static bool nfsd_ffv2_dp_service_start(struct kunit *test,
				       struct nfsd_ffv2_dp_service *s)
{
	struct qstr name = QSTR(NFSD_FFV2_DP_ROOT_NAME);
	struct svc_export *seeded;
	struct svc_export exp;
	struct dentry *child;
	int error;

	memset(s, 0, sizeof(*s));
	s->rqstp = kunit_kzalloc(test, sizeof(*s->rqstp), GFP_KERNEL);
	s->xprt = kunit_kzalloc(test, sizeof(*s->xprt), GFP_KERNEL);
	if (!s->rqstp || !s->xprt) {
		KUNIT_FAIL(test, "failed to allocate producer request");
		return false;
	}

	s->net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	if (IS_ERR(s->net)) {
		KUNIT_FAIL(test, "no namespace: %ld", PTR_ERR(s->net));
		s->net = NULL;
		return false;
	}
	s->nn = net_generic(s->net, nfsd_net_id);
	s->xprt->xpt_net = s->net;
	s->rqstp->rq_xprt = s->xprt;

	s->domain = unix_domain_find("ffv2-dp-kunit");
	if (!s->domain) {
		KUNIT_FAIL(test, "failed to create producer auth domain");
		return false;
	}

	/*
	 * fh_verify() looks the export up by rq_client, and nfsd_setuser()
	 * dereferences the credential's group list.  A zero-filled request
	 * has neither.
	 */
	s->rqstp->rq_client = s->domain;
	s->rqstp->rq_cred.cr_flavor = RPC_AUTH_UNIX;
	s->rqstp->rq_cred.cr_uid = GLOBAL_ROOT_UID;
	s->rqstp->rq_cred.cr_gid = GLOBAL_ROOT_GID;
	s->rqstp->rq_cred.cr_group_info = groups_alloc(0);
	if (!s->rqstp->rq_cred.cr_group_info) {
		KUNIT_FAIL(test, "failed to allocate producer groups");
		return false;
	}

	get_fs_root(current->fs, &s->root);
	s->root_held = true;

	/* A directory of its own: an export is keyed by client and path. */
	child = start_creating(mnt_idmap(s->root.mnt), s->root.dentry, &name);
	if (IS_ERR(child)) {
		KUNIT_FAIL(test, "failed to start export root: %ld",
			   PTR_ERR(child));
		return false;
	}
	child = vfs_mkdir(mnt_idmap(s->root.mnt), d_inode(s->root.dentry),
			  child, 0700, NULL);
	if (IS_ERR(child)) {
		KUNIT_FAIL(test, "failed to create export root: %ld",
			   PTR_ERR(child));
		return false;
	}
	s->export_root.mnt = mntget(s->root.mnt);
	s->export_root.dentry = dget(child);
	s->export_root_held = true;
	end_creating(child);

	nfsd_ffv2_init_test_export(&exp, s->nn, s->domain, &s->export_root);
	/*
	 * This transport has no originating port, so the check in
	 * nfsd_setuser_and_check_port() has nothing meaningful to look at.
	 * Carry the ordinary "insecure" export option rather than claiming
	 * on the request that it came from a reserved port.
	 */
	exp.ex_flags |= NFSEXP_INSECURE_PORT;
	seeded = nfsd_export_cache_update(&exp);
	if (IS_ERR(seeded)) {
		KUNIT_FAIL(test, "export publication failed: %ld",
			   PTR_ERR(seeded));
		return false;
	}
	s->export = seeded;

	/*
	 * Install the park before the service starts, so the thread it
	 * creates stops in the hook ahead of its request loop and never
	 * becomes a consumer while a schedule is observing.
	 */
	error = nfsd_ffv2_worker_ctx_install(&s->worker, s->net);
	if (error) {
		KUNIT_FAIL(test, "worker install failed: %d", error);
		return false;
	}
	s->worker_installed = true;

	error = nfsd_ffv2_start_test_service(s->net, &s->worker, NULL);
	if (error) {
		KUNIT_FAIL(test, "service start failed: %d", error);
		return false;
	}
	s->service_up = true;
	return true;
}

/*
 * Teardown in the order the parts depend on each other.
 *
 * The worker context is the one that bites: it is a global singleton holding
 * storage this frame owns, and removing it is what waits for a thread still
 * inside the hook.  It has to come after the threads are joined, or the wait
 * is for a thread nothing has stopped, and before the storage goes out of
 * scope.  Leaving it installed would also fail every later install.
 */
static void nfsd_ffv2_dp_service_stop(struct kunit *test,
				      struct nfsd_ffv2_dp_service *s)
{
	if (s->worker_installed && !s->worker_released) {
		complete_all(&s->worker.run);
		complete_all(&s->worker.allow_complete);
		s->worker_released = true;
	}
	if (s->service_up) {
		nfsd_shutdown_threads(s->net);
		s->service_up = false;
	}
	if (s->worker_installed) {
		nfsd_ffv2_worker_ctx_remove(&s->worker);
		s->worker_installed = false;
	}

	while (s->file_count) {
		struct nfsd_ffv2_dp_file *df = &s->files[--s->file_count];
		struct dentry *parent;
		struct inode *dir;
		int error;

		if (!df->created)
			continue;
		parent = dget_parent(df->path.dentry);
		dir = d_inode(parent);
		inode_lock_nested(dir, I_MUTEX_PARENT);
		error = vfs_unlink(mnt_idmap(df->path.mnt), dir,
				   df->path.dentry, NULL);
		inode_unlock(dir);
		dput(parent);
		/*
		 * The path reference belongs to this frame and goes either
		 * way.  @created is what says the file is still on the
		 * filesystem, so it survives a failed unlink.
		 */
		path_put(&df->path);
		if (error)
			KUNIT_FAIL(test, "failed to unlink producer file: %d",
				   error);
		else
			df->created = false;
	}
	if (s->export) {
		exp_put(s->export);
		s->export = NULL;
	}
	if (s->net)
		nfsd_export_flush(s->net);
	if (s->export_root_held) {
		struct qstr name = QSTR(NFSD_FFV2_DP_ROOT_NAME);
		struct dentry *victim;

		path_put(&s->export_root);
		s->export_root_held = false;
		victim = start_removing(mnt_idmap(s->root.mnt), s->root.dentry,
					&name);
		if (IS_ERR(victim)) {
			KUNIT_FAIL(test,
				   "failed to start removing the export root: %ld",
				   PTR_ERR(victim));
		} else {
			int error = vfs_rmdir(mnt_idmap(s->root.mnt),
					      d_inode(s->root.dentry), victim,
					      NULL);

			end_removing(victim);
			if (error)
				KUNIT_FAIL(test,
					   "failed to remove the export root: %d",
					   error);
		}
	}
	if (s->root_held) {
		path_put(&s->root);
		s->root_held = false;
	}
	if (s->rqstp) {
		if (s->rqstp->rq_cred.cr_group_info) {
			put_group_info(s->rqstp->rq_cred.cr_group_info);
			s->rqstp->rq_cred.cr_group_info = NULL;
		}
		s->rqstp->rq_client = NULL;
	}
	if (s->domain) {
		auth_domain_put(s->domain);
		s->domain = NULL;
	}
	if (s->net) {
		put_net(s->net);
		s->net = NULL;
		net_ns_barrier();
	}
}

static struct nfsd_ffv2_dp_file *
nfsd_ffv2_dp_file_create(struct kunit *test, struct nfsd_ffv2_dp_service *s,
			 const char *name)
{
	struct nfsd_ffv2_dp_file *df;
	struct file *file;

	if (s->file_count >= ARRAY_SIZE(s->files)) {
		KUNIT_FAIL(test, "too many producer files");
		return NULL;
	}
	df = &s->files[s->file_count];
	file = file_open_root(&s->export_root, name,
			      O_CREAT | O_EXCL | O_RDWR, 0600);
	if (IS_ERR(file)) {
		KUNIT_FAIL(test, "failed to create backing file %s: %ld",
			   name, PTR_ERR(file));
		return NULL;
	}
	df->path = file->f_path;
	path_get(&df->path);
	fput(file);
	df->created = true;
	s->file_count++;
	return df;
}

/*
 * Acquire a garbage-collected file through the production path.
 *
 * fh_verify() resolves a handle only when it does not already carry a
 * dentry, so hand it one.  Every permission check it performs still runs;
 * what is skipped is the wire encoding and the fsid lookup, neither of
 * which these schedules are about.
 *
 * nfsd_file_do_acquire() calls nfsd_setuser(), which overrides the calling
 * task's credentials and restores nothing.  An nfsd thread reverts at its
 * request boundary; this caller has none, so the override would outlive the
 * test.  Save and restore around the call, with nothing in between that can
 * leave the frame.
 */
static __be32 nfsd_ffv2_dp_acquire(struct nfsd_ffv2_dp_service *s,
				   struct nfsd_ffv2_dp_file *df,
				   struct nfsd_file **nfp)
{
	const struct cred *save_cred;
	struct svc_fh fh;
	__be32 status;

	fh_init(&fh, NFS4_FHSIZE);
	fh.fh_export = nfsd_export_get(s->export);
	fh.fh_dentry = dget(df->path.dentry);
	save_cred = get_current_cred();
	status = nfsd_file_acquire_gc(s->rqstp, &fh, NFSD_MAY_READ, nfp);
	put_cred(revert_creds(save_cred));
	fh_put(&fh);
	return status;
}

/*
 * One producer cycle: a fresh file, acquired and then released so the cache
 * holds the only reference, the real delayed-close producer, and the
 * publication it must have made.
 *
 * The non-empty check is the whole point.  Every later assertion in these
 * schedules is that the list is *empty*, which a list nothing was ever put
 * on satisfies for free.
 */
static bool nfsd_ffv2_dp_publish(struct kunit *test,
				 struct nfsd_ffv2_dp_service *s,
				 struct nfsd_ffv2_dp_file *df)
{
	struct nfsd_file *nf = NULL;
	__be32 status;

	status = nfsd_ffv2_dp_acquire(s, df, &nf);
	if (status != nfs_ok) {
		KUNIT_FAIL(test, "producer file acquire failed: %u",
			   be32_to_cpu(status));
		return false;
	}
	nfsd_file_put(nf);
	nfsd_file_ffv2_test_close_inode(d_inode(df->path.dentry));
	if (nfsd_ffv2_dispose_list_empty(s->net)) {
		KUNIT_FAIL(test,
			   "producer published nothing to the disposal list");
		return false;
	}
	return true;
}

/*
 * Let the parked worker go, all the way back into its request loop.
 *
 * Releasing the park is not one completion: the worker runs an admission and
 * waits twice more before it returns.  Until it does, it is not in the loop,
 * so nothing is consuming the disposal list.  The admission's own result is
 * incidental here and is not asserted on.
 */
static bool nfsd_ffv2_dp_worker_release(struct kunit *test,
					struct nfsd_ffv2_dp_service *s)
{
	complete(&s->worker.run);
	if (!wait_for_completion_timeout(&s->worker.admitted,
					 NFSD_FFV2_DP_WORKER_WAIT)) {
		KUNIT_FAIL(test, "worker did not reach admission");
		return false;
	}
	complete(&s->worker.allow_complete);
	if (!wait_for_completion_timeout(&s->worker.returned,
					 NFSD_FFV2_DP_WORKER_WAIT)) {
		KUNIT_FAIL(test, "worker did not return to its request loop");
		return false;
	}
	s->worker_released = true;
	return true;
}

/*
 * The isolation gate, with both namespaces live at once.
 *
 * The sequential case above shows that a namespace starts cold and admits only
 * after its own seeding.  What it cannot show is the simultaneous property,
 * that flushing one live namespace leaves another live namespace admitting,
 * because that needs the two to exist together.
 *
 * Neither service brings the global file cache up on its own account: each
 * nfsd_svc() does, through the count that keeps it up for the second service
 * while the first one stops.  That is what makes stopping A underneath B safe
 * to ask about at all.
 *
 * The drained-list checks are cleanup assertions on a namespace whose service
 * has already stopped.  They are not evidence about a disposal producer racing
 * a per-net shutdown; nothing here drives one.
 */
static void nfsd_ffv2_auth_cache_two_service_test(struct kunit *test)
{
	static const char domain_a[] = "ffv2-p0-service-a-domain";
	static const char domain_b[] = "ffv2-p0-service-b-domain";
	const u32 uid_a = 4244;
	const u32 uid_b = 4245;
	struct nfsd_ffv2_auth_service a = {};
	struct nfsd_ffv2_auth_service b = {};
	struct nfsd_ffv2_auth_record rec;
	u64 expiry;
	int error;

	if (!nfsd_ffv2_auth_service_start(test, &a, "A"))
		goto out;
	if (!nfsd_ffv2_auth_service_start(test, &b, "B"))
		goto out;

	/*
	 * Both services are live, so the global file cache is up and the start
	 * seam reports that without touching it.  This is a diagnostic only:
	 * neither service owns the cache, and the seam must not be called once
	 * a service has stopped, because it brings the cache back up when the
	 * bit is clear.
	 */
	mutex_lock(&nfsd_mutex);
	error = nfsd_file_ffv2_test_cache_start();
	mutex_unlock(&nfsd_mutex);
	pr_info("FFV2P0C: cache start while both are live=%d\n", error);
	KUNIT_EXPECT_EQ(test, -EBUSY, error);

	expiry = ktime_get_real_seconds() + 300;

	/* A is cold until it is seeded in its own right. */
	nfsd_ffv2_test_auth_record_reset();
	error = nfsd_ffv2_admit_authsys(a.net, a.nn, uid_a);
	pr_info("FFV2P0C: A cold admit=%d\n", error);
	if (error != -ETIMEDOUT) {
		KUNIT_FAIL(test, "an unseeded A admitted: %d", error);
		goto out;
	}
	error = nfsd_ffv2_nl_seed_ip(&a.nl, "nfsd", "127.0.0.1", domain_a,
				     expiry);
	if (!error)
		error = nfsd_ffv2_nl_seed_gid(&a.nl, uid_a, expiry);
	if (error) {
		KUNIT_FAIL(test, "A refused a seed: %d", error);
		goto out;
	}
	nfsd_ffv2_test_auth_record_reset();
	error = nfsd_ffv2_admit_authsys(a.net, a.nn, uid_a);
	pr_info("FFV2P0C: A seeded admit=%d\n", error);
	if (error) {
		KUNIT_FAIL(test, "a seeded A did not admit: %d", error);
		goto out;
	}
	nfsd_ffv2_test_auth_record(&rec);
	KUNIT_EXPECT_TRUE(test, rec.have_client);
	KUNIT_EXPECT_STREQ(test, rec.domain, domain_a);

	/*
	 * B is cold while A is seeded and live.  This is the half the
	 * sequential case could not reach: A's entries exist right now.
	 */
	nfsd_ffv2_test_auth_record_reset();
	error = nfsd_ffv2_admit_authsys(b.net, b.nn, uid_b);
	pr_info("FFV2P0C: B cold admit while A is seeded=%d\n", error);
	if (error != -ETIMEDOUT) {
		KUNIT_FAIL(test, "A's seed admitted in B: %d", error);
		goto out;
	}
	error = nfsd_ffv2_nl_seed_ip(&b.nl, "nfsd", "127.0.0.1", domain_b,
				     expiry);
	if (!error)
		error = nfsd_ffv2_nl_seed_gid(&b.nl, uid_b, expiry);
	if (error) {
		KUNIT_FAIL(test, "B refused a seed: %d", error);
		goto out;
	}
	nfsd_ffv2_test_auth_record_reset();
	error = nfsd_ffv2_admit_authsys(b.net, b.nn, uid_b);
	pr_info("FFV2P0C: B seeded admit=%d\n", error);
	if (error) {
		KUNIT_FAIL(test, "a seeded B did not admit: %d", error);
		goto out;
	}
	nfsd_ffv2_test_auth_record(&rec);
	KUNIT_EXPECT_TRUE(test, rec.have_client);
	KUNIT_EXPECT_STREQ(test, rec.domain, domain_b);

	/* The gate: flushing A, with B live, must leave B admitting. */
	error = nfsd_ffv2_nl_flush(&a.nl, 0);
	if (error) {
		KUNIT_FAIL(test, "A refused a flush: %d", error);
		goto out;
	}
	nfsd_ffv2_test_auth_record_reset();
	error = nfsd_ffv2_admit_authsys(b.net, b.nn, uid_b);
	pr_info("FFV2P0C: B admit after flushing A=%d\n", error);
	if (error) {
		KUNIT_FAIL(test, "A's flush stopped B admitting: %d", error);
		goto out;
	}
	nfsd_ffv2_test_auth_record(&rec);
	KUNIT_EXPECT_STREQ(test, rec.domain, domain_b);

	/* And A must have stopped, so the flush did reach something. */
	nfsd_ffv2_test_auth_record_reset();
	error = nfsd_ffv2_admit_authsys(a.net, a.nn, uid_a);
	pr_info("FFV2P0C: A admit after its own flush=%d\n", error);
	KUNIT_EXPECT_EQ(test, -ETIMEDOUT, error);

	/*
	 * A stops while B keeps serving.  This is the teardown that was
	 * unreachable before: A's per-net shutdown runs with the global file
	 * cache still up, because B is still holding it.
	 */
	nfsd_ffv2_auth_service_stop(&a);
	KUNIT_EXPECT_EQ(test, 0, a.flush_error);
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_dispose_list_empty(a.net));

	nfsd_ffv2_test_auth_record_reset();
	error = nfsd_ffv2_admit_authsys(b.net, b.nn, uid_b);
	pr_info("FFV2P0C: B admit after A stopped=%d\n", error);
	if (error) {
		KUNIT_FAIL(test, "stopping A stopped B admitting: %d", error);
		goto out;
	}
	nfsd_ffv2_test_auth_record(&rec);
	KUNIT_EXPECT_STREQ(test, rec.domain, domain_b);

out:
	nfsd_ffv2_test_reply_shape_reset();
	nfsd_ffv2_test_auth_record_reset();
	/*
	 * Both are stopped whatever happened, and stopping decides what to do
	 * from the state each one is actually in: a start that failed while
	 * bringing up a loopback or a sender still left a service running.
	 * Only a namespace that completed a service start has a disposal lock
	 * and list to look at.
	 */
	nfsd_ffv2_auth_service_stop(&b);
	if (b.started) {
		KUNIT_EXPECT_EQ(test, 0, b.flush_error);
		KUNIT_EXPECT_TRUE(test, nfsd_ffv2_dispose_list_empty(b.net));
	}
	nfsd_ffv2_auth_service_stop(&a);
	nfsd_ffv2_auth_service_put(&b);
	nfsd_ffv2_auth_service_put(&a);
}

/*
 * The teardown itself, driven from each point a start can give up.
 *
 * A stays up throughout, so each case also shows that one service failing
 * leaves the other one serving.  What is checked after every teardown is that
 * neither namespace still has a service, that a namespace which never started
 * one is never asked about a disposal list it does not have, and that a fresh
 * service can still be started afterwards, which no leftover global state
 * would allow.
 */
static void nfsd_ffv2_auth_cache_service_cleanup_test(struct kunit *test)
{
	static const enum nfsd_ffv2_auth_fail points[] = {
		NFSD_FFV2_AUTH_FAIL_BEFORE_SERVICE,
		NFSD_FFV2_AUTH_FAIL_AFTER_SERVICE,
		NFSD_FFV2_AUTH_FAIL_AFTER_LOOPBACK,
	};
	struct nfsd_ffv2_auth_service a;
	struct nfsd_ffv2_auth_service b;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(points); i++) {
		if (!nfsd_ffv2_auth_service_start(test, &a, "A")) {
			nfsd_ffv2_auth_service_stop(&a);
			nfsd_ffv2_auth_service_put(&a);
			return;
		}

		KUNIT_EXPECT_FALSE(test,
				   nfsd_ffv2_auth_service_start_fail(test, &b,
								     "B",
								     points[i]));
		pr_info("FFV2P0D: injected failure %u started=%d\n",
			(unsigned int)points[i], b.started);

		nfsd_ffv2_auth_service_stop(&b);
		nfsd_ffv2_auth_service_stop(&a);

		/* Nothing is left running on either side. */
		mutex_lock(&nfsd_mutex);
		KUNIT_EXPECT_PTR_EQ(test, a.nn->nfsd_serv, NULL);
		if (b.net)
			KUNIT_EXPECT_PTR_EQ(test, b.nn->nfsd_serv, NULL);
		mutex_unlock(&nfsd_mutex);

		KUNIT_EXPECT_TRUE(test, nfsd_ffv2_dispose_list_empty(a.net));
		if (b.started)
			KUNIT_EXPECT_TRUE(test,
					  nfsd_ffv2_dispose_list_empty(b.net));

		nfsd_ffv2_auth_service_put(&b);
		nfsd_ffv2_auth_service_put(&a);
	}

	/* Nothing left behind stops the next service from starting. */
	if (nfsd_ffv2_auth_service_start(test, &a, "after")) {
		nfsd_ffv2_auth_service_stop(&a);
		KUNIT_EXPECT_EQ(test, 0, a.flush_error);
		KUNIT_EXPECT_TRUE(test, nfsd_ffv2_dispose_list_empty(a.net));
	}
	nfsd_ffv2_auth_service_stop(&a);
	nfsd_ffv2_auth_service_put(&a);
}

static void nfsd_ffv2_transport_null_test(struct kunit *test)
{
	__be32 call[16], reply[16];
	struct sockaddr_in addr = {};
	struct nfsd_ffv2_ro_fixture f;
	struct nfsd_ffv2_reply_shape shape = {};
	u64 admissions_before, providers_before;
	u64 admissions, providers;
	struct socket *sock = NULL;
	struct msghdr msg = {};
	struct kvec iov;
	int port, error;
	__be32 marker;
	__be32 xid;
	u32 frame;
	u32 words;

	if (!nfsd_ffv2_ro_fixture_init_wired(test, &f))
		goto out;
	nfsd_ffv2_test_release_counters(&admissions_before, &providers_before);

	if (nfsd_ffv2_ro_loopback_up(f.net)) {
		KUNIT_FAIL(test, "could not bring the namespace loopback up");
		goto out;
	}
	port = nfsd_ffv2_ro_listener_port(f.nn);
	if (port <= 0) {
		KUNIT_FAIL(test, "the service has no listener: %d", port);
		goto out;
	}

	error = sock_create_kern(f.net, PF_INET, SOCK_STREAM, IPPROTO_TCP,
				 &sock);
	if (error) {
		KUNIT_FAIL(test, "failed to create a client socket: %d", error);
		goto out;
	}
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = htons(port);
	error = kernel_connect(sock, (struct sockaddr_unsized *)&addr,
			       sizeof(addr), 0);
	if (error) {
		KUNIT_FAIL(test, "failed to reach the service: %d", error);
		goto out;
	}

	/*
	 * An RPC NULL call: a record mark, then a call naming the NFS
	 * program and version four, with no authentication to speak of.
	 */
	xid = cpu_to_be32(0x46465632);
	words = 0;
	call[++words] = xid;
	call[++words] = cpu_to_be32(0);		/* CALL */
	call[++words] = cpu_to_be32(2);		/* RPC version */
	call[++words] = cpu_to_be32(100003);	/* NFS */
	call[++words] = cpu_to_be32(4);		/* version */
	call[++words] = cpu_to_be32(0);		/* NULL */
	call[++words] = cpu_to_be32(0);		/* credential flavour */
	call[++words] = cpu_to_be32(0);		/* credential length */
	call[++words] = cpu_to_be32(0);		/* verifier flavour */
	call[++words] = cpu_to_be32(0);		/* verifier length */
	call[0] = cpu_to_be32(0x80000000 | (words * XDR_UNIT));

	iov.iov_base = call;
	iov.iov_len = (words + 1) * XDR_UNIT;
	error = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
	if (error != (int)iov.iov_len) {
		KUNIT_FAIL(test, "the call was not sent whole: %d", error);
		goto out;
	}

	/*
	 * Read the record marker, then exactly the record it announces.  A
	 * deadline is set on the socket first: a test that blocks here would
	 * take the whole suite with it, and a service that answers nothing
	 * is a result rather than something to wait out.
	 */
	if (nfsd_ffv2_ro_recvfull(sock, &marker, XDR_UNIT)) {
		KUNIT_FAIL(test, "no record marker came back");
		goto out;
	}
	frame = be32_to_cpu(marker);
	if (!(frame & 0x80000000)) {
		KUNIT_FAIL(test, "the reply was fragmented, which is unexpected");
		goto out;
	}
	frame &= 0x7fffffff;
	/*
	 * A NULL reply is exactly six words and no body: the transaction
	 * identifier, the direction, the accept state, an empty verifier,
	 * and the status.  Anything longer is not the reply to this call.
	 */
	if (frame != 6 * XDR_UNIT || frame > sizeof(reply)) {
		KUNIT_FAIL(test, "the reply's length is not usable: %u", frame);
		goto out;
	}
	if (nfsd_ffv2_ro_recvfull(sock, reply, frame)) {
		KUNIT_FAIL(test, "the reply was truncated");
		goto out;
	}

	/* Answered, accepted, and executed, for the call that was sent. */
	KUNIT_EXPECT_EQ(test, xid, reply[0]);
	KUNIT_EXPECT_EQ(test, 1U, be32_to_cpu(reply[1]));	/* REPLY */
	KUNIT_EXPECT_EQ(test, 0U, be32_to_cpu(reply[2]));	/* accepted */
	KUNIT_EXPECT_EQ(test, 0U, be32_to_cpu(reply[3]));	/* verifier */
	KUNIT_EXPECT_EQ(test, 0U, be32_to_cpu(reply[4]));	/* empty */
	KUNIT_EXPECT_EQ(test, 0U, be32_to_cpu(reply[5]));	/* success */

	/*
	 * The observation the server records for a compound reply is not
	 * recorded here, because a NULL call is not a compound.  Checking
	 * that keeps this test to what it actually shows: a real listener
	 * accepted and answered a request.  It says nothing about an FFv2
	 * compound or a page-spliced reply, neither of which it sends, and
	 * it confirms the observation does not fire for traffic that never
	 * reached the compound path.
	 */
	nfsd_ffv2_test_reply_shape(&shape);
	KUNIT_EXPECT_FALSE(test, shape.valid);

	/* No provider was reached, so nothing was admitted or released. */
	nfsd_ffv2_test_release_counters(&admissions, &providers);
	KUNIT_EXPECT_EQ(test, admissions_before, admissions);
	KUNIT_EXPECT_EQ(test, providers_before, providers);

out:
	if (sock)
		sock_release(sock);
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

static void nfsd_ffv2_provider_result_contract_test(struct kunit *test)
{
	const struct nfsd_ffv2_chunk_request req = { .offset = 0, .count = 1 };
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_ffv2_ro_fixture f;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

#define RO_READ()	nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &f.stateid, \
					       &req, &result)
#define RO_HEADER()	nfsd_ffv2_ro_operation(&f, OP_CHUNK_HEADER_READ, \
					       &f.stateid, &req, &result)

	/* The unedited result is served, so every rejection below is the edit. */
	KUNIT_EXPECT_EQ(test, nfs_ok, RO_READ());
	KUNIT_EXPECT_EQ(test, nfs_ok, RO_HEADER());

	/* A committed chunk needs the bytes it claims. */
	f.provider->chunks[0].cr_chunk = NULL;
	KUNIT_EXPECT_EQ(test, nfserr_serverfault, RO_READ());
	f.provider->chunks[0].cr_chunk = f.provider->data[0];

	/* A length no chunk could hold. */
	f.provider->chunks[0].cr_effective_len = NFSD_FFV2_MAX_PAYLOAD_BYTES + 1;
	KUNIT_EXPECT_EQ(test, nfserr_serverfault, RO_READ());
	f.provider->chunks[0].cr_effective_len = NFSD_FFV2_RO_CHUNK_SIZE;

	/* A checksum this server cannot encode. */
	f.provider->chunks[0].cr_checksum.cs_len = 8;
	KUNIT_EXPECT_EQ(test, nfserr_serverfault, RO_READ());
	f.provider->chunks[0].cr_checksum.cs_len = 4;
	f.provider->chunks[0].cr_checksum.cs_algorithm = NFSD_FFV2_CHECKSUM_ALG_NONE;
	KUNIT_EXPECT_EQ(test, nfserr_serverfault, RO_READ());
	f.provider->chunks[0].cr_checksum.cs_algorithm = NFSD_FFV2_CHECKSUM_ALG_CRC32;

	/* Terminally lost carries no bytes, and is refused if it claims any. */
	f.provider->chunks[0].cr_status = nfserr_payload_lost;
	f.provider->chunks[0].cr_effective_len = 0;
	KUNIT_EXPECT_EQ(test, nfs_ok, RO_READ());
	f.provider->chunks[0].cr_effective_len = NFSD_FFV2_RO_CHUNK_SIZE;
	KUNIT_EXPECT_EQ(test, nfserr_serverfault, RO_READ());

	/* An operation-level status is not a per-chunk status. */
	f.provider->chunks[0].cr_status = nfserr_acces;
	f.provider->chunks[0].cr_effective_len = 0;
	KUNIT_EXPECT_EQ(test, nfserr_serverfault, RO_READ());
	f.provider->chunks[0].cr_status = nfserr_delay;
	KUNIT_EXPECT_EQ(test, nfserr_serverfault, RO_READ());

	/* EMPTY needs a synthetic payload this slice cannot verify. */
	f.provider->chunks[0].cr_status = nfserr_noent;
	KUNIT_EXPECT_EQ(test, nfserr_serverfault, RO_READ());
	f.provider->chunks[0].cr_status = nfs_ok;
	f.provider->chunks[0].cr_effective_len = NFSD_FFV2_RO_CHUNK_SIZE;

	/* Lock state is reported beside the status, never inside it. */
	f.provider->status[0] = nfserr_chunk_locked;
	KUNIT_EXPECT_EQ(test, nfserr_serverfault, RO_HEADER());

	/* An in-progress generation is a legal header status. */
	f.provider->status[0] = nfserr_payload_not_atomic;
	KUNIT_EXPECT_EQ(test, nfs_ok, RO_HEADER());

	/* EMPTY reports the all-zeros guard and holds no predecessor. */
	f.provider->status[0] = nfserr_noent;
	f.provider->guards[0].cg_gen_id = 0;
	f.provider->guards[0].cg_client_id = NFSD_FFV2_GUARD_CLIENT_ID_NONE;
	KUNIT_EXPECT_EQ(test, nfs_ok, RO_HEADER());
	f.provider->guards[0].cg_gen_id = 1;
	KUNIT_EXPECT_EQ(test, nfserr_serverfault, RO_HEADER());
	f.provider->guards[0].cg_gen_id = 0;
	f.provider->guards[0].cg_client_id = 1;
	KUNIT_EXPECT_EQ(test, nfserr_serverfault, RO_HEADER());
	f.provider->guards[0].cg_client_id = NFSD_FFV2_GUARD_CLIENT_ID_NONE;
	f.provider->predecessors[0].disposition = NFSD_FFV2_RETAINED_PRESENT;
	KUNIT_EXPECT_EQ(test, nfserr_serverfault, RO_HEADER());

	/*
	 * A terminally lost chunk constrains neither: its metadata still
	 * names the last retained generation where one is held, so the
	 * EMPTY rules must not be applied to it.
	 */
	f.provider->status[0] = nfserr_payload_lost;
	f.provider->guards[0].cg_gen_id = 7;
	f.provider->guards[0].cg_client_id = 9;
	KUNIT_EXPECT_EQ(test, nfs_ok, RO_HEADER());

	/* A discriminant that selects no union arm. */
	f.provider->predecessors[0].disposition =
		(enum nfsd_ffv2_retained_disposition)3;
	KUNIT_EXPECT_EQ(test, nfserr_serverfault, RO_HEADER());

#undef RO_READ
#undef RO_HEADER
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

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
	if (nfsd_ffv2_test_provider_install(f.nn, &overcount, f.provider,
					    NFSD_FFV2_RO_CHUNK_SIZE)) {
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
	if (nfsd_ffv2_test_provider_install(f.nn, &empty, f.provider,
					    NFSD_FFV2_RO_CHUNK_SIZE)) {
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
	if (nfsd_ffv2_test_provider_install(f.nn, &partial, f.provider,
					    NFSD_FFV2_RO_CHUNK_SIZE)) {
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
					    f.provider,
					    NFSD_FFV2_RO_CHUNK_SIZE)) {
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
					result, U32_MAX, admission);
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
	if (nfsd_ffv2_test_provider_install(f.nn, ops, dynamic,
					    NFSD_FFV2_RO_CHUNK_SIZE)) {
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
	if (nfsd_ffv2_test_provider_install(f.nn, ops, dynamic,
					    NFSD_FFV2_RO_CHUNK_SIZE)) {
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
/*
 * An admission keeps the provider it first used.  Removal takes a provider
 * out of the registry before it waits for the callbacks still inside, so
 * the slot can be filled again while an older admission is live: a second
 * call on that admission must still reach the provider it pinned, whose
 * storage the first result borrows, rather than whatever is published now.
 */
static void nfsd_ffv2_provider_pinned_reference_test(struct kunit *test)
{
	const struct nfsd_ffv2_chunk_request req = { .offset = 0, .count = 1 };
	struct nfsd_ffv2_chunk_result first = {}, second = {};
	struct nfsd_ffv2_admission admission = {};
	struct nfsd_ffv2_ro_provider *replacement;
	struct nfsd_ffv2_ro_fixture f;
	void *unpublished = NULL;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	replacement = kunit_kzalloc(test, sizeof(*replacement), GFP_KERNEL);
	if (!replacement) {
		KUNIT_FAIL(test, "failed to allocate the second provider");
		goto out;
	}
	nfsd_ffv2_ro_provider_init(replacement);
	replacement->object = f.object;
	/* Distinct payload bytes, so a result names which provider served it. */
	memset(replacement->data[0], 0xd0, NFSD_FFV2_RO_CHUNK_SIZE);

	/* The first call pins the published provider on this admission. */
	if (nfsd_ffv2_ro_operation_hold(&f, OP_CHUNK_READ, &req, &first,
					&admission) != nfs_ok) {
		KUNIT_FAIL(test, "the first call did not reach the provider");
		goto out;
	}
	KUNIT_EXPECT_EQ(test, 0x40, first.read.chunks[0].cr_chunk[0]);

	/*
	 * Free the registry slot without waiting: the drain would wait for
	 * this very admission.  The provider stays alive because the
	 * admission holds it.
	 */
	unpublished = nfsd_ffv2_test_provider_unpublish(f.nn);
	f.provider_installed = false;
	if (!unpublished) {
		/*
		 * Reported rather than asserted: an assertion would leave
		 * this test case at once, and the admission it is holding
		 * would never be completed.
		 */
		KUNIT_FAIL(test, "no provider was published to unpublish");
		goto out;
	}

	if (nfsd_ffv2_test_provider_install(f.nn, &nfsd_ffv2_ro_provider_ops,
					    replacement,
					    NFSD_FFV2_RO_CHUNK_SIZE)) {
		KUNIT_FAIL(test, "failed to publish the second provider");
		goto out;
	}
	f.provider_installed = true;

	/* The second call on this admission still reaches the first provider. */
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_provider_probe(f.rqstp, f.mapped,
						 OP_CHUNK_READ, &req, &second,
						 U32_MAX, &admission));
	KUNIT_EXPECT_EQ(test, 0, atomic_read(&replacement->reads));
	KUNIT_EXPECT_PTR_EQ(test, first.read.chunks, second.read.chunks);
	KUNIT_EXPECT_EQ(test, 0x40, second.read.chunks[0].cr_chunk[0]);

	/* Both results stay readable until the admission completes. */
	KUNIT_EXPECT_EQ(test, 0x40, first.read.chunks[0].cr_chunk[0]);

out:
	/*
	 * One exit for every path: completing an admission that was never
	 * granted is a no-op, and draining a provider that was never
	 * unpublished is one too, so neither an early assertion nor a setup
	 * failure can strand a provider or an admission here.
	 */
	nfsd_ffv2_complete(&admission);
	nfsd_ffv2_test_provider_drain(unpublished);
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

/*
 * A provider states one chunk size and serves objects of that size only.
 * An object carrying a different one is refused at the boundary: the reply
 * would have been admitted against a size that does not describe it, so the
 * callback is never entered and nothing is left holding a reference.
 */
static void nfsd_ffv2_provider_size_mismatch_test(struct kunit *test)
{
	const struct nfsd_ffv2_chunk_request req = { .offset = 0, .count = 1 };
	struct nfsd_ffv2_chunk_result result = {};
	struct nfsd_ffv2_admission admission = {};
	struct nfsd_ffv2_ro_fixture f;
	u64 callbacks;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	/* The size a layout would have carried, and not the one served. */
	nfsd_ffv2_test_fh_set_chunk_size(f.mapped,
					 NFSD_FFV2_RO_CHUNK_SIZE * 2);
	callbacks = nfsd_ffv2_test_provider_callbacks();
	KUNIT_EXPECT_EQ(test, nfserr_serverfault,
			nfsd_ffv2_ro_operation_hold(&f, OP_CHUNK_READ, &req,
						    &result, &admission));
	/* Refused before the provider was asked. */
	KUNIT_EXPECT_EQ(test, callbacks,
			nfsd_ffv2_test_provider_callbacks());
	KUNIT_EXPECT_EQ(test, 0U, result.count);
	KUNIT_EXPECT_NULL(test, result.read.chunks);
	nfsd_ffv2_complete(&admission);

	/* The same object at the size the provider serves is answered. */
	memset(&admission, 0, sizeof(admission));
	memset(&result, 0, sizeof(result));
	nfsd_ffv2_test_fh_set_chunk_size(f.mapped, NFSD_FFV2_RO_CHUNK_SIZE);
	callbacks = nfsd_ffv2_test_provider_callbacks();
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_ro_operation_hold(&f, OP_CHUNK_READ, &req,
						    &result, &admission));
	KUNIT_EXPECT_EQ(test, callbacks + 1,
			nfsd_ffv2_test_provider_callbacks());
	KUNIT_EXPECT_EQ(test, 1U, result.count);

out:
	nfsd_ffv2_complete(&admission);
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

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
	if (nfsd_ffv2_test_provider_install(f.nn, ops, dynamic,
					    NFSD_FFV2_RO_CHUNK_SIZE)) {
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
			nfsd_ffv2_test_provider_install(f.nn, ops, dynamic,
							NFSD_FFV2_RO_CHUNK_SIZE));
	KUNIT_EXPECT_EQ(test, fenced + 1, nfsd_ffv2_test_provider_fenced());
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
	/* Drained by the fence and never republished, so this is safe. */
	kfree(dynamic);
	kfree(ops);
}

/*
 * S1: a delayed producer publishes to its own namespace's disposal list.
 *
 * The worker is parked before its request loop for the whole observation, so
 * the only thing that could have put an entry on the list is the producer,
 * and nothing can have taken it off again.
 */
static void nfsd_ffv2_delayed_producer_publish_test(struct kunit *test)
{
	struct nfsd_ffv2_dp_service s;
	struct nfsd_ffv2_dp_file *df;

	if (!nfsd_ffv2_dp_service_start(test, &s))
		goto out;
	df = nfsd_ffv2_dp_file_create(test, &s, "s1");
	if (!df)
		goto out;
	if (!nfsd_ffv2_dp_publish(test, &s, df))
		goto out;
	nfsd_ffv2_dp_worker_release(test, &s);
out:
	nfsd_ffv2_dp_service_stop(test, &s);
}

/*
 * S2: repeated producers, each on a file of its own.
 *
 * A cycle cannot reuse a file.  The producer unhashes its victim before
 * queueing it, so a second call against the same inode finds nothing in the
 * cache's hash table and publishes silently nothing.
 */
static void nfsd_ffv2_delayed_producer_repeat_test(struct kunit *test)
{
	static const char * const names[] = { "s2-0", "s2-1", "s2-2", "s2-3" };
	struct nfsd_ffv2_dp_service s;
	struct nfsd_ffv2_dp_file *df;
	unsigned int i;

	if (!nfsd_ffv2_dp_service_start(test, &s))
		goto out;
	for (i = 0; i < ARRAY_SIZE(names); i++) {
		df = nfsd_ffv2_dp_file_create(test, &s, names[i]);
		if (!df)
			goto out;
		if (!nfsd_ffv2_dp_publish(test, &s, df))
			goto out;
	}
	nfsd_ffv2_dp_worker_release(test, &s);
out:
	nfsd_ffv2_dp_service_stop(test, &s);
}

/*
 * S3: the nfsd thread drains what the producer published.
 *
 * The publication is established while the worker is still parked, so the
 * drain that follows is measured against something known to have been there.
 * The wait is bounded because this is a wakeup-driven event; the thread also
 * disposes once per pass of its request loop, so a lost wakeup costs time
 * rather than correctness.  A timeout is a failure.
 */
static void nfsd_ffv2_delayed_producer_drain_test(struct kunit *test)
{
	struct nfsd_ffv2_dp_service s;
	struct nfsd_ffv2_dp_file *df;
	unsigned long deadline;
	bool drained = false;

	if (!nfsd_ffv2_dp_service_start(test, &s))
		goto out;
	df = nfsd_ffv2_dp_file_create(test, &s, "s3");
	if (!df)
		goto out;
	if (!nfsd_ffv2_dp_publish(test, &s, df))
		goto out;
	if (!nfsd_ffv2_dp_worker_release(test, &s))
		goto out;

	deadline = jiffies + NFSD_FFV2_DP_DRAIN_WAIT;
	while (!time_after(jiffies, deadline)) {
		if (nfsd_ffv2_dispose_list_empty(s.net)) {
			drained = true;
			break;
		}
		msleep(50);
	}
	KUNIT_EXPECT_TRUE_MSG(test, drained,
			      "nfsd thread did not drain the disposal list");
out:
	nfsd_ffv2_dp_service_stop(test, &s);
}

/*
 * S4: a per-net shutdown with entries on the disposal list.
 *
 * This does not attribute the drain.  Teardown releases the worker before the
 * per-net shutdown runs, so either the thread or the shutdown's own final
 * pass may have emptied the list and the test cannot tell which.  What it
 * covers is bounded: that entries outstanding across that boundary leave the
 * list empty and the namespace's disposal state intact.  It is list and
 * lifetime evidence, not exhaustive use-after-free detection.
 *
 * The namespace is pinned for the observation because the service drops its
 * own reference during teardown, and the list lives in struct nfsd_net.
 */
static void nfsd_ffv2_delayed_producer_shutdown_test(struct kunit *test)
{
	struct nfsd_ffv2_dp_service s;
	struct nfsd_ffv2_dp_file *df;
	struct net *pinned = NULL;

	if (!nfsd_ffv2_dp_service_start(test, &s))
		goto out;
	df = nfsd_ffv2_dp_file_create(test, &s, "s4");
	if (!df)
		goto out;
	if (!nfsd_ffv2_dp_publish(test, &s, df))
		goto out;
	pinned = get_net(s.net);
out:
	nfsd_ffv2_dp_service_stop(test, &s);
	if (pinned) {
		KUNIT_EXPECT_TRUE_MSG(test,
				      nfsd_ffv2_dispose_list_empty(pinned),
				      "disposal list outlived the per-net shutdown");
		put_net(pinned);
		net_ns_barrier();
	}
}

/*
 * S5: cleanup after a failure at each stage.
 *
 * The stages are defined by how far through the setup they get, because
 * cleanup of a state that was never reached proves nothing.  The early
 * stages stop before the producer runs and so assert no publication.  The
 * last stage leaves the worker parked, which teardown has to cope with.
 *
 * The check that matters comes after the loop.  A service that leaked would
 * hold nfsd_users above zero and leave the global file cache up, so the
 * ownership seam would refuse to bring it up; that it succeeds is what says
 * nothing was orphaned.
 */
static void nfsd_ffv2_delayed_producer_cleanup_test(struct kunit *test)
{
	enum {
		NFSD_FFV2_DP_STOP_AFTER_START,
		NFSD_FFV2_DP_STOP_AFTER_CREATE,
		NFSD_FFV2_DP_STOP_AFTER_ACQUIRE,
		NFSD_FFV2_DP_STOP_AFTER_PRODUCE,
		NFSD_FFV2_DP_STOP_PARKED,
		NFSD_FFV2_DP_STOP_COUNT,
	};
	struct nfsd_ffv2_dp_service s;
	unsigned int stage;
	int error;

	for (stage = 0; stage < NFSD_FFV2_DP_STOP_COUNT; stage++) {
		struct nfsd_ffv2_dp_file *df;
		struct nfsd_file *nf = NULL;
		__be32 status;

		if (!nfsd_ffv2_dp_service_start(test, &s))
			goto next;
		if (stage == NFSD_FFV2_DP_STOP_AFTER_START)
			goto next;

		df = nfsd_ffv2_dp_file_create(test, &s, "s5");
		if (!df)
			goto next;
		if (stage == NFSD_FFV2_DP_STOP_AFTER_CREATE)
			goto next;

		if (stage == NFSD_FFV2_DP_STOP_AFTER_ACQUIRE) {
			status = nfsd_ffv2_dp_acquire(&s, df, &nf);
			if (status != nfs_ok)
				KUNIT_FAIL(test,
					   "cleanup stage acquire failed: %u",
					   be32_to_cpu(status));
			else
				nfsd_file_put(nf);
			goto next;
		}

		if (!nfsd_ffv2_dp_publish(test, &s, df))
			goto next;
		if (stage == NFSD_FFV2_DP_STOP_AFTER_PRODUCE)
			goto next;

		/* NFSD_FFV2_DP_STOP_PARKED: teardown releases the worker. */
next:
		nfsd_ffv2_dp_service_stop(test, &s);
	}

	mutex_lock(&nfsd_mutex);
	error = nfsd_file_ffv2_test_cache_start();
	if (!error)
		nfsd_file_cache_shutdown();
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ_MSG(test, error, 0,
			    "global file cache was still held after cleanup");
}

/* One thread's admission, held live while another thread tries to use it. */
struct nfsd_ffv2_foreign_admission {
	struct nfsd_ffv2_ro_fixture	*f;
	struct nfsd_ffv2_admission	admission;
	__be32				status;
	struct completion		admitted;
	struct completion		release;
	struct completion		done;
};

static int nfsd_ffv2_foreign_admission_thread(void *data)
{
	struct nfsd_ffv2_foreign_admission *ctx = data;

	ctx->status = nfsd_ffv2_test_validate_operation(ctx->f->rqstp,
							ctx->f->mapped,
							ctx->f->session,
							OP_CHUNK_READ,
							&ctx->f->stateid, NULL,
							&ctx->admission);
	complete(&ctx->admitted);
	wait_for_completion(&ctx->release);
	if (ctx->status == nfs_ok)
		nfsd_ffv2_complete(&ctx->admission);
	complete(&ctx->done);
	return 0;
}

/*
 * The boundary refuses to cross without a live admission.
 *
 * A structure that merely exists is not one.  Completion consumes an
 * admission exactly once and returns immediately for one already spent,
 * so a provider reference parked on a spent admission would never be
 * dropped and provider removal would then wait for it forever.  An
 * admission held by another task bounds that task, not this one.
 *
 * The refusals are proved by removing the provider afterwards, which is
 * what a leaked reference would prevent.
 */
static void nfsd_ffv2_provider_unadmitted_test(struct kunit *test)
{
	const struct nfsd_ffv2_chunk_request req = { .offset = 0, .count = 2 };
	struct nfsd_ffv2_foreign_admission foreign = {};
	struct nfsd_ffv2_admission admission = {};
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_ffv2_ro_fixture f;
	struct task_struct *thread;
	u64 callbacks, refused;

	if (!nfsd_ffv2_ro_fixture_init(test, &f))
		goto out;

	/* An admission that was never taken. */
	callbacks = nfsd_ffv2_test_provider_callbacks();
	refused = nfsd_ffv2_test_provider_unadmitted();
	KUNIT_EXPECT_EQ(test, nfserr_serverfault,
			nfsd_ffv2_provider_probe(f.rqstp, f.mapped,
						 OP_CHUNK_READ, &req, &result,
						 U32_MAX, &admission));
	KUNIT_EXPECT_EQ(test, refused + 1,
			nfsd_ffv2_test_provider_unadmitted());
	KUNIT_EXPECT_EQ(test, callbacks,
			nfsd_ffv2_test_provider_callbacks());

	/* One that was taken and has already been completed. */
	KUNIT_ASSERT_EQ(test, nfs_ok,
			nfsd_ffv2_test_validate_operation(f.rqstp, f.mapped,
							  f.session,
							  OP_CHUNK_READ,
							  &f.stateid, NULL,
							  &admission));
	nfsd_ffv2_complete(&admission);
	refused = nfsd_ffv2_test_provider_unadmitted();
	KUNIT_EXPECT_EQ(test, nfserr_serverfault,
			nfsd_ffv2_provider_probe(f.rqstp, f.mapped,
						 OP_CHUNK_READ, &req, &result,
						 U32_MAX, &admission));
	KUNIT_EXPECT_EQ(test, refused + 1,
			nfsd_ffv2_test_provider_unadmitted());
	KUNIT_EXPECT_EQ(test, callbacks,
			nfsd_ffv2_test_provider_callbacks());

	/* A live admission, but another task's. */
	foreign.f = &f;
	init_completion(&foreign.admitted);
	init_completion(&foreign.release);
	init_completion(&foreign.done);
	thread = kthread_run(nfsd_ffv2_foreign_admission_thread, &foreign,
			     "ffv2-foreign");
	if (IS_ERR(thread)) {
		KUNIT_FAIL(test, "failed to start the admitting thread");
		goto out;
	}
	/*
	 * From here that thread holds a live admission until it is released,
	 * and retiring the generation waits for it.  So every way out below
	 * releases it and waits for the thread to leave before the fixture
	 * is torn down, including the ways out that have already failed:
	 * abandoning a live admission would turn a diagnosed failure into a
	 * teardown that never returns.
	 */
	if (!wait_for_completion_timeout(&foreign.admitted, 15 * HZ)) {
		KUNIT_FAIL(test, "the admitting thread never admitted");
		goto join;
	}
	if (foreign.status != nfs_ok) {
		KUNIT_FAIL(test, "the admitting thread failed: 0x%x",
			   be32_to_cpu(foreign.status));
		goto join;
	}

	/*
	 * The live admission itself, so what refuses the crossing is the
	 * owning task and not a spent generation.
	 */
	callbacks = nfsd_ffv2_test_provider_callbacks();
	refused = nfsd_ffv2_test_provider_unadmitted();
	KUNIT_EXPECT_EQ(test, nfserr_serverfault,
			nfsd_ffv2_provider_probe(f.rqstp, f.mapped,
						 OP_CHUNK_READ, &req,
						 &result, U32_MAX,
						 &foreign.admission));
	KUNIT_EXPECT_EQ(test, refused + 1,
			nfsd_ffv2_test_provider_unadmitted());
	KUNIT_EXPECT_EQ(test, callbacks,
			nfsd_ffv2_test_provider_callbacks());
join:
	complete(&foreign.release);
	if (!wait_for_completion_timeout(&foreign.done, 15 * HZ)) {
		KUNIT_FAIL(test, "the admitting thread never left");
		wait_for_completion(&foreign.done);
	}

	/*
	 * The foreign admission is spent and gave its provider reference
	 * back, so an authorized crossing still works.
	 */
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_ro_operation(&f, OP_CHUNK_READ, &f.stateid,
					       &req, &result));

	/*
	 * Nothing leaked: removal waits for the last provider reference, so
	 * it returns only because every crossing gave its reference back.
	 */
	nfsd_ffv2_test_provider_remove(f.nn);
	f.provider_installed = false;
out:
	nfsd_ffv2_ro_fixture_exit(test, &f);
}

/* One encoded word, wherever in the reply buffer it landed. */
static u32 nfsd_ffv2_ro_word(struct xdr_buf *buf, u32 offset)
{
	__be32 word = 0;

	read_bytes_from_xdr_buf(buf, offset, &word, sizeof(word));
	return be32_to_cpu(word);
}

/*
 * Encode one reply into a buffer that has a page vector, not just a head,
 * and hand back its length.  A payload larger than a page has nowhere to
 * go in a single-page buffer, so the transitions this exercises are the
 * point of the buffer.
 */
#define NFSD_FFV2_RO_ENCODE_PAGES	4

static int nfsd_ffv2_ro_encode_paged(struct kunit *test, union nfsd4_op_u *u,
				     struct xdr_buf *buf, struct page **pages,
				     unsigned int npages)
{
	struct xdr_stream xdr;
	__be32 *head;
	__be32 status;
	unsigned int i;

	head = kunit_kzalloc(test, PAGE_SIZE, GFP_KERNEL);
	if (!head)
		return -ENOMEM;
	/* Poison, so an unwritten pad byte cannot read as a zeroed one. */
	memset(head, 0xa5, PAGE_SIZE);
	for (i = 0; i < npages; i++) {
		pages[i] = alloc_page(GFP_KERNEL);
		if (!pages[i])
			return -ENOMEM;
		memset(page_address(pages[i]), 0xa5, PAGE_SIZE);
	}

	memset(buf, 0, sizeof(*buf));
	buf->head[0].iov_base = head;
	buf->head[0].iov_len = 0;
	buf->pages = pages;
	buf->buflen = PAGE_SIZE * (npages + 1);
	xdr.buf = buf;
	xdr.iov = buf->head;
	xdr.p = head;
	xdr.end = (__be32 *)((char *)head + PAGE_SIZE);
	xdr.page_ptr = buf->pages - 1;
	xdr.rqst = NULL;
	xdr_reset_scratch_buffer(&xdr);

	status = nfsd_ffv2_test_encode_chunk_read(&xdr, u);
	if (status != nfs_ok)
		return -EIO;
	return buf->len;
}

/*
 * A single chunk payload larger than a page.
 *
 * The payload is a counted opaque, and a reservation cannot exceed a page:
 * one reservation for the whole opaque fails outright for a chunk this
 * size, whatever the response budget says.  A chunk size comes from the
 * layout and is normally far larger than a page, so this is the ordinary
 * case rather than an extreme one.
 *
 * The length is long enough to leave the head and then leave a page as
 * well, because those are two different transitions: the first ends a
 * partly filled buffer of whatever size the head had left, the second
 * ends a full page and is the one that repeats for the rest of a real
 * chunk.  The bytes are checked either side of both.  The tail padding is
 * checked because the length is deliberately not a multiple of four.
 */
static void nfsd_ffv2_encode_large_payload_test(struct kunit *test)
{
	/* Where the payload's bytes start, once the fixed fields are out. */
	static const u32 off = 8 + 56;
	static const u32 len = 2 * PAGE_SIZE + 509;
	struct page *pages[NFSD_FFV2_RO_ENCODE_PAGES] = {};
	struct nfsd4_chunk_read_ent ent = {};
	struct nfsd4_chunk_read *cr;
	union nfsd4_op_u u = {};
	struct xdr_buf buf;
	unsigned int i;
	u8 *payload;
	u32 at[6];
	u8 byte;
	int size;

	payload = kvmalloc(len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, payload);
	for (i = 0; i < len; i++)
		payload[i] = (u8)(i & 0xff);

	ent.cre_checksum.cs_algorithm = 1;
	ent.cre_checksum.cs_len = 4;
	memset(ent.cre_checksum.cs_value, 0x5a, 4);
	ent.cre_effective_len = len;
	ent.cre_payload_off = 0;
	ent.cre_status = nfs_ok;

	cr = &u.chunk_read;
	cr->cra_eof = true;
	cr->cra_nchunks = 1;
	cr->cra_chunks = &ent;
	cr->cra_payload = payload;
	cr->cra_payload_len = len;

	size = nfsd_ffv2_ro_encode_paged(test, &u, &buf, pages,
					 NFSD_FFV2_RO_ENCODE_PAGES);
	if (size < 0) {
		KUNIT_FAIL(test, "encoding a large payload failed: %d", size);
		goto out;
	}

	/* eof, the chunk count, then the chunk's own fields. */
	KUNIT_EXPECT_EQ(test, 1U, nfsd_ffv2_ro_word(&buf, 0));
	KUNIT_EXPECT_EQ(test, 1U, nfsd_ffv2_ro_word(&buf, 4));
	KUNIT_EXPECT_EQ(test, len, nfsd_ffv2_ro_word(&buf, 8 + 12));
	KUNIT_EXPECT_EQ(test, len, nfsd_ffv2_ro_word(&buf, 8 + 52));

	/*
	 * The payload's own bytes: its two ends, and either side of the
	 * point where the head is exhausted and of the point where the
	 * first page is.
	 */
	at[0] = 0;
	at[1] = PAGE_SIZE - off - 1;
	at[2] = PAGE_SIZE - off;
	at[3] = 2 * PAGE_SIZE - off - 1;
	at[4] = 2 * PAGE_SIZE - off;
	at[5] = len - 1;
	for (i = 0; i < ARRAY_SIZE(at); i++) {
		read_bytes_from_xdr_buf(&buf, off + at[i], &byte, 1);
		KUNIT_EXPECT_EQ_MSG(test, (u8)(at[i] & 0xff), byte,
				    "payload byte %u", at[i]);
	}

	/* The tail padding is zeroed, not left as the poison. */
	for (i = 0; i < xdr_pad_size(len); i++) {
		read_bytes_from_xdr_buf(&buf, off + len + i, &byte, 1);
		KUNIT_EXPECT_EQ(test, 0, byte);
	}
	KUNIT_EXPECT_EQ(test, off + xdr_align_size(len), (u32)size);
out:
	for (i = 0; i < NFSD_FFV2_RO_ENCODE_PAGES; i++)
		if (pages[i])
			__free_page(pages[i]);
	kvfree(payload);
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
/*
 * Prototype authority gate.
 *
 * The gate's hard part is the interval after an enable has claimed the
 * namespace and before it has opened: a namespace exit or a second
 * administrator arriving there must not find a half-built gate to tear
 * down, and must not tear it down twice.  The tests below hold an enable
 * inside that interval with the setup hook and then drive the other
 * callers against it, so the handoff is exercised rather than assumed.
 */

struct nfsd_ffv2_prototype_call_ctx {
	struct nfsd_net		*nn;
	const struct net	*net;
	int			result;
	struct completion	done;
};

static int nfsd_ffv2_prototype_enable_thread(void *data)
{
	struct nfsd_ffv2_prototype_call_ctx *ctx = data;

	ctx->result = nfsd_ffv2_prototype_enable(ctx->nn, ctx->net);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static int nfsd_ffv2_prototype_disable_thread(void *data)
{
	struct nfsd_ffv2_prototype_call_ctx *ctx = data;

	ctx->result = nfsd_ffv2_prototype_disable(ctx->nn, ctx->net);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static int nfsd_ffv2_prototype_pre_exit_thread(void *data)
{
	struct nfsd_ffv2_prototype_call_ctx *ctx = data;

	nfsd_ffv2_net_pre_exit(ctx->nn);
	ctx->result = 0;
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

/* Wait until @want callers are parked on the close owner's completion. */
static bool nfsd_ffv2_prototype_wait_waiters(struct nfsd_net *nn,
					     unsigned int want)
{
	unsigned long deadline = jiffies + 15 * HZ;

	while (nfsd_ffv2_prototype_test_close_waiters(nn) < want) {
		if (time_after(jiffies, deadline))
			return false;
		msleep(20);
	}
	return true;
}

/* Wait for the gate to reach @want, so a race is observed rather than timed. */
static bool nfsd_ffv2_prototype_wait_state(struct nfsd_net *nn,
					   enum nfsd_ffv2_prototype_state want)
{
	unsigned long deadline = jiffies + 15 * HZ;

	while (nfsd_ffv2_prototype_state_get(nn) != want) {
		if (time_after(jiffies, deadline))
			return false;
		msleep(20);
	}
	return true;
}

/*
 * The ordinary cycle, and the exclusions around it: one gate per
 * namespace, no metadata-server source while it is up, and repeated
 * transitions refused rather than silently accepted.
 */
static void nfsd_ffv2_prototype_gate_test(struct kunit *test)
{
	struct nfsd_net *nn;
	int error;

	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_test_net_exit, nn);
	KUNIT_ASSERT_EQ(test, error, 0);

	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OFF,
			nfsd_ffv2_prototype_state_get(nn));
	/* Disabling a gate that is off is a repeated transition, not a no-op. */
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP,
			nfsd_ffv2_prototype_disable(nn, &init_net));

	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_enable(nn, &init_net));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OPEN,
			nfsd_ffv2_prototype_state_get(nn));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_SOURCE_PROTOTYPE,
			nfsd_ffv2_source_get(nn));

	/* A second gate, and a metadata-server source, are both refused. */
	KUNIT_EXPECT_EQ(test, -EBUSY,
			nfsd_ffv2_prototype_enable(nn, &init_net));
	mutex_lock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, -EBUSY,
			nfsd_ffv2_source_claim_locked(nn,
						      NFSD_FFV2_SOURCE_MDS));
	mutex_unlock(&nfsd_mutex);

	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_disable(nn, &init_net));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OFF,
			nfsd_ffv2_prototype_state_get(nn));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_SOURCE_NONE, nfsd_ffv2_source_get(nn));
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP,
			nfsd_ffv2_prototype_disable(nn, &init_net));

	/* The namespace is claimable again, by either source. */
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_enable(nn, &init_net));
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_disable(nn, &init_net));
	mutex_lock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_source_claim_locked(nn,
						      NFSD_FFV2_SOURCE_MDS));
	mutex_unlock(&nfsd_mutex);
	nfsd_ffv2_source_release(nn, NFSD_FFV2_SOURCE_MDS);
}

/*
 * CAP_SYS_ADMIN is not a claim to somebody else's prototype: the four
 * commands after enable require the identity that enabled, and each
 * component of it counts.
 */
static void nfsd_ffv2_prototype_owner_test(struct kunit *test)
{
	const struct cred *old_cred;
	struct cred *other_cred;
	struct nfsd_net *nn;
	struct net *other;
	int error;

	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_test_net_exit, nn);
	KUNIT_ASSERT_EQ(test, error, 0);
	other = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	KUNIT_ASSERT_FALSE(test, IS_ERR(other));

	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_enable(nn, &init_net));

	/* A different network namespace is a different administrator. */
	KUNIT_EXPECT_EQ(test, -EPERM, nfsd_ffv2_prototype_disable(nn, other));

	/* So is the same one in a different user identity. */
	other_cred = prepare_creds();
	KUNIT_ASSERT_NOT_NULL(test, other_cred);
	other_cred->fsuid = make_kuid(current_user_ns(), 1);
	other_cred->uid = other_cred->fsuid;
	old_cred = override_creds(other_cred);
	KUNIT_EXPECT_EQ(test, -EPERM,
			nfsd_ffv2_prototype_disable(nn, &init_net));
	revert_creds(old_cred);
	put_cred(other_cred);

	/* The gate is untouched by either refusal. */
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OPEN,
			nfsd_ffv2_prototype_state_get(nn));
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_disable(nn, &init_net));
	put_net(other);
}

/*
 * A setup that fails while nobody else is closing takes the close role
 * itself and runs both phases, so the reservation and every reference it
 * staged are returned rather than stranded in ENABLING.
 */
static void nfsd_ffv2_prototype_setup_failure_test(struct kunit *test)
{
	struct nfsd_net *nn;
	int error;

	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_test_net_exit, nn);
	KUNIT_ASSERT_EQ(test, error, 0);

	nfsd_ffv2_test_fault_arm(NFSD_FFV2_FAULT_PROTOTYPE_SETUP);
	KUNIT_EXPECT_EQ(test, -ENOMEM,
			nfsd_ffv2_prototype_enable(nn, &init_net));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_FAULT_PROTOTYPE_SETUP,
			nfsd_ffv2_fault_hit());
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OFF,
			nfsd_ffv2_prototype_state_get(nn));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_SOURCE_NONE, nfsd_ffv2_source_get(nn));

	/* And the namespace is enabled normally afterwards. */
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_enable(nn, &init_net));
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_disable(nn, &init_net));
}

/*
 * A closer that arrives while the gate is still ENABLING takes the close
 * role away from the enabling caller.  The enable then only rolls back
 * what it staged, the closer alone drains and releases, and a third caller
 * that finds CLOSING waits rather than draining a second time.
 */
static void nfsd_ffv2_prototype_enabling_close_test(struct kunit *test)
{
	struct nfsd_ffv2_prototype_call_ctx enable = {}, first = {}, second = {};
	struct task_struct *enable_task, *first_task, *second_task;
	struct completion reached, proceed;
	struct nfsd_net *nn;
	bool closing, waited;
	int error;

	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_test_net_exit, nn);
	KUNIT_ASSERT_EQ(test, error, 0);

	init_completion(&reached);
	init_completion(&proceed);
	init_completion(&enable.done);
	init_completion(&first.done);
	init_completion(&second.done);
	enable.nn = nn;
	first.nn = nn;
	second.nn = nn;
	enable.net = &init_net;
	first.net = &init_net;
	second.net = &init_net;
	nfsd_ffv2_prototype_test_setup_hook(&reached, &proceed);

	enable_task = kthread_run(nfsd_ffv2_prototype_enable_thread, &enable,
				  "ffv2-proto-enable");
	KUNIT_ASSERT_FALSE(test, IS_ERR(enable_task));
	KUNIT_ASSERT_TRUE(test,
			  wait_for_completion_timeout(&reached, 15 * HZ) != 0);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_ENABLING,
			nfsd_ffv2_prototype_state_get(nn));

	first_task = kthread_run(nfsd_ffv2_prototype_disable_thread, &first,
				 "ffv2-proto-close1");
	KUNIT_ASSERT_FALSE(test, IS_ERR(first_task));
	/*
	 * The close role is claimed before the enabling caller is released,
	 * which is the interval this test exists for.
	 */
	closing = nfsd_ffv2_prototype_wait_state(nn,
						 NFSD_FFV2_PROTOTYPE_CLOSING);
	KUNIT_EXPECT_TRUE(test, closing);
	second_task = kthread_run(nfsd_ffv2_prototype_disable_thread, &second,
				  "ffv2-proto-close2");
	KUNIT_ASSERT_FALSE(test, IS_ERR(second_task));
	/*
	 * Wait until that closer is actually parked on the owner's
	 * completion.  Starting a thread is not the same as running one, and
	 * a second closer that arrived after the teardown had finished would
	 * be reporting that the gate is off rather than that it waited.
	 */
	waited = nfsd_ffv2_prototype_wait_waiters(nn, 1);
	KUNIT_EXPECT_TRUE(test, waited);

	complete(&proceed);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&enable.done, 30 * HZ) != 0);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&first.done, 30 * HZ) != 0);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&second.done, 30 * HZ) != 0);
	kthread_stop(enable_task);
	kthread_stop(first_task);
	kthread_stop(second_task);

	/* The enable never opened, the first closer owned the teardown. */
	KUNIT_EXPECT_EQ(test, -EBUSY, enable.result);
	KUNIT_EXPECT_EQ(test, 0, first.result);
	KUNIT_EXPECT_EQ(test, -EBUSY, second.result);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OFF,
			nfsd_ffv2_prototype_state_get(nn));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_SOURCE_NONE, nfsd_ffv2_source_get(nn));
}

/*
 * The same handoff, with namespace exit as the closer.  Exit joins the
 * gate's completion rather than releasing the namespace underneath a setup
 * that is still running.
 */
static void nfsd_ffv2_prototype_enabling_pre_exit_test(struct kunit *test)
{
	struct nfsd_ffv2_prototype_call_ctx enable = {}, exiting = {};
	struct task_struct *enable_task, *exit_task;
	struct completion reached, proceed;
	struct nfsd_net *nn;
	bool closing;
	int error;

	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_test_net_exit, nn);
	KUNIT_ASSERT_EQ(test, error, 0);

	init_completion(&reached);
	init_completion(&proceed);
	init_completion(&enable.done);
	init_completion(&exiting.done);
	enable.nn = nn;
	exiting.nn = nn;
	enable.net = &init_net;
	nfsd_ffv2_prototype_test_setup_hook(&reached, &proceed);

	enable_task = kthread_run(nfsd_ffv2_prototype_enable_thread, &enable,
				  "ffv2-proto-enable");
	KUNIT_ASSERT_FALSE(test, IS_ERR(enable_task));
	KUNIT_ASSERT_TRUE(test,
			  wait_for_completion_timeout(&reached, 15 * HZ) != 0);

	exit_task = kthread_run(nfsd_ffv2_prototype_pre_exit_thread, &exiting,
				"ffv2-proto-exit");
	KUNIT_ASSERT_FALSE(test, IS_ERR(exit_task));
	closing = nfsd_ffv2_prototype_wait_state(nn,
						 NFSD_FFV2_PROTOTYPE_CLOSING);
	KUNIT_EXPECT_TRUE(test, closing);
	/* Exit is still inside the gate, not past it. */
	KUNIT_EXPECT_EQ(test, 0, exiting.result);

	complete(&proceed);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&enable.done, 30 * HZ) != 0);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&exiting.done, 30 * HZ) != 0);
	kthread_stop(enable_task);
	kthread_stop(exit_task);

	KUNIT_EXPECT_EQ(test, -EBUSY, enable.result);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OFF,
			nfsd_ffv2_prototype_state_get(nn));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_SOURCE_NONE, nfsd_ffv2_source_get(nn));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_NET_EXITING, nn->ffv2.net_state);
}

/*
 * Challenges.  A registration has to name something this server issued, to
 * the administrator it issued it to, before it expired -- and each of those
 * failures has to be distinguishable, because they mean different things to
 * whoever is driving the demonstrator.
 */
static void nfsd_ffv2_prototype_challenge_test(struct kunit *test)
{
	u8 first[NFSD_FFV2_PROTOTYPE_NONCE_LEN];
	u8 second[NFSD_FFV2_PROTOTYPE_NONCE_LEN];
	u8 forged[NFSD_FFV2_PROTOTYPE_NONCE_LEN];
	const struct cred *old_cred;
	struct cred *other_cred;
	u64 expires = 0, before;
	struct nfsd_net *nn;
	int error;

	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_test_net_exit, nn);
	KUNIT_ASSERT_EQ(test, error, 0);

	/* A gate that is off issues nothing. */
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP,
			nfsd_ffv2_prototype_challenge(nn, &init_net, first,
						      &expires));

	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_enable(nn, &init_net));
	before = ktime_get_ns();
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_prototype_challenge(nn, &init_net, first,
						      &expires));
	KUNIT_EXPECT_GT(test, expires, before);
	KUNIT_EXPECT_LE(test, expires,
			before + 2 * NFSD_FFV2_PROTOTYPE_NONCE_TTL_NS);
	KUNIT_EXPECT_EQ(test, 1u, nfsd_ffv2_prototype_test_nonce_count(nn));
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_prototype_test_nonce_check(nn, &init_net,
							     first));

	/* Two challenges are two distinct nonces, both live. */
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_prototype_challenge(nn, &init_net, second,
						      &expires));
	KUNIT_EXPECT_NE(test, 0,
			memcmp(first, second,
			       NFSD_FFV2_PROTOTYPE_NONCE_LEN));
	KUNIT_EXPECT_EQ(test, 2u, nfsd_ffv2_prototype_test_nonce_count(nn));

	/*
	 * A nonce with the right index and the wrong remainder is unknown,
	 * not merely refused: knowing which record a guess landed on would
	 * tell the guesser that the index was right.
	 */
	memcpy(forged, first, sizeof(forged));
	forged[sizeof(forged) - 1] ^= 0xff;
	KUNIT_EXPECT_EQ(test, -ENOENT,
			nfsd_ffv2_prototype_test_nonce_check(nn, &init_net,
							     forged));
	/* And an index that names nothing is unknown too. */
	memset(forged, 0xff, sizeof(forged));
	KUNIT_EXPECT_EQ(test, -ENOENT,
			nfsd_ffv2_prototype_test_nonce_check(nn, &init_net,
							     forged));

	/* Another administrator cannot present this one's challenge. */
	other_cred = prepare_creds();
	KUNIT_ASSERT_NOT_NULL(test, other_cred);
	other_cred->fsuid = make_kuid(current_user_ns(), 1);
	other_cred->uid = other_cred->fsuid;
	old_cred = override_creds(other_cred);
	KUNIT_EXPECT_EQ(test, -EPERM,
			nfsd_ffv2_prototype_test_nonce_check(nn, &init_net,
							     first));
	KUNIT_EXPECT_EQ(test, -EPERM,
			nfsd_ffv2_prototype_challenge(nn, &init_net, forged,
						      &expires));
	revert_creds(old_cred);
	put_cred(other_cred);

	/* An expired challenge reports its expiry once and is then gone. */
	nfsd_ffv2_prototype_test_nonce_age(nn, first);
	KUNIT_EXPECT_EQ(test, -ETIMEDOUT,
			nfsd_ffv2_prototype_test_nonce_check(nn, &init_net,
							     first));
	KUNIT_EXPECT_EQ(test, 1u, nfsd_ffv2_prototype_test_nonce_count(nn));
	KUNIT_EXPECT_EQ(test, -ENOENT,
			nfsd_ffv2_prototype_test_nonce_check(nn, &init_net,
							     first));

	/* Challenges do not survive the gate that issued them. */
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_disable(nn, &init_net));
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_enable(nn, &init_net));
	KUNIT_EXPECT_EQ(test, 0u, nfsd_ffv2_prototype_test_nonce_count(nn));
	KUNIT_EXPECT_EQ(test, -ENOENT,
			nfsd_ffv2_prototype_test_nonce_check(nn, &init_net,
							     second));
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_disable(nn, &init_net));
}

/*
 * Registration and one authorized read through the prototype profile.
 *
 * The fixture below is deliberately smaller than the read-only one: it
 * publishes nothing itself, because the registration under test is what
 * has to publish.  Everything it builds is what an operator would have
 * arranged beforehand -- a service, an export, a client domain and a
 * regular file under that export -- and nothing else.
 */
#define NFSD_FFV2_PROTO_CHUNK_SIZE	64
#define NFSD_FFV2_PROTO_CHUNKS		4
#define NFSD_FFV2_PROTO_DOMAIN		"ffv2-proto-kunit"

struct nfsd_ffv2_proto_fixture {
	struct net			*net;
	struct nfsd_net			*nn;
	struct nfsd4_session		*session;
	struct svc_rqst			*rqstp;
	struct svc_xprt			*xprt;
	struct svc_fh			*mapped;
	struct auth_domain		*domain;
	struct svc_export		*seeded;
	struct svc_export		*published;
	struct nfsd_ffv2_binding	*binding;
	struct path			root;
	struct dentry			*object_dentry;
	u8				uuid[16];
	/* The ordinary handle the substituted resolution hands back. */
	u8				inner[8];
	u16				inner_len;
	u8				bytes[NFSD_FFV2_PROTO_CHUNKS *
					      NFSD_FFV2_PROTO_CHUNK_SIZE];
	bool				enabled;
	bool				service_up;
	bool				filecache_up;
	bool				root_held;
};

static void nfsd_ffv2_proto_fixture_exit(struct nfsd_ffv2_proto_fixture *f)
{
	nfsd_ffv2_prototype_test_object_hook(NULL, NULL, NULL, 0, NULL, 0, 0);
	if (f->mapped && f->mapped->fh_dentry) {
		fh_put(f->mapped);
		f->binding = NULL;
	}
	if (f->binding) {
		nfsd_ffv2_binding_put(f->binding);
		f->binding = NULL;
	}
	if (f->published) {
		exp_put(f->published);
		f->published = NULL;
	}
	if (f->seeded) {
		exp_put(f->seeded);
		f->seeded = NULL;
	}
	if (f->enabled) {
		nfsd_ffv2_prototype_disable(f->nn, f->net);
		f->enabled = false;
	}
	if (f->service_up) {
		struct nfsd_ffv2_generation *generation;

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

static bool nfsd_ffv2_proto_fixture_init(struct kunit *test,
					 struct nfsd_ffv2_proto_fixture *f)
{
	static const u8 inner[] = { 1, 0, 1, 1, 0xa7, 0xb7, 0xc7, 0xd7 };
	struct inode *object_inode;
	struct svc_export exp;
	struct svc_export *cached;
	unsigned int i;
	int error;

	memset(f, 0, sizeof(*f));
	memset(f->uuid, 0x3d, sizeof(f->uuid));
	for (i = 0; i < sizeof(f->bytes); i++)
		f->bytes[i] = (u8)(i * 7 + 1);

	f->rqstp = kunit_kzalloc(test, sizeof(*f->rqstp), GFP_KERNEL);
	f->xprt = kunit_kzalloc(test, sizeof(*f->xprt), GFP_KERNEL);
	f->mapped = kunit_kzalloc(test, sizeof(*f->mapped), GFP_KERNEL);
	f->session = nfsd_ffv2_test_session(test);
	if (!f->rqstp || !f->xprt || !f->mapped || !f->session) {
		KUNIT_FAIL(test, "failed to allocate prototype fixture");
		return false;
	}
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
	spin_lock_init(&f->nn->client_lock);

	f->domain = unix_domain_find(NFSD_FFV2_PROTO_DOMAIN);
	if (!f->domain) {
		KUNIT_FAIL(test, "failed to create fixture auth domain");
		return false;
	}
	get_fs_root(current->fs, &f->root);
	f->root_held = true;

	f->object_dentry = d_alloc_name(f->root.dentry, "ffv2-proto-object");
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

	nfsd_ffv2_init_test_export(&exp, f->nn, f->domain, &f->root);
	exp.ex_uuid = kmemdup(f->uuid, sizeof(f->uuid), GFP_KERNEL);
	if (!exp.ex_uuid) {
		KUNIT_FAIL(test, "failed to allocate fixture export UUID");
		return false;
	}
	cached = nfsd_export_cache_update(&exp);
	if (IS_ERR(cached)) {
		KUNIT_FAIL(test, "fixture export publication failed: %ld",
			   PTR_ERR(cached));
		kfree(exp.ex_uuid);
		return false;
	}
	f->seeded = cached;

	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_service_up(f->nn);
	f->service_up = !error;
	if (!error) {
		error = nfsd_file_ffv2_test_cache_start();
		f->filecache_up = !error;
	}
	mutex_unlock(&nfsd_mutex);
	if (error) {
		KUNIT_FAIL(test, "fixture service start failed: %d", error);
		return false;
	}

	/*
	 * The resolution a registration would perform, and the object's
	 * bytes: see the hook's own comment for why neither can happen here.
	 */
	memcpy(f->inner, inner, sizeof(inner));
	f->inner_len = sizeof(inner);
	nfsd_ffv2_prototype_test_object_hook(f->seeded, f->object_dentry,
					     f->inner, f->inner_len, f->bytes,
					     sizeof(f->bytes), 0);
	return true;
}

/* Fill in a registration request the fixture's object satisfies. */
static void nfsd_ffv2_proto_request(struct nfsd_ffv2_prototype_request *req,
				    const u8 *nonce)
{
	static const u8 handle[] = { 1, 0, 1, 1, 0xa7, 0xb7, 0xc7, 0xd7 };

	memset(req, 0, sizeof(*req));
	req->nonce = nonce;
	req->auth_domain = NFSD_FFV2_PROTO_DOMAIN;
	req->handle = handle;
	req->handle_len = sizeof(handle);
	req->chunk_size = NFSD_FFV2_PROTO_CHUNK_SIZE;
	req->data_count = NFSD_FFV2_PROTO_CHUNKS;
	req->parity_count = 0;
}

/*
 * The whole transaction: enable, challenge, register, map, read, and
 * unregister.  What it proves is that the profile publishes an object a
 * client can actually read through the production boundary, that a mapping
 * is refused on either side of READY, and that a retry is recognised as
 * the same registration rather than performed twice.
 */
static void nfsd_ffv2_prototype_read_test(struct kunit *test)
{
	const struct nfsd_ffv2_chunk_request creq = { .offset = 0, .count = 4 };
	u8 nonce[NFSD_FFV2_PROTOTYPE_NONCE_LEN];
	u8 spent[NFSD_FFV2_PROTOTYPE_NONCE_LEN];
	struct nfsd_ffv2_prototype_request req;
	struct nfsd_ffv2_prototype_bundle *bundle, *replay;
	struct nfsd_ffv2_admission admission = {};
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_ffv2_proto_fixture *f;
	struct nfsd_ffv2_fh_info info;
	struct nfsd_ffv2_binding *again;
	struct knfsd_fh outer = {};
	struct svc_export exp;
	stateid_t stateid;
	u64 expires = 0;
	u64 callbacks;
	unsigned int i;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	bundle = kunit_kzalloc(test, sizeof(*bundle), GFP_KERNEL);
	replay = kunit_kzalloc(test, sizeof(*replay), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_NOT_NULL(test, bundle);
	KUNIT_ASSERT_NOT_NULL(test, replay);
	if (!nfsd_ffv2_proto_fixture_init(test, f))
		goto out;

	KUNIT_ASSERT_EQ(test, 0, nfsd_ffv2_prototype_enable(f->nn, f->net));
	f->enabled = true;
	KUNIT_ASSERT_EQ(test, 0,
			nfsd_ffv2_prototype_challenge(f->nn, f->net, nonce,
						      &expires));
	memcpy(spent, nonce, sizeof(spent));
	nfsd_ffv2_proto_request(&req, spent);
	KUNIT_ASSERT_EQ(test, 0,
			nfsd_ffv2_prototype_register(f->nn, f->net, &req,
						     bundle));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_READY,
			nfsd_ffv2_prototype_state_get(f->nn));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_SOURCE_PROTOTYPE,
			nfsd_ffv2_source_get(f->nn));
	KUNIT_EXPECT_NE(test, 0ULL, bundle->generation);
	KUNIT_EXPECT_GT(test, bundle->handle_len, 0u);

	/*
	 * The same request again is the same registration, and is answered
	 * even though the gate has moved on to READY: a lost reply is
	 * exactly the case a replay exists for.
	 */
	memset(replay, 0, sizeof(*replay));
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_prototype_register(f->nn, f->net, &req,
						     replay));
	/* Complete, not merely equal: a zeroed reply would compare equal to
	 * a zeroed original.
	 */
	KUNIT_EXPECT_EQ(test, bundle->generation, replay->generation);
	KUNIT_EXPECT_NE(test, 0ULL, replay->generation);
	KUNIT_EXPECT_EQ(test, bundle->handle_len, replay->handle_len);
	KUNIT_EXPECT_GT(test, replay->handle_len, 0u);
	KUNIT_EXPECT_EQ(test, 0, memcmp(bundle, replay, sizeof(*bundle)));
	/* A different request wearing the same nonce is not. */
	req.chunk_size = NFSD_FFV2_PROTO_CHUNK_SIZE * 2;
	KUNIT_EXPECT_EQ(test, -EEXIST,
			nfsd_ffv2_prototype_register(f->nn, f->net, &req,
						     replay));
	req.chunk_size = NFSD_FFV2_PROTO_CHUNK_SIZE;

	/*
	 * A challenge is still issued while a registration is published --
	 * nothing about it depends on the gate being idle -- but a second
	 * registration is refused until the first is unregistered.
	 */
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_prototype_challenge(f->nn, f->net, nonce,
						      &expires));
	nfsd_ffv2_proto_request(&req, nonce);
	KUNIT_EXPECT_EQ(test, -EBUSY,
			nfsd_ffv2_prototype_register(f->nn, f->net, &req,
						     replay));
	/* Back to the nonce the published registration was made with. */
	nfsd_ffv2_proto_request(&req, spent);

	/* Map what the registration handed back, exactly as PUTFH would. */
	memcpy(outer.fh_raw, bundle->handle, bundle->handle_len);
	outer.fh_size = bundle->handle_len;
	KUNIT_ASSERT_EQ(test, 0, nfsd_ffv2_fh_parse(&outer, &info));
	f->binding = nfsd_ffv2_test_binding_create(f->nn, &info);
	if (IS_ERR(f->binding)) {
		KUNIT_FAIL(test, "prototype binding admission failed: %ld",
			   PTR_ERR(f->binding));
		f->binding = NULL;
		goto out;
	}
	nfsd_ffv2_init_test_export(&exp, f->nn, f->domain, &f->root);
	f->published = nfsd_ffv2_test_export_lookup(&exp);
	if (!f->published) {
		KUNIT_FAIL(test, "prototype service export not found");
		goto out;
	}
	fh_init(f->mapped, NFS4_FHSIZE);
	f->mapped->fh_handle = outer;
	f->mapped->fh_export = nfsd_export_get(f->published);
	f->mapped->fh_dentry = dget(f->object_dentry);
	f->mapped->fh_ffv2_binding = f->binding;
	f->binding = NULL;

	memcpy(&stateid, bundle->stateid, sizeof(stateid));
	callbacks = nfsd_ffv2_test_provider_callbacks();
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_test_validate_operation(f->rqstp, f->mapped,
							  f->session,
							  OP_CHUNK_READ,
							  &stateid, NULL,
							  &admission));
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_provider_probe(f->rqstp, f->mapped,
						 OP_CHUNK_READ, &creq, &result,
						 U32_MAX, &admission));
	KUNIT_EXPECT_EQ(test, callbacks + 1,
			nfsd_ffv2_test_provider_callbacks());
	KUNIT_EXPECT_EQ(test, (u32)NFSD_FFV2_PROTO_CHUNKS, result.count);
	KUNIT_EXPECT_TRUE(test, result.eof);
	if (result.read.chunks) {
		for (i = 0; i < result.count; i++) {
			const struct nfsd_ffv2_read_chunk *chunk =
				&result.read.chunks[i];
			const u8 *want = f->bytes +
					 i * NFSD_FFV2_PROTO_CHUNK_SIZE;
			u32 crc = crc32_le(~0U, want,
					   NFSD_FFV2_PROTO_CHUNK_SIZE) ^ ~0U;

			KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTO_CHUNK_SIZE,
					chunk->cr_effective_len);
			KUNIT_EXPECT_EQ(test, nfs_ok, chunk->cr_status);
			KUNIT_EXPECT_EQ(test, bundle->generation,
					chunk->cr_owner.co_cohort_id);
			KUNIT_EXPECT_EQ(test, i, chunk->cr_owner.co_id);
			KUNIT_EXPECT_EQ(test,
					NFSD_FFV2_CHECKSUM_ALG_CRC32,
					chunk->cr_checksum.cs_algorithm);
			KUNIT_EXPECT_EQ(test, NFSD_FFV2_CHECKSUM_CRC32_LEN,
					chunk->cr_checksum.cs_len);
			KUNIT_EXPECT_EQ(test, crc,
					get_unaligned_be32(chunk->cr_checksum.cs_value));
			if (!chunk->cr_chunk) {
				KUNIT_FAIL(test, "chunk %u carried no bytes",
					   i);
				continue;
			}
			KUNIT_EXPECT_EQ(test, 0,
					memcmp(chunk->cr_chunk, want,
					       NFSD_FFV2_PROTO_CHUNK_SIZE));
		}
	} else {
		KUNIT_FAIL(test, "read returned no chunk array");
	}
	nfsd_ffv2_complete(&admission);

	/*
	 * Release the mapping and the fixture's own reference to the
	 * published export before the registration they belong to: retiring
	 * a generation waits for its export to be released, so holding one
	 * across the unregister would be waiting on this thread.
	 */
	fh_put(f->mapped);
	exp_put(f->published);
	f->published = NULL;

	KUNIT_EXPECT_EQ(test, -ESTALE,
			nfsd_ffv2_prototype_unregister(f->nn, f->net,
						       bundle->source_uuid,
						       bundle->generation + 1));
	/*
	 * Retiring the object closes the gate: it is the same teardown, and
	 * one implementation of it is what keeps a replay from racing it.
	 */
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_prototype_unregister(f->nn, f->net,
						       bundle->source_uuid,
						       bundle->generation));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OFF,
			nfsd_ffv2_prototype_state_get(f->nn));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_SOURCE_NONE,
			nfsd_ffv2_source_get(f->nn));
	f->enabled = false;
	/* Nothing is published, so nothing maps. */
	again = nfsd_ffv2_test_binding_create(f->nn, &info);
	KUNIT_EXPECT_TRUE(test, IS_ERR(again));
	if (!IS_ERR(again))
		nfsd_ffv2_binding_put(again);
	/* And the nonce that named it went with the gate that issued it. */
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP,
			nfsd_ffv2_prototype_register(f->nn, f->net, &req,
						     replay));
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP,
			nfsd_ffv2_prototype_unregister(f->nn, f->net,
						       bundle->source_uuid,
						       bundle->generation));
out:
	nfsd_ffv2_proto_fixture_exit(f);
}

/*
 * The interval between a registration publishing its generation and the
 * gate reaching READY.
 *
 * The generation is active inside it -- publication is what makes it
 * active -- so the only thing keeping an operation out is the gate's own
 * final transition.  This holds a registration open in exactly that
 * interval and asks the production admission predicate what it would say
 * about a mapping arriving there.
 */
struct nfsd_ffv2_proto_register_ctx {
	struct nfsd_ffv2_proto_fixture		*f;
	struct nfsd_ffv2_prototype_request	req;
	struct nfsd_ffv2_prototype_bundle	*bundle;
	int					result;
	struct completion			done;
};

static int nfsd_ffv2_proto_register_thread(void *data)
{
	struct nfsd_ffv2_proto_register_ctx *ctx = data;

	ctx->result = nfsd_ffv2_prototype_register(ctx->f->nn, ctx->f->net,
						   &ctx->req, ctx->bundle);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static void nfsd_ffv2_prototype_publish_window_test(struct kunit *test)
{
	struct nfsd_ffv2_proto_register_ctx *ctx;
	struct nfsd_ffv2_generation *generation;
	static const u8 unpublished[16] = { 0 };
	u8 nonce[NFSD_FFV2_PROTOTYPE_NONCE_LEN];
	struct nfsd_ffv2_proto_fixture *f;
	struct completion reached, proceed;
	struct task_struct *task;
	bool counted = false;
	u64 expires = 0;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	KUNIT_ASSERT_NOT_NULL(test, f);
	ctx->bundle = kunit_kzalloc(test, sizeof(*ctx->bundle), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx->bundle);
	if (!nfsd_ffv2_proto_fixture_init(test, f))
		goto out;

	KUNIT_ASSERT_EQ(test, 0, nfsd_ffv2_prototype_enable(f->nn, f->net));
	f->enabled = true;
	KUNIT_ASSERT_EQ(test, 0,
			nfsd_ffv2_prototype_challenge(f->nn, f->net, nonce,
						      &expires));
	nfsd_ffv2_proto_request(&ctx->req, nonce);
	ctx->f = f;
	init_completion(&ctx->done);
	init_completion(&reached);
	init_completion(&proceed);
	nfsd_ffv2_prototype_test_publish_hook(&reached, &proceed);

	task = kthread_run(nfsd_ffv2_proto_register_thread, ctx,
			   "ffv2-proto-reg");
	if (IS_ERR(task)) {
		KUNIT_FAIL(test, "failed to start the registering thread");
		goto out;
	}
	if (!wait_for_completion_timeout(&reached, 30 * HZ)) {
		KUNIT_FAIL(test, "the registration never reached publication");
		goto join;
	}

	/* The generation is already active... */
	generation = nfsd_ffv2_test_active_generation_get(f->nn);
	KUNIT_EXPECT_NOT_NULL(test, generation);
	if (generation)
		nfsd_ffv2_test_generation_put(generation);
	/* ...and the gate still refuses every mapping into it. */
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OPEN,
			nfsd_ffv2_prototype_state_get(f->nn));
	KUNIT_EXPECT_EQ(test, -ESTALE,
			nfsd_ffv2_prototype_op_admit(f->nn, &counted));
	KUNIT_EXPECT_FALSE(test, counted);
	/*
	 * An unregister cannot claim the gate here either.  It names the
	 * registration it expects to find, and this one has not published
	 * yet, so there is nothing for it to retire and nothing for it to
	 * take the close role over.
	 */
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP,
			nfsd_ffv2_prototype_unregister(f->nn, f->net,
						       unpublished, 1));

join:
	complete(&proceed);
	if (!wait_for_completion_timeout(&ctx->done, 30 * HZ)) {
		KUNIT_FAIL(test, "the registering thread never returned");
		wait_for_completion(&ctx->done);
	}
	kthread_stop(task);

	KUNIT_EXPECT_EQ(test, 0, ctx->result);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_READY,
			nfsd_ffv2_prototype_state_get(f->nn));
	/* And admits one once the registration has finished. */
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_prototype_op_admit(f->nn, &counted));
	KUNIT_EXPECT_TRUE(test, counted);
	if (counted)
		nfsd_ffv2_prototype_op_release(f->nn);
out:
	nfsd_ffv2_proto_fixture_exit(f);
}

/*
 * Two challenges reaping the same expired records at once.
 *
 * The reaper walks a table another challenge may be erasing from, and what
 * it reads to judge a record is storage that other caller is entitled to
 * have freed.  This starts both walks on the same expired records and
 * asks for the arithmetic afterwards: three records went in, three were
 * removed once each, and two new ones remain.  A second removal of any
 * record would take the count below zero and warn, and the run is checked
 * for warnings.
 */
struct nfsd_ffv2_proto_challenge_ctx {
	struct nfsd_net		*nn;
	const struct net	*net;
	struct completion	*start;
	u8			nonce[NFSD_FFV2_PROTOTYPE_NONCE_LEN];
	u64			expires;
	int			result;
	struct completion	done;
};

static int nfsd_ffv2_proto_challenge_thread(void *data)
{
	struct nfsd_ffv2_proto_challenge_ctx *ctx = data;

	wait_for_completion(ctx->start);
	ctx->result = nfsd_ffv2_prototype_challenge(ctx->nn, ctx->net,
						    ctx->nonce, &ctx->expires);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static void nfsd_ffv2_prototype_nonce_reap_test(struct kunit *test)
{
	u8 aged[3][NFSD_FFV2_PROTOTYPE_NONCE_LEN];
	struct nfsd_ffv2_proto_challenge_ctx *first, *second;
	struct task_struct *first_task, *second_task;
	struct completion start;
	struct nfsd_net *nn;
	u64 expires = 0;
	unsigned int i;
	int error;

	first = kunit_kzalloc(test, sizeof(*first), GFP_KERNEL);
	second = kunit_kzalloc(test, sizeof(*second), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, first);
	KUNIT_ASSERT_NOT_NULL(test, second);
	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_test_net_exit, nn);
	KUNIT_ASSERT_EQ(test, error, 0);
	KUNIT_ASSERT_EQ(test, 0, nfsd_ffv2_prototype_enable(nn, &init_net));

	for (i = 0; i < ARRAY_SIZE(aged); i++)
		KUNIT_ASSERT_EQ(test, 0,
				nfsd_ffv2_prototype_challenge(nn, &init_net,
							      aged[i],
							      &expires));
	KUNIT_EXPECT_EQ(test, ARRAY_SIZE(aged),
			nfsd_ffv2_prototype_test_nonce_count(nn));
	for (i = 0; i < ARRAY_SIZE(aged); i++)
		nfsd_ffv2_prototype_test_nonce_age(nn, aged[i]);

	init_completion(&start);
	init_completion(&first->done);
	init_completion(&second->done);
	first->nn = nn;
	second->nn = nn;
	first->net = &init_net;
	second->net = &init_net;
	first->start = &start;
	second->start = &start;
	first_task = kthread_run(nfsd_ffv2_proto_challenge_thread, first,
				 "ffv2-proto-reap1");
	KUNIT_ASSERT_FALSE(test, IS_ERR(first_task));
	second_task = kthread_run(nfsd_ffv2_proto_challenge_thread, second,
				  "ffv2-proto-reap2");
	if (IS_ERR(second_task)) {
		KUNIT_FAIL(test, "failed to start the second challenge");
		complete_all(&start);
		wait_for_completion(&first->done);
		kthread_stop(first_task);
		goto out;
	}
	complete_all(&start);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&first->done,
						      30 * HZ) != 0);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&second->done,
						      30 * HZ) != 0);
	kthread_stop(first_task);
	kthread_stop(second_task);

	KUNIT_EXPECT_EQ(test, 0, first->result);
	KUNIT_EXPECT_EQ(test, 0, second->result);
	/* The three expired records are gone, and only the two new remain. */
	KUNIT_EXPECT_EQ(test, 2u, nfsd_ffv2_prototype_test_nonce_count(nn));
	for (i = 0; i < ARRAY_SIZE(aged); i++)
		KUNIT_EXPECT_EQ(test, -ENOENT,
				nfsd_ffv2_prototype_test_nonce_check(nn,
								     &init_net,
								     aged[i]));
	/* And what the two threads were issued is still usable. */
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_prototype_test_nonce_check(nn, &init_net,
							     first->nonce));
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_prototype_test_nonce_check(nn, &init_net,
							     second->nonce));
out:
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_disable(nn, &init_net));
}

/*
 * A registration that reaches its final publication after a close owner
 * has claimed the gate.
 *
 * Everything between admitting a registration and publishing it is
 * sleepable -- an export lookup, a publication, a whole object read -- so
 * a DISABLE can arrive in the middle of it.  This holds a registration at
 * exactly its last step, closes the gate underneath it, and then asks what
 * each side did: the registration must publish nothing and the close owner
 * must have nothing of it left to remove.
 *
 * What proves the namespace really was returned is the registration that
 * follows.  A provider left installed would refuse the next install, and a
 * generation left published would refuse the next publication, so a second
 * cycle succeeding is a stronger statement than any counter.
 */
static void nfsd_ffv2_prototype_publish_close_race_test(struct kunit *test)
{
	struct nfsd_ffv2_proto_register_ctx *ctx;
	struct nfsd_ffv2_prototype_call_ctx *closer;
	struct nfsd_ffv2_generation *generation;
	u8 nonce[NFSD_FFV2_PROTOTYPE_NONCE_LEN];
	struct task_struct *task, *close_task;
	struct nfsd_ffv2_ro_provider *spare;
	struct nfsd_ffv2_proto_fixture *f;
	struct completion reached, proceed;
	u64 expires = 0;
	bool closing;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	closer = kunit_kzalloc(test, sizeof(*closer), GFP_KERNEL);
	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	KUNIT_ASSERT_NOT_NULL(test, closer);
	KUNIT_ASSERT_NOT_NULL(test, f);
	ctx->bundle = kunit_kzalloc(test, sizeof(*ctx->bundle), GFP_KERNEL);
	spare = kunit_kzalloc(test, sizeof(*spare), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx->bundle);
	KUNIT_ASSERT_NOT_NULL(test, spare);
	nfsd_ffv2_ro_provider_init(spare);
	if (!nfsd_ffv2_proto_fixture_init(test, f))
		goto out;

	KUNIT_ASSERT_EQ(test, 0, nfsd_ffv2_prototype_enable(f->nn, f->net));
	f->enabled = true;
	KUNIT_ASSERT_EQ(test, 0,
			nfsd_ffv2_prototype_challenge(f->nn, f->net, nonce,
						      &expires));
	/* A bundle the registration must not fill in. */
	memset(ctx->bundle, 0xa5, sizeof(*ctx->bundle));
	nfsd_ffv2_proto_request(&ctx->req, nonce);
	ctx->f = f;
	init_completion(&ctx->done);
	init_completion(&closer->done);
	init_completion(&reached);
	init_completion(&proceed);
	closer->nn = f->nn;
	closer->net = f->net;
	nfsd_ffv2_prototype_test_publish_hook(&reached, &proceed);

	task = kthread_run(nfsd_ffv2_proto_register_thread, ctx,
			   "ffv2-proto-reg");
	if (IS_ERR(task)) {
		KUNIT_FAIL(test, "failed to start the registering thread");
		goto out;
	}
	if (!wait_for_completion_timeout(&reached, 30 * HZ)) {
		KUNIT_FAIL(test, "the registration never reached publication");
		goto join;
	}
	close_task = kthread_run(nfsd_ffv2_prototype_disable_thread, closer,
				 "ffv2-proto-close");
	if (IS_ERR(close_task)) {
		KUNIT_FAIL(test, "failed to start the closing thread");
		goto join;
	}
	/* The close role is claimed while the registration is still inside. */
	closing = nfsd_ffv2_prototype_wait_state(f->nn,
						 NFSD_FFV2_PROTOTYPE_CLOSING);
	KUNIT_EXPECT_TRUE(test, closing);

	complete(&proceed);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&ctx->done, 60 * HZ) != 0);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&closer->done,
						      60 * HZ) != 0);
	kthread_stop(task);
	kthread_stop(close_task);

	/* The registration published nothing and said so. */
	KUNIT_EXPECT_EQ(test, -EBUSY, ctx->result);
	KUNIT_EXPECT_EQ(test, 0, closer->result);
	KUNIT_EXPECT_EQ(test, 0xa5, ctx->bundle->handle[0]);
	KUNIT_EXPECT_EQ(test, 0xa5a5a5a5u, ctx->bundle->handle_len);
	/* The close owner finished, and took the generation with it. */
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OFF,
			nfsd_ffv2_prototype_state_get(f->nn));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_SOURCE_NONE,
			nfsd_ffv2_source_get(f->nn));
	f->enabled = false;
	generation = nfsd_ffv2_test_active_generation_get(f->nn);
	KUNIT_EXPECT_NULL(test, generation);
	if (generation)
		nfsd_ffv2_test_generation_put(generation);

	/*
	 * And the provider slot is free.  A namespace admits one provider,
	 * so installing one here succeeds only if the abandoned registration
	 * really did take its own out; a provider left behind would refuse
	 * this with -EBUSY.
	 */
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_test_provider_install(f->nn,
							&nfsd_ffv2_ro_provider_ops,
							spare,
							NFSD_FFV2_RO_CHUNK_SIZE));
	nfsd_ffv2_test_provider_remove(f->nn);
	goto out;

join:
	complete(&proceed);
	wait_for_completion(&ctx->done);
	kthread_stop(task);
out:
	nfsd_ffv2_proto_fixture_exit(f);
}

/*
 * An object that measures larger than it can supply.
 *
 * The snapshot is read in one call after the size is sampled, and a file
 * that shrinks between the two returns fewer bytes than the layout
 * describes.  The zeroed remainder of the buffer is not data the object
 * ever held, and reporting it as though it were would hand a client
 * fabricated bytes under a checksum this server computed over them.  The
 * registration has to fail instead.
 */
static void nfsd_ffv2_prototype_short_read_test(struct kunit *test)
{
	u8 nonce[NFSD_FFV2_PROTOTYPE_NONCE_LEN];
	struct nfsd_ffv2_prototype_request req;
	struct nfsd_ffv2_prototype_bundle *bundle;
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_ro_provider *spare;
	struct nfsd_ffv2_proto_fixture *f;
	u64 expires = 0;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	bundle = kunit_kzalloc(test, sizeof(*bundle), GFP_KERNEL);
	spare = kunit_kzalloc(test, sizeof(*spare), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_NOT_NULL(test, bundle);
	KUNIT_ASSERT_NOT_NULL(test, spare);
	nfsd_ffv2_ro_provider_init(spare);
	if (!nfsd_ffv2_proto_fixture_init(test, f))
		goto out;

	KUNIT_ASSERT_EQ(test, 0, nfsd_ffv2_prototype_enable(f->nn, f->net));
	f->enabled = true;
	KUNIT_ASSERT_EQ(test, 0,
			nfsd_ffv2_prototype_challenge(f->nn, f->net, nonce,
						      &expires));
	/* Measured whole, able to supply one chunk less. */
	nfsd_ffv2_prototype_test_object_hook(f->seeded, f->object_dentry,
					     f->inner, f->inner_len, f->bytes,
					     sizeof(f->bytes) -
						NFSD_FFV2_PROTO_CHUNK_SIZE,
					     sizeof(f->bytes));
	nfsd_ffv2_proto_request(&req, nonce);
	memset(bundle, 0x5a, sizeof(*bundle));
	KUNIT_EXPECT_EQ(test, -EIO,
			nfsd_ffv2_prototype_register(f->nn, f->net, &req,
						     bundle));
	/* No bundle, no generation, no provider, and the gate still open. */
	KUNIT_EXPECT_EQ(test, 0x5a, bundle->handle[0]);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OPEN,
			nfsd_ffv2_prototype_state_get(f->nn));
	generation = nfsd_ffv2_test_active_generation_get(f->nn);
	KUNIT_EXPECT_NULL(test, generation);
	if (generation)
		nfsd_ffv2_test_generation_put(generation);
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_test_provider_install(f->nn,
							&nfsd_ffv2_ro_provider_ops,
							spare,
							NFSD_FFV2_RO_CHUNK_SIZE));
	nfsd_ffv2_test_provider_remove(f->nn);
out:
	nfsd_ffv2_proto_fixture_exit(f);
}

/*
 * A superseded enable, and the cycle that follows it.
 *
 * The enabling caller that loses the gate has to wait for the close owner
 * before it returns, and the completion it waits on is reused by the next
 * cycle.  If it registered that wait after signalling that its setup was
 * over, the close owner could finish and a new enable could reinitialise
 * the completion in between, leaving the loser waiting for a teardown that
 * belongs to somebody else.
 *
 * This stops the loser in exactly that gap and asks whether a new enable
 * can start.  It must not: the wait is registered before the signal, so the
 * next enable is refused until the loser has consumed it.
 */
static void nfsd_ffv2_prototype_supersede_cycle_test(struct kunit *test)
{
	struct nfsd_ffv2_prototype_call_ctx enable = {}, closer = {};
	struct completion reached, proceed, parked, resume;
	struct task_struct *enable_task, *close_task;
	struct nfsd_net *nn;
	bool closing;
	int error;

	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_test_net_exit, nn);
	KUNIT_ASSERT_EQ(test, error, 0);

	init_completion(&reached);
	init_completion(&proceed);
	init_completion(&parked);
	init_completion(&resume);
	init_completion(&enable.done);
	init_completion(&closer.done);
	enable.nn = nn;
	closer.nn = nn;
	enable.net = &init_net;
	closer.net = &init_net;
	nfsd_ffv2_prototype_test_setup_hook(&reached, &proceed);

	enable_task = kthread_run(nfsd_ffv2_prototype_enable_thread, &enable,
				  "ffv2-proto-enable");
	KUNIT_ASSERT_FALSE(test, IS_ERR(enable_task));
	KUNIT_ASSERT_TRUE(test,
			  wait_for_completion_timeout(&reached, 15 * HZ) != 0);

	close_task = kthread_run(nfsd_ffv2_prototype_disable_thread, &closer,
				 "ffv2-proto-close");
	KUNIT_ASSERT_FALSE(test, IS_ERR(close_task));
	closing = nfsd_ffv2_prototype_wait_state(nn,
						 NFSD_FFV2_PROTOTYPE_CLOSING);
	KUNIT_EXPECT_TRUE(test, closing);

	/* Stop the loser between registering its wait and consuming it. */
	nfsd_ffv2_prototype_test_supersede_hook(&parked, &resume);
	complete(&proceed);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&parked, 30 * HZ) != 0);

	/* The close owner may finish; the loser has not returned yet. */
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&closer.done,
						      30 * HZ) != 0);
	KUNIT_EXPECT_EQ(test, 0, closer.result);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OFF,
			nfsd_ffv2_prototype_state_get(nn));
	KUNIT_EXPECT_EQ(test, 1u,
			nfsd_ffv2_prototype_test_close_waiters(nn));
	/*
	 * And no new cycle may start while that wait is outstanding, which
	 * is what stops the loser being carried into one.
	 */
	KUNIT_EXPECT_EQ(test, -EBUSY,
			nfsd_ffv2_prototype_enable(nn, &init_net));

	complete(&resume);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&enable.done,
						      30 * HZ) != 0);
	kthread_stop(enable_task);
	kthread_stop(close_task);
	KUNIT_EXPECT_EQ(test, -EBUSY, enable.result);
	KUNIT_EXPECT_EQ(test, 0u,
			nfsd_ffv2_prototype_test_close_waiters(nn));

	/* With the wait consumed, the namespace enables again. */
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_enable(nn, &init_net));
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_disable(nn, &init_net));
}

/*
 * What an unregister waits for, and what it refuses.
 *
 * Retiring the published object is the gate's own teardown, so it has to
 * behave like one: work admitted before the close role was claimed keeps
 * the gate open until it finishes, and work arriving after it is refused
 * rather than allowed to run against objects that are being removed.  A
 * held mapping is the clearest "admitted before" there is, so this holds
 * one across the whole claim.
 */
struct nfsd_ffv2_proto_unregister_ctx {
	struct nfsd_ffv2_proto_fixture	*f;
	u8				source_uuid[16];
	u64				generation;
	int				result;
	struct completion		done;
};

static int nfsd_ffv2_proto_unregister_thread(void *data)
{
	struct nfsd_ffv2_proto_unregister_ctx *ctx = data;

	ctx->result = nfsd_ffv2_prototype_unregister(ctx->f->nn, ctx->f->net,
						     ctx->source_uuid,
						     ctx->generation);
	complete(&ctx->done);
	nfsd_ffv2_test_thread_park();
	return 0;
}

static void nfsd_ffv2_prototype_unregister_drain_test(struct kunit *test)
{
	struct nfsd_ffv2_proto_unregister_ctx *ctx;
	struct nfsd_ffv2_prototype_bundle *bundle, *replay;
	u8 nonce[NFSD_FFV2_PROTOTYPE_NONCE_LEN];
	struct nfsd_ffv2_prototype_request req;
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_proto_fixture *f;
	struct nfsd_ffv2_fh_info info;
	struct task_struct *task;
	struct knfsd_fh outer = {};
	struct svc_export exp;
	u64 expires = 0;
	bool closing;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	bundle = kunit_kzalloc(test, sizeof(*bundle), GFP_KERNEL);
	replay = kunit_kzalloc(test, sizeof(*replay), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_NOT_NULL(test, bundle);
	KUNIT_ASSERT_NOT_NULL(test, replay);
	if (!nfsd_ffv2_proto_fixture_init(test, f))
		goto out;

	KUNIT_ASSERT_EQ(test, 0, nfsd_ffv2_prototype_enable(f->nn, f->net));
	f->enabled = true;
	KUNIT_ASSERT_EQ(test, 0,
			nfsd_ffv2_prototype_challenge(f->nn, f->net, nonce,
						      &expires));
	nfsd_ffv2_proto_request(&req, nonce);
	KUNIT_ASSERT_EQ(test, 0,
			nfsd_ffv2_prototype_register(f->nn, f->net, &req,
						     bundle));

	/* One mapping, admitted before anything closes. */
	memcpy(outer.fh_raw, bundle->handle, bundle->handle_len);
	outer.fh_size = bundle->handle_len;
	KUNIT_ASSERT_EQ(test, 0, nfsd_ffv2_fh_parse(&outer, &info));
	f->binding = nfsd_ffv2_test_binding_create(f->nn, &info);
	if (IS_ERR(f->binding)) {
		KUNIT_FAIL(test, "binding admission failed: %ld",
			   PTR_ERR(f->binding));
		f->binding = NULL;
		goto out;
	}
	nfsd_ffv2_init_test_export(&exp, f->nn, f->domain, &f->root);
	f->published = nfsd_ffv2_test_export_lookup(&exp);
	if (!f->published) {
		KUNIT_FAIL(test, "service export not found");
		goto out;
	}
	fh_init(f->mapped, NFS4_FHSIZE);
	f->mapped->fh_handle = outer;
	f->mapped->fh_export = nfsd_export_get(f->published);
	f->mapped->fh_dentry = dget(f->object_dentry);
	f->mapped->fh_ffv2_binding = f->binding;
	f->binding = NULL;

	ctx->f = f;
	ctx->generation = bundle->generation;
	memcpy(ctx->source_uuid, bundle->source_uuid,
	       sizeof(ctx->source_uuid));
	init_completion(&ctx->done);
	task = kthread_run(nfsd_ffv2_proto_unregister_thread, ctx,
			   "ffv2-proto-unreg");
	if (IS_ERR(task)) {
		KUNIT_FAIL(test, "failed to start the unregistering thread");
		goto out;
	}
	closing = nfsd_ffv2_prototype_wait_state(f->nn,
						 NFSD_FFV2_PROTOTYPE_CLOSING);
	KUNIT_EXPECT_TRUE(test, closing);
	/* It is waiting for the mapping, not finished. */
	KUNIT_EXPECT_EQ(test, 0,
			wait_for_completion_timeout(&ctx->done, HZ / 5));

	/* Arriving after the claim: refused, not run against a teardown. */
	KUNIT_EXPECT_EQ(test, -EBUSY,
			nfsd_ffv2_prototype_register(f->nn, f->net, &req,
						     replay));
	KUNIT_EXPECT_EQ(test, -EBUSY,
			nfsd_ffv2_prototype_challenge(f->nn, f->net, nonce,
						      &expires));

	/* Release the mapping, and the teardown proceeds. */
	fh_put(f->mapped);
	exp_put(f->published);
	f->published = NULL;
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&ctx->done, 60 * HZ) != 0);
	kthread_stop(task);
	KUNIT_EXPECT_EQ(test, 0, ctx->result);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OFF,
			nfsd_ffv2_prototype_state_get(f->nn));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_SOURCE_NONE,
			nfsd_ffv2_source_get(f->nn));
	f->enabled = false;
	generation = nfsd_ffv2_test_active_generation_get(f->nn);
	KUNIT_EXPECT_NULL(test, generation);
	if (generation)
		nfsd_ffv2_test_generation_put(generation);
	/* And the committed nonce is gone with the gate that issued it. */
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP,
			nfsd_ffv2_prototype_register(f->nn, f->net, &req,
						     replay));
out:
	nfsd_ffv2_proto_fixture_exit(f);
}

/*
 * An object that grew after it was measured.
 *
 * The layout is computed from the size that was sampled, so a file that
 * has since grown supplies more than the snapshot describes.  That is not
 * an error -- nothing has been lost, and nothing beyond the sampled size
 * is named by any chunk -- so the registration succeeds and the last chunk
 * is still reported at the length the sample gave it.
 */
static void nfsd_ffv2_prototype_growth_test(struct kunit *test)
{
	const struct nfsd_ffv2_chunk_request creq = { .offset = 0, .count = 4 };
	/* A sampled size that ends part way through the last chunk. */
	static const size_t sampled = 3 * NFSD_FFV2_PROTO_CHUNK_SIZE + 8;
	struct nfsd_ffv2_admission admission = {};
	u8 nonce[NFSD_FFV2_PROTOTYPE_NONCE_LEN];
	struct nfsd_ffv2_prototype_request req;
	struct nfsd_ffv2_prototype_bundle *bundle;
	struct nfsd_ffv2_chunk_result result;
	struct nfsd_ffv2_proto_fixture *f;
	struct nfsd_ffv2_fh_info info;
	struct knfsd_fh outer = {};
	struct svc_export exp;
	stateid_t stateid;
	u64 expires = 0;

	f = kunit_kzalloc(test, sizeof(*f), GFP_KERNEL);
	bundle = kunit_kzalloc(test, sizeof(*bundle), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, f);
	KUNIT_ASSERT_NOT_NULL(test, bundle);
	if (!nfsd_ffv2_proto_fixture_init(test, f))
		goto out;

	KUNIT_ASSERT_EQ(test, 0, nfsd_ffv2_prototype_enable(f->nn, f->net));
	f->enabled = true;
	KUNIT_ASSERT_EQ(test, 0,
			nfsd_ffv2_prototype_challenge(f->nn, f->net, nonce,
						      &expires));
	/* Measured at @sampled, able to supply every byte the fixture holds. */
	nfsd_ffv2_prototype_test_object_hook(f->seeded, f->object_dentry,
					     f->inner, f->inner_len, f->bytes,
					     sizeof(f->bytes), sampled);
	nfsd_ffv2_proto_request(&req, nonce);
	KUNIT_ASSERT_EQ(test, 0,
			nfsd_ffv2_prototype_register(f->nn, f->net, &req,
						     bundle));

	memcpy(outer.fh_raw, bundle->handle, bundle->handle_len);
	outer.fh_size = bundle->handle_len;
	KUNIT_ASSERT_EQ(test, 0, nfsd_ffv2_fh_parse(&outer, &info));
	f->binding = nfsd_ffv2_test_binding_create(f->nn, &info);
	if (IS_ERR(f->binding)) {
		KUNIT_FAIL(test, "binding admission failed: %ld",
			   PTR_ERR(f->binding));
		f->binding = NULL;
		goto out;
	}
	nfsd_ffv2_init_test_export(&exp, f->nn, f->domain, &f->root);
	f->published = nfsd_ffv2_test_export_lookup(&exp);
	if (!f->published) {
		KUNIT_FAIL(test, "service export not found");
		goto out;
	}
	fh_init(f->mapped, NFS4_FHSIZE);
	f->mapped->fh_handle = outer;
	f->mapped->fh_export = nfsd_export_get(f->published);
	f->mapped->fh_dentry = dget(f->object_dentry);
	f->mapped->fh_ffv2_binding = f->binding;
	f->binding = NULL;

	memcpy(&stateid, bundle->stateid, sizeof(stateid));
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_test_validate_operation(f->rqstp, f->mapped,
							  f->session,
							  OP_CHUNK_READ,
							  &stateid, NULL,
							  &admission));
	KUNIT_EXPECT_EQ(test, nfs_ok,
			nfsd_ffv2_provider_probe(f->rqstp, f->mapped,
						 OP_CHUNK_READ, &creq, &result,
						 U32_MAX, &admission));
	/* Four chunks, the last of them as short as the sample made it. */
	KUNIT_EXPECT_EQ(test, (u32)NFSD_FFV2_PROTO_CHUNKS, result.count);
	if (result.read.chunks && result.count == NFSD_FFV2_PROTO_CHUNKS) {
		const struct nfsd_ffv2_read_chunk *last =
			&result.read.chunks[NFSD_FFV2_PROTO_CHUNKS - 1];

		KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTO_CHUNK_SIZE,
				result.read.chunks[0].cr_effective_len);
		KUNIT_EXPECT_EQ(test, 8u, last->cr_effective_len);
		if (last->cr_chunk)
			KUNIT_EXPECT_EQ(test, 0,
					memcmp(last->cr_chunk,
					       f->bytes + 3 *
						NFSD_FFV2_PROTO_CHUNK_SIZE,
					       8));
	} else {
		KUNIT_FAIL(test, "read returned no chunk array");
	}
	nfsd_ffv2_complete(&admission);
out:
	nfsd_ffv2_proto_fixture_exit(f);
}

/*
 * The interval between a gate reading off and the completion that says so.
 *
 * The completion is shared with whatever cycle comes next, so an enable
 * starting in that interval would reinitialise it, and the old owner's
 * signal would then land on the new cycle -- letting one of that cycle's
 * closers return before its own teardown had happened.
 *
 * Two cycles, because the two halves have to be asked separately.  The
 * first has no other closer, so the only thing that can refuse a new enable
 * is the close role the old owner still holds.  The second has a closer
 * parked on the completion, so the only thing that can keep it parked is
 * the signal not having happened.
 */
static void nfsd_ffv2_prototype_close_signal_test(struct kunit *test)
{
	struct nfsd_ffv2_prototype_call_ctx owner = {}, waiter = {};
	struct completion entered, proceed, published, resume;
	struct task_struct *owner_task, *waiter_task;
	struct nfsd_net *nn;
	bool closing;
	int error;

	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_test_net_exit, nn);
	KUNIT_ASSERT_EQ(test, error, 0);
	owner.nn = nn;
	waiter.nn = nn;
	owner.net = &init_net;
	waiter.net = &init_net;

	/* One: nothing else is closing, so nothing else can refuse. */
	init_completion(&published);
	init_completion(&resume);
	init_completion(&owner.done);
	KUNIT_ASSERT_EQ(test, 0, nfsd_ffv2_prototype_enable(nn, &init_net));
	nfsd_ffv2_prototype_test_close_hooks(NULL, NULL, &published, &resume);
	owner_task = kthread_run(nfsd_ffv2_prototype_disable_thread, &owner,
				 "ffv2-proto-owner");
	KUNIT_ASSERT_FALSE(test, IS_ERR(owner_task));
	KUNIT_ASSERT_TRUE(test,
			  wait_for_completion_timeout(&published, 30 * HZ) != 0);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OFF,
			nfsd_ffv2_prototype_state_get(nn));
	KUNIT_EXPECT_EQ(test, 0u,
			nfsd_ffv2_prototype_test_close_waiters(nn));
	/*
	 * The gate reads off and nobody is waiting, so an enable is refused
	 * only because the owner has not signalled yet.  This is the whole
	 * fix: without the role held here, this enable would start a cycle
	 * and reinitialise the completion the owner is about to signal.
	 */
	KUNIT_EXPECT_EQ(test, -EBUSY,
			nfsd_ffv2_prototype_enable(nn, &init_net));
	complete(&resume);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&owner.done, 30 * HZ) != 0);
	kthread_stop(owner_task);
	KUNIT_EXPECT_EQ(test, 0, owner.result);

	/* Two: a closer parked on the completion, and the signal withheld. */
	init_completion(&entered);
	init_completion(&proceed);
	init_completion(&published);
	init_completion(&resume);
	init_completion(&owner.done);
	init_completion(&waiter.done);
	KUNIT_ASSERT_EQ(test, 0, nfsd_ffv2_prototype_enable(nn, &init_net));
	nfsd_ffv2_prototype_test_close_hooks(&entered, &proceed, &published,
					     &resume);
	owner_task = kthread_run(nfsd_ffv2_prototype_disable_thread, &owner,
				 "ffv2-proto-owner2");
	KUNIT_ASSERT_FALSE(test, IS_ERR(owner_task));
	KUNIT_ASSERT_TRUE(test,
			  wait_for_completion_timeout(&entered, 15 * HZ) != 0);
	closing = nfsd_ffv2_prototype_wait_state(nn,
						 NFSD_FFV2_PROTOTYPE_CLOSING);
	KUNIT_EXPECT_TRUE(test, closing);
	waiter_task = kthread_run(nfsd_ffv2_prototype_disable_thread, &waiter,
				  "ffv2-proto-waiter");
	KUNIT_ASSERT_FALSE(test, IS_ERR(waiter_task));
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_prototype_wait_waiters(nn, 1));
	KUNIT_EXPECT_EQ(test, 0,
			wait_for_completion_timeout(&waiter.done, HZ / 5));

	complete(&proceed);
	KUNIT_ASSERT_TRUE(test,
			  wait_for_completion_timeout(&published, 30 * HZ) != 0);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OFF,
			nfsd_ffv2_prototype_state_get(nn));
	/* The gate reads off, and the waiter is still not satisfied. */
	KUNIT_EXPECT_EQ(test, 0,
			wait_for_completion_timeout(&waiter.done, HZ / 5));

	complete(&resume);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&owner.done, 30 * HZ) != 0);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&waiter.done,
						      30 * HZ) != 0);
	kthread_stop(owner_task);
	kthread_stop(waiter_task);
	KUNIT_EXPECT_EQ(test, 0, owner.result);
	KUNIT_EXPECT_EQ(test, -EBUSY, waiter.result);

	/*
	 * Three: the same shape again, in a cycle that follows a completed
	 * one.  The completion this cycle's closers use has already been
	 * fired once, by the owner above, so a waiter parked on it now is
	 * parked on a reinitialised completion; if it were not, the old
	 * signal would satisfy it the moment it arrived.
	 */
	init_completion(&entered);
	init_completion(&proceed);
	init_completion(&published);
	init_completion(&resume);
	init_completion(&owner.done);
	init_completion(&waiter.done);
	KUNIT_ASSERT_EQ(test, 0, nfsd_ffv2_prototype_enable(nn, &init_net));
	nfsd_ffv2_prototype_test_close_hooks(&entered, &proceed, &published,
					     &resume);
	owner_task = kthread_run(nfsd_ffv2_prototype_disable_thread, &owner,
				 "ffv2-proto-owner3");
	KUNIT_ASSERT_FALSE(test, IS_ERR(owner_task));
	KUNIT_ASSERT_TRUE(test,
			  wait_for_completion_timeout(&entered, 15 * HZ) != 0);
	closing = nfsd_ffv2_prototype_wait_state(nn,
						 NFSD_FFV2_PROTOTYPE_CLOSING);
	KUNIT_EXPECT_TRUE(test, closing);
	waiter_task = kthread_run(nfsd_ffv2_prototype_disable_thread, &waiter,
				  "ffv2-proto-waiter3");
	KUNIT_ASSERT_FALSE(test, IS_ERR(waiter_task));
	KUNIT_EXPECT_TRUE(test, nfsd_ffv2_prototype_wait_waiters(nn, 1));
	KUNIT_EXPECT_EQ(test, 0,
			wait_for_completion_timeout(&waiter.done, HZ / 5));

	complete(&proceed);
	KUNIT_ASSERT_TRUE(test,
			  wait_for_completion_timeout(&published, 30 * HZ) != 0);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OFF,
			nfsd_ffv2_prototype_state_get(nn));
	/* Still parked: this cycle's owner has not signalled either. */
	KUNIT_EXPECT_EQ(test, 0,
			wait_for_completion_timeout(&waiter.done, HZ / 5));
	KUNIT_EXPECT_EQ(test, 1u,
			nfsd_ffv2_prototype_test_close_waiters(nn));

	complete(&resume);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&owner.done, 30 * HZ) != 0);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&waiter.done,
						      30 * HZ) != 0);
	kthread_stop(owner_task);
	kthread_stop(waiter_task);
	KUNIT_EXPECT_EQ(test, 0, owner.result);
	KUNIT_EXPECT_EQ(test, -EBUSY, waiter.result);
	KUNIT_EXPECT_EQ(test, 0u,
			nfsd_ffv2_prototype_test_close_waiters(nn));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OFF,
			nfsd_ffv2_prototype_state_get(nn));
	/* And the namespace enables again, on a completion of its own. */
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_enable(nn, &init_net));
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_prototype_disable(nn, &init_net));
}

/*
 * Namespace exit arriving in the interval after OFF and before the signal.
 *
 * This is the schedule the earlier reports listed as uncovered.  The gate
 * deliberately reads OFF before its owner signals, so an exit arriving
 * there finds nothing to close and returns at once -- and what keeps that
 * safe is the execution reference the owner still holds on the anchor,
 * which is what a namespace waiting to be destroyed waits for.  Both halves
 * are asserted: the exit does not block, and the reference is still there
 * until the owner has finished with it.
 *
 * No new seam is needed for this; the close hooks already reach the point.
 */
static void nfsd_ffv2_prototype_close_pre_exit_test(struct kunit *test)
{
	struct nfsd_ffv2_prototype_call_ctx owner = {}, exiting = {};
	struct task_struct *owner_task, *exit_task;
	struct completion published, resume;
	unsigned int parked_ref;
	struct nfsd_net *nn;
	int error;

	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_test_net_exit, nn);
	KUNIT_ASSERT_EQ(test, error, 0);

	init_completion(&published);
	init_completion(&resume);
	init_completion(&owner.done);
	init_completion(&exiting.done);
	owner.nn = nn;
	exiting.nn = nn;
	owner.net = &init_net;

	KUNIT_ASSERT_EQ(test, 0, nfsd_ffv2_prototype_enable(nn, &init_net));
	nfsd_ffv2_prototype_test_close_hooks(NULL, NULL, &published, &resume);
	owner_task = kthread_run(nfsd_ffv2_prototype_disable_thread, &owner,
				 "ffv2-proto-owner");
	KUNIT_ASSERT_FALSE(test, IS_ERR(owner_task));
	KUNIT_ASSERT_TRUE(test,
			  wait_for_completion_timeout(&published, 30 * HZ) != 0);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OFF,
			nfsd_ffv2_prototype_state_get(nn));

	/* The owner has given up the gate's reference but not its own. */
	parked_ref = nfsd_ffv2_test_anchor_refcount(nn);
	KUNIT_EXPECT_GT(test, parked_ref, 1u);

	exit_task = kthread_run(nfsd_ffv2_prototype_pre_exit_thread, &exiting,
				"ffv2-proto-exit");
	if (IS_ERR(exit_task)) {
		KUNIT_FAIL(test, "failed to start the exiting thread");
		complete(&resume);
		wait_for_completion(&owner.done);
		kthread_stop(owner_task);
		return;
	}
	/* It finds an off gate and returns, rather than waiting on a signal. */
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&exiting.done,
						      30 * HZ) != 0);
	/* And it did not disturb the owner, which is still holding on. */
	KUNIT_EXPECT_EQ(test, 0,
			wait_for_completion_timeout(&owner.done, HZ / 5));
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_PROTOTYPE_OFF,
			nfsd_ffv2_prototype_state_get(nn));
	KUNIT_EXPECT_GT(test, nfsd_ffv2_test_anchor_refcount(nn), 1u);

	complete(&resume);
	KUNIT_EXPECT_TRUE(test,
			  wait_for_completion_timeout(&owner.done, 30 * HZ) != 0);
	kthread_stop(owner_task);
	kthread_stop(exit_task);
	KUNIT_EXPECT_EQ(test, 0, owner.result);
	/* Only once it has finished does the anchor come back down. */
	KUNIT_EXPECT_LT(test, nfsd_ffv2_test_anchor_refcount(nn), parked_ref);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_NET_EXITING, nn->ffv2.net_state);
}

#endif /* CONFIG_NFSD_FFV2_PROTOTYPE_AUTH */

/*
 * A namespace admits one FFv2 authority source.  The second claimant is
 * refused whichever order the two arrive in, a holder cannot claim a second
 * time, and the namespace becomes claimable again only once the holder has
 * released.  The ordinary registration path is held to the same rule, so a
 * prototype profile cannot be enabled underneath an open registration.
 */
static void nfsd_ffv2_source_reservation_test(struct kunit *test)
{
	struct nfsd_ffv2_export_update registration;
	struct nfsd_net *nn;
	int error;

	nn = nfsd_ffv2_test_net(test);
	KUNIT_ASSERT_NOT_NULL(test, nn);
	error = kunit_add_action_or_reset(test, nfsd_ffv2_test_net_exit, nn);
	KUNIT_ASSERT_EQ(test, error, 0);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_SOURCE_NONE, nfsd_ffv2_source_get(nn));

	mutex_lock(&nfsd_mutex);
	/* Claiming nothing is a caller error, not an idle success. */
	KUNIT_EXPECT_EQ(test, -EINVAL,
			nfsd_ffv2_source_claim_locked(nn,
						      NFSD_FFV2_SOURCE_NONE));
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_source_claim_locked(nn,
						      NFSD_FFV2_SOURCE_MDS));
	/*
	 * Both the other source and the one already held are refused: a
	 * second claim of the same source would be a second owner of one
	 * release.
	 */
	KUNIT_EXPECT_EQ(test, -EBUSY,
			nfsd_ffv2_source_claim_locked(nn,
						      NFSD_FFV2_SOURCE_PROTOTYPE));
	KUNIT_EXPECT_EQ(test, -EBUSY,
			nfsd_ffv2_source_claim_locked(nn,
						      NFSD_FFV2_SOURCE_MDS));
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_SOURCE_MDS, nfsd_ffv2_source_get(nn));

	nfsd_ffv2_source_release(nn, NFSD_FFV2_SOURCE_MDS);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_SOURCE_NONE, nfsd_ffv2_source_get(nn));

	/* The other order excludes just as well. */
	mutex_lock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_source_claim_locked(nn,
						      NFSD_FFV2_SOURCE_PROTOTYPE));
	KUNIT_EXPECT_EQ(test, -EBUSY,
			nfsd_ffv2_source_claim_locked(nn,
						      NFSD_FFV2_SOURCE_MDS));
	mutex_unlock(&nfsd_mutex);
	nfsd_ffv2_source_release(nn, NFSD_FFV2_SOURCE_PROTOTYPE);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_SOURCE_NONE, nfsd_ffv2_source_get(nn));

	/*
	 * The ordinary registration path claims the same reservation before
	 * anything fallible, and gives it back when the registration cannot
	 * be admitted at all.  This namespace has no attached participant,
	 * which is the earliest way for that to happen, so what is proved
	 * here is that the earliest failure still leaves the namespace
	 * claimable.
	 */
	mutex_lock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, 0, nfsd_ffv2_service_up(nn));
	KUNIT_EXPECT_EQ(test, -ESHUTDOWN,
			nfsd_ffv2_registration_begin(nn, &registration));
	mutex_unlock(&nfsd_mutex);
	KUNIT_EXPECT_EQ(test, NFSD_FFV2_SOURCE_NONE, nfsd_ffv2_source_get(nn));
	mutex_lock(&nfsd_mutex);
	nfsd_ffv2_service_down(nn);
	mutex_unlock(&nfsd_mutex);
}

/*
 * The prototype profile's five commands, driven through the real
 * generic-netlink parser and policy from a socket in the namespace they
 * act on.
 *
 * The same test runs in a build with the profile and in one without it,
 * and asserts what each build owes.  A build without it answers every
 * command -EOPNOTSUPP, which is how it is told apart from a build with it
 * and the gate closed, where an enable succeeds.  What both owe is the
 * same: a request the policy refuses is refused before any handler runs,
 * so the shape of the interface does not depend on the profile being
 * compiled in.
 */
static size_t nfsd_ffv2_nl_proto_begin(struct nfsd_ffv2_nl *nl, void *buf,
				       u8 cmd)
{
	return nfsd_ffv2_nl_begin(buf, nl->family, cmd, ++nl->seq, NLM_F_ACK);
}

/* One prototype command with no attributes. */
static int nfsd_ffv2_nl_proto_bare(struct nfsd_ffv2_nl *nl, u8 cmd,
				   void *reply, size_t reply_cap)
{
	char buf[NFSD_FFV2_NL_BUF];
	size_t off = nfsd_ffv2_nl_proto_begin(nl, buf, cmd);

	return nfsd_ffv2_nl_call(nl, cmd, buf, off, reply, reply_cap);
}

/* A registration request, with every attribute a caller may vary. */
struct nfsd_ffv2_nl_register_args {
	const u8	*nonce;
	u16		nonce_len;
	const char	*domain;
	u16		handle_len;
	u32		chunk_size;
	u32		data_count;
	u32		parity_count;
	bool		omit_domain;
	u16		unknown_attr;
};

static int nfsd_ffv2_nl_proto_register(struct nfsd_ffv2_nl *nl,
				       const struct nfsd_ffv2_nl_register_args *a,
				       void *reply, size_t reply_cap)
{
	u8 handle[NFS4_FHSIZE] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	char buf[NFSD_FFV2_NL_BUF];
	size_t off;
	int error;

	off = nfsd_ffv2_nl_proto_begin(nl, buf,
				       NFSD_CMD_FFV2_PROTOTYPE_REGISTER);
	error = nfsd_ffv2_nl_put(buf, sizeof(buf), &off,
				 NFSD_A_FFV2_PROTOTYPE_NONCE, a->nonce,
				 a->nonce_len);
	if (!error && !a->omit_domain)
		error = nfsd_ffv2_nl_put_str(buf, sizeof(buf), &off,
					     NFSD_A_FFV2_PROTOTYPE_AUTH_DOMAIN,
					     a->domain);
	if (!error)
		error = nfsd_ffv2_nl_put(buf, sizeof(buf), &off,
					 NFSD_A_FFV2_PROTOTYPE_HANDLE, handle,
					 a->handle_len);
	if (!error)
		error = nfsd_ffv2_nl_put_u32(buf, sizeof(buf), &off,
					     NFSD_A_FFV2_PROTOTYPE_CHUNK_SIZE,
					     a->chunk_size);
	if (!error)
		error = nfsd_ffv2_nl_put_u32(buf, sizeof(buf), &off,
					     NFSD_A_FFV2_PROTOTYPE_DATA_COUNT,
					     a->data_count);
	if (!error)
		error = nfsd_ffv2_nl_put_u32(buf, sizeof(buf), &off,
					     NFSD_A_FFV2_PROTOTYPE_PARITY_COUNT,
					     a->parity_count);
	if (!error && a->unknown_attr)
		error = nfsd_ffv2_nl_put_u32(buf, sizeof(buf), &off,
					     a->unknown_attr, 0);
	if (error)
		return error;
	return nfsd_ffv2_nl_call(nl, NFSD_CMD_FFV2_PROTOTYPE_REGISTER, buf,
				 off, reply, reply_cap);
}

/* An unregister naming a registration that does not exist. */
static int nfsd_ffv2_nl_proto_unregister(struct nfsd_ffv2_nl *nl, void *reply,
					 size_t reply_cap)
{
	static const u8 source[16] = { 0 };
	char buf[NFSD_FFV2_NL_BUF];
	size_t off;
	int error;

	off = nfsd_ffv2_nl_proto_begin(nl, buf,
				       NFSD_CMD_FFV2_PROTOTYPE_UNREGISTER);
	error = nfsd_ffv2_nl_put(buf, sizeof(buf), &off,
				 NFSD_A_FFV2_PROTOTYPE_SOURCE_UUID, source,
				 sizeof(source));
	if (!error)
		error = nfsd_ffv2_nl_put_u64(buf, sizeof(buf), &off,
					     NFSD_A_FFV2_PROTOTYPE_GENERATION,
					     1);
	if (error)
		return error;
	return nfsd_ffv2_nl_call(nl, NFSD_CMD_FFV2_PROTOTYPE_UNREGISTER, buf,
				 off, reply, reply_cap);
}

static void nfsd_ffv2_prototype_nl_test(struct kunit *test)
{
	static const u8 stranger[NFSD_FFV2_PROTOTYPE_NONCE_LEN] = { 0 };
	const bool built = IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH);
	struct nfsd_ffv2_nl_register_args args = {};
	char reply[NFSD_FFV2_NL_BUF];
	const struct nlattr *nla;
	struct nfsd_ffv2_nl *nl;
	struct net *net;
	int got, error;

	nl = kunit_kzalloc(test, sizeof(*nl), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, nl);
	net = copy_net_ns(CLONE_NEWNET, current_user_ns(), &init_net);
	KUNIT_ASSERT_FALSE(test, IS_ERR(net));
	error = nfsd_ffv2_nl_open_named(net, nl, NFSD_FAMILY_NAME);
	if (error) {
		KUNIT_FAIL(test, "failed to reach the nfsd family: %d", error);
		put_net(net);
		return;
	}

	/*
	 * Shape first, and in both builds: a malformed request never
	 * reaches a handler, so it cannot be told which build it reached.
	 */
	args.nonce = stranger;
	args.nonce_len = sizeof(stranger) - 1;
	args.domain = "ffv2-proto-kunit";
	args.handle_len = 8;
	args.chunk_size = 64;
	args.data_count = 1;
	/* A length the policy pins exactly is a range violation, not a
	 * malformed message: netlink distinguishes the two, and the
	 * distinction is worth holding the interface to.
	 */
	KUNIT_EXPECT_EQ(test, -ERANGE,
			nfsd_ffv2_nl_proto_register(nl, &args, reply,
						    sizeof(reply)));
	args.nonce_len = sizeof(stranger);
	args.omit_domain = true;
	KUNIT_EXPECT_EQ(test, -EINVAL,
			nfsd_ffv2_nl_proto_register(nl, &args, reply,
						    sizeof(reply)));
	args.omit_domain = false;
	/*
	 * An attribute this command has no policy for is refused too.  Which
	 * status netlink chooses for it is netlink's to decide, so what is
	 * asserted is that the request did not reach a handler.
	 */
	args.unknown_attr = NFSD_A_FFV2_PROTOTYPE_MAX + 1;
	KUNIT_EXPECT_LT(test,
			nfsd_ffv2_nl_proto_register(nl, &args, reply,
						    sizeof(reply)), 0);
	args.unknown_attr = 0;

	/* A closed gate refuses everything a repeated transition would. */
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP,
			nfsd_ffv2_nl_proto_bare(nl,
						NFSD_CMD_FFV2_PROTOTYPE_DISABLE,
						reply, sizeof(reply)));
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP,
			nfsd_ffv2_nl_proto_bare(nl,
						NFSD_CMD_FFV2_PROTOTYPE_CHALLENGE,
						reply, sizeof(reply)));

	error = nfsd_ffv2_nl_proto_bare(nl, NFSD_CMD_FFV2_PROTOTYPE_ENABLE,
					reply, sizeof(reply));
	if (!built) {
		/*
		 * The whole profile is absent, and the enable is where that
		 * shows: everything else already refuses in both builds.
		 */
		KUNIT_EXPECT_EQ(test, -EOPNOTSUPP, error);
		goto out_close;
	}
	KUNIT_EXPECT_EQ(test, 0, error);
	KUNIT_EXPECT_EQ(test, -EBUSY,
			nfsd_ffv2_nl_proto_bare(nl,
						NFSD_CMD_FFV2_PROTOTYPE_ENABLE,
						reply, sizeof(reply)));

	/* A challenge answers with a nonce and a deadline, not an ack. */
	got = nfsd_ffv2_nl_proto_bare(nl, NFSD_CMD_FFV2_PROTOTYPE_CHALLENGE,
				      reply, sizeof(reply));
	KUNIT_EXPECT_GT(test, got, 0);
	if (got > 0) {
		nla = nfsd_ffv2_nl_find(reply, got,
					NFSD_A_FFV2_PROTOTYPE_NONCE,
					NFSD_FFV2_PROTOTYPE_NONCE_LEN);
		KUNIT_EXPECT_NOT_NULL(test, nla);
		nla = nfsd_ffv2_nl_find(reply, got,
					NFSD_A_FFV2_PROTOTYPE_EXPIRES,
					sizeof(u64));
		KUNIT_EXPECT_NOT_NULL(test, nla);
	}

	/* A nonce this gate never issued is unknown, not merely refused. */
	KUNIT_EXPECT_EQ(test, -ENOENT,
			nfsd_ffv2_nl_proto_register(nl, &args, reply,
						    sizeof(reply)));
	/*
	 * A layout that cannot describe an object is refused before the
	 * nonce is even consulted, so an unusable request cannot spend one.
	 */
	args.parity_count = 1;
	KUNIT_EXPECT_EQ(test, -EINVAL,
			nfsd_ffv2_nl_proto_register(nl, &args, reply,
						    sizeof(reply)));
	args.parity_count = 0;
	args.chunk_size = 0;
	KUNIT_EXPECT_EQ(test, -EINVAL,
			nfsd_ffv2_nl_proto_register(nl, &args, reply,
						    sizeof(reply)));
	args.chunk_size = 64;

	/* Nothing is registered, so there is nothing to unregister. */
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP,
			nfsd_ffv2_nl_proto_unregister(nl, reply,
						      sizeof(reply)));

	KUNIT_EXPECT_EQ(test, 0,
			nfsd_ffv2_nl_proto_bare(nl,
						NFSD_CMD_FFV2_PROTOTYPE_DISABLE,
						reply, sizeof(reply)));
	KUNIT_EXPECT_EQ(test, -EOPNOTSUPP,
			nfsd_ffv2_nl_proto_bare(nl,
						NFSD_CMD_FFV2_PROTOTYPE_DISABLE,
						reply, sizeof(reply)));
out_close:
	nfsd_ffv2_nl_close(nl);
	put_net(net);
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
	KUNIT_CASE(nfsd_ffv2_provider_result_contract_test),
	KUNIT_CASE(nfsd_ffv2_encode_read_test),
	KUNIT_CASE(nfsd_ffv2_encode_large_payload_test),
	KUNIT_CASE(nfsd_ffv2_provider_unadmitted_test),
	KUNIT_CASE(nfsd_ffv2_encode_header_test),
	KUNIT_CASE(nfsd_ffv2_auth_cache_nl_parser_test),
	KUNIT_CASE(nfsd_ffv2_auth_cache_p0_probe_test),
	KUNIT_CASE(nfsd_ffv2_auth_cache_second_net_test),
	KUNIT_CASE_SLOW(nfsd_ffv2_auth_cache_two_service_test),
	KUNIT_CASE_SLOW(nfsd_ffv2_auth_cache_service_cleanup_test),
	KUNIT_CASE_SLOW(nfsd_ffv2_delayed_producer_publish_test),
	KUNIT_CASE_SLOW(nfsd_ffv2_delayed_producer_repeat_test),
	KUNIT_CASE_SLOW(nfsd_ffv2_delayed_producer_drain_test),
	KUNIT_CASE_SLOW(nfsd_ffv2_delayed_producer_shutdown_test),
	KUNIT_CASE_SLOW(nfsd_ffv2_delayed_producer_cleanup_test),
	KUNIT_CASE(nfsd_ffv2_transport_null_test),
	KUNIT_CASE(nfsd_ffv2_compound_header_capacity_test),
	KUNIT_CASE(nfsd_ffv2_compound_read_capacity_test),
	KUNIT_CASE(nfsd_ffv2_provider_retired_generation_test),
	KUNIT_CASE(nfsd_ffv2_provider_result_lifetime_test),
	KUNIT_CASE(nfsd_ffv2_provider_netns_fence_test),
	KUNIT_CASE(nfsd_ffv2_provider_concurrent_results_test),
	KUNIT_CASE(nfsd_ffv2_provider_pinned_reference_test),
	KUNIT_CASE(nfsd_ffv2_provider_size_mismatch_test),
	KUNIT_CASE(nfsd_ffv2_provider_install_race_test),
	KUNIT_CASE(nfsd_ffv2_source_reservation_test),
	KUNIT_CASE(nfsd_ffv2_prototype_nl_test),
#if IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
	KUNIT_CASE(nfsd_ffv2_prototype_gate_test),
	KUNIT_CASE(nfsd_ffv2_prototype_owner_test),
	KUNIT_CASE(nfsd_ffv2_prototype_setup_failure_test),
	KUNIT_CASE(nfsd_ffv2_prototype_enabling_close_test),
	KUNIT_CASE(nfsd_ffv2_prototype_enabling_pre_exit_test),
	KUNIT_CASE(nfsd_ffv2_prototype_supersede_cycle_test),
	KUNIT_CASE(nfsd_ffv2_prototype_close_signal_test),
	KUNIT_CASE(nfsd_ffv2_prototype_close_pre_exit_test),
	KUNIT_CASE(nfsd_ffv2_prototype_challenge_test),
	KUNIT_CASE(nfsd_ffv2_prototype_nonce_reap_test),
	KUNIT_CASE(nfsd_ffv2_prototype_read_test),
	KUNIT_CASE(nfsd_ffv2_prototype_publish_window_test),
	KUNIT_CASE(nfsd_ffv2_prototype_publish_close_race_test),
	KUNIT_CASE(nfsd_ffv2_prototype_short_read_test),
	KUNIT_CASE(nfsd_ffv2_prototype_growth_test),
	KUNIT_CASE(nfsd_ffv2_prototype_unregister_drain_test),
#endif
	{}
};

static struct kunit_suite nfsd_ffv2_test_suite = {
	.name = "nfsd_ffv2_lifecycle",
	.test_cases = nfsd_ffv2_test_cases,
};

kunit_test_suite(nfsd_ffv2_test_suite);

MODULE_LICENSE("GPL");
