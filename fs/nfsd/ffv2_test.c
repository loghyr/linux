// SPDX-License-Identifier: GPL-2.0-only
#include <kunit/test.h>
#include <linux/completion.h>
#include <linux/iopoll.h>
#include <linux/kthread.h>
#include <linux/module.h>

#include "ffv2.h"
#include "nfsd.h"
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

static void nfsd_ffv2_count_release(void *payload)
{
	atomic_inc(payload);
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

static struct kunit_case nfsd_ffv2_test_cases[] = {
	KUNIT_CASE(nfsd_ffv2_lifecycle_test),
	KUNIT_CASE(nfsd_ffv2_admission_unregister_test),
	KUNIT_CASE(nfsd_ffv2_zero_threads_test),
	KUNIT_CASE(nfsd_ffv2_multi_retirement_test),
	{}
};

static struct kunit_suite nfsd_ffv2_test_suite = {
	.name = "nfsd_ffv2_lifecycle",
	.test_cases = nfsd_ffv2_test_cases,
};

kunit_test_suite(nfsd_ffv2_test_suite);

MODULE_LICENSE("GPL");
