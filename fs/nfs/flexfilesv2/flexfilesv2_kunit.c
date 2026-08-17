// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit coverage for pNFS FlexFiles v2 verifier predicates.
 */

#include <kunit/test.h>
#include <linux/module.h>
#include <linux/nfs4.h>
#include <linux/nfs_common.h>
#include <linux/nfs_fs.h>
#include <linux/slab.h>
#include <linux/sunrpc/sched.h>

#include "../internal.h"
#include "../iostat.h"
#include "../nfs4_fs.h"
#include "../pnfs.h"
#include "flexfilesv2.h"
#include "flexfilesv2_xdr_chunk.h"

static void ffv2_mixed_cohort_verifier_test(struct kunit *test)
{
	struct ffv2_pending_chunk first = { };
	struct ffv2_pending_chunk second = { };
	struct ffv2_pending_chunk *cohort_a[] = { &first };
	struct ffv2_pending_chunk *cohort_b[] = { &second };
	struct ffv2_pending_chunk *mixed[] = { &first, &second };
	nfs4_verifier verifier_a = { .data = { 0xa1 } };
	nfs4_verifier verifier_b = { .data = { 0xb2 } };

	first.writeverf = verifier_a;
	first.finalize_writeverf = verifier_a;
	second.writeverf = verifier_b;
	second.finalize_writeverf = verifier_b;

	KUNIT_EXPECT_TRUE(test,
		ffv2_deferred_finalize_verifier_matches(cohort_a, 1,
							&verifier_a));
	KUNIT_EXPECT_TRUE(test,
		ffv2_deferred_finalize_verifier_matches(cohort_b, 1,
							&verifier_b));
	KUNIT_EXPECT_FALSE(test,
		ffv2_deferred_finalize_verifier_matches(mixed, 2,
							&verifier_a));

	KUNIT_EXPECT_TRUE(test,
		ffv2_deferred_commit_verifier_matches(cohort_a, 1,
							&verifier_a));
	KUNIT_EXPECT_TRUE(test,
		ffv2_deferred_commit_verifier_matches(cohort_b, 1,
							&verifier_b));
	KUNIT_EXPECT_FALSE(test,
		ffv2_deferred_commit_verifier_matches(mixed, 2,
							&verifier_b));
	mixed[1] = NULL;
	KUNIT_EXPECT_FALSE(test,
		ffv2_deferred_finalize_verifier_matches(mixed, 2,
							&verifier_a));
	KUNIT_EXPECT_FALSE(test,
		ffv2_deferred_commit_verifier_matches(mixed, 2,
							&verifier_a));
}

static void ffv2_deferred_group_wait_test(struct kunit *test)
{
	struct ffv2_deferred_drain drain = { };
	struct ffv2_deferred_group first = { };
	struct ffv2_deferred_group second = { };

	atomic_set(&drain.pending_ops, 2);
	drain.launch_done = true;

	KUNIT_EXPECT_FALSE(test,
		ffv2_deferred_group_complete(&drain, &first, -EIO));
	KUNIT_EXPECT_EQ(test, 1, atomic_read(&drain.pending_ops));
	KUNIT_EXPECT_EQ(test, -EIO, drain.status);
	KUNIT_EXPECT_TRUE(test,
		ffv2_deferred_group_complete(&drain, &second, 0));
	KUNIT_EXPECT_EQ(test, 0, atomic_read(&drain.pending_ops));
	KUNIT_EXPECT_EQ(test, -EIO, drain.status);
	KUNIT_EXPECT_FALSE(test,
		ffv2_deferred_group_complete(&drain, &second, 0));
}

static void ffv2_deferred_owner_identity_test(struct kunit *test)
{
	struct ffv2_deferred_drain drain = { };
	struct ffv2_pending_chunk pending = { };
	struct nfs_commit_data data = { };
	struct pnfs_layout_segment lseg = { };
	struct nfs_direct_req dreq = { };

	drain.data = &data;
	drain.lseg = &lseg;
	data.dreq = &dreq;
	data.ds_commit_index = 3;
	pending.lseg = &lseg;
	pending.dreq = &dreq;
	pending.commit_bucket = 3;
	pending.state = FFV2_PENDING_DEFERRED;

	KUNIT_EXPECT_TRUE(test,
		ffv2_deferred_pending_matches_drain(&drain, &pending));

	pending.commit_bucket++;
	KUNIT_EXPECT_FALSE(test,
		ffv2_deferred_pending_matches_drain(&drain, &pending));
	pending.commit_bucket--;
	pending.state = FFV2_PENDING_LIFECYCLE_DONE;
	KUNIT_EXPECT_FALSE(test,
		ffv2_deferred_pending_matches_drain(&drain, &pending));
	pending.state = FFV2_PENDING_DEFERRED;
	pending.dreq = NULL;
	KUNIT_EXPECT_FALSE(test,
		ffv2_deferred_pending_matches_drain(&drain, &pending));
}

static void ffv2_pending_state_transition_test(struct kunit *test)
{
	struct ffv2_pending_chunk pending = { };
	spinlock_t stripe_lock; /* protects pending state in this fixture */
	refcount_t stripe_ref;

	spin_lock_init(&stripe_lock);
	refcount_set(&stripe_ref, 1);
	pending.stripe_lock = &stripe_lock;
	pending.stripe_ref = &stripe_ref;
	pending.state = FFV2_PENDING_IMMEDIATE;

	ffv2_pending_chunk_retain(&pending);
	KUNIT_EXPECT_EQ(test, FFV2_PENDING_RETAINED, pending.state);
	KUNIT_EXPECT_EQ(test, 2, refcount_read(&stripe_ref));
	ffv2_pending_chunk_defer(&pending);
	KUNIT_EXPECT_EQ(test, FFV2_PENDING_DEFERRED, pending.state);
	ffv2_pending_chunk_abort(&pending);
	KUNIT_EXPECT_EQ(test, FFV2_PENDING_IMMEDIATE, pending.state);

	pending.state = FFV2_PENDING_RETAINED;
	ffv2_pending_chunk_lifecycle_done(&pending);
	KUNIT_EXPECT_EQ(test, FFV2_PENDING_LIFECYCLE_DONE, pending.state);
}

static void ffv2_deferred_drain_abort_test(struct kunit *test)
{
	struct ffv2_deferred_drain drain = { };
	struct nfs_commit_data data = { };
	struct nfs_page page = { };
	struct nfs_page *actual;

	INIT_LIST_HEAD(&drain.cohorts);
	INIT_LIST_HEAD(&drain.groups);
	INIT_LIST_HEAD(&drain.retry_pages);
	INIT_LIST_HEAD(&data.pages);
	drain.data = &data;
	list_add(&page.wb_list, &drain.retry_pages);

	ffv2_deferred_drain_abort(&drain);

	KUNIT_EXPECT_TRUE(test, list_empty(&drain.retry_pages));
	KUNIT_ASSERT_FALSE(test, list_empty(&data.pages));
	KUNIT_EXPECT_TRUE(test, list_is_singular(&data.pages));
	actual = list_first_entry(&data.pages, struct nfs_page, wb_list);
	KUNIT_EXPECT_PTR_EQ(test, &page, actual);
}

static void ffv2_deferred_rollback_ownership_test(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 0, ffv2_kunit_deferred_rollback_state_test());
}

static void ffv2_deferred_group_identity_test(struct kunit *test)
{
	struct ffv2_deferred_group group = { };
	struct ffv2_pending_chunk first = { };
	struct ffv2_pending_chunk pending = { };
	struct nfs_client *first_clp = (void *)&group;
	struct nfs_client *other_clp = (void *)&pending;

	group.pending[0] = &first;
	group.nowners = 1;
	first.ds_clp = first_clp;
	pending.ds_clp = first.ds_clp;
	first.fh.size = pending.fh.size = 1;
	first.fh.data[0] = pending.fh.data[0] = 0x11;
	first.stateid.seqid = pending.stateid.seqid = 7;
	first.stateid.other[0] = pending.stateid.other[0] = 0x22;
	first.commit_bucket = pending.commit_bucket = 4;

	KUNIT_EXPECT_TRUE(test,
		ffv2_deferred_group_matches_pending(&group, &pending));

	pending.ds_clp = other_clp;
	KUNIT_EXPECT_FALSE(test,
		ffv2_deferred_group_matches_pending(&group, &pending));
	pending.ds_clp = first.ds_clp;
	pending.fh.data[0]++;
	KUNIT_EXPECT_FALSE(test,
		ffv2_deferred_group_matches_pending(&group, &pending));
	pending.fh.data[0]--;
	pending.stateid.seqid++;
	KUNIT_EXPECT_FALSE(test,
		ffv2_deferred_group_matches_pending(&group, &pending));
	pending.stateid.seqid--;
	pending.commit_bucket++;
	KUNIT_EXPECT_FALSE(test,
		ffv2_deferred_group_matches_pending(&group, &pending));
}

static void ffv2_pending_identity_test(struct kunit *test)
{
	struct ffv2_pending_chunk first = { };
	struct ffv2_pending_chunk pending = { };
	struct pnfs_layout_segment lseg;
	struct nfs_direct_req dreq;
	struct nfs_client *clp = (void *)&first;

	first.lseg = pending.lseg = &lseg;
	first.dreq = pending.dreq = &dreq;
	first.ds_clp = pending.ds_clp = clp;
	first.commit_bucket = pending.commit_bucket = 5;
	KUNIT_EXPECT_TRUE(test,
		ffv2_pending_chunk_identity_matches(&first, &pending));

	pending.lseg = NULL;
	KUNIT_EXPECT_FALSE(test,
		ffv2_pending_chunk_identity_matches(&first, &pending));
	pending.lseg = first.lseg;
	pending.dreq = NULL;
	KUNIT_EXPECT_FALSE(test,
		ffv2_pending_chunk_identity_matches(&first, &pending));
	pending.dreq = first.dreq;
	pending.ds_clp = (void *)&pending;
	KUNIT_EXPECT_FALSE(test,
		ffv2_pending_chunk_identity_matches(&first, &pending));
	pending.ds_clp = first.ds_clp;
	pending.commit_bucket++;
	KUNIT_EXPECT_FALSE(test,
		ffv2_pending_chunk_identity_matches(&first, &pending));
	pending.commit_bucket--;
	pending.fh.size = 1;
	KUNIT_EXPECT_FALSE(test,
		ffv2_pending_chunk_identity_matches(&first, &pending));
	pending.fh = first.fh;
	pending.stateid.seqid++;
	KUNIT_EXPECT_FALSE(test,
		ffv2_pending_chunk_identity_matches(&first, &pending));
}

static void ffv2_deferred_group_range_test(struct kunit *test)
{
	struct ffv2_deferred_group group = {
		.offset = 100,
		.count = 10,
	};
	struct ffv2_pending_chunk pending = {
		.offset = 105,
		.count = 20,
	};

	KUNIT_EXPECT_EQ(test, 0,
		ffv2_deferred_group_extend_range(&group, &pending));
	KUNIT_EXPECT_EQ(test, (u64)100, group.offset);
	KUNIT_EXPECT_EQ(test, (u32)25, group.count);

	pending.offset = 90;
	pending.count = 5;
	KUNIT_EXPECT_EQ(test, 0,
		ffv2_deferred_group_extend_range(&group, &pending));
	KUNIT_EXPECT_EQ(test, (u64)90, group.offset);
	KUNIT_EXPECT_EQ(test, (u32)35, group.count);

	group.offset = U64_MAX - 1;
	group.count = 4;
	KUNIT_EXPECT_EQ(test, -EOVERFLOW,
		ffv2_deferred_group_extend_range(&group, &pending));

	group.offset = 0;
	group.count = U32_MAX;
	pending.offset = U32_MAX;
	pending.count = 1;
	KUNIT_EXPECT_EQ(test, -E2BIG,
		ffv2_deferred_group_extend_range(&group, &pending));
}

static struct kunit_case ffv2_deferred_test_cases[] = {
	KUNIT_CASE(ffv2_mixed_cohort_verifier_test),
	KUNIT_CASE(ffv2_deferred_group_wait_test),
	KUNIT_CASE(ffv2_deferred_owner_identity_test),
	KUNIT_CASE(ffv2_pending_state_transition_test),
	KUNIT_CASE(ffv2_deferred_drain_abort_test),
	KUNIT_CASE(ffv2_deferred_rollback_ownership_test),
	KUNIT_CASE(ffv2_deferred_group_identity_test),
	KUNIT_CASE(ffv2_pending_identity_test),
	KUNIT_CASE(ffv2_deferred_group_range_test),
	{}
};

static struct kunit_suite ffv2_deferred_test_suite = {
	.name = "ffv2-deferred",
	.test_cases = ffv2_deferred_test_cases,
};

kunit_test_suite(ffv2_deferred_test_suite);

MODULE_LICENSE("GPL");
