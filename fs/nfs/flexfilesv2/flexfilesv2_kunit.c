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
}

static struct kunit_case ffv2_verifier_test_cases[] = {
	KUNIT_CASE(ffv2_mixed_cohort_verifier_test),
	{}
};

static struct kunit_suite ffv2_verifier_test_suite = {
	.name = "ffv2-verifier",
	.test_cases = ffv2_verifier_test_cases,
};

kunit_test_suite(ffv2_verifier_test_suite);

MODULE_LICENSE("GPL");
