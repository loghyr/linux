// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sunrpc/cache.h>

struct cache_test_entry {
	struct cache_head h;
	struct rcu_head rcu;
	unsigned int key;
	unsigned int value;
};

struct cache_test_context {
	struct cache_detail detail;
	struct hlist_head bucket;
};

static atomic_t cache_test_live = ATOMIC_INIT(0);

static struct cache_head *cache_test_alloc(void)
{
	struct cache_test_entry *entry;

	entry = kzalloc_obj(*entry, GFP_KERNEL);
	if (!entry)
		return NULL;
	atomic_inc(&cache_test_live);
	return &entry->h;
}

static void cache_test_put(struct kref *ref)
{
	struct cache_test_entry *entry;

	entry = container_of(ref, struct cache_test_entry, h.ref);
	atomic_dec(&cache_test_live);
	kfree_rcu(entry, rcu);
}

static int cache_test_match(struct cache_head *a, struct cache_head *b)
{
	struct cache_test_entry *first, *second;

	first = container_of(a, struct cache_test_entry, h);
	second = container_of(b, struct cache_test_entry, h);
	return first->key == second->key;
}

static void cache_test_init(struct cache_head *dest, struct cache_head *key)
{
	struct cache_test_entry *entry, *source;

	entry = container_of(dest, struct cache_test_entry, h);
	source = container_of(key, struct cache_test_entry, h);
	entry->key = source->key;
}

static void cache_test_update(struct cache_head *dest, struct cache_head *new)
{
	struct cache_test_entry *entry, *source;

	entry = container_of(dest, struct cache_test_entry, h);
	source = container_of(new, struct cache_test_entry, h);
	entry->value = source->value;
}

static void cache_test_setup(struct cache_test_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	INIT_HLIST_HEAD(&ctx->bucket);
	ctx->detail.hash_size = 1;
	ctx->detail.hash_table = &ctx->bucket;
	ctx->detail.alloc = cache_test_alloc;
	ctx->detail.cache_put = cache_test_put;
	ctx->detail.match = cache_test_match;
	ctx->detail.init = cache_test_init;
	ctx->detail.update = cache_test_update;
	spin_lock_init(&ctx->detail.hash_lock);
}

static struct cache_head *cache_test_seed(struct cache_test_context *ctx)
{
	struct cache_test_entry key = { .key = 7 };
	struct cache_test_entry initial = { .key = 7, .value = 1 };
	struct cache_head *old;

	initial.h.expiry_time = TIME64_MAX;
	old = sunrpc_cache_lookup_rcu(&ctx->detail, &key.h, 0);
	if (!old)
		return ERR_PTR(-ENOMEM);
	return sunrpc_cache_update(&ctx->detail, &initial.h, old, 0);
}

static struct cache_head *cache_test_replace(struct cache_test_context *ctx,
					     struct cache_head *old)
{
	struct cache_test_entry next = { .key = 7, .value = 2 };

	next.h.expiry_time = TIME64_MAX;
	return sunrpc_cache_update_exact(&ctx->detail, &next.h, old, 0);
}

static void cache_test_remove(struct cache_test_context *ctx,
			      struct cache_head *entry)
{
	spin_lock(&ctx->detail.hash_lock);
	hlist_del_init_rcu(&entry->cache_list);
	ctx->detail.entries--;
	spin_unlock(&ctx->detail.hash_lock);
	cache_put(entry, &ctx->detail);
}

static void cache_test_success_and_stale(struct kunit *test)
{
	struct cache_test_context ctx;
	struct cache_head *old, *replacement, *stale;
	struct cache_test_entry *entry;
	int initial_live = atomic_read(&cache_test_live);

	cache_test_setup(&ctx);
	old = cache_test_seed(&ctx);
	KUNIT_ASSERT_FALSE(test, IS_ERR(old));
	replacement = cache_test_replace(&ctx, old);
	if (IS_ERR(replacement)) {
		KUNIT_FAIL(test, "exact replacement failed: %ld",
			   PTR_ERR(replacement));
		cache_test_remove(&ctx, old);
		cache_put(old, &ctx.detail);
		return;
	}
	entry = container_of(replacement, struct cache_test_entry, h);
	KUNIT_EXPECT_EQ(test, entry->value, 2U);
	KUNIT_EXPECT_EQ(test, kref_read(&old->ref), 1U);
	KUNIT_EXPECT_EQ(test, kref_read(&replacement->ref), 2U);
	KUNIT_EXPECT_EQ(test, ctx.detail.entries, 1);
	stale = cache_test_replace(&ctx, old);
	KUNIT_EXPECT_TRUE(test, IS_ERR(stale));
	if (IS_ERR(stale)) {
		KUNIT_EXPECT_EQ(test, PTR_ERR(stale), -ESTALE);
	} else {
		cache_test_remove(&ctx, stale);
		cache_put(stale, &ctx.detail);
	}
	KUNIT_EXPECT_EQ(test, kref_read(&old->ref), 1U);
	cache_test_remove(&ctx, replacement);
	if (!hlist_unhashed(&old->cache_list))
		cache_test_remove(&ctx, old);
	cache_put(replacement, &ctx.detail);
	cache_put(old, &ctx.detail);
	KUNIT_EXPECT_EQ(test, atomic_read(&cache_test_live), initial_live);
}

static void cache_test_expired_predecessor(struct kunit *test)
{
	struct cache_test_context ctx;
	struct cache_head *old, *result;
	int initial_live = atomic_read(&cache_test_live);

	cache_test_setup(&ctx);
	old = cache_test_seed(&ctx);
	KUNIT_ASSERT_FALSE(test, IS_ERR(old));
	old->expiry_time = -1;
	result = cache_test_replace(&ctx, old);
	KUNIT_EXPECT_TRUE(test, IS_ERR(result));
	if (IS_ERR(result)) {
		KUNIT_EXPECT_EQ(test, PTR_ERR(result), -ESTALE);
	} else {
		cache_test_remove(&ctx, result);
		cache_put(result, &ctx.detail);
	}
	KUNIT_EXPECT_EQ(test, kref_read(&old->ref), 2U);
	cache_test_remove(&ctx, old);
	cache_put(old, &ctx.detail);
	KUNIT_EXPECT_EQ(test, atomic_read(&cache_test_live), initial_live);
}

static void cache_test_predecessor_cannot_resurrect(struct kunit *test)
{
	struct cache_test_context ctx;
	struct cache_head *old, *replacement;
	int initial_live = atomic_read(&cache_test_live);

	cache_test_setup(&ctx);
	old = cache_test_seed(&ctx);
	KUNIT_ASSERT_FALSE(test, IS_ERR(old));
	replacement = cache_test_replace(&ctx, old);
	if (IS_ERR(replacement)) {
		KUNIT_FAIL(test, "exact replacement failed: %ld",
			   PTR_ERR(replacement));
		cache_test_remove(&ctx, old);
		cache_put(old, &ctx.detail);
		return;
	}
	/* Expiry zero is still current during boot second zero. */
	old->expiry_time = 0;
	KUNIT_EXPECT_TRUE(test, hlist_unhashed(&old->cache_list));
	cache_test_remove(&ctx, replacement);
	KUNIT_EXPECT_TRUE(test, hlist_empty(&ctx.bucket));
	KUNIT_EXPECT_EQ(test, ctx.detail.entries, 0);
	if (!hlist_unhashed(&old->cache_list))
		cache_test_remove(&ctx, old);
	cache_put(replacement, &ctx.detail);
	cache_put(old, &ctx.detail);
	KUNIT_EXPECT_EQ(test, atomic_read(&cache_test_live), initial_live);
}

static struct kunit_case cache_test_cases[] = {
	KUNIT_CASE(cache_test_success_and_stale),
	KUNIT_CASE(cache_test_expired_predecessor),
	KUNIT_CASE(cache_test_predecessor_cannot_resurrect),
	{}
};

static struct kunit_suite cache_test_suite = {
	.name = "sunrpc_cache_exact",
	.test_cases = cache_test_cases,
};

kunit_test_suite(cache_test_suite);

MODULE_LICENSE("GPL");
