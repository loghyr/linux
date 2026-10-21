// SPDX-License-Identifier: GPL-2.0-only

#include <crypto/utils.h>
#include <linux/completion.h>
#include <linux/crc32.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/overflow.h>
#include <linux/random.h>
#include <linux/sunrpc/svcauth.h>
#include <linux/unaligned.h>
#include <linux/xarray.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <net/net_namespace.h>

#include "export.h"
#include "ffv2.h"
#include "ffv2_prototype.h"
#include "ffv2_store.h"
#include "ffv2_trust.h"
#include "nfsd.h"
#include "netns.h"
#include "nfsfh.h"
#include "state.h"
#include "vfs.h"

#define NFSD_FFV2_PROTOTYPE_DOMAIN_MAX NAME_MAX

enum nfsd_ffv2_prototype_nonce_state {
	NFSD_FFV2_NONCE_ISSUED,
	NFSD_FFV2_NONCE_COMMITTED,
};

struct nfsd_ffv2_prototype_committed {
	char auth_domain[NFSD_FFV2_PROTOTYPE_DOMAIN_MAX + 1];
	u32 chunk_size;
	u32 data_count;
	u32 parity_count;
	u8 store_uuid[16];
	u8 binding_token[32];
	u32 writer_id;
	u64 pnfs_clientid;
	u32 object_count;
	struct {
		u8 handle[NFS4_FHSIZE];
		u32 handle_len;
		u8 persisted_handle[32];
	} objects[NFSD_FFV2_PROTOTYPE_OBJECT_MAX];
};

struct nfsd_ffv2_prototype_nonce {
	u8 value[NFSD_FFV2_PROTOTYPE_NONCE_LEN];
	u64 expires;
	enum nfsd_ffv2_prototype_nonce_state state;

	kuid_t uid;
	struct user_namespace *userns;
	const struct net *net;
	u32 secid;
	bool secid_valid;

	bool busy;

	struct list_head dead;

	struct nfsd_ffv2_prototype_committed committed;
	struct nfsd_ffv2_prototype_bundle bundle;
};

struct nfsd_ffv2_prototype_ctx {
	const struct cred *cred;

	struct xarray nonces;
	u64 next_nonce;
	unsigned int nonce_count;
};

#define NFSD_FFV2_PROTOTYPE_NONCE_MAX 64

#define NFSD_FFV2_PROTOTYPE_TRUST_TTL_SEC 3600

static_assert(sizeof(stateid_t) == NFS4_STATEID_SIZE,
	      "the registration bundle carries a stateid verbatim");
static_assert(NFSD_FFV2_FH_MAX <= NFS4_FHSIZE,
	      "the registration bundle carries a mapped handle verbatim");

static void nfsd_ffv2_prototype_teardown_published(struct nfsd_net *nn);
static int __nfsd_ffv2_prototype_close(struct nfsd_net *nn, const struct net *net,
				       const u8 *source_uuid, u64 generation);

static struct nfsd_ffv2_prototype *nfsd_ffv2_prototype_of(struct nfsd_net *nn)
{
	return &nn->ffv2.prototype;
}

void nfsd_ffv2_prototype_net_init(struct nfsd_net *nn)
{
	struct nfsd_ffv2_prototype *proto = nfsd_ffv2_prototype_of(nn);

	proto->state = NFSD_FFV2_PROTOTYPE_OFF;
	proto->users = 0;
	proto->setup_ref = 0;
	proto->close_claimed = false;
	proto->exiting = false;
	proto->owns_provider = false;
	proto->owns_generation = false;
	proto->provider = NULL;
	proto->close_waiters = 0;
	proto->owns_ctx = false;
	proto->owns_anchor = false;
	proto->owns_source = false;
	proto->ctx = NULL;
	memset(&proto->owner, 0, sizeof(proto->owner));
	init_waitqueue_head(&proto->users_wait);
	init_completion(&proto->setup_done);
	init_completion(&proto->close_done);
}

void nfsd_ffv2_prototype_net_destroy(struct nfsd_net *nn)
{
	struct nfsd_ffv2_prototype *proto = nfsd_ffv2_prototype_of(nn);

	WARN_ON_ONCE(proto->state != NFSD_FFV2_PROTOTYPE_OFF);
	WARN_ON_ONCE(proto->users || proto->setup_ref || proto->close_waiters);
	WARN_ON_ONCE(proto->owns_ctx || proto->owns_anchor || proto->owns_source);
	WARN_ON_ONCE(proto->owner.valid);
}

static void nfsd_ffv2_prototype_ctx_free(struct nfsd_ffv2_prototype_ctx *ctx)
{
	struct nfsd_ffv2_prototype_nonce *nonce;
	unsigned long index;

	if (!ctx)
		return;

	xa_for_each(&ctx->nonces, index, nonce) {
		xa_erase(&ctx->nonces, index);
		kfree_sensitive(nonce);
	}
	xa_destroy(&ctx->nonces);
	put_cred(ctx->cred);
	kfree(ctx);
}

static void nfsd_ffv2_prototype_owner_set(struct nfsd_ffv2_prototype_owner *owner,
					  const struct net *net, struct user_namespace *userns,
					  u32 secid)
{
	owner->uid = current_uid();
	owner->userns = userns;
	owner->net = net;
	owner->secid = secid;
	owner->secid_valid = secid != 0;
	owner->valid = true;
}

static bool nfsd_ffv2_prototype_owner_is(const struct nfsd_ffv2_prototype_owner *owner,
					 const struct net *net, u32 secid)
{
	bool has_secid = secid != 0;

	if (!owner->valid)
		return false;
	if (owner->net != net || owner->userns != current_user_ns() ||
	    !uid_eq(owner->uid, current_uid()))
		return false;

	if (owner->secid_valid != has_secid)
		return false;
	return !owner->secid_valid || owner->secid == secid;
}

static struct user_namespace *
nfsd_ffv2_prototype_owner_clear(struct nfsd_ffv2_prototype_owner *owner)
{
	struct user_namespace *userns = owner->userns;

	memset(owner, 0, sizeof(*owner));
	return userns;
}

enum nfsd_ffv2_prototype_state nfsd_ffv2_prototype_state_get(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	enum nfsd_ffv2_prototype_state state;

	spin_lock(&anchor->prototype_gate_lock);
	state = anchor->prototype.state;
	spin_unlock(&anchor->prototype_gate_lock);
	return state;
}

bool nfsd_ffv2_prototype_ds_role(struct nfsd_net *nn)
{
	enum nfsd_ffv2_prototype_state state;

	state = nfsd_ffv2_prototype_state_get(nn);
	return state == NFSD_FFV2_PROTOTYPE_OPEN || state == NFSD_FFV2_PROTOTYPE_READY;
}

static bool nfsd_ffv2_prototype_quiet(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	bool quiet;

	spin_lock(&anchor->prototype_gate_lock);
	quiet = !anchor->prototype.users;
	spin_unlock(&anchor->prototype_gate_lock);
	return quiet;
}

/* One closer drains setup and gate users before provider/store teardown. */
static void nfsd_ffv2_prototype_close_finish(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype *proto = &anchor->prototype;
	struct nfsd_ffv2_prototype_ctx *ctx = NULL;
	struct user_namespace *userns;
	bool drop_anchor;

	nfsd_ffv2_prototype_test_event(nn, NFSD_FFV2_TEST_PROTO_CLOSE);
	wait_for_completion(&proto->setup_done);
	wait_event(proto->users_wait, nfsd_ffv2_prototype_quiet(nn));

	nfsd_ffv2_prototype_teardown_published(nn);

	mutex_lock(&nfsd_mutex);
	spin_lock(&anchor->prototype_gate_lock);
	if (proto->owns_ctx) {
		ctx = proto->ctx;
		proto->ctx = NULL;
		proto->owns_ctx = false;
	}
	if (proto->owns_source) {
		nfsd_ffv2_source_release_gated(anchor, NFSD_FFV2_SOURCE_PROTOTYPE);
		proto->owns_source = false;
	}
	drop_anchor = proto->owns_anchor;
	proto->owns_anchor = false;
	userns = nfsd_ffv2_prototype_owner_clear(&proto->owner);
	proto->state = NFSD_FFV2_PROTOTYPE_OFF;

	spin_unlock(&anchor->prototype_gate_lock);
	mutex_unlock(&nfsd_mutex);

	nfsd_ffv2_prototype_ctx_free(ctx);
	put_user_ns(userns);

	/* Keep the close role until the old completion has been signalled. */
	complete_all(&proto->close_done);
	spin_lock(&anchor->prototype_gate_lock);
	proto->close_claimed = false;
	spin_unlock(&anchor->prototype_gate_lock);
	if (drop_anchor)
		nfsd_ffv2_anchor_release(nn);
}

static void nfsd_ffv2_prototype_close_wait(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype *proto = &anchor->prototype;

	wait_for_completion(&proto->close_done);
	spin_lock(&anchor->prototype_gate_lock);
	if (!WARN_ON_ONCE(!proto->close_waiters))
		proto->close_waiters--;
	spin_unlock(&anchor->prototype_gate_lock);
}

static int nfsd_ffv2_prototype_close_claim(struct nfsd_net *nn, const struct net *net, u32 secid,
					   bool owner_check, const u8 *source_uuid, u64 generation)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype *proto = &anchor->prototype;
	int result;

	mutex_lock(&nfsd_mutex);
	spin_lock(&anchor->prototype_gate_lock);
	if (proto->state == NFSD_FFV2_PROTOTYPE_OFF) {
		result = -EOPNOTSUPP;
	} else if (owner_check && !nfsd_ffv2_prototype_owner_is(&proto->owner, net, secid)) {
		result = -EPERM;
	} else if (proto->close_claimed) {
		proto->close_waiters++;
		result = 0;
	} else if (source_uuid && proto->state != NFSD_FFV2_PROTOTYPE_READY) {
		result = -EOPNOTSUPP;
	} else if (source_uuid &&
		   (proto->generation != generation ||
		    memcmp(proto->source_uuid, source_uuid, sizeof(proto->source_uuid)))) {
		result = -ESTALE;
	} else {
		proto->close_claimed = true;
		proto->state = NFSD_FFV2_PROTOTYPE_CLOSING;
		result = 1;
	}
	spin_unlock(&anchor->prototype_gate_lock);
	mutex_unlock(&nfsd_mutex);
	return result;
}

/* A superseded setup registers its close waiter before signalling setup_done. */
static int nfsd_ffv2_prototype_setup_finish(struct nfsd_net *nn,
					    struct nfsd_ffv2_prototype_ctx *ctx, int error)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype *proto = &anchor->prototype;
	bool close_owner = false;
	bool superseded = false;

	mutex_lock(&nfsd_mutex);
	spin_lock(&anchor->prototype_gate_lock);
	if (proto->state != NFSD_FFV2_PROTOTYPE_ENABLING) {
		superseded = true;
		proto->close_waiters++;
	} else if (error) {
		proto->close_claimed = true;
		proto->state = NFSD_FFV2_PROTOTYPE_CLOSING;
		close_owner = true;
	} else {
		proto->ctx = ctx;
		proto->owns_ctx = true;
		ctx = NULL;
		proto->state = NFSD_FFV2_PROTOTYPE_OPEN;
	}
	proto->setup_ref = 0;
	spin_unlock(&anchor->prototype_gate_lock);
	mutex_unlock(&nfsd_mutex);

	nfsd_ffv2_prototype_ctx_free(ctx);
	complete_all(&proto->setup_done);
	if (close_owner) {
		nfsd_ffv2_prototype_close_finish(nn);
		return error;
	}
	if (superseded) {
		nfsd_ffv2_prototype_close_wait(nn);
		return error ? error : -EBUSY;
	}
	return 0;
}

static int __nfsd_ffv2_prototype_user_get(struct nfsd_net *nn, const struct net *net, u32 secid,
					  bool open_only)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype *proto = &anchor->prototype;
	int error = 0;

	spin_lock(&anchor->prototype_gate_lock);
	if (proto->state == NFSD_FFV2_PROTOTYPE_OFF)
		error = -EOPNOTSUPP;
	else if (proto->state != NFSD_FFV2_PROTOTYPE_OPEN &&
		 (open_only || proto->state != NFSD_FFV2_PROTOTYPE_READY))
		error = -EBUSY;
	else if (!nfsd_ffv2_prototype_owner_is(&proto->owner, net, secid))
		error = -EPERM;
	else if (WARN_ON_ONCE(!proto->owns_ctx))
		error = -EOPNOTSUPP;
	else
		proto->users++;
	spin_unlock(&anchor->prototype_gate_lock);
	return error;
}

static int nfsd_ffv2_prototype_user_get(struct nfsd_net *nn, const struct net *net, u32 secid)
{
	return __nfsd_ffv2_prototype_user_get(nn, net, secid, false);
}

static void nfsd_ffv2_prototype_user_put(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype *proto = &anchor->prototype;
	bool quiet = false;

	spin_lock(&anchor->prototype_gate_lock);
	if (!WARN_ON_ONCE(!proto->users))
		quiet = --proto->users == 0;
	spin_unlock(&anchor->prototype_gate_lock);
	if (quiet)
		wake_up_all(&proto->users_wait);
}

int nfsd_ffv2_prototype_op_admit(struct nfsd_net *nn, bool *counted)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype *proto = &anchor->prototype;
	int error = 0;

	*counted = false;
	spin_lock(&anchor->prototype_gate_lock);
	if (anchor->source != NFSD_FFV2_SOURCE_PROTOTYPE) {
		error = 0;
	} else if (proto->state != NFSD_FFV2_PROTOTYPE_READY) {
		error = -ESTALE;
	} else {
		proto->users++;
		*counted = true;
	}
	spin_unlock(&anchor->prototype_gate_lock);
	return error;
}

void nfsd_ffv2_prototype_op_release(struct nfsd_net *nn)
{
	nfsd_ffv2_prototype_user_put(nn);
}

static struct nfsd_ffv2_prototype_ctx *nfsd_ffv2_prototype_ctx_of(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype_ctx *ctx;

	spin_lock(&anchor->prototype_gate_lock);
	ctx = anchor->prototype.owns_ctx ? anchor->prototype.ctx : NULL;
	spin_unlock(&anchor->prototype_gate_lock);
	return ctx;
}

static bool nfsd_ffv2_prototype_nonce_take_locked(struct nfsd_ffv2_anchor *anchor,
						  struct nfsd_ffv2_prototype_ctx *ctx,
						  unsigned long index,
						  struct nfsd_ffv2_prototype_nonce *record,
						  struct list_head *dead)
{
	lockdep_assert_held(&anchor->prototype_gate_lock);
	if (record->busy)
		return false;
	if (WARN_ON_ONCE(xa_erase(&ctx->nonces, index) != record))
		return false;
	if (!WARN_ON_ONCE(!ctx->nonce_count))
		ctx->nonce_count--;
	list_add(&record->dead, dead);
	return true;
}

static void nfsd_ffv2_prototype_nonce_free(struct list_head *dead)
{
	struct nfsd_ffv2_prototype_nonce *record, *tmp;

	list_for_each_entry_safe(record, tmp, dead, dead) {
		list_del(&record->dead);
		kfree_sensitive(record);
	}
}

static void nfsd_ffv2_prototype_nonce_reap(struct nfsd_net *nn, struct nfsd_ffv2_prototype_ctx *ctx)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype_nonce *record;
	u64 now = ktime_get_ns();
	unsigned long index;
	LIST_HEAD(dead);

	spin_lock(&anchor->prototype_gate_lock);
	xa_for_each(&ctx->nonces, index, record) {
		if (record->state != NFSD_FFV2_NONCE_ISSUED || now <= record->expires)
			continue;
		nfsd_ffv2_prototype_nonce_take_locked(anchor, ctx, index, record, &dead);
	}
	spin_unlock(&anchor->prototype_gate_lock);
	nfsd_ffv2_prototype_nonce_free(&dead);
}

/* Claim and expiry/reaping are one decision under the gate lock. */
static int nfsd_ffv2_prototype_nonce_lookup(struct nfsd_net *nn,
					    struct nfsd_ffv2_prototype_ctx *ctx,
					    const struct net *net, u32 secid, const u8 *value,
					    bool claim, struct nfsd_ffv2_prototype_nonce **result)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype_nonce *record;
	bool has_secid = secid != 0;
	unsigned long index;
	LIST_HEAD(dead);
	u64 carried;
	int error;

	carried = get_unaligned_be64(value);
	if (carried > (u64)ULONG_MAX)
		return -ENOENT;
	index = carried;

	spin_lock(&anchor->prototype_gate_lock);
	record = xa_load(&ctx->nonces, index);
	if (!record || crypto_memneq(record->value, value, NFSD_FFV2_PROTOTYPE_NONCE_LEN)) {
		error = -ENOENT;
	} else if (record->net != net || record->userns != current_user_ns() ||
		   !uid_eq(record->uid, current_uid()) || record->secid_valid != has_secid ||
		   (record->secid_valid && record->secid != secid)) {
		error = -EPERM;
	} else if (record->busy) {
		error = -EBUSY;
	} else if (record->state == NFSD_FFV2_NONCE_ISSUED && ktime_get_ns() > record->expires) {
		nfsd_ffv2_prototype_nonce_take_locked(anchor, ctx, index, record, &dead);
		error = -ETIMEDOUT;
	} else {
		record->busy = claim;
		*result = record;
		error = 0;
	}
	spin_unlock(&anchor->prototype_gate_lock);
	nfsd_ffv2_prototype_nonce_free(&dead);
	return error;
}

static void nfsd_ffv2_prototype_nonce_release(struct nfsd_net *nn,
					      struct nfsd_ffv2_prototype_nonce *record)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	spin_lock(&anchor->prototype_gate_lock);
	record->busy = false;
	spin_unlock(&anchor->prototype_gate_lock);
}

int nfsd_ffv2_prototype_challenge(struct nfsd_net *nn, const struct net *net,
				  u8 nonce[NFSD_FFV2_PROTOTYPE_NONCE_LEN], u64 *expires)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype_nonce *record;
	struct nfsd_ffv2_prototype_ctx *ctx;
	unsigned long index = 0;
	u32 secid = 0;
	int error;

	if (!ns_capable(net->user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	security_cred_getsecid(current_cred(), &secid);
	error = nfsd_ffv2_prototype_user_get(nn, net, secid);
	if (error)
		return error;
	ctx = nfsd_ffv2_prototype_ctx_of(nn);
	if (WARN_ON_ONCE(!ctx)) {
		error = -EOPNOTSUPP;
		goto out_put;
	}
	record = kzalloc_obj(*record, GFP_KERNEL);
	if (!record) {
		error = -ENOMEM;
		goto out_put;
	}
	nfsd_ffv2_prototype_nonce_reap(nn, ctx);

	spin_lock(&anchor->prototype_gate_lock);
	if (ctx->nonce_count >= NFSD_FFV2_PROTOTYPE_NONCE_MAX || ctx->next_nonce == ULONG_MAX) {
		error = -EBUSY;
	} else {
		index = ctx->next_nonce++;
		ctx->nonce_count++;
	}
	spin_unlock(&anchor->prototype_gate_lock);
	if (error) {
		kfree(record);
		goto out_put;
	}

	put_unaligned_be64(index, record->value);
	get_random_bytes(record->value + sizeof(u64), NFSD_FFV2_PROTOTYPE_NONCE_LEN - sizeof(u64));
	record->expires = ktime_get_ns() + NFSD_FFV2_PROTOTYPE_NONCE_TTL_NS;
	record->state = NFSD_FFV2_NONCE_ISSUED;

	record->uid = current_uid();
	record->userns = current_user_ns();
	record->net = net;
	record->secid = secid;
	record->secid_valid = secid != 0;

	memcpy(nonce, record->value, NFSD_FFV2_PROTOTYPE_NONCE_LEN);
	*expires = record->expires;
	error = xa_err(xa_store(&ctx->nonces, index, record, GFP_KERNEL));
	if (error) {
		spin_lock(&anchor->prototype_gate_lock);
		if (!WARN_ON_ONCE(!ctx->nonce_count))
			ctx->nonce_count--;
		spin_unlock(&anchor->prototype_gate_lock);
		kfree_sensitive(record);
		goto out_put;
	}

out_put:
	nfsd_ffv2_prototype_user_put(nn);
	return error;
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
int nfsd_ffv2_prototype_test_member(struct nfsd_net *nn, enum nfsd_ffv2_prototype_test_site site,
				    u32 member)
{
	const struct nfsd_ffv2_prototype_test *test = READ_ONCE(nn->ffv2.test_prototype);

	return test && test->event ? test->event(test->data, site, member) : 0;
}

int nfsd_ffv2_prototype_test_event(struct nfsd_net *nn, enum nfsd_ffv2_prototype_test_site site)
{
	return nfsd_ffv2_prototype_test_member(nn, site, 0);
}

static bool nfsd_ffv2_prototype_fixture(struct nfsd_net *nn)
{
	return !!READ_ONCE(nn->ffv2.test_prototype);
}
#else
static bool nfsd_ffv2_prototype_fixture(struct nfsd_net *nn)
{
	return false;
}
#endif
struct nfsd_ffv2_prototype_member {
	u8 object_uuid[16];
	u8 store_handle[32];
	u32 admission_id;
	u8 stateid[NFS4_STATEID_SIZE];
	struct nfsd_ffv2_store_file file;
};

struct nfsd_ffv2_prototype_provider {
	struct nfsd_net *nn;
	u32 chunk_size;
	u32 count;
	struct nfsd_ffv2_store *store;
	struct nfsd_ffv2_prototype_member members[NFSD_FFV2_MAX_OBJECTS];
};

struct nfsd_ffv2_prototype_registration {
	struct nfsd_ffv2_prototype_committed record;
	struct nfsd_ffv2_store_admission admitted[NFSD_FFV2_PROTOTYPE_OBJECT_MAX];
	struct knfsd_fh outer_fhs[NFSD_FFV2_PROTOTYPE_OBJECT_MAX];
	u8 persisted_handles[NFSD_FFV2_PROTOTYPE_OBJECT_MAX][32];
	u8 object_uuids[NFSD_FFV2_PROTOTYPE_OBJECT_MAX][16];
	struct svc_fh fhps[NFSD_FFV2_PROTOTYPE_OBJECT_MAX];
	u8 source_input[32 + 8 + 32 * NFSD_FFV2_PROTOTYPE_OBJECT_MAX];
};

static struct nfsd_ffv2_prototype_member *
nfsd_ffv2_prototype_member(struct nfsd_ffv2_prototype_provider *provider,
			   const struct nfsd_ffv2_object *object)
{
	struct nfsd_ffv2_prototype_member *found = NULL;
	u32 i;

	if (!object)
		return provider->count == 1 ? &provider->members[0] : NULL;
	for (i = 0; i < provider->count; i++) {
		struct nfsd_ffv2_prototype_member *member = &provider->members[i];

		if (memcmp(member->object_uuid, nfsd_ffv2_object_uuid(object), 16))
			continue;
		if (found)
			return NULL;
		found = member;
	}
	return found;
}

static void nfsd_ffv2_prototype_provider_free(struct nfsd_ffv2_prototype_provider *provider)
{
	if (!provider)
		return;
	nfsd_ffv2_store_close(provider->store);
	kfree(provider);
}

/* Each operation owns its metadata and bytes through admission completion. */
struct nfsd_ffv2_store_read_result {
	struct nfsd_net *nn;
	struct nfsd_ffv2_read_chunk *chunks;
	struct nfsd_ffv2_visible_chunk *visible;
	u8 *bytes;
};

static void nfsd_ffv2_store_read_result_free(void *private)
{
	struct nfsd_ffv2_store_read_result *result = private;

	if (!result)
		return;
	nfsd_ffv2_prototype_test_event(result->nn, NFSD_FFV2_TEST_PROTO_RELEASE);
	kvfree(result->bytes);
	kvfree(result->chunks);
	kvfree(result->visible);
	kfree(result);
}

static bool nfsd_ffv2_prototype_checksum_valid(const struct nfsd_ffv2_visible_chunk *chunk,
					       const u8 *data, u32 len)
{
	return nfsd_ffv2_store_checksum_valid(chunk->checksum_algorithm, chunk->checksum,
					      chunk->checksum_len, data, len);
}

/* Snapshot current committed metadata; payload extents remain append-only. */
static __be32 nfsd_ffv2_prototype_store_chunk_read(void *opaque,
						   const struct nfsd_ffv2_object *object,
						   const struct nfsd_ffv2_chunk_request *req,
						   struct nfsd_ffv2_chunk_result *result)
{
	struct nfsd_ffv2_prototype_provider *provider = opaque;
	struct nfsd_ffv2_prototype_member *member;
	struct nfsd_ffv2_store_read_result *owned;
	u64 file_chunks, file_eof, last_len, end;
	u32 capacity, count, i;
	size_t bytes;
	int error;

	member = nfsd_ffv2_prototype_member(provider, object);
	if (!member)
		return nfserr_serverfault;
	capacity = req->offset >= member->file.max_chunks ?
			   0 :
			   min_t(u64, req->count, member->file.max_chunks - req->offset);
	if (nfsd_ffv2_prototype_test_member(provider->nn, NFSD_FFV2_TEST_PROTO_READ_ALLOC, 0))
		return nfserr_jukebox;
	owned = kzalloc_obj(*owned, GFP_KERNEL);
	if (!owned)
		return nfserr_jukebox;
	owned->nn = provider->nn;
	if (capacity) {
		owned->visible = nfsd_ffv2_prototype_test_member(provider->nn,
								 NFSD_FFV2_TEST_PROTO_READ_ALLOC,
								 1) ?
					 NULL :
					 kvcalloc(capacity, sizeof(*owned->visible), GFP_KERNEL);
		if (!owned->visible) {
			nfsd_ffv2_store_read_result_free(owned);
			return nfserr_jukebox;
		}
	}
	error = nfsd_ffv2_store_read_snapshot(provider->store, member->file.file_key, req->offset,
					      capacity, owned->visible, &file_eof, &count);
	if (error) {
		nfsd_ffv2_store_read_result_free(owned);
		return error == -ENOMEM ? nfserr_jukebox : nfserr_io;
	}
	file_chunks = DIV_ROUND_UP_ULL(file_eof, member->file.chunk_bytes);
	if (!count) {
		result->eof = req->offset >= file_chunks;
		nfsd_ffv2_store_read_result_free(owned);
		return nfs_ok;
	}
	result->eof = count < req->count || req->offset + count == file_chunks;
	if (check_mul_overflow((size_t)count, (size_t)member->file.chunk_bytes, &bytes) ||
	    bytes > NFSD_FFV2_MAX_PAYLOAD_BYTES) {
		nfsd_ffv2_store_read_result_free(owned);
		return nfserr_serverfault;
	}
	owned->chunks =
		nfsd_ffv2_prototype_test_member(provider->nn, NFSD_FFV2_TEST_PROTO_READ_ALLOC, 2) ?
			NULL :
			kvcalloc(count, sizeof(*owned->chunks), GFP_KERNEL);
	owned->bytes =
		nfsd_ffv2_prototype_test_member(provider->nn, NFSD_FFV2_TEST_PROTO_READ_ALLOC, 3) ?
			NULL :
			kvzalloc(bytes, GFP_KERNEL);
	if (!owned->chunks || !owned->bytes) {
		nfsd_ffv2_store_read_result_free(owned);
		return nfserr_jukebox;
	}

	for (i = 0; i < count; i++) {
		struct nfsd_ffv2_visible_chunk visible;
		struct nfsd_ffv2_read_chunk *chunk = &owned->chunks[i];
		u8 *data = owned->bytes + (size_t)i * member->file.chunk_bytes;
		u64 index = req->offset + i, payload_offset;
		u32 crc, len = member->file.chunk_bytes;
		bool checksum_valid;
		int visible_error;

		end = (index + 1) * (u64)member->file.chunk_bytes;
		if (end > file_eof) {
			last_len = file_eof - index * (u64)member->file.chunk_bytes;
			len = last_len;
		}
		visible = owned->visible[i];
		visible_error = visible.payload_object_id ? 0 : -ENOENT;
		if (!visible_error) {
			if (visible.file_eof != file_eof || visible.content_len != len ||
			    !visible.payload_object_id || visible.guard_never_written) {
				nfsd_ffv2_store_read_result_free(owned);
				return nfserr_serverfault;
			}
			if (check_add_overflow(visible.payload_object_offset,
					       (u64)NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE,
					       &payload_offset) ||
			    payload_offset > S64_MAX) {
				nfsd_ffv2_store_read_result_free(owned);
				return nfserr_serverfault;
			}
			error = nfsd_ffv2_store_read_payload(provider->store, data, len,
							     payload_offset);
			if (error) {
				nfsd_ffv2_store_read_result_free(owned);
				return error == -ENOMEM ? nfserr_jukebox : nfserr_io;
			}
			checksum_valid = nfsd_ffv2_prototype_checksum_valid(&visible, data, len);
			if (!checksum_valid ||
			    visible.content_crc32c != (~crc32c(~0U, data, len))) {
				nfsd_ffv2_store_read_result_free(owned);
				return nfserr_io;
			}
			chunk->cr_owner.co_cohort_id = visible.owner_cohort;
			chunk->cr_owner.co_client_id = visible.owner_client_id;
			chunk->cr_owner.co_id = visible.owner_co_id;
			chunk->cr_guard.cg_gen_id = visible.guard_generation;
			chunk->cr_guard.cg_client_id = visible.guard_writer;
			chunk->cr_payload_id = visible.writer_payload_id;
		} else if (visible_error != -ENOENT) {
			nfsd_ffv2_store_read_result_free(owned);
			return visible_error == -ENOMEM ? nfserr_jukebox : nfserr_io;
		}
		crc = crc32_le(~0U, data, len) ^ ~0U;
		chunk->cr_checksum.cs_algorithm = NFSD_FFV2_CHECKSUM_ALG_CRC32;
		chunk->cr_checksum.cs_len = NFSD_FFV2_CHECKSUM_CRC32_LEN;
		put_unaligned_be32(crc, chunk->cr_checksum.cs_value);
		chunk->cr_effective_len = len;
		chunk->cr_status = visible_error == -ENOENT ? nfserr_noent : nfs_ok;
		chunk->cr_chunk = data;
	}
	nfsd_ffv2_prototype_test_event(provider->nn, NFSD_FFV2_TEST_PROTO_RESULT);
	result->count = count;
	result->read.chunks = owned->chunks;
	result->private = owned;
	result->release = nfsd_ffv2_store_read_result_free;
	return nfs_ok;
}

static __be32 nfsd_ffv2_prototype_chunk_header_read(void *opaque,
						    const struct nfsd_ffv2_object *object,
						    const struct nfsd_ffv2_chunk_request *req,
						    struct nfsd_ffv2_chunk_result *result)
{
	return nfserr_notsupp;
}

static const struct nfsd_ffv2_provider_ops nfsd_ffv2_prototype_provider_ops = {
	.chunk_read = nfsd_ffv2_prototype_store_chunk_read,
	.chunk_header_read = nfsd_ffv2_prototype_chunk_header_read,
};

static bool nfsd_ffv2_prototype_file_geometry_valid(u64 max_chunks, u32 chunk_bytes,
						    u64 logical_eof)
{
	u64 capacity;

	return max_chunks && max_chunks <= 64 &&
	       !check_mul_overflow(max_chunks, (u64)chunk_bytes, &capacity) && capacity &&
	       capacity <= NFSD_FFV2_MAX_PAYLOAD_BYTES && logical_eof <= capacity;
}

static int
nfsd_ffv2_prototype_store_vector_validate(const struct nfsd_ffv2_store_file *const *files,
					  u32 count, u32 chunk_size)
{
	u64 max_chunks = 0, total = 0;
	u32 i, j;

	for (i = 0; i < count; i++) {
		if (!nfsd_ffv2_prototype_file_geometry_valid(files[i]->max_chunks,
							     files[i]->chunk_bytes,
							     files[i]->logical_eof) ||
		    files[i]->chunk_bytes != chunk_size ||
		    (max_chunks && files[i]->max_chunks != max_chunks))
			return -EINVAL;
		for (j = 0; j < i; j++)
			if (!memcmp(files[i]->file_key, files[j]->file_key,
				    sizeof(files[i]->file_key)))
				return -EEXIST;
		if (check_add_overflow(total, files[i]->max_chunks * (u64)chunk_size, &total) ||
		    total > NFSD_FFV2_MAX_PAYLOAD_BYTES)
			return -E2BIG;
		max_chunks = files[i]->max_chunks;
	}
	return count ? 0 : -EINVAL;
}

static int nfsd_ffv2_prototype_provider_build(struct nfsd_net *nn, const u8 uuids[][16],
					      const u8 handles[][32], u32 count, u32 chunk_size,
					      u64 generation,
					      struct nfsd_ffv2_prototype_provider **result)
{
	struct nfsd_ffv2_prototype_provider *provider;
	const struct nfsd_ffv2_store_file *files[NFSD_FFV2_MAX_OBJECTS];
	u32 i;
	int error;

	if (nfsd_ffv2_prototype_test_event(nn, NFSD_FFV2_TEST_PROTO_PROVIDER_ALLOC))
		return -ENOMEM;
	provider = kzalloc_obj(*provider, GFP_KERNEL);
	if (!provider)
		return -ENOMEM;
	provider->nn = nn;
	provider->count = count;
	error = nfsd_ffv2_store_open_generation(nn, generation, &provider->store);
	if (error)
		goto out;
	for (i = 0; i < count; i++) {
		struct nfsd_ffv2_prototype_member *member = &provider->members[i];

		memcpy(member->object_uuid, uuids[i], 16);
		memcpy(member->store_handle, handles[i], 32);
		error = nfsd_ffv2_store_lookup_file(provider->store, handles[i], &member->file);
		if (error)
			goto out;
		files[i] = &member->file;
	}
	error = nfsd_ffv2_prototype_store_vector_validate(files, count, chunk_size);
	if (error)
		goto out;
	provider->chunk_size = chunk_size;
	*result = provider;
	return 0;
out:
	nfsd_ffv2_prototype_provider_free(provider);
	return error;
}

/* Drain the provider before releasing its store, then retire the generation. */
static void nfsd_ffv2_prototype_teardown_published(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype *proto = &anchor->prototype;
	struct nfsd_ffv2_prototype_provider *provider = NULL;
	u64 generation = 0;

	spin_lock(&anchor->prototype_gate_lock);
	if (proto->owns_provider) {
		provider = proto->provider;
		proto->provider = NULL;
		proto->owns_provider = false;
	}
	if (proto->owns_generation) {
		generation = proto->generation;
		proto->owns_generation = false;
	}
	spin_unlock(&anchor->prototype_gate_lock);

	if (provider) {
		nfsd_ffv2_provider_remove(nn);
		nfsd_ffv2_prototype_provider_free(provider);
	}
	if (generation) {
		mutex_lock(&nfsd_mutex);
		nfsd_ffv2_service_generation_retire(nn, generation);
		mutex_unlock(&nfsd_mutex);
	}
}

static int nfsd_ffv2_prototype_resolve(const struct net *net, const struct cred *cred,
				       const struct nfsd_ffv2_prototype_request *req,
				       const u8 *handle, u32 handle_len, struct svc_fh *fhp)
{
	struct auth_domain *domain;
	struct svc_cred rq_cred = {};
	__be32 status;
	int error;

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	const struct nfsd_ffv2_prototype_test *test = READ_ONCE(nn->ffv2.test_prototype);

	if (test && test->resolve)
		return test->resolve(test->data, handle, handle_len, fhp);
#endif
	domain = auth_domain_find((char *)req->auth_domain);
	if (!domain)
		return -ENOENT;
	rq_cred.cr_uid = cred->fsuid;
	rq_cred.cr_gid = cred->fsgid;
	rq_cred.cr_flavor = RPC_AUTH_UNIX;
	rq_cred.cr_group_info = groups_alloc(0);
	if (!rq_cred.cr_group_info) {
		auth_domain_put(domain);
		return -ENOMEM;
	}
	fh_init(fhp, NFS4_FHSIZE);
	fhp->fh_handle.fh_size = handle_len;
	memcpy(fhp->fh_handle.fh_raw, handle, handle_len);
	status = fh_verify_local((struct net *)net, &rq_cred, domain, fhp, S_IFREG, NFSD_MAY_READ);
	put_group_info(rq_cred.cr_group_info);
	auth_domain_put(domain);
	if (status) {
		fh_put(fhp);
		error = -ESTALE;
	} else {
		error = 0;
	}
	return error;
}

static void nfsd_ffv2_prototype_commit_record(struct nfsd_ffv2_prototype_committed *rec,
					      const struct nfsd_ffv2_prototype_request *req)
{
	u32 count = req->object_count ?: 1;
	u32 i;

	memset(rec, 0, sizeof(*rec));
	strscpy(rec->auth_domain, req->auth_domain, sizeof(rec->auth_domain));
	rec->chunk_size = req->chunk_size;
	rec->data_count = req->data_count;
	rec->parity_count = req->parity_count;
	memcpy(rec->store_uuid, req->store_uuid, sizeof(rec->store_uuid));
	memcpy(rec->binding_token, req->binding_token, sizeof(rec->binding_token));
	rec->writer_id = req->writer_id;
	rec->pnfs_clientid = req->pnfs_clientid;
	rec->object_count = count;
	for (i = 0; i < count; i++) {
		const u8 *handle = req->object_count ? req->objects[i].handle : req->handle;
		const u8 *persisted = req->object_count ? req->objects[i].persisted_handle :
							  req->persisted_handle;
		u32 handle_len = req->object_count ? req->objects[i].handle_len : req->handle_len;

		memcpy(rec->objects[i].handle, handle, handle_len);
		rec->objects[i].handle_len = handle_len;
		memcpy(rec->objects[i].persisted_handle, persisted, 32);
	}
}

static int nfsd_ffv2_prototype_trust(struct nfsd_net *nn, const u8 object_uuid[16],
				     const struct nfsd_ffv2_prototype_request *request,
				     const u8 raw_stateid[16], stateid_t *stateid)
{
	struct nfsd_ffv2_trust_request req = {};
	__be32 status;

	stateid->si_generation = get_unaligned_be32(raw_stateid);
	memcpy(&stateid->si_opaque, raw_stateid + sizeof(__be32), sizeof(stateid->si_opaque));
	req.stateid = *stateid;
	req.object_uuid = object_uuid;
	req.actor = NFSD_FFV2_CALLER_DATA_CLIENT;
	static_assert(sizeof(req.pnfs_clientid) == sizeof(request->pnfs_clientid));
	/* The proc-exported scalar already contains native clientid_t bytes. */
	memcpy(&req.pnfs_clientid, &request->pnfs_clientid, sizeof(req.pnfs_clientid));
	req.client_id = request->writer_id;
	req.iomode = IOMODE_RW;
	req.profile_mask = NFSD_FFV2_PROFILE_READ_DATA | NFSD_FFV2_PROFILE_READ_METADATA |
			   NFSD_FFV2_PROFILE_WRITE_DATA | NFSD_FFV2_PROFILE_WRITE_LIFECYCLE;
	ktime_get_real_ts64(&req.expires);
	req.expires.tv_sec += NFSD_FFV2_PROTOTYPE_TRUST_TTL_SEC;
	status = nfsd_ffv2_trust_install_active(nn, &req);
	return status == nfs_ok ? 0 : -EIO;
}

/**
 * nfsd_ffv2_prototype_register - construct and publish one bounded object set
 * @nn: namespace whose gate is open
 * @net: requesting administrator's namespace
 * @req: nonce and exact member identities retained for replay
 * @bundle: receives the committed handles and trusted stateids
 *
 * Registration owns staged resources until READY transfers them to the gate.
 * Failed replies retain a committed nonce for an exact retry.
 *
 * Context: Sleeps. Caller holds no FFv2 lock or nfsd_mutex.
 * Return: Zero on success, or a negative errno without a new bundle.
 */
int nfsd_ffv2_prototype_register(struct nfsd_net *nn, const struct net *net,
				 const struct nfsd_ffv2_prototype_request *req,
				 struct nfsd_ffv2_prototype_bundle *bundle)
{
	struct nfsd_ffv2_prototype_provider *provider = NULL;
	struct nfsd_ffv2_prototype_registration *work;
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype *proto = &anchor->prototype;
	struct nfsd_ffv2_export_update registration;
	struct nfsd_ffv2_prototype_bundle *staged;
	struct nfsd_ffv2_prototype_nonce *nonce;
	struct nfsd_ffv2_prototype_ctx *ctx;
	bool slot_open = false, installed = false, claimed = false;
	bool fhs_live = false;
	bool spent = false;
	const struct cred *cred;
	u64 generation_id = 0;
	u8 source_uuid[16], digest[SHA256_DIGEST_SIZE];

	u32 object_count, total_count, i;
	u32 secid = 0;
	int error = 0;

	if (!ns_capable(net->user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	if (check_add_overflow(req->data_count, req->parity_count, &total_count))
		return -EINVAL;
	object_count = req->object_count ?: 1;
	if (!req->nonce || !req->auth_domain || !req->chunk_size || !req->data_count ||
	    !req->store_uuid || !req->binding_token || !req->writer_id ||
	    req->writer_id == U32_MAX || object_count > NFSD_FFV2_PROTOTYPE_OBJECT_MAX ||
	    (req->object_count && object_count != total_count) ||
	    (req->object_count && !req->parity_count && object_count != 1) ||
	    (!req->object_count && req->parity_count) ||
	    req->chunk_size > NFSD_FFV2_MAX_PAYLOAD_BYTES)
		return -EINVAL;
	for (i = 0; i < object_count; i++) {
		const u8 *handle = req->object_count ? req->objects[i].handle : req->handle;
		const u8 *persisted = req->object_count ? req->objects[i].persisted_handle :
							  req->persisted_handle;
		u32 handle_len = req->object_count ? req->objects[i].handle_len : req->handle_len;

		if (!handle || !handle_len || handle_len > NFS4_FHSIZE || !persisted)
			return -EINVAL;
	}
	if (strnlen(req->auth_domain, NFSD_FFV2_PROTOTYPE_DOMAIN_MAX + 1) >
	    NFSD_FFV2_PROTOTYPE_DOMAIN_MAX)
		return -EINVAL;
	if (nfsd_ffv2_prototype_test_event(nn, NFSD_FFV2_TEST_PROTO_WORK_ALLOC))
		return -ENOMEM;
	work = kzalloc_obj(*work, GFP_KERNEL);
	if (!work)
		return -ENOMEM;
	for (i = 0; i < object_count; i++) {
		const u8 *persisted = req->object_count ? req->objects[i].persisted_handle :
							  req->persisted_handle;

		memcpy(work->persisted_handles[i], persisted, 32);
	}

	security_cred_getsecid(current_cred(), &secid);

	error = nfsd_ffv2_prototype_user_get(nn, net, secid);
	if (error)
		goto out_free;
	ctx = nfsd_ffv2_prototype_ctx_of(nn);
	if (WARN_ON_ONCE(!ctx)) {
		error = -EOPNOTSUPP;
		goto out_put;
	}
	error = nfsd_ffv2_prototype_nonce_lookup(nn, ctx, net, secid, req->nonce, true, &nonce);
	if (error)
		goto out_put;
	claimed = true;

	staged = &nonce->bundle;
	nfsd_ffv2_prototype_commit_record(&work->record, req);

	spin_lock(&anchor->prototype_gate_lock);
	if (nonce->state == NFSD_FFV2_NONCE_COMMITTED) {
		spent = true;
		if (memcmp(&nonce->committed, &work->record, sizeof(work->record)))
			error = -EEXIST;
		else
			*bundle = *staged;
	} else if (proto->state != NFSD_FFV2_PROTOTYPE_OPEN) {
		error = -EBUSY;
	}
	spin_unlock(&anchor->prototype_gate_lock);
	if (spent || error)
		goto out_put;
	cred = ctx->cred;
	for (i = 0; i < object_count; i++) {
		const u8 *handle = req->object_count ? req->objects[i].handle : req->handle;
		struct svc_fh *fhp = &work->fhps[i];
		u32 handle_len = req->object_count ? req->objects[i].handle_len : req->handle_len;

		error = nfsd_ffv2_prototype_resolve(net, cred, req, handle, handle_len, fhp);
		if (error) {
			while (i)
				fh_put(&work->fhps[--i]);
			goto out_put;
		}
	}
	fhs_live = true;
	if (nfsd_ffv2_prototype_test_event(nn, NFSD_FFV2_TEST_PROTO_RESOLVE)) {
		error = -EIO;
		goto out_registration;
	}
	memset(work->source_input, 0, sizeof(work->source_input));
	memcpy(work->source_input, "NFSD-FFV2-SET-V1", 16);
	memcpy(work->source_input + 16, req->store_uuid, 16);
	put_unaligned_be32(req->data_count, work->source_input + 32);
	put_unaligned_be32(req->parity_count, work->source_input + 36);
	for (i = 0; i < object_count; i++)
		memcpy(work->source_input + 40 + i * 32, work->persisted_handles[i], 32);
	sha256(work->source_input, 40 + object_count * 32, digest);
	memcpy(source_uuid, digest, sizeof(source_uuid));

	mutex_lock(&nfsd_mutex);
	error = nfsd_ffv2_registration_begin_prototype(nn, &registration);
	mutex_unlock(&nfsd_mutex);
	if (error)
		goto out_registration;
	slot_open = true;
	error = nfsd_ffv2_authority_prototype_create(nn, &registration.authority);
	if (error)
		goto out_registration;
	error = nfsd_ffv2_object_register_fhs(nn, &registration, work->fhps,
					      work->persisted_handles, object_count,
					      req->chunk_size, req->store_uuid, req->binding_token,
					      cred, !nfsd_ffv2_prototype_fixture(nn), source_uuid,
					      work->object_uuids, work->outer_fhs, &generation_id);
	fhs_live = false;
	if (error)
		goto out_registration;

	error = nfsd_ffv2_prototype_test_event(nn, NFSD_FFV2_TEST_PROTO_PUBLISHED);
	if (error)
		goto out_published;
	error = nfsd_ffv2_prototype_provider_build(nn, work->object_uuids, work->persisted_handles,
						   object_count, req->chunk_size, generation_id,
						   &provider);
	if (error)
		goto out_published;
	if (nfsd_ffv2_prototype_test_event(nn, NFSD_FFV2_TEST_PROTO_FILE_LOOKUP)) {
		error = -EIO;
		goto out_published;
	}
	error = nfsd_ffv2_store_admit_writers(provider->store, req->writer_id, object_count,
					      work->admitted);
	if (!error) {
		for (i = 0; i < object_count; i++) {
			provider->members[i].admission_id = work->admitted[i].id;
			memcpy(provider->members[i].stateid, work->admitted[i].stateid, 16);
		}
	}

	if (error)
		goto out_published;
	if (nfsd_ffv2_prototype_test_event(nn, NFSD_FFV2_TEST_PROTO_ADMITTED)) {
		error = -EIO;
		goto out_published;
	}
	error = nfsd_ffv2_provider_install(nn, &nfsd_ffv2_prototype_provider_ops, provider,
					   req->chunk_size);
	if (error)
		goto out_published;
	installed = true;
	if (nfsd_ffv2_prototype_test_event(nn, NFSD_FFV2_TEST_PROTO_PROVIDER)) {
		error = -EIO;
		goto out_published;
	}
	memset(staged, 0, sizeof(*staged));
	for (i = 0; i < object_count; i++) {
		stateid_t stateid;

		if (nfsd_ffv2_prototype_test_member(nn, NFSD_FFV2_TEST_PROTO_TRUST, i))
			error = -EIO;
		else
			error = nfsd_ffv2_prototype_trust(nn, work->object_uuids[i], req,
							  work->admitted[i].stateid, &stateid);
		if (error)
			goto out_published;
		memcpy(staged->objects[i].stateid, &stateid, sizeof(stateid));
	}

	memcpy(staged->source_uuid, source_uuid, sizeof(staged->source_uuid));
	get_random_bytes(staged->service_uuid, sizeof(staged->service_uuid));
	get_random_bytes(staged->replay_uuid, sizeof(staged->replay_uuid));
	staged->generation = generation_id;
	staged->object_count = object_count;
	for (i = 0; i < object_count; i++) {
		memcpy(staged->objects[i].handle, work->outer_fhs[i].fh_raw,
		       work->outer_fhs[i].fh_size);
		staged->objects[i].handle_len = work->outer_fhs[i].fh_size;
	}
	memcpy(staged->stateid, staged->objects[0].stateid, sizeof(staged->stateid));
	memcpy(staged->handle, staged->objects[0].handle, staged->objects[0].handle_len);
	staged->handle_len = staged->objects[0].handle_len;
	if (nfsd_ffv2_prototype_test_event(nn, NFSD_FFV2_TEST_PROTO_READY)) {
		error = -EIO;
		goto out_published;
	}

	mutex_lock(&anchor->lock);
	spin_lock(&anchor->prototype_gate_lock);

	if (proto->state != NFSD_FFV2_PROTOTYPE_OPEN || proto->close_claimed ||
	    !nfsd_ffv2_prototype_generation_matches(nn, source_uuid, generation_id)) {
		memzero_explicit(staged, sizeof(*staged));
		spin_unlock(&anchor->prototype_gate_lock);
		mutex_unlock(&anchor->lock);
		error = -EBUSY;
		goto out_published;
	}
	/* READY, committed identities and ownership transfer are indivisible. */
	proto->provider = provider;
	proto->owns_provider = true;
	proto->generation = generation_id;
	proto->owns_generation = true;
	memcpy(proto->source_uuid, staged->source_uuid, sizeof(proto->source_uuid));
	nonce->committed = work->record;
	nonce->state = NFSD_FFV2_NONCE_COMMITTED;
	proto->state = NFSD_FFV2_PROTOTYPE_READY;
	*bundle = *staged;
	spin_unlock(&anchor->prototype_gate_lock);
	mutex_unlock(&anchor->lock);

	nfsd_ffv2_registration_end(nn, &registration);

	nfsd_ffv2_prototype_nonce_release(nn, nonce);
	nfsd_ffv2_prototype_user_put(nn);
	kfree_sensitive(work);
	return 0;

out_published:

	memzero_explicit(staged, sizeof(*staged));
	if (installed)
		nfsd_ffv2_provider_remove(nn);
	mutex_lock(&nfsd_mutex);
	nfsd_ffv2_service_generation_retire(nn, generation_id);
	mutex_unlock(&nfsd_mutex);
	nfsd_ffv2_prototype_provider_free(provider);
out_registration:
	if (slot_open)
		nfsd_ffv2_registration_end(nn, &registration);
	if (fhs_live)
		for (i = 0; i < object_count; i++)
			fh_put(&work->fhps[i]);
out_put:

	if (claimed)
		nfsd_ffv2_prototype_nonce_release(nn, nonce);
	nfsd_ffv2_prototype_user_put(nn);
	kfree_sensitive(work);
	return error;
out_free:
	kfree_sensitive(work);
	return error;
}

int nfsd_ffv2_prototype_unregister(struct nfsd_net *nn, const struct net *net,
				   const u8 source_uuid[16], u64 generation)
{
	if (!generation)
		return -EINVAL;
	return __nfsd_ffv2_prototype_close(nn, net, source_uuid, generation);
}

int nfsd_ffv2_prototype_enable(struct nfsd_net *nn, const struct net *net)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype *proto = &anchor->prototype;
	struct nfsd_ffv2_prototype_ctx *ctx;
	struct user_namespace *userns;
	u32 secid = 0;
	int error;

	if (!ns_capable(net->user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	security_cred_getsecid(current_cred(), &secid);
	if (!nfsd_ffv2_anchor_hold(nn))
		return -ESHUTDOWN;
	userns = get_user_ns(current_user_ns());

	mutex_lock(&nfsd_mutex);
	spin_lock(&anchor->prototype_gate_lock);

	if (proto->exiting) {
		error = -ESHUTDOWN;
		goto out_unlock;
	}
	if (proto->state != NFSD_FFV2_PROTOTYPE_OFF || proto->close_claimed ||
	    proto->close_waiters) {
		error = -EBUSY;
		goto out_unlock;
	}
	error = nfsd_ffv2_source_claim_gated(anchor, NFSD_FFV2_SOURCE_PROTOTYPE);
	if (error)
		goto out_unlock;
	proto->owns_source = true;
	proto->owns_anchor = true;
	proto->setup_ref = 1;
	proto->close_claimed = false;
	reinit_completion(&proto->setup_done);
	reinit_completion(&proto->close_done);
	nfsd_ffv2_prototype_owner_set(&proto->owner, net, userns, secid);
	userns = NULL;
	proto->state = NFSD_FFV2_PROTOTYPE_ENABLING;
	spin_unlock(&anchor->prototype_gate_lock);
	mutex_unlock(&nfsd_mutex);

	if (nfsd_ffv2_prototype_test_event(nn, NFSD_FFV2_TEST_PROTO_SETUP))
		return nfsd_ffv2_prototype_setup_finish(nn, NULL, -ENOMEM);
	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	if (ctx) {
		ctx->cred = get_cred(current_cred());
		xa_init(&ctx->nonces);
		ctx->next_nonce = 1;
	}
	return nfsd_ffv2_prototype_setup_finish(nn, ctx, ctx ? 0 : -ENOMEM);

out_unlock:
	spin_unlock(&anchor->prototype_gate_lock);
	mutex_unlock(&nfsd_mutex);
	put_user_ns(userns);
	nfsd_ffv2_anchor_release(nn);
	return error;
}

static int __nfsd_ffv2_prototype_close(struct nfsd_net *nn, const struct net *net,
				       const u8 *source_uuid, u64 generation)
{
	u32 secid = 0;
	int claim;

	if (!ns_capable(net->user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	security_cred_getsecid(current_cred(), &secid);
	claim = nfsd_ffv2_prototype_close_claim(nn, net, secid, true, source_uuid, generation);
	if (claim < 0)
		return claim;
	if (!claim) {
		nfsd_ffv2_prototype_close_wait(nn);
		return -EBUSY;
	}
	nfsd_ffv2_prototype_close_finish(nn);
	return 0;
}

int nfsd_ffv2_prototype_disable(struct nfsd_net *nn, const struct net *net)
{
	return __nfsd_ffv2_prototype_close(nn, net, NULL, 0);
}

void nfsd_ffv2_prototype_net_pre_exit(struct nfsd_net *nn)
{
	int claim;

	spin_lock(&nn->ffv2.prototype_gate_lock);
	nn->ffv2.prototype.exiting = true;
	spin_unlock(&nn->ffv2.prototype_gate_lock);
	claim = nfsd_ffv2_prototype_close_claim(nn, NULL, 0, false, NULL, 0);

	if (claim < 0)
		return;
	if (claim)
		nfsd_ffv2_prototype_close_finish(nn);
	else
		nfsd_ffv2_prototype_close_wait(nn);
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
int nfsd_ffv2_prototype_test_write(struct nfsd_net *nn, u32 member,
				   struct nfsd_ffv2_store_write *request,
				   struct nfsd_ffv2_store_mutation_result *result)
{
	struct nfsd_ffv2_prototype_provider *provider;
	bool counted;
	int error;

	error = nfsd_ffv2_prototype_op_admit(nn, &counted);
	if (error || !counted)
		return error ?: -EINVAL;
	provider = nn->ffv2.prototype.provider;
	if (member >= provider->count) {
		error = -EINVAL;
	} else {
		request->admission_id = provider->members[member].admission_id;
		error = nfsd_ffv2_store_test_write(provider->store,
						   provider->members[member].file.file_key, request,
						   result);
	}
	nfsd_ffv2_prototype_op_release(nn);
	return error;
}
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
void nfsd_ffv2_prototype_test_age(struct nfsd_net *nn, const u8 value[32])
{
	struct nfsd_ffv2_prototype_ctx *ctx;
	struct nfsd_ffv2_prototype_nonce *nonce;

	spin_lock(&nn->ffv2.prototype_gate_lock);
	ctx = nn->ffv2.prototype.ctx;
	nonce = xa_load(&ctx->nonces, get_unaligned_be64(value));
	if (nonce)
		nonce->expires = 0;
	spin_unlock(&nn->ffv2.prototype_gate_lock);
}
#endif
