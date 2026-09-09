// SPDX-License-Identifier: GPL-2.0-only
/*
 * The Flex Files v2 prototype authority profile.
 *
 * See ffv2_prototype.h for the gate's state machine and for why this
 * profile exists at all.  Everything here is compiled only when
 * CONFIG_NFSD_FFV2_PROTOTYPE_AUTH is set; an ordinary server has no
 * prototype state and no way to reach any of it.
 */
#include <crypto/utils.h>
#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/ktime.h>
#include <linux/random.h>
#include <linux/unaligned.h>
#include <linux/xarray.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/user_namespace.h>
#include <net/net_namespace.h>

#include "export.h"
#include "ffv2.h"
#include "ffv2_prototype.h"
#include "nfsd.h"
#include "netns.h"

/*
 * One challenge.
 *
 * The nonce exists so that a registration names something this server
 * issued rather than something the caller invented, and so that a retried
 * registration is recognisably the same registration.  It is bound to the
 * administrator that asked for it: another administrator presenting it is
 * refused even while the gate is open to them both.
 *
 * The first eight bytes are the record's index in the table and the rest
 * are random.  That makes the lookup a single load rather than a walk, and
 * gives away nothing: the index is a counter, and what has to be unguessable
 * is the remainder, which is compared without a data-dependent early exit.
 */
enum nfsd_ffv2_prototype_nonce_state {
	NFSD_FFV2_NONCE_ISSUED,
};

struct nfsd_ffv2_prototype_nonce {
	u8				value[NFSD_FFV2_PROTOTYPE_NONCE_LEN];
	u64				expires;
	enum nfsd_ffv2_prototype_nonce_state state;
	/* The identity the challenge was issued to; see the owner tuple. */
	kuid_t				uid;
	struct user_namespace		*userns;
	const struct net		*net;
	u32				secid;
	bool				secid_valid;
};

/*
 * What the enabling administrator staged.  Allocated by the enable, owned
 * by the gate once the enable publishes OPEN, and disposed of exactly once
 * -- by the enable's own rollback if it never published, and by the close
 * owner otherwise.
 */
struct nfsd_ffv2_prototype_ctx {
	/*
	 * The enabling credential.  A later registration publishes its
	 * service context with this rather than with whatever credential
	 * happens to be current when the object is registered.
	 */
	const struct cred	*cred;
	/*
	 * Challenges this gate has issued, indexed by the counter carried in
	 * the first eight bytes of each nonce.  Only a caller holding a
	 * counted gate reference touches the table, and the close owner
	 * drains those before it disposes of this, so the table needs no
	 * lock of its own beyond the xarray's.
	 */
	struct xarray		nonces;
	u64			next_nonce;
	unsigned int		nonce_count;
};

/* No more challenges may be outstanding at once than a demonstrator needs. */
#define NFSD_FFV2_PROTOTYPE_NONCE_MAX	64

static struct nfsd_ffv2_prototype *nfsd_ffv2_prototype_of(struct nfsd_net *nn)
{
	return &nn->ffv2.prototype;
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
/*
 * A one-shot pause inside the enabling caller's sleepable setup.  The
 * ENABLING interval is the whole point of the state, and it is otherwise
 * too short to race against deterministically: this lets a test hold an
 * enable there while another thread closes the gate or exits the
 * namespace.  Armed by the test that uses it and consumed once.
 */
static struct completion *nfsd_ffv2_prototype_setup_reached;
static struct completion *nfsd_ffv2_prototype_setup_proceed;

void nfsd_ffv2_prototype_test_setup_hook(struct completion *reached,
					 struct completion *proceed)
{
	WRITE_ONCE(nfsd_ffv2_prototype_setup_proceed, proceed);
	WRITE_ONCE(nfsd_ffv2_prototype_setup_reached, reached);
}

static void nfsd_ffv2_prototype_setup_pause(void)
{
	struct completion *reached =
		READ_ONCE(nfsd_ffv2_prototype_setup_reached);
	struct completion *proceed =
		READ_ONCE(nfsd_ffv2_prototype_setup_proceed);

	if (!reached)
		return;
	WRITE_ONCE(nfsd_ffv2_prototype_setup_reached, NULL);
	WRITE_ONCE(nfsd_ffv2_prototype_setup_proceed, NULL);
	complete(reached);
	if (proceed)
		wait_for_completion(proceed);
}
#else
static inline void nfsd_ffv2_prototype_setup_pause(void) { }
#endif

void nfsd_ffv2_prototype_net_init(struct nfsd_net *nn)
{
	struct nfsd_ffv2_prototype *proto = nfsd_ffv2_prototype_of(nn);

	proto->state = NFSD_FFV2_PROTOTYPE_OFF;
	proto->users = 0;
	proto->setup_ref = 0;
	proto->close_claimed = false;
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

	/*
	 * Namespace pre-exit closes the gate and joins its owner, so a
	 * namespace reaching teardown with anything still held means that
	 * fence was missed rather than that the gate was left open.
	 */
	WARN_ON_ONCE(proto->state != NFSD_FFV2_PROTOTYPE_OFF);
	WARN_ON_ONCE(proto->users || proto->setup_ref || proto->close_waiters);
	WARN_ON_ONCE(proto->owns_ctx || proto->owns_anchor ||
		     proto->owns_source);
	WARN_ON_ONCE(proto->owner.valid);
}

static void nfsd_ffv2_prototype_ctx_free(struct nfsd_ffv2_prototype_ctx *ctx)
{
	struct nfsd_ffv2_prototype_nonce *nonce;
	unsigned long index;

	if (!ctx)
		return;
	/*
	 * Every challenge dies with the gate that issued it.  No lookup can
	 * be in flight: a lookup holds a counted gate reference, and the
	 * close owner drained those before it got here.
	 */
	xa_for_each(&ctx->nonces, index, nonce) {
		xa_erase(&ctx->nonces, index);
		kfree_sensitive(nonce);
	}
	xa_destroy(&ctx->nonces);
	put_cred(ctx->cred);
	kfree(ctx);
}

/*
 * The identity an enable recorded, and the comparison the other four
 * commands are held to.  The security identifier is read by the caller
 * before either lock is taken, because an LSM hook is not a leaf.
 */
static void
nfsd_ffv2_prototype_owner_set(struct nfsd_ffv2_prototype_owner *owner,
			      const struct net *net,
			      struct user_namespace *userns, u32 secid)
{
	owner->uid = current_uid();
	owner->userns = userns;
	owner->net = net;
	owner->secid = secid;
	owner->secid_valid = secid != 0;
	owner->valid = true;
}

static bool
nfsd_ffv2_prototype_owner_is(const struct nfsd_ffv2_prototype_owner *owner,
			     const struct net *net, u32 secid)
{
	bool has_secid = secid != 0;

	if (!owner->valid)
		return false;
	if (owner->net != net || owner->userns != current_user_ns() ||
	    !uid_eq(owner->uid, current_uid()))
		return false;
	/*
	 * An administrator whose credential carries no security identifier
	 * is not the same administrator as one whose does, even when the
	 * rest of the tuple matches.
	 */
	if (owner->secid_valid != has_secid)
		return false;
	return !owner->secid_valid || owner->secid == secid;
}

/* Drop what the tuple held, and forget it.  Gate lock held. */
static struct user_namespace *
nfsd_ffv2_prototype_owner_clear(struct nfsd_ffv2_prototype_owner *owner)
{
	struct user_namespace *userns = owner->userns;

	memset(owner, 0, sizeof(*owner));
	return userns;
}

enum nfsd_ffv2_prototype_state
nfsd_ffv2_prototype_state_get(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	enum nfsd_ffv2_prototype_state state;

	spin_lock(&anchor->prototype_gate_lock);
	state = anchor->prototype.state;
	spin_unlock(&anchor->prototype_gate_lock);
	return state;
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

/*
 * The one teardown.  Its caller owns the close role, so nothing else is
 * draining, removing, or releasing while this runs.
 *
 * The order is fixed: the setup owner has to be finished before anything
 * it staged can be judged, the counted work has to drain before the
 * objects it borrows are removed, and the source reservation is returned
 * last, once nothing in the namespace can reach the gate any more.
 */
static void nfsd_ffv2_prototype_close_finish(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype *proto = &anchor->prototype;
	struct nfsd_ffv2_prototype_ctx *ctx = NULL;
	struct user_namespace *userns;
	bool drop_anchor;

	wait_for_completion(&proto->setup_done);
	wait_event(proto->users_wait, nfsd_ffv2_prototype_quiet(nn));

	mutex_lock(&nfsd_mutex);
	spin_lock(&anchor->prototype_gate_lock);
	if (proto->owns_ctx) {
		ctx = proto->ctx;
		proto->ctx = NULL;
		proto->owns_ctx = false;
	}
	if (proto->owns_source) {
		nfsd_ffv2_source_release_gated(anchor,
					       NFSD_FFV2_SOURCE_PROTOTYPE);
		proto->owns_source = false;
	}
	drop_anchor = proto->owns_anchor;
	proto->owns_anchor = false;
	userns = nfsd_ffv2_prototype_owner_clear(&proto->owner);
	proto->state = NFSD_FFV2_PROTOTYPE_OFF;
	proto->close_claimed = false;
	spin_unlock(&anchor->prototype_gate_lock);
	mutex_unlock(&nfsd_mutex);

	nfsd_ffv2_prototype_ctx_free(ctx);
	put_user_ns(userns);
	/*
	 * Only now: a waiter returning from here may go on to release the
	 * namespace, and the reservation and every reference the gate held
	 * are already gone.
	 */
	complete_all(&proto->close_done);
	if (drop_anchor)
		nfsd_ffv2_anchor_release(nn);
}

/* Park on the owner's completion, holding the anchor across the wait. */
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

/*
 * Take the close role, or arrange to wait for whoever has it.
 *
 * Return: 1 when the caller is now the sole teardown owner, 0 when it must
 * call nfsd_ffv2_prototype_close_wait(), -EOPNOTSUPP when the gate is
 * already off, or -EPERM when @owner_check is asked for and the caller is
 * not the administrator that enabled.  Both locks are taken here, in the
 * only order any reservation transition uses.
 */
static int nfsd_ffv2_prototype_close_claim(struct nfsd_net *nn,
					   const struct net *net, u32 secid,
					   bool owner_check)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype *proto = &anchor->prototype;
	int result;

	mutex_lock(&nfsd_mutex);
	spin_lock(&anchor->prototype_gate_lock);
	if (proto->state == NFSD_FFV2_PROTOTYPE_OFF) {
		result = -EOPNOTSUPP;
	} else if (owner_check &&
		   !nfsd_ffv2_prototype_owner_is(&proto->owner, net, secid)) {
		result = -EPERM;
	} else if (proto->close_claimed) {
		proto->close_waiters++;
		result = 0;
	} else {
		/*
		 * ENABLING counts: the enable that published it has not
		 * finished, and this is the point at which its outcome is
		 * taken away from it.  It rolls back what it staged and
		 * signals setup_done; the teardown below is this caller's.
		 */
		proto->close_claimed = true;
		proto->state = NFSD_FFV2_PROTOTYPE_CLOSING;
		result = 1;
	}
	spin_unlock(&anchor->prototype_gate_lock);
	mutex_unlock(&nfsd_mutex);
	return result;
}

/*
 * Finish an enable, whichever way it went.  Exactly one of three things is
 * true by the time both locks are held again: nobody interfered and the
 * gate opens; the setup failed and this caller has to close what it
 * claimed; or a competitor already took the close role, in which case this
 * caller only rolls back and lets that competitor finish.
 */
static int nfsd_ffv2_prototype_setup_finish(struct nfsd_net *nn,
					    struct nfsd_ffv2_prototype_ctx *ctx,
					    int error)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype *proto = &anchor->prototype;
	bool close_owner = false;
	bool superseded = false;

	mutex_lock(&nfsd_mutex);
	spin_lock(&anchor->prototype_gate_lock);
	if (proto->state != NFSD_FFV2_PROTOTYPE_ENABLING) {
		superseded = true;
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

	/* Whatever was not handed over is this caller's to dispose of. */
	nfsd_ffv2_prototype_ctx_free(ctx);
	complete_all(&proto->setup_done);
	if (close_owner) {
		nfsd_ffv2_prototype_close_finish(nn);
		return error;
	}
	if (superseded) {
		/*
		 * The gate never became usable, and the caller is told so
		 * only once the namespace is quiet again: returning while
		 * the close owner still holds the reservation would make an
		 * immediate retry fail for a reason that has already passed.
		 */
		spin_lock(&anchor->prototype_gate_lock);
		proto->close_waiters++;
		spin_unlock(&anchor->prototype_gate_lock);
		nfsd_ffv2_prototype_close_wait(nn);
		return error ? error : -EBUSY;
	}
	return 0;
}

/*
 * Take one counted reference on a live gate.  Everything that has to be
 * finished before teardown -- a challenge, a registration, an admitted
 * operation -- holds one of these across its whole sleepable body, which
 * is what lets the close owner know when the namespace is quiet.
 *
 * Return: 0, -EOPNOTSUPP when the namespace has no gate, -EBUSY while one
 * is still enabling or already closing, or -EPERM for an administrator
 * other than the one that enabled it.
 */
static int nfsd_ffv2_prototype_user_get(struct nfsd_net *nn,
					const struct net *net, u32 secid)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype *proto = &anchor->prototype;
	int error = 0;

	spin_lock(&anchor->prototype_gate_lock);
	if (proto->state == NFSD_FFV2_PROTOTYPE_OFF)
		error = -EOPNOTSUPP;
	else if (proto->state != NFSD_FFV2_PROTOTYPE_OPEN &&
		 proto->state != NFSD_FFV2_PROTOTYPE_READY)
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

/*
 * The staged context, for a caller that holds a gate reference.  The close
 * owner drains those references before it disposes of the context, so what
 * this returns stays valid until the caller puts its reference back.
 */
static struct nfsd_ffv2_prototype_ctx *
nfsd_ffv2_prototype_ctx_of(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype_ctx *ctx;

	spin_lock(&anchor->prototype_gate_lock);
	ctx = anchor->prototype.owns_ctx ? anchor->prototype.ctx : NULL;
	spin_unlock(&anchor->prototype_gate_lock);
	return ctx;
}

/* Drop challenges nobody came back for, so one gate cannot fill up. */
static void nfsd_ffv2_prototype_nonce_reap(struct nfsd_net *nn,
					   struct nfsd_ffv2_prototype_ctx *ctx)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype_nonce *record;
	u64 now = ktime_get_ns();
	unsigned long index;

	xa_for_each(&ctx->nonces, index, record) {
		if (record->state != NFSD_FFV2_NONCE_ISSUED ||
		    now <= record->expires)
			continue;
		if (xa_cmpxchg(&ctx->nonces, index, record, NULL,
			       GFP_KERNEL) != record)
			continue;
		spin_lock(&anchor->prototype_gate_lock);
		if (!WARN_ON_ONCE(!ctx->nonce_count))
			ctx->nonce_count--;
		spin_unlock(&anchor->prototype_gate_lock);
		kfree_sensitive(record);
	}
}

/*
 * The record a nonce names, if this administrator was issued it and it is
 * still live.  The comparison covers the whole opaque, including the index
 * the lookup already used, and runs without a data-dependent early exit.
 *
 * Return: 0 with @result set, -ENOENT for an unknown nonce, -ETIMEDOUT for
 * one that expired, or -EPERM for one issued to somebody else.
 */
static int
nfsd_ffv2_prototype_nonce_lookup(struct nfsd_net *nn,
				 struct nfsd_ffv2_prototype_ctx *ctx,
				 const struct net *net, u32 secid,
				 const u8 *value,
				 struct nfsd_ffv2_prototype_nonce **result)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype_nonce *record;
	bool has_secid = secid != 0;
	unsigned long index;
	u64 carried;

	carried = get_unaligned_be64(value);
	index = (unsigned long)carried;
	if (carried != index)
		return -ENOENT;
	record = xa_load(&ctx->nonces, index);
	if (!record)
		return -ENOENT;
	if (crypto_memneq(record->value, value,
			  NFSD_FFV2_PROTOTYPE_NONCE_LEN))
		return -ENOENT;
	if (record->net != net || record->userns != current_user_ns() ||
	    !uid_eq(record->uid, current_uid()) ||
	    record->secid_valid != has_secid ||
	    (record->secid_valid && record->secid != secid))
		return -EPERM;
	if (record->state == NFSD_FFV2_NONCE_ISSUED &&
	    ktime_get_ns() > record->expires) {
		/*
		 * An expired challenge is gone, not merely refused: leaving
		 * it would let the same nonce report -ETIMEDOUT forever
		 * while occupying one of the gate's few slots.
		 */
		if (xa_cmpxchg(&ctx->nonces, index, record, NULL,
			       GFP_KERNEL) == record) {
			spin_lock(&anchor->prototype_gate_lock);
			if (!WARN_ON_ONCE(!ctx->nonce_count))
				ctx->nonce_count--;
			spin_unlock(&anchor->prototype_gate_lock);
			kfree_sensitive(record);
		}
		return -ETIMEDOUT;
	}
	*result = record;
	return 0;
}

/**
 * nfsd_ffv2_prototype_challenge - issue one registration nonce
 * @nn: the nfsd namespace
 * @net: the caller's network namespace
 * @nonce: receives the opaque the registration must present
 * @expires: receives the monotonic deadline, in nanoseconds
 *
 * Return: 0, -EPERM without CAP_SYS_ADMIN or for an administrator other
 * than the one that enabled, -EOPNOTSUPP when the gate is off, -EBUSY
 * while it is enabling, closing, or already holding as many outstanding
 * challenges as it will, or -ENOMEM.
 */
int nfsd_ffv2_prototype_challenge(struct nfsd_net *nn, const struct net *net,
				  u8 nonce[NFSD_FFV2_PROTOTYPE_NONCE_LEN],
				  u64 *expires)
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
	if (ctx->nonce_count >= NFSD_FFV2_PROTOTYPE_NONCE_MAX ||
	    ctx->next_nonce == ULONG_MAX) {
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
	get_random_bytes(record->value + sizeof(u64),
			 NFSD_FFV2_PROTOTYPE_NONCE_LEN - sizeof(u64));
	record->expires = ktime_get_ns() + NFSD_FFV2_PROTOTYPE_NONCE_TTL_NS;
	record->state = NFSD_FFV2_NONCE_ISSUED;
	/*
	 * The issuing identity, which must equal the gate's owner tuple for
	 * the challenge to have been admitted at all.  The user namespace is
	 * not referenced here: the gate holds that reference, and no record
	 * outlives the gate that issued it.
	 */
	record->uid = current_uid();
	record->userns = current_user_ns();
	record->net = net;
	record->secid = secid;
	record->secid_valid = secid != 0;

	error = xa_err(xa_store(&ctx->nonces, index, record, GFP_KERNEL));
	if (error) {
		spin_lock(&anchor->prototype_gate_lock);
		if (!WARN_ON_ONCE(!ctx->nonce_count))
			ctx->nonce_count--;
		spin_unlock(&anchor->prototype_gate_lock);
		kfree_sensitive(record);
		goto out_put;
	}
	memcpy(nonce, record->value, NFSD_FFV2_PROTOTYPE_NONCE_LEN);
	*expires = record->expires;
out_put:
	nfsd_ffv2_prototype_user_put(nn);
	return error;
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
/* Run one nonce through the real lookup and report only its status. */
int nfsd_ffv2_prototype_test_nonce_check(struct nfsd_net *nn,
					 const struct net *net,
					 const u8 *nonce)
{
	struct nfsd_ffv2_prototype_nonce *record = NULL;
	struct nfsd_ffv2_prototype_ctx *ctx;
	u32 secid = 0;
	int error;

	security_cred_getsecid(current_cred(), &secid);
	error = nfsd_ffv2_prototype_user_get(nn, net, secid);
	if (error)
		return error;
	ctx = nfsd_ffv2_prototype_ctx_of(nn);
	error = ctx ? nfsd_ffv2_prototype_nonce_lookup(nn, ctx, net, secid,
						       nonce, &record) :
		      -EOPNOTSUPP;
	nfsd_ffv2_prototype_user_put(nn);
	return error;
}

/* Backdate one challenge so its expiry can be reached without waiting. */
void nfsd_ffv2_prototype_test_nonce_age(struct nfsd_net *nn, const u8 *nonce)
{
	struct nfsd_ffv2_prototype_nonce *record;
	struct nfsd_ffv2_prototype_ctx *ctx;

	ctx = nfsd_ffv2_prototype_ctx_of(nn);
	if (!ctx)
		return;
	record = xa_load(&ctx->nonces, (unsigned long)get_unaligned_be64(nonce));
	if (record)
		record->expires = 0;
}

/*
 * Callers parked on the close owner's completion.  A race test uses this
 * to know that a second closer has actually arrived and is waiting, rather
 * than assuming that starting a thread is the same as running one.
 */
unsigned int nfsd_ffv2_prototype_test_close_waiters(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	unsigned int waiters;

	spin_lock(&anchor->prototype_gate_lock);
	waiters = anchor->prototype.close_waiters;
	spin_unlock(&anchor->prototype_gate_lock);
	return waiters;
}

unsigned int nfsd_ffv2_prototype_test_nonce_count(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype_ctx *ctx = nfsd_ffv2_prototype_ctx_of(nn);
	unsigned int count = 0;

	if (!ctx)
		return 0;
	spin_lock(&anchor->prototype_gate_lock);
	count = ctx->nonce_count;
	spin_unlock(&anchor->prototype_gate_lock);
	return count;
}
#endif

/**
 * nfsd_ffv2_prototype_enable - open the prototype gate for this namespace
 * @nn: the nfsd namespace
 * @net: the caller's network namespace, which becomes part of the owner
 *
 * Claims the namespace's authority source and publishes ENABLING before
 * any sleepable work, so namespace exit and a competing administrator both
 * find something to arbitrate rather than a gap.
 *
 * Return: 0, -EPERM without CAP_SYS_ADMIN in @net's user namespace,
 * -EBUSY when the namespace already has a gate or another authority
 * source, -ESHUTDOWN once the namespace is exiting, or -ENOMEM.
 */
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
	if (proto->state != NFSD_FFV2_PROTOTYPE_OFF || proto->close_waiters) {
		error = -EBUSY;
		goto out_unlock;
	}
	error = nfsd_ffv2_source_claim_gated(anchor,
					     NFSD_FFV2_SOURCE_PROTOTYPE);
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

	/* Sleepable from here, with the setup reference holding the gate. */
	nfsd_ffv2_prototype_setup_pause();
	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_PROTOTYPE_SETUP))
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

/**
 * nfsd_ffv2_prototype_disable - close the prototype gate
 * @nn: the nfsd namespace
 * @net: the caller's network namespace
 *
 * Return: 0 when this caller performed the teardown, -EBUSY when another
 * caller was already performing it and this one waited it out,
 * -EOPNOTSUPP when the gate was already off, or -EPERM for an
 * administrator that did not enable it.
 */
int nfsd_ffv2_prototype_disable(struct nfsd_net *nn, const struct net *net)
{
	u32 secid = 0;
	int claim;

	if (!ns_capable(net->user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	security_cred_getsecid(current_cred(), &secid);
	claim = nfsd_ffv2_prototype_close_claim(nn, net, secid, true);
	if (claim < 0)
		return claim;
	if (!claim) {
		nfsd_ffv2_prototype_close_wait(nn);
		return -EBUSY;
	}
	nfsd_ffv2_prototype_close_finish(nn);
	return 0;
}

/**
 * nfsd_ffv2_prototype_net_pre_exit - fence the gate against namespace exit
 * @nn: the departing nfsd namespace
 *
 * Runs before the namespace's own FFv2 fence, so the gate's objects are
 * gone before that fence looks for them.  There is no owner check: the
 * namespace is going away whether or not the administrator that enabled
 * the gate is still around to ask.
 */
void nfsd_ffv2_prototype_net_pre_exit(struct nfsd_net *nn)
{
	int claim = nfsd_ffv2_prototype_close_claim(nn, NULL, 0, false);

	if (claim < 0)
		return;
	if (claim)
		nfsd_ffv2_prototype_close_finish(nn);
	else
		nfsd_ffv2_prototype_close_wait(nn);
}
