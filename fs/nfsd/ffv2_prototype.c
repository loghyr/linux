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

/* Longest client name a registration may name, matching the export cache. */
#define NFSD_FFV2_PROTOTYPE_DOMAIN_MAX	NAME_MAX

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
	NFSD_FFV2_NONCE_COMMITTED,
};

/*
 * The inputs a committed registration was made with, kept so a retry can
 * be told from a different registration wearing the same nonce.  Copied,
 * never aliased: the message they arrived in is long gone by the time a
 * retry is compared against them.
 */
struct nfsd_ffv2_prototype_committed {
	char	auth_domain[NFSD_FFV2_PROTOTYPE_DOMAIN_MAX + 1];
	u32	chunk_size;
	u32	data_count;
	u32	parity_count;
	u8	store_uuid[16];
	u8	binding_token[32];
	u32	writer_id;
	u64	pnfs_clientid;
	u32	object_count;
	struct {
		u8 handle[NFS4_FHSIZE];
		u32 handle_len;
		u8 persisted_handle[32];
	} objects[NFSD_FFV2_PROTOTYPE_OBJECT_MAX];
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
	/*
	 * Set while a registration is using this record.  A registration
	 * sleeps -- it reads a whole object -- and a challenge running
	 * beside it drops challenges nobody came back for, so without this
	 * the record could be freed from under the registration that is
	 * still committing to it.
	 */
	bool				busy;
	/*
	 * Off-table staging for a record the reaper removed.  Freeing under
	 * the gate lock would be legal but pointless; carrying the record
	 * out on this list keeps the removal and the free in one decision
	 * without holding the lock across either.
	 */
	struct list_head		dead;
	/* Set once the registration this nonce named succeeded. */
	struct nfsd_ffv2_prototype_committed committed;
	struct nfsd_ffv2_prototype_bundle bundle;
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

/*
 * How long the trusted stateid a registration mints stays valid.  A
 * demonstrator runs for minutes; an entry that outlived the machine it was
 * demonstrated on would be a stateid nothing remembers issuing.
 */
#define NFSD_FFV2_PROTOTYPE_TRUST_TTL_SEC	3600

static_assert(sizeof(stateid_t) == NFS4_STATEID_SIZE,
	      "the registration bundle carries a stateid verbatim");
static_assert(NFSD_FFV2_FH_MAX <= NFS4_FHSIZE,
	      "the registration bundle carries a mapped handle verbatim");

static void nfsd_ffv2_prototype_teardown_published(struct nfsd_net *nn);
static int __nfsd_ffv2_prototype_close(struct nfsd_net *nn,
				       const struct net *net,
				       const u8 *source_uuid, u64 generation);

static struct nfsd_ffv2_prototype *nfsd_ffv2_prototype_of(struct nfsd_net *nn)
{
	return &nn->ffv2.prototype;
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
/*
 * The one-shot pauses a test can hold a caller at.
 *
 * Each names an interval the design turns on and which is otherwise far
 * too short to enter deliberately: the enabling caller's sleepable setup,
 * the gap between a registration publishing its generation and reaching
 * READY, the gap between a superseded enable registering its wait and
 * consuming it, and two points inside a close -- before the owner drains
 * anything, where a second closer can still arrive, and after the gate
 * reads off but before the completion that says so is signalled.
 *
 * Every slot below is process-global, and what a pause completes belongs
 * to whichever test armed it.  Arming, taking an arming down and consuming
 * one are therefore a single protocol rather than three sets of stores:
 * the record is immutable and refcounted, a consumer takes a reference
 * before it reads anything and holds it past its last use, and a test
 * taking its own arming down does so under the lock that decides which
 * arming is current -- so it cannot take down one that replaced it, and a
 * consumer cannot be left reading a record that has gone.
 */
static DEFINE_SPINLOCK(nfsd_ffv2_prototype_test_hook_lock);
static struct nfsd_ffv2_prototype_test_pause
	*nfsd_ffv2_prototype_test_pauses[NFSD_FFV2_PAUSE_SITES];

void nfsd_ffv2_prototype_test_pause_put(struct nfsd_ffv2_prototype_test_pause *pause)
{
	if (pause && refcount_dec_and_test(&pause->ref))
		kfree(pause);
}

/*
 * Arm @site, and hand back the arming with a reference of the caller's
 * own: it is what the caller waits on, and it is what the caller names to
 * take this arming and no other back down.
 */
struct nfsd_ffv2_prototype_test_pause *
nfsd_ffv2_prototype_test_pause_arm(enum nfsd_ffv2_prototype_test_pause_site site)
{
	struct nfsd_ffv2_prototype_test_pause *pause, *old;

	if (site >= NFSD_FFV2_PAUSE_SITES)
		return NULL;
	pause = kzalloc_obj(*pause, GFP_KERNEL);
	if (!pause)
		return NULL;
	/* One for the caller and one for the slot. */
	refcount_set(&pause->ref, 2);
	init_completion(&pause->reached);
	init_completion(&pause->proceed);

	spin_lock(&nfsd_ffv2_prototype_test_hook_lock);
	old = nfsd_ffv2_prototype_test_pauses[site];
	nfsd_ffv2_prototype_test_pauses[site] = pause;
	spin_unlock(&nfsd_ffv2_prototype_test_hook_lock);
	nfsd_ffv2_prototype_test_pause_put(old);
	return pause;
}

/*
 * Take @pause out of @site, and only if it is still what @site holds.  The
 * comparison and the store are the same critical section, so an arming
 * that replaced it between the two is not the one taken out.  Returns
 * whether this arming was the one removed; the caller's own reference is
 * its to put either way.
 */
bool nfsd_ffv2_prototype_test_pause_disarm(enum nfsd_ffv2_prototype_test_pause_site site,
					   struct nfsd_ffv2_prototype_test_pause *pause)
{
	bool taken = false;

	if (!pause || site >= NFSD_FFV2_PAUSE_SITES)
		return false;
	spin_lock(&nfsd_ffv2_prototype_test_hook_lock);
	if (nfsd_ffv2_prototype_test_pauses[site] == pause) {
		nfsd_ffv2_prototype_test_pauses[site] = NULL;
		taken = true;
	}
	spin_unlock(&nfsd_ffv2_prototype_test_hook_lock);
	if (taken)
		nfsd_ffv2_prototype_test_pause_put(pause);
	return taken;
}

/*
 * Consume one arming of @site, once.
 *
 * Whoever takes the arming out of the slot is the one that runs it, so a
 * second caller arriving here finds nothing, and a test taking its own
 * arming down concurrently either wins -- and this runs nothing -- or
 * loses, and this runs an arming the test still holds a reference to.  The
 * wait is what the pause is for; the test that armed it completes
 * @proceed on every path it can end on.
 */
static void nfsd_ffv2_prototype_test_pause_run(enum nfsd_ffv2_prototype_test_pause_site site)
{
	struct nfsd_ffv2_prototype_test_pause *pause;

	spin_lock(&nfsd_ffv2_prototype_test_hook_lock);
	pause = nfsd_ffv2_prototype_test_pauses[site];
	if (pause)
		refcount_inc(&pause->ref);
	spin_unlock(&nfsd_ffv2_prototype_test_hook_lock);
	if (!pause)
		return;
	if (!nfsd_ffv2_prototype_test_pause_disarm(site, pause)) {
		nfsd_ffv2_prototype_test_pause_put(pause);
		return;
	}
	complete(&pause->reached);
	wait_for_completion(&pause->proceed);
	nfsd_ffv2_prototype_test_pause_put(pause);
}

static void nfsd_ffv2_prototype_setup_pause(void)
{
	nfsd_ffv2_prototype_test_pause_run(NFSD_FFV2_PAUSE_SETUP);
}

static void nfsd_ffv2_prototype_entered_pause(void)
{
	nfsd_ffv2_prototype_test_pause_run(NFSD_FFV2_PAUSE_ENTERED);
}

static void nfsd_ffv2_prototype_published_pause(void)
{
	nfsd_ffv2_prototype_test_pause_run(NFSD_FFV2_PAUSE_PUBLISHED);
}

static void nfsd_ffv2_prototype_supersede_pause(void)
{
	nfsd_ffv2_prototype_test_pause_run(NFSD_FFV2_PAUSE_SUPERSEDE);
}

static void nfsd_ffv2_prototype_publish_pause(void)
{
	nfsd_ffv2_prototype_test_pause_run(NFSD_FFV2_PAUSE_PUBLISH);
}
#else
static inline void nfsd_ffv2_prototype_setup_pause(void) { }
static inline void nfsd_ffv2_prototype_publish_pause(void) { }
static inline void nfsd_ffv2_prototype_supersede_pause(void) { }
static inline void nfsd_ffv2_prototype_entered_pause(void) { }
static inline void nfsd_ffv2_prototype_published_pause(void) { }
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

bool nfsd_ffv2_prototype_ds_role(struct nfsd_net *nn)
{
	enum nfsd_ffv2_prototype_state state;

	state = nfsd_ffv2_prototype_state_get(nn);
	return state == NFSD_FFV2_PROTOTYPE_OPEN ||
	       state == NFSD_FFV2_PROTOTYPE_READY;
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

	nfsd_ffv2_prototype_entered_pause();
	wait_for_completion(&proto->setup_done);
	wait_event(proto->users_wait, nfsd_ffv2_prototype_quiet(nn));
	/*
	 * Nothing is counted against the gate any more, so no result is
	 * still borrowing provider storage and no mapping can be admitted.
	 * Whatever the one registration published is removed here, and only
	 * if it is still owned: an unregister may have removed it already.
	 */
	nfsd_ffv2_prototype_teardown_published(nn);

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
	/*
	 * The close role is held past this point on purpose.  The state says
	 * the gate is off, which is what namespace teardown checks, but the
	 * completion below has not been signalled yet, and it is shared with
	 * whatever cycle comes next.  An enable that started here would
	 * reinitialise it, and this owner's signal would then land on the
	 * new cycle's completion and let one of its closers return before
	 * its own teardown had happened.  Holding the role is what an enable
	 * refuses on, so no next cycle exists until the signal is out.
	 */
	spin_unlock(&anchor->prototype_gate_lock);
	mutex_unlock(&nfsd_mutex);

	nfsd_ffv2_prototype_ctx_free(ctx);
	put_user_ns(userns);
	nfsd_ffv2_prototype_published_pause();
	/*
	 * Only now: a waiter returning from here may go on to release the
	 * namespace, and everything the gate owned -- the reservation, the
	 * provider, the generation, the staged context -- has been detached.
	 *
	 * This owner's own execution reference on the anchor is the one thing
	 * still held, on purpose: the completion below and the role released
	 * after it both live in the anchor, so it cannot be let go until they
	 * have been touched.  It is dropped as soon as they have been, and a
	 * namespace waiting to be destroyed waits for exactly that.
	 */
	complete_all(&proto->close_done);
	spin_lock(&anchor->prototype_gate_lock);
	proto->close_claimed = false;
	spin_unlock(&anchor->prototype_gate_lock);
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
					   bool owner_check,
					   const u8 *source_uuid, u64 generation)
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
	} else if (source_uuid &&
		   proto->state != NFSD_FFV2_PROTOTYPE_READY) {
		/* Nothing is published, so there is nothing to retire. */
		result = -EOPNOTSUPP;
	} else if (source_uuid &&
		   (proto->generation != generation ||
		    memcmp(proto->source_uuid, source_uuid,
			   sizeof(proto->source_uuid)))) {
		/*
		 * The name is checked here, at the point the close role is
		 * decided, and not before it: a request naming a
		 * registration that has already gone must be refused rather
		 * than allowed to retire the one that replaced it.
		 */
		result = -ESTALE;
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
		/*
		 * Superseded.  The wait is registered here, before this
		 * caller signals that its setup is over, and not after: the
		 * close owner is only waiting for that signal, and once it
		 * has it there is nothing to stop it finishing, publishing
		 * OFF and letting the next enable reinitialise the
		 * completion this caller has not reached yet.  Counted from
		 * inside this section, the next enable is refused until the
		 * wait has been consumed, so there is no cycle for it to be
		 * carried into.
		 */
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
		nfsd_ffv2_prototype_supersede_pause();
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
static int __nfsd_ffv2_prototype_user_get(struct nfsd_net *nn,
					  const struct net *net, u32 secid,
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

static int nfsd_ffv2_prototype_user_get(struct nfsd_net *nn,
					const struct net *net, u32 secid)
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

/**
 * nfsd_ffv2_prototype_op_admit - admit one mapped operation against the gate
 * @nn: the namespace the mapping resolved in
 * @counted: set when a gate reference was taken and must be released
 *
 * A namespace whose authority came from a metadata server has no gate to
 * pass, and is admitted without counting anything.  A namespace whose
 * authority came from this profile is admitted only once the registration
 * has published everything an operation needs, which is what READY means:
 * the generation is active from the moment it is published, before its
 * trust entry and provider exist, so the gate's own final transition is
 * what a lookup has to wait for.  The source and the gate state are read
 * together under one lock, so a namespace cannot appear to have neither.
 *
 * Return: 0 when the operation may proceed, or -ESTALE when this
 * namespace's gate is not, or is no longer, serving.
 */
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

/* Release the reference nfsd_ffv2_prototype_op_admit() took. */
void nfsd_ffv2_prototype_op_release(struct nfsd_net *nn)
{
	nfsd_ffv2_prototype_user_put(nn);
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

/*
 * Take one record out of the table.
 *
 * Every removal happens here and every removal holds the gate lock, so a
 * record still in the table is a record nothing else is in the middle of
 * freeing.  A record a registration is using is left alone: it is about to
 * be committed, and the registration is still reading it.
 *
 * The caller frees what it took out, after it has dropped the lock.
 */
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

/* Free what a removal took out of the table.  No lock is held here. */
static void nfsd_ffv2_prototype_nonce_free(struct list_head *dead)
{
	struct nfsd_ffv2_prototype_nonce *record, *tmp;

	list_for_each_entry_safe(record, tmp, dead, dead) {
		list_del(&record->dead);
		kfree_sensitive(record);
	}
}

/*
 * Drop challenges nobody came back for, so one gate cannot fill up.
 *
 * The whole walk runs under the gate lock.  The iterator hands back a raw
 * pointer, and every field this has to read to judge a record -- its state,
 * its deadline, whether a registration holds it -- is a field another
 * caller may be changing; reading any of them outside the lock would be
 * reading storage a concurrent challenge is entitled to have freed.
 */
static void nfsd_ffv2_prototype_nonce_reap(struct nfsd_net *nn,
					   struct nfsd_ffv2_prototype_ctx *ctx)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype_nonce *record;
	u64 now = ktime_get_ns();
	unsigned long index;
	LIST_HEAD(dead);

	spin_lock(&anchor->prototype_gate_lock);
	xa_for_each(&ctx->nonces, index, record) {
		if (record->state != NFSD_FFV2_NONCE_ISSUED ||
		    now <= record->expires)
			continue;
		nfsd_ffv2_prototype_nonce_take_locked(anchor, ctx, index,
						      record, &dead);
	}
	spin_unlock(&anchor->prototype_gate_lock);
	nfsd_ffv2_prototype_nonce_free(&dead);
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
				 const u8 *value, bool claim,
				 struct nfsd_ffv2_prototype_nonce **result)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype_nonce *record;
	bool has_secid = secid != 0;
	unsigned long index;
	LIST_HEAD(dead);
	u64 carried;
	int error;

	/*
	 * The index is carried as eight bytes and used as a table index, so
	 * a value a table index cannot hold names nothing.
	 */
	carried = get_unaligned_be64(value);
	if (carried > (u64)ULONG_MAX)
		return -ENOENT;
	index = carried;

	/*
	 * The whole decision is one step under the gate lock, so a record
	 * this returns cannot be reaped between being found and being
	 * claimed by the caller that is about to use it.
	 */
	spin_lock(&anchor->prototype_gate_lock);
	record = xa_load(&ctx->nonces, index);
	if (!record ||
	    crypto_memneq(record->value, value,
			  NFSD_FFV2_PROTOTYPE_NONCE_LEN)) {
		error = -ENOENT;
	} else if (record->net != net ||
		   record->userns != current_user_ns() ||
		   !uid_eq(record->uid, current_uid()) ||
		   record->secid_valid != has_secid ||
		   (record->secid_valid && record->secid != secid)) {
		error = -EPERM;
	} else if (record->busy) {
		error = -EBUSY;
	} else if (record->state == NFSD_FFV2_NONCE_ISSUED &&
		   ktime_get_ns() > record->expires) {
		/*
		 * An expired challenge is gone, not merely refused: leaving
		 * it would let the same nonce report -ETIMEDOUT forever
		 * while occupying one of the gate's few slots.
		 */
		nfsd_ffv2_prototype_nonce_take_locked(anchor, ctx, index,
						      record, &dead);
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

/* Give back a record a registration claimed. */
static void
nfsd_ffv2_prototype_nonce_release(struct nfsd_net *nn,
				  struct nfsd_ffv2_prototype_nonce *record)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	spin_lock(&anchor->prototype_gate_lock);
	record->busy = false;
	spin_unlock(&anchor->prototype_gate_lock);
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
/*
 * Substitute the two things a KUnit build cannot produce: the resolution
 * of an ordinary filehandle, which goes through the exporting
 * filesystem's export operations, and the object's bytes, which come from
 * a file.  A KUnit root filesystem has no export operations, and the
 * object a fixture publishes is a dentry and an inode with nothing behind
 * it.  Everything on either side of these two steps is the production
 * path; this is the only way to reach it here.
 */
static struct nfsd_ffv2_prototype_test_object *nfsd_ffv2_prototype_test_object;

void nfsd_ffv2_prototype_test_object_put(struct nfsd_ffv2_prototype_test_object *obj)
{
	if (!obj || !refcount_dec_and_test(&obj->ref))
		return;
	if (obj->dentry)
		dput(obj->dentry);
	if (obj->dentry2)
		dput(obj->dentry2);
	if (obj->exp)
		exp_put(obj->exp);
	if (obj->store)
		nfsd_ffv2_store_test_close(obj->store);
	kfree(obj);
}

int nfsd_ffv2_prototype_test_object_store(
	struct nfsd_ffv2_prototype_test_object *obj,
	struct nfsd_ffv2_store *store)
{
	if (!obj || !store)
		return -EINVAL;
	if (cmpxchg(&obj->store, NULL, store))
		return -EBUSY;
	return 0;
}

int nfsd_ffv2_prototype_test_object_member(
	struct nfsd_ffv2_prototype_test_object *obj, u32 index,
	const u8 *request_handle, u16 request_handle_len,
	struct dentry *dentry, const u8 *inner, u16 inner_len)
{
	if (!obj || index > 1 || !request_handle || !request_handle_len ||
	    request_handle_len > NFS4_FHSIZE || !dentry || !inner ||
	    inner_len > NFS4_FHSIZE)
		return -EINVAL;
	memcpy(obj->request_handle[index], request_handle, request_handle_len);
	obj->request_handle_len[index] = request_handle_len;
	if (!index)
		return 0;
	if (obj->dentry2)
		dput(obj->dentry2);
	obj->dentry2 = dget(dentry);
	memcpy(obj->inner2, inner, inner_len);
	obj->inner2_len = inner_len;
	return 0;
}

void nfsd_ffv2_prototype_test_fail_second_trust(
	struct nfsd_ffv2_prototype_test_object *obj)
{
	if (obj)
		obj->fail_second_trust = true;
}

static bool nfsd_ffv2_prototype_test_second_trust_fails(u32 index)
{
	struct nfsd_ffv2_prototype_test_object *obj;
	bool fail = false;

	obj = nfsd_ffv2_prototype_test_object_acquire();
	if (obj && index == 1)
		fail = xchg(&obj->fail_second_trust, false);
	nfsd_ffv2_prototype_test_object_put(obj);
	return fail;
}

static struct nfsd_ffv2_store *
nfsd_ffv2_prototype_test_store_take(void)
{
	struct nfsd_ffv2_prototype_test_object *obj;
	struct nfsd_ffv2_store *store = NULL;

	obj = nfsd_ffv2_prototype_test_object_acquire();
	if (obj)
		store = xchg(&obj->store, NULL);
	nfsd_ffv2_prototype_test_object_put(obj);
	return store;
}

/*
 * Substitute the object, and hand the arming back with a reference of the
 * caller's own.
 *
 * @len is what the substituted object can supply and @sampled is what its
 * size looks like when it is measured; passing a @sampled larger than @len
 * is how a test reproduces a file that shrank between the two, which is
 * the one case a real read can hit and this environment otherwise cannot.
 * Zero means the two agree.  @claim asks the substituted resolve to take
 * the ordinary export access fh_verify_local() would take, which is off by
 * default because most fixtures have no use for it.
 *
 * The arming is immutable and carries everything a consumer reads: copies
 * of the handle and of the bytes, and references of its own on the export
 * and the dentry.  So a consumer that has taken a reference on it is
 * reading one fixture's object and not a mixture of two, and is reading
 * storage that cannot go while it holds that reference -- including when
 * the test that armed it has been over for some time.
 */
struct nfsd_ffv2_prototype_test_object *
nfsd_ffv2_prototype_test_object_arm(struct svc_export *exp,
				    struct dentry *dentry,
				    const u8 *inner, u16 inner_len,
				    const void *bytes, size_t len,
				    size_t sampled, bool claim)
{
	struct nfsd_ffv2_prototype_test_object *obj, *old;

	if (inner_len > sizeof(obj->inner))
		return NULL;
	obj = kzalloc(struct_size(obj, bytes, len), GFP_KERNEL);
	if (!obj)
		return NULL;
	/* One for the caller and one for the slot. */
	refcount_set(&obj->ref, 2);
	obj->exp = exp ? exp_get(exp) : NULL;
	obj->dentry = dentry ? dget(dentry) : NULL;
	if (inner_len)
		memcpy(obj->inner, inner, inner_len);
	obj->inner_len = inner_len;
	if (len)
		memcpy(obj->bytes, bytes, len);
	obj->len = len;
	obj->sampled = sampled ?: len;
	obj->claim = claim;

	spin_lock(&nfsd_ffv2_prototype_test_hook_lock);
	old = nfsd_ffv2_prototype_test_object;
	nfsd_ffv2_prototype_test_object = obj;
	spin_unlock(&nfsd_ffv2_prototype_test_hook_lock);
	nfsd_ffv2_prototype_test_object_put(old);
	return obj;
}

/*
 * Take @obj out of the slot, and only if it is still what the slot holds.
 * Comparison and store are one critical section, so an arming that
 * replaced it is not the one taken out.
 */
bool nfsd_ffv2_prototype_test_object_disarm(struct nfsd_ffv2_prototype_test_object *obj)
{
	bool taken = false;

	if (!obj)
		return false;
	spin_lock(&nfsd_ffv2_prototype_test_hook_lock);
	if (nfsd_ffv2_prototype_test_object == obj) {
		nfsd_ffv2_prototype_test_object = NULL;
		taken = true;
	}
	spin_unlock(&nfsd_ffv2_prototype_test_hook_lock);
	if (taken)
		nfsd_ffv2_prototype_test_object_put(obj);
	return taken;
}

/*
 * The arming in force, with a reference of the caller's own, or NULL.
 * This is how every consumer starts: what it reads afterwards is that
 * arming's and stays readable until it puts the reference back.
 */
struct nfsd_ffv2_prototype_test_object *
nfsd_ffv2_prototype_test_object_acquire(void)
{
	struct nfsd_ffv2_prototype_test_object *obj;

	spin_lock(&nfsd_ffv2_prototype_test_hook_lock);
	obj = nfsd_ffv2_prototype_test_object;
	if (obj)
		refcount_inc(&obj->ref);
	spin_unlock(&nfsd_ffv2_prototype_test_hook_lock);
	return obj;
}

/* Whether any arming of the object is in force. */
bool nfsd_ffv2_prototype_test_object_armed(void)
{
	struct nfsd_ffv2_prototype_test_object *obj;

	obj = nfsd_ffv2_prototype_test_object_acquire();
	nfsd_ffv2_prototype_test_object_put(obj);
	return obj;
}

/* Whether a test has substituted the object; see the arming above. */
static bool nfsd_ffv2_prototype_test_armed(void)
{
	return nfsd_ffv2_prototype_test_object_armed();
}

static bool nfsd_ffv2_prototype_test_resolve(struct svc_fh *fhp,
					      const u8 *handle, u32 handle_len)
{
	struct nfsd_ffv2_prototype_test_object *obj;
	struct dentry *dentry;
	const u8 *inner;
	u16 inner_len;
	u32 index = 0;

	obj = nfsd_ffv2_prototype_test_object_acquire();
	if (!obj)
		return false;
	/*
	 * An arming with no export resolves nothing: a test that is asking
	 * about the arming protocol itself has no fixture behind it, and
	 * substituting one would hand back a handle with no export.
	 */
	if (!obj->exp) {
		nfsd_ffv2_prototype_test_object_put(obj);
		return false;
	}
	if (obj->request_handle_len[0]) {
		for (index = 0; index < ARRAY_SIZE(obj->request_handle_len); index++)
			if (obj->request_handle_len[index] == handle_len &&
			    !memcmp(obj->request_handle[index], handle, handle_len))
				break;
		if (index == ARRAY_SIZE(obj->request_handle_len) ||
		    (index && !obj->dentry2)) {
			nfsd_ffv2_prototype_test_object_put(obj);
			return false;
		}
	}
	dentry = index ? obj->dentry2 : obj->dentry;
	inner = index ? obj->inner2 : obj->inner;
	inner_len = index ? obj->inner2_len : obj->inner_len;
	fh_init(fhp, NFS4_FHSIZE);
	fhp->fh_export = exp_get(obj->exp);
	fhp->fh_dentry = dget(dentry);
	fhp->fh_handle.fh_size = inner_len;
	memcpy(fhp->fh_handle.fh_raw, inner, inner_len);
	if (obj->claim) {
		if (nfsd_ffv2_export_access_get(obj->exp)) {
			fh_put(fhp);
			nfsd_ffv2_prototype_test_object_put(obj);
			return false;
		}
		fhp->fh_ffv2_admitted = true;
	}
	nfsd_ffv2_prototype_test_object_put(obj);
	return true;
}
#else
static inline bool nfsd_ffv2_prototype_test_armed(void)
{
	return false;
}

static inline bool nfsd_ffv2_prototype_test_resolve(struct svc_fh *fhp,
					     const u8 *handle, u32 handle_len)
{
	return false;
}

static inline bool nfsd_ffv2_prototype_test_second_trust_fails(u32 index)
{
	return false;
}
#endif

/*
 * The provider this profile installs.
 *
 * A result borrows provider storage until the caller's execution admission
 * completes, and callbacks run concurrently on one provider, so that
 * storage has to be immutable and never reused for another operation.  The
 * simplest thing that is both is a snapshot: the registered object is read
 * once, here, and every reply is served from those bytes.
 *
 * That immutable snapshot remains the fallback for the original KUnit
 * provider.  A file-backed registration instead reads visible payloads from
 * its store and implements the bounded ordinary write lifecycle, using
 * per-operation result storage held until the admission is released.
 */
struct nfsd_ffv2_prototype_member {
	u8			object_uuid[16];
	u8			store_handle[32];
	u32			admission_id;
	u8			stateid[NFS4_STATEID_SIZE];
	struct nfsd_ffv2_store_file file;
};

struct nfsd_ffv2_prototype_provider {
	u32				chunk_size;
	u32				chunks;
	u32				count;
	struct nfsd_ffv2_store		*store;
	struct nfsd_ffv2_prototype_member members[NFSD_FFV2_MAX_OBJECTS];
	int (*visible)(void *store, const u8 file_key[32], u64 chunk_index,
		       struct nfsd_ffv2_visible_chunk *chunk);
	int (*read_payload)(void *store, void *data, size_t len, loff_t offset);
	void				*reader;
	bool				fail_alloc;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	bool				test_store;
#endif
	u8				*bytes;
	struct nfsd_ffv2_read_chunk	*read;
	__be32				*status;
	u32				*locked;
	struct nfsd_ffv2_chunk_owner	*owners;
	struct nfsd_ffv2_chunk_guard	*guards;
	struct nfsd_ffv2_retained	*predecessors;
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

static void
nfsd_ffv2_prototype_provider_free(struct nfsd_ffv2_prototype_provider *provider)
{
	if (!provider)
		return;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (provider->test_store)
		nfsd_ffv2_store_test_close(provider->store);
	else
#endif
		nfsd_ffv2_store_close(provider->store);
	kvfree(provider->bytes);
	kvfree(provider->read);
	kvfree(provider->status);
	kvfree(provider->locked);
	kvfree(provider->owners);
	kvfree(provider->guards);
	kvfree(provider->predecessors);
	kfree(provider);
}

/* Chunks this provider still holds from @offset, and whether that is all. */
static u32 nfsd_ffv2_prototype_range(const struct nfsd_ffv2_prototype_provider *p,
				     const struct nfsd_ffv2_chunk_request *req,
				     bool *eof)
{
	u32 available;

	if (req->offset >= p->chunks) {
		*eof = true;
		return 0;
	}
	available = p->chunks - (u32)req->offset;
	if (req->count >= available) {
		*eof = true;
		return available;
	}
	*eof = false;
	return req->count;
}

static __be32
nfsd_ffv2_prototype_chunk_read(void *opaque,
			       const struct nfsd_ffv2_object *object,
			       const struct nfsd_ffv2_chunk_request *req,
			       struct nfsd_ffv2_chunk_result *result)
{
	struct nfsd_ffv2_prototype_provider *provider = opaque;

	if (provider->visible)
		return nfserr_notsupp;

	result->count = nfsd_ffv2_prototype_range(provider, req, &result->eof);
	if (result->count)
		result->read.chunks = &provider->read[req->offset];
	return nfs_ok;
}

struct nfsd_ffv2_store_read_result {
	struct nfsd_ffv2_read_chunk	*chunks;
	u8				*bytes;
};

static void nfsd_ffv2_store_read_result_free(void *private)
{
	struct nfsd_ffv2_store_read_result *result = private;

	if (!result)
		return;
	kvfree(result->bytes);
	kvfree(result->chunks);
	kfree(result);
}

static int nfsd_ffv2_prototype_store_visible(void *store,
					     const u8 file_key[32], u64 chunk_index,
	struct nfsd_ffv2_visible_chunk *chunk)
{
	return nfsd_ffv2_store_visible_chunk(store, file_key, chunk_index,
					     chunk);
}

static int nfsd_ffv2_prototype_store_read_payload(void *store, void *data,
						  size_t len, loff_t offset)
{
	return nfsd_ffv2_store_read_payload(store, data, len, offset);
}

static bool
nfsd_ffv2_prototype_checksum_valid(const struct nfsd_ffv2_visible_chunk *chunk,
				   const u8 *data, u32 len)
{
	return nfsd_ffv2_store_checksum_valid(chunk->checksum_algorithm,
					      chunk->checksum,
					      chunk->checksum_len,
					      data, len);
}

static __be32
nfsd_ffv2_prototype_store_chunk_read(void *opaque,
				     const struct nfsd_ffv2_object *object,
				     const struct nfsd_ffv2_chunk_request *req,
				     struct nfsd_ffv2_chunk_result *result)
{
	struct nfsd_ffv2_prototype_provider *provider = opaque;
	struct nfsd_ffv2_prototype_member *member;
	struct nfsd_ffv2_store_read_result *owned;
	u64 file_chunks, last_len, end;
	u32 count, i;
	size_t bytes;

	if (!provider->visible)
		return nfsd_ffv2_prototype_chunk_read(opaque, object, req, result);
	member = nfsd_ffv2_prototype_member(provider, object);
	if (!member)
		return nfserr_serverfault;
	file_chunks = DIV_ROUND_UP_ULL(member->file.logical_eof,
				       member->file.chunk_bytes);
	if (req->offset >= file_chunks) {
		result->eof = true;
		return nfs_ok;
	}
	count = min_t(u64, req->count, file_chunks - req->offset);
	result->eof = count < req->count || req->offset + count == file_chunks;
	if (!count)
		return nfs_ok;
	if (check_mul_overflow((size_t)count,
			       (size_t)member->file.chunk_bytes, &bytes))
		return nfserr_serverfault;
	owned = provider->fail_alloc ? NULL : kzalloc_obj(*owned, GFP_KERNEL);
	if (!owned)
		return nfserr_jukebox;
	owned->chunks = kvcalloc(count, sizeof(*owned->chunks), GFP_KERNEL);
	owned->bytes = kvzalloc(bytes, GFP_KERNEL);
	if (!owned->chunks || !owned->bytes) {
		nfsd_ffv2_store_read_result_free(owned);
		return nfserr_jukebox;
	}

	for (i = 0; i < count; i++) {
		struct nfsd_ffv2_visible_chunk visible;
		struct nfsd_ffv2_read_chunk *chunk = &owned->chunks[i];
		u8 *data =
			owned->bytes + (size_t)i * member->file.chunk_bytes;
		u64 index = req->offset + i, payload_offset;
		u32 crc, len = member->file.chunk_bytes;
		bool checksum_valid;
		int error;

		end = (index + 1) * (u64)member->file.chunk_bytes;
		if (end > member->file.logical_eof) {
			last_len = member->file.logical_eof -
				   index * (u64)member->file.chunk_bytes;
			len = last_len;
		}
		error = provider->visible(provider->reader,
				  member->file.file_key, index,
					  &visible);
		if (!error) {
			if (visible.file_eof != member->file.logical_eof ||
			    visible.content_len != len ||
			    !visible.payload_object_id ||
			    visible.guard_never_written) {
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
			error = provider->read_payload(provider->reader, data,
						       len, payload_offset);
			if (error) {
				nfsd_ffv2_store_read_result_free(owned);
				return error == -ENOMEM ? nfserr_jukebox :
							  nfserr_io;
			}
			checksum_valid =
				nfsd_ffv2_prototype_checksum_valid(&visible, data, len);
			if (!checksum_valid ||
			    visible.content_crc32c !=
						(~crc32c(~0U, data, len))) {
				nfsd_ffv2_store_read_result_free(owned);
				return nfserr_io;
			}
			chunk->cr_owner.co_cohort_id = visible.owner_cohort;
			chunk->cr_owner.co_client_id = visible.owner_client_id;
			chunk->cr_owner.co_id = visible.owner_co_id;
			chunk->cr_guard.cg_gen_id = visible.guard_generation;
			chunk->cr_guard.cg_client_id = visible.guard_writer;
			chunk->cr_payload_id = visible.writer_payload_id;
		} else if (error != -ENOENT) {
			nfsd_ffv2_store_read_result_free(owned);
			return error == -ENOMEM ? nfserr_jukebox : nfserr_io;
		}
		crc = crc32_le(~0U, data, len) ^ ~0U;
		chunk->cr_checksum.cs_algorithm = NFSD_FFV2_CHECKSUM_ALG_CRC32;
		chunk->cr_checksum.cs_len = NFSD_FFV2_CHECKSUM_CRC32_LEN;
		put_unaligned_be32(crc, chunk->cr_checksum.cs_value);
		chunk->cr_effective_len = len;
		chunk->cr_status = error == -ENOENT ? nfserr_noent : nfs_ok;
		chunk->cr_chunk = data;
	}
	result->count = count;
	result->read.chunks = owned->chunks;
	result->private = owned;
	result->release = nfsd_ffv2_store_read_result_free;
	return nfs_ok;
}

static __be32
nfsd_ffv2_prototype_chunk_header_read(void *opaque,
				      const struct nfsd_ffv2_object *object,
				      const struct nfsd_ffv2_chunk_request *req,
				      struct nfsd_ffv2_chunk_result *result)
{
	struct nfsd_ffv2_prototype_provider *provider = opaque;
	u32 first;

	if (provider->visible)
		return nfserr_notsupp;

	result->count = nfsd_ffv2_prototype_range(provider, req, &result->eof);
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

static __be32 nfsd_ffv2_prototype_mutation_status(int error)
{
	switch (error) {
	case 0:
		return nfs_ok;
	case -EAGAIN:
		return nfserr_chunk_guarded;
	case -ENOSPC:
		return nfserr_nospc;
	case -ENOMEM:
		return nfserr_jukebox;
	case -EEXIST:
		return nfserr_seq_false_retry;
	case -ESTALE:
		return nfserr_stale_stateid;
	case -EIO:
	case -EBADMSG:
		return nfserr_io;
	default:
		return nfserr_inval;
	}
}

static int
nfsd_ffv2_prototype_mutation_begin(struct nfsd_ffv2_prototype_provider *provider,
				   const struct nfsd_ffv2_chunk_owner *owner,
				   struct nfsd_ffv2_mutation_result *result)
{
	struct nfsd_ffv2_super_record super;
	int error;

	if (!provider->store)
		return -EOPNOTSUPP;
	error = nfsd_ffv2_store_get_super(provider->store, &super);
	if (error)
		return error;
	result->count = 1;
	result->owner = *owner;
	memcpy(result->verifier, super.write_verifier,
	       sizeof(result->verifier));
	return 0;
}

static void
nfsd_ffv2_prototype_operation(const struct nfsd_ffv2_mutation_operation *source,
			      struct nfsd_ffv2_store_operation *target)
{
	memcpy(target->session, source->session, sizeof(target->session));
	target->slot = source->slot;
	target->sequence = source->sequence;
	target->ordinal = source->ordinal;
	memcpy(target->request_digest, source->request_digest,
	       sizeof(target->request_digest));
}

static void
nfsd_ffv2_prototype_result(const struct nfsd_ffv2_store_mutation_result *source,
			   struct nfsd_ffv2_mutation_result *target)
{
	target->count = 1;
	target->stability = source->stability;
	target->activated = source->activated;
	memcpy(target->verifier, source->verifier, sizeof(target->verifier));
	target->owner.co_cohort_id = source->owner.cohort;
	target->owner.co_client_id = source->owner.client_id;
	target->owner.co_id = source->owner.co_id;
	target->status = nfsd_ffv2_prototype_mutation_status(source->status == 1 ?
							       0 : -EINVAL);
}

static __be32
nfsd_ffv2_prototype_chunk_write(void *opaque,
				const struct nfsd_ffv2_object *object,
				const struct nfsd_ffv2_write_request *request,
				struct nfsd_ffv2_mutation_result *result)
{
	struct nfsd_ffv2_prototype_provider *provider = opaque;
	struct nfsd_ffv2_prototype_member *member;
	struct nfsd_ffv2_store_mutation_result stored = {};
	struct nfsd_ffv2_store_write write = {};
	int error;

	error = nfsd_ffv2_prototype_mutation_begin(provider,
						   &request->owner,
						   result);
	if (error)
		return error == -EOPNOTSUPP ? nfserr_notsupp : nfserr_io;
	member = nfsd_ffv2_prototype_member(provider, object);
	if (!member) {
		result->status = nfserr_serverfault;
		return nfs_ok;
	}
	if (request->chunk_size != member->file.chunk_bytes) {
		result->status = nfserr_inval;
		return nfs_ok;
	}
	nfsd_ffv2_prototype_operation(&request->operation, &write.operation);
	write.admission_id = member->admission_id;
	write.chunk_index = request->chunk_index;
	write.stability = request->stability;
	write.owner_cohort = request->owner.co_cohort_id;
	write.owner_client_id = request->owner.co_client_id;
	write.owner_co_id = request->owner.co_id;
	write.writer_payload_id = request->payload_id;
	write.guard_check = request->guard_check;
	write.guard_never_written = request->guard_never_written;
	write.guard_generation = request->guard_generation;
	write.guard_writer = request->guard_writer;
	write.activate_if_empty = request->activate_if_empty;
	write.checksum_algorithm = request->checksum.cs_algorithm;
	write.checksum_len = request->checksum.cs_len;
	memcpy(write.checksum, request->checksum.cs_value,
	       sizeof(write.checksum));
	write.content = request->payload;
	write.content_len = request->payload_len;
	error = nfsd_ffv2_store_write(provider->store, member->file.file_key,
				      &write, &stored);
	if (error) {
		result->status = nfsd_ffv2_prototype_mutation_status(error);
		return nfs_ok;
	}
	nfsd_ffv2_prototype_result(&stored, result);
	result->bytes = request->payload_len;
	return nfs_ok;
}

static __be32
nfsd_ffv2_prototype_lifecycle(void *opaque,
			      const struct nfsd_ffv2_object *object,
			      const struct nfsd_ffv2_lifecycle_request *request,
			      struct nfsd_ffv2_mutation_result *result,
			      bool commit)
{
	struct nfsd_ffv2_prototype_provider *provider = opaque;
	struct nfsd_ffv2_prototype_member *member;
	struct nfsd_ffv2_store_mutation_result stored = {};
	struct nfsd_ffv2_store_lifecycle lifecycle = {};
	int error;

	error = nfsd_ffv2_prototype_mutation_begin(provider,
						   &request->owner,
						   result);
	if (error)
		return error == -EOPNOTSUPP ? nfserr_notsupp : nfserr_io;
	member = nfsd_ffv2_prototype_member(provider, object);
	if (!member) {
		result->status = nfserr_serverfault;
		return nfs_ok;
	}
	nfsd_ffv2_prototype_operation(&request->operation,
				      &lifecycle.operation);
	lifecycle.admission_id = member->admission_id;
	lifecycle.chunk_index = request->chunk_index;
	lifecycle.owner_cohort = request->owner.co_cohort_id;
	lifecycle.owner_client_id = request->owner.co_client_id;
	lifecycle.owner_co_id = request->owner.co_id;
	if (commit)
		error = nfsd_ffv2_store_commit(provider->store,
					       member->file.file_key,
					       &lifecycle, &stored);
	else
		error = nfsd_ffv2_store_finalize(provider->store,
						 member->file.file_key,
						 &lifecycle, &stored);
	if (error) {
		result->status = nfsd_ffv2_prototype_mutation_status(error);
		return nfs_ok;
	}
	nfsd_ffv2_prototype_result(&stored, result);
	return nfs_ok;
}

static __be32
nfsd_ffv2_prototype_chunk_finalize(void *opaque,
				   const struct nfsd_ffv2_object *object,
				   const struct nfsd_ffv2_lifecycle_request *request,
				   struct nfsd_ffv2_mutation_result *result)
{
	return nfsd_ffv2_prototype_lifecycle(opaque, object, request, result,
					     false);
}

static __be32
nfsd_ffv2_prototype_chunk_commit(void *opaque,
				 const struct nfsd_ffv2_object *object,
				 const struct nfsd_ffv2_lifecycle_request *request,
				 struct nfsd_ffv2_mutation_result *result)
{
	return nfsd_ffv2_prototype_lifecycle(opaque, object, request, result,
					     true);
}

static const struct nfsd_ffv2_provider_ops nfsd_ffv2_prototype_provider_ops = {
	.chunk_read		= nfsd_ffv2_prototype_store_chunk_read,
	.chunk_header_read	= nfsd_ffv2_prototype_chunk_header_read,
	.chunk_write		= nfsd_ffv2_prototype_chunk_write,
	.chunk_finalize		= nfsd_ffv2_prototype_chunk_finalize,
	.chunk_commit		= nfsd_ffv2_prototype_chunk_commit,
};

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
/*
 * Read the registered object and derive everything a reply needs from it.
 *
 * The checksum is the zlib CRC32 of the chunk's own bytes,
 * crc32_le(~0, data, len) ^ ~0, which is what the Flex Files v2 client
 * computes.  It covers the payload only; the chunk header is not folded
 * in, and no consumer of this profile verifies one yet.
 */
static int
nfsd_ffv2_prototype_snapshot_build(struct path *path, const struct cred *cred,
				   u32 chunk_size, u32 data_count,
				   u64 generation,
				   struct nfsd_ffv2_prototype_provider **result)
{
	struct nfsd_ffv2_prototype_provider *provider;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	struct nfsd_ffv2_prototype_test_object *obj;
#endif
	struct file *file;
	loff_t pos = 0;
	size_t total;
	u32 chunks;
	u64 want;
	u64 size;
	int error;
	int got;
	u32 i;

	file = NULL;
	size = 0;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	/*
	 * Taken once and held to the end: the substituted object's measured
	 * size and its bytes are read at two points, and a reference across
	 * both is what makes them the same object's -- and keeps the storage
	 * they are in from going in between.
	 */
	obj = nfsd_ffv2_prototype_test_object_acquire();
	if (obj && obj->exp && obj->len)
		size = obj->sampled;
#endif
	if (!size) {
		file = dentry_open(path, O_RDONLY | O_LARGEFILE, cred);
		if (IS_ERR(file)) {
			error = PTR_ERR(file);
			file = NULL;
			goto out_close;
		}
		size = i_size_read(file_inode(file));
	}
	/*
	 * A layout says how many chunks the object has; the file says how
	 * many it can fill.  Serving the smaller of the two keeps the reply
	 * describing bytes that exist.
	 */
	chunks = min_t(u64, data_count, DIV_ROUND_UP_ULL(size, chunk_size));
	if (!chunks) {
		error = -EINVAL;
		goto out_close;
	}
	total = (size_t)chunks * chunk_size;

	provider = kzalloc_obj(*provider, GFP_KERNEL);
	if (!provider) {
		error = -ENOMEM;
		goto out_close;
	}
	provider->chunk_size = chunk_size;
	provider->chunks = chunks;
	provider->bytes = kvzalloc(total, GFP_KERNEL);
	provider->read = kvcalloc(chunks, sizeof(*provider->read), GFP_KERNEL);
	provider->status = kvcalloc(chunks, sizeof(*provider->status),
				    GFP_KERNEL);
	provider->locked = kvcalloc(chunks, sizeof(*provider->locked),
				    GFP_KERNEL);
	provider->owners = kvcalloc(chunks, sizeof(*provider->owners),
				    GFP_KERNEL);
	provider->guards = kvcalloc(chunks, sizeof(*provider->guards),
				    GFP_KERNEL);
	provider->predecessors = kvcalloc(chunks,
					  sizeof(*provider->predecessors),
					  GFP_KERNEL);
	if (!provider->bytes || !provider->read || !provider->status ||
	    !provider->locked || !provider->owners || !provider->guards ||
	    !provider->predecessors) {
		error = -ENOMEM;
		goto out_free;
	}

	/*
	 * Every byte the layout describes has to be read.  The request is
	 * for whole chunks and the file may end inside the last one, so what
	 * is owed is the smaller of the two; less than that means the file
	 * shrank after it was measured, and the zeroed remainder of the
	 * buffer is not data the object ever held.  Reporting it as though
	 * it were would hand a client fabricated bytes under a checksum this
	 * server computed over them.
	 */
	want = min_t(u64, total, size);
	if (file) {
		got = kernel_read(file, provider->bytes, total, &pos);
	} else {
		got = -EIO;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
		/* The same arming the size came from, still referenced. */
		got = min_t(size_t, total, obj->len);
		memcpy(provider->bytes, obj->bytes, got);
#endif
	}
	if (got < 0) {
		error = got;
		goto out_free;
	}
	if ((u64)got < want) {
		error = -EIO;
		goto out_free;
	}
	/*
	 * More than that is an object that grew after it was measured, which
	 * is not an error and not this snapshot's business: the layout was
	 * computed from the size that was sampled, and the loop below
	 * describes only that much, so the extra bytes are read into the
	 * buffer and never named by any chunk.
	 */
	/*
	 * The last chunk may be shorter than the rest, which the loop below
	 * reports at its real length; the bytes past it are never described.
	 */
	for (i = 0; i < chunks; i++) {
		u8 *bytes = provider->bytes + (size_t)i * chunk_size;
		u32 len = chunk_size;
		u32 crc;

		if ((u64)(i + 1) * chunk_size > size)
			len = (u32)(size - (u64)i * chunk_size);
		crc = crc32_le(~0U, bytes, len) ^ ~0U;

		provider->read[i].cr_checksum.cs_algorithm =
			NFSD_FFV2_CHECKSUM_ALG_CRC32;
		provider->read[i].cr_checksum.cs_len =
			NFSD_FFV2_CHECKSUM_CRC32_LEN;
		put_unaligned_be32(crc, provider->read[i].cr_checksum.cs_value);
		provider->read[i].cr_effective_len = len;
		provider->read[i].cr_owner.co_cohort_id = generation;
		provider->read[i].cr_owner.co_id = i;
		provider->read[i].cr_guard.cg_gen_id = 1;
		provider->read[i].cr_payload_id = i;
		provider->read[i].cr_status = nfs_ok;
		provider->read[i].cr_chunk = bytes;

		provider->status[i] = nfs_ok;
		provider->owners[i] = provider->read[i].cr_owner;
		provider->guards[i] = provider->read[i].cr_guard;
		provider->predecessors[i].disposition = NFSD_FFV2_RETAINED_ABSENT;
	}
	*result = provider;
	error = 0;
	goto out_close;

out_free:
	nfsd_ffv2_prototype_provider_free(provider);
out_close:
	if (file)
		fput(file);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	nfsd_ffv2_prototype_test_object_put(obj);
#endif
	return error;
}
#endif

static bool nfsd_ffv2_prototype_file_geometry_valid(u64 max_chunks,
						    u32 chunk_bytes,
						    u64 logical_eof)
{
	u64 capacity;

	return max_chunks && max_chunks <= 64 &&
	       !check_mul_overflow(max_chunks, (u64)chunk_bytes, &capacity) &&
	       capacity && capacity <= NFSD_FFV2_MAX_PAYLOAD_BYTES &&
	       logical_eof <= capacity;
}

static int nfsd_ffv2_prototype_store_vector_validate(
	const struct nfsd_ffv2_store_file *const *files, u32 count,
	u32 chunk_size)
{
	u64 max_chunks = 0;
	u32 i, j;

	for (i = 0; i < count; i++) {
		if (!nfsd_ffv2_prototype_file_geometry_valid(
			    files[i]->max_chunks, files[i]->chunk_bytes,
			    files[i]->logical_eof) ||
		    files[i]->chunk_bytes != chunk_size ||
		    (max_chunks && files[i]->max_chunks != max_chunks))
			return -EINVAL;
		for (j = 0; j < i; j++)
			if (!memcmp(files[i]->file_key, files[j]->file_key,
				    sizeof(files[i]->file_key)))
				return -EEXIST;
		max_chunks = files[i]->max_chunks;
	}
	return count ? 0 : -EINVAL;
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
bool nfsd_ffv2_prototype_test_geometry_valid(u64 max_chunks, u32 chunk_bytes,
					     u64 logical_eof)
{
	return nfsd_ffv2_prototype_file_geometry_valid(max_chunks, chunk_bytes,
						       logical_eof);
}

bool nfsd_ffv2_prototype_test_store_vector_valid(
	const struct nfsd_ffv2_store_file *files, u32 count, u32 chunk_size)
{
	const struct nfsd_ffv2_store_file *members[NFSD_FFV2_MAX_OBJECTS];
	u32 i;

	if (!count || count > ARRAY_SIZE(members))
		return false;
	for (i = 0; i < count; i++)
		members[i] = &files[i];
	return !nfsd_ffv2_prototype_store_vector_validate(members, count,
							  chunk_size);
}
#endif

static int
nfsd_ffv2_prototype_provider_build(struct nfsd_net *nn, struct path *path,
				   const struct cred *cred,
				   const u8 object_uuids[][16],
				   const u8 persisted_handles[][32], u32 count,
				   u32 chunk_size, u32 data_count, u64 generation,
				   struct nfsd_ffv2_prototype_provider **result)
{
	struct nfsd_ffv2_prototype_provider *provider;
	struct nfsd_ffv2_prototype_member *member;
	const struct nfsd_ffv2_store_file *files[NFSD_FFV2_MAX_OBJECTS];
	u32 i;
	int error;

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (nfsd_ffv2_prototype_test_armed()) {
		struct nfsd_ffv2_store *store;

		store = nfsd_ffv2_prototype_test_store_take();
		if (!store) {
			if (count != 1)
				return -EOPNOTSUPP;
			return nfsd_ffv2_prototype_snapshot_build(
				path, cred, chunk_size, data_count, generation,
				result);
		}
		provider = kzalloc_obj(*provider, GFP_KERNEL);
		if (!provider) {
			nfsd_ffv2_store_test_close(store);
			return -ENOMEM;
		}
		provider->count = count;
		provider->store = store;
		provider->test_store = true;
		goto lookup_files;
	}
#endif
	provider = kzalloc_obj(*provider, GFP_KERNEL);
	if (!provider)
		return -ENOMEM;
	provider->count = count;
	error = nfsd_ffv2_store_open_generation(nn, generation,
						&provider->store);
	if (error)
		goto out_free;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
lookup_files:
#endif
	for (i = 0; i < count; i++) {
		member = &provider->members[i];
		memcpy(member->object_uuid, object_uuids[i], 16);
		error = nfsd_ffv2_store_lookup_file(provider->store,
						    persisted_handles[i],
						    &member->file);
		if (error)
			goto out_free;
		files[i] = &member->file;
		memcpy(member->store_handle, persisted_handles[i], 32);
	}
	error = nfsd_ffv2_prototype_store_vector_validate(files, count,
							  chunk_size);
	if (error)
		goto out_free;
	provider->chunk_size = chunk_size;
	provider->chunks = files[0]->max_chunks;
	provider->visible = nfsd_ffv2_prototype_store_visible;
	provider->read_payload = nfsd_ffv2_prototype_store_read_payload;
	provider->reader = provider->store;
	*result = provider;
	return 0;

out_free:
	nfsd_ffv2_prototype_provider_free(provider);
	return error;
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
__be32 nfsd_ffv2_prototype_test_store_read(const struct nfsd_ffv2_store_file *file,
					   const struct nfsd_ffv2_prototype_test_store_ops *ops,
					   void *store, bool fail_alloc,
					   const struct nfsd_ffv2_chunk_request *request,
					   struct nfsd_ffv2_chunk_result *result)
{
	struct nfsd_ffv2_prototype_provider provider = {
		.chunk_size = file->chunk_bytes,
		.chunks = file->max_chunks,
		.count = 1,
		.visible = ops->visible,
		.read_payload = ops->read,
		.reader = store,
		.fail_alloc = fail_alloc,
	};

	provider.members[0].file = *file;

	memset(result, 0, sizeof(*result));
	return nfsd_ffv2_prototype_store_chunk_read(&provider, NULL, request,
						    result);
}

void nfsd_ffv2_prototype_test_result_release(struct nfsd_ffv2_chunk_result *result)
{
	if (result->release)
		result->release(result->private);
	memset(result, 0, sizeof(*result));
}
#endif

/*
 * Remove whatever the one registration published, if it is still owned.
 * Both the unregister and the close owner come through here, and the
 * ownership bits are taken under the gate lock, so exactly one of them
 * removes the provider and exactly one retires the generation.
 */
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

	/*
	 * The provider first: its removal waits for the callbacks and the
	 * result-holding admissions still inside it, which is what makes the
	 * snapshot safe to free.  Retirement then waits for the generation's
	 * own admissions and releases the service context, its object, its
	 * trust registry and its authority.
	 */
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

/* Resolve the ordinary filehandle a registration named. */
static int ffv2_prototype_resolve(const struct net *net,
				  const struct cred *cred,
				  const struct nfsd_ffv2_prototype_request *req,
				  const u8 *handle, u32 handle_len,
				  struct svc_fh *fhp)
{
	struct auth_domain *domain;
	struct svc_cred rq_cred = {};
	__be32 status;
	int error;

	if (nfsd_ffv2_prototype_test_resolve(fhp, handle, handle_len))
		return 0;
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
	status = fh_verify_local((struct net *)net, &rq_cred, domain, fhp,
				 S_IFREG, NFSD_MAY_READ);
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

/* The immutable inputs, as a committed registration records them. */
static void
nfsd_ffv2_prototype_commit_record(struct nfsd_ffv2_prototype_committed *rec,
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
	memcpy(rec->binding_token, req->binding_token,
	       sizeof(rec->binding_token));
	rec->writer_id = req->writer_id;
	rec->pnfs_clientid = req->pnfs_clientid;
	rec->object_count = count;
	for (i = 0; i < count; i++) {
		const u8 *handle = req->object_count ? req->objects[i].handle :
						      req->handle;
		const u8 *persisted = req->object_count ?
					 req->objects[i].persisted_handle :
					 req->persisted_handle;
		u32 handle_len = req->object_count ? req->objects[i].handle_len :
							 req->handle_len;

		memcpy(rec->objects[i].handle, handle, handle_len);
		rec->objects[i].handle_len = handle_len;
		memcpy(rec->objects[i].persisted_handle, persisted, 32);
	}
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
bool nfsd_ffv2_prototype_test_request_equal(
	const struct nfsd_ffv2_prototype_request *left,
	const struct nfsd_ffv2_prototype_request *right)
{
	struct nfsd_ffv2_prototype_committed *records;
	bool equal = false;

	records = kcalloc(2, sizeof(*records), GFP_KERNEL);
	if (!records)
		return false;
	nfsd_ffv2_prototype_commit_record(&records[0], left);
	nfsd_ffv2_prototype_commit_record(&records[1], right);
	equal = !memcmp(&records[0], &records[1], sizeof(*records));
	kfree(records);
	return equal;
}
#endif

/*
 * Install the one trust entry the demonstrator reads through, and mint the
 * stateid that names it.  The stateid is the server's: a caller that could
 * choose it could name an entry another registration installed.
 */
static int nfsd_ffv2_prototype_trust(struct nfsd_net *nn,
				     const u8 object_uuid[16],
				     const struct nfsd_ffv2_prototype_request *request,
				     const u8 raw_stateid[16], stateid_t *stateid)
{
	struct nfsd_ffv2_trust_request req = {};
	__be32 status;

	stateid->si_generation = get_unaligned_be32(raw_stateid);
	memcpy(&stateid->si_opaque, raw_stateid + sizeof(__be32),
	       sizeof(stateid->si_opaque));
	req.stateid = *stateid;
	req.object_uuid = object_uuid;
	req.actor = NFSD_FFV2_CALLER_DATA_CLIENT;
	req.pnfs_clientid.cl_boot =
		be32_to_cpu((__force __be32)upper_32_bits(request->pnfs_clientid));
	req.pnfs_clientid.cl_id =
		be32_to_cpu((__force __be32)lower_32_bits(request->pnfs_clientid));
	req.client_id = request->writer_id;
	req.iomode = IOMODE_RW;
	req.profile_mask = NFSD_FFV2_PROFILE_READ_DATA |
			   NFSD_FFV2_PROFILE_READ_METADATA |
			   NFSD_FFV2_PROFILE_WRITE_DATA |
			   NFSD_FFV2_PROFILE_WRITE_LIFECYCLE;
	ktime_get_real_ts64(&req.expires);
	req.expires.tv_sec += NFSD_FFV2_PROTOTYPE_TRUST_TTL_SEC;
	status = nfsd_ffv2_trust_install_active(nn, NULL, &req);
	return status == nfs_ok ? 0 : -EIO;
}

/**
 * nfsd_ffv2_prototype_register - publish the object set this gate serves
 * @nn: the nfsd namespace
 * @net: the caller's network namespace
 * @req: nonce, client name, ordinary filehandle and layout parameters
 * @bundle: receives everything the demonstrator needs to read
 *
 * The transaction is staged: the nonce, the layout and the filehandle are
 * validated and the object is read before anything is published, and each
 * step that publishes something records that it owns it, so a failure
 * unwinds exactly what it created.  READY is the last step and the only
 * one a mapping can observe -- the generation is active before the trust
 * entry and the provider exist, and no operation may cross that interval.
 *
 * A retry of an identical request returns the original bundle rather than
 * publishing a second time; a retry that changed anything is refused.
 *
 * Return: 0, or a negative errno from the table in the design gate.
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
	struct path path = {};
	u32 object_count, total_count, i;
	u32 secid = 0;
	int error = 0;

	if (!ns_capable(net->user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	/*
	 * The layout is checked before the gate is even entered: a request
	 * that cannot describe an object must not consume a nonce.
	 */
	if (check_add_overflow(req->data_count, req->parity_count,
			       &total_count))
		return -EINVAL;
	object_count = req->object_count ?: 1;
	if (!req->chunk_size || !req->data_count ||
	    !req->store_uuid || !req->binding_token ||
	    !req->writer_id || req->writer_id == U32_MAX ||
	    object_count > NFSD_FFV2_PROTOTYPE_OBJECT_MAX ||
	    (req->object_count && object_count != total_count) ||
	    (req->object_count && !req->parity_count && object_count != 1) ||
	    (!req->object_count && req->parity_count) ||
	    req->chunk_size > NFSD_FFV2_MAX_PAYLOAD_BYTES)
		return -EINVAL;
	for (i = 0; i < object_count; i++) {
		const u8 *handle = req->object_count ? req->objects[i].handle :
						      req->handle;
		const u8 *persisted = req->object_count ?
					 req->objects[i].persisted_handle :
					 req->persisted_handle;
		u32 handle_len = req->object_count ? req->objects[i].handle_len :
							 req->handle_len;

		if (!handle || !handle_len || handle_len > NFS4_FHSIZE ||
		    !persisted)
			return -EINVAL;
	}
	if (strnlen(req->auth_domain, NFSD_FFV2_PROTOTYPE_DOMAIN_MAX + 1) >
	    NFSD_FFV2_PROTOTYPE_DOMAIN_MAX)
		return -EINVAL;
	work = kzalloc_obj(*work, GFP_KERNEL);
	if (!work)
		return -ENOMEM;
	for (i = 0; i < object_count; i++) {
		const u8 *persisted = req->object_count ?
					 req->objects[i].persisted_handle :
					 req->persisted_handle;

		memcpy(work->persisted_handles[i], persisted, 32);
	}

	security_cred_getsecid(current_cred(), &secid);
	/*
	 * A live gate is enough to be let in: whether a fresh registration
	 * is possible depends on the nonce, and is decided once the nonce
	 * has been looked up.  A gate that already published a registration
	 * must still answer a replay of it.
	 */
	error = nfsd_ffv2_prototype_user_get(nn, net, secid);
	if (error)
		goto out_free;
	ctx = nfsd_ffv2_prototype_ctx_of(nn);
	if (WARN_ON_ONCE(!ctx)) {
		error = -EOPNOTSUPP;
		goto out_put;
	}
	error = nfsd_ffv2_prototype_nonce_lookup(nn, ctx, net, secid,
						 req->nonce, true, &nonce);
	if (error)
		goto out_put;
	claimed = true;
	/*
	 * Assigned once, before anything branches on the record's state, so
	 * every path that reads the staged bundle reads the record's own
	 * storage and none can read an unset pointer.
	 */
	staged = &nonce->bundle;
	nfsd_ffv2_prototype_commit_record(&work->record, req);

	/*
	 * One decision, under the lock that publishes the state it reads:
	 * whether this nonce has already been spent, and if it has not,
	 * whether the gate is free to serve a new registration.  The bundle
	 * of a spent nonce is copied here rather than afterwards, because
	 * the record's state and its bundle are one fact and reading them
	 * apart is reading them at two different times.
	 */
	spin_lock(&anchor->prototype_gate_lock);
	if (nonce->state == NFSD_FFV2_NONCE_COMMITTED) {
		/*
		 * The same request again is the same registration: hand back
		 * what it produced.  Anything else wearing this nonce is a
		 * different registration and is refused rather than merged.
		 */
		spent = true;
		if (memcmp(&nonce->committed, &work->record, sizeof(work->record)))
			error = -EEXIST;
		else
			*bundle = *staged;
	} else if (proto->state != NFSD_FFV2_PROTOTYPE_OPEN) {
		/* A gate serves one registration at a time. */
		error = -EBUSY;
	}
	spin_unlock(&anchor->prototype_gate_lock);
	if (spent || error)
		goto out_put;
	cred = ctx->cred;
	for (i = 0; i < object_count; i++) {
		const u8 *handle = req->object_count ? req->objects[i].handle :
						      req->handle;
		struct svc_fh *fhp = &work->fhps[i];
		u32 handle_len = req->object_count ? req->objects[i].handle_len :
							 req->handle_len;

		error = ffv2_prototype_resolve(net, cred, req, handle, handle_len,
					       fhp);
		if (error) {
			while (i)
				fh_put(&work->fhps[--i]);
			goto out_put;
		}
	}
	fhs_live = true;
	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_PROTOTYPE_RESOLVE)) {
		error = -EIO;
		goto out_registration;
	}
	path.mnt = work->fhps[0].fh_export->ex_path.mnt;
	path.dentry = work->fhps[0].fh_dentry;
	/*
	 * The registration releases the handle that named the object before
	 * it publishes, so the file this profile reads is named by a
	 * reference of this function's own from here on.
	 */
	path_get(&path);
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
					      req->chunk_size, req->store_uuid,
					      req->binding_token, cred,
					      !nfsd_ffv2_prototype_test_armed(),
					      source_uuid, work->object_uuids,
					      work->outer_fhs, &generation_id);
	fhs_live = false;
	if (error)
		goto out_registration;
	if (!nfsd_ffv2_prototype_generation_matches(nn, source_uuid,
						    generation_id)) {
		error = -ESTALE;
		goto out_published;
	}

	/*
	 * The snapshot is taken now rather than earlier because a chunk
	 * names the generation it belongs to, and there is no generation to
	 * name until the object has been published.
	 */
	error = nfsd_ffv2_prototype_provider_build(nn, &path, cred,
						   work->object_uuids,
						   work->persisted_handles,
						   object_count,
						   req->chunk_size,
						   req->data_count,
						   generation_id, &provider);
	if (error)
		goto out_published;
	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_PROTOTYPE_FILE_LOOKUP)) {
		error = -EIO;
		goto out_published;
	}
	if (provider->store) {
		error = nfsd_ffv2_store_admit_writers(provider->store,
						      req->writer_id,
						      object_count, work->admitted);
		if (!error) {
			for (i = 0; i < object_count; i++) {
				provider->members[i].admission_id = work->admitted[i].id;
				memcpy(provider->members[i].stateid,
				       work->admitted[i].stateid,
				       sizeof(provider->members[i].stateid));
			}
		}
	} else {
		error = -EOPNOTSUPP;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
		if (nfsd_ffv2_prototype_test_armed()) {
			put_unaligned_be32(0x44324253, work->admitted[0].stateid);
			memcpy(work->admitted[0].stateid + 4, "TATE", 4);
			put_unaligned_be64(1, work->admitted[0].stateid + 8);
			error = 0;
		}
#endif
	}
	if (error)
		goto out_published;
	if (nfsd_ffv2_fault_inject(
		    NFSD_FFV2_FAULT_PROTOTYPE_WRITER_ADMISSION)) {
		error = -EIO;
		goto out_published;
	}
	error = nfsd_ffv2_provider_install(nn, &nfsd_ffv2_prototype_provider_ops,
					   provider, req->chunk_size);
	if (error)
		goto out_published;
	installed = true;
	if (nfsd_ffv2_fault_inject(
		    NFSD_FFV2_FAULT_PROTOTYPE_PROVIDER_INSTALL)) {
		error = -EIO;
		goto out_published;
	}
	memset(staged, 0, sizeof(*staged));
	for (i = 0; i < object_count; i++) {
		stateid_t stateid;

		if (nfsd_ffv2_prototype_test_second_trust_fails(i))
			error = -EIO;
		else
			error = nfsd_ffv2_prototype_trust(
				nn, work->object_uuids[i], req,
				work->admitted[i].stateid, &stateid);
		if (error)
			goto out_published;
		memcpy(staged->objects[i].stateid, &stateid,
		       sizeof(stateid));
	}

	/*
	 * Staged in the record it belongs to rather than in the caller's
	 * bundle: a registration that is refused below must hand nothing
	 * back, and a caller cannot be given a bundle and an error for the
	 * same request.  The record is claimed, so no other registration is
	 * writing it and no replay can read it: a replay of a claimed
	 * record is refused by the lookup.
	 */
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
	memcpy(staged->stateid, staged->objects[0].stateid,
	       sizeof(staged->stateid));
	memcpy(staged->handle, staged->objects[0].handle,
	       staged->objects[0].handle_len);
	staged->handle_len = staged->objects[0].handle_len;
	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_PROTOTYPE_PRE_READY)) {
		error = -EIO;
		goto out_published;
	}

	/*
	 * The single linearization point.  Until this store a mapping is
	 * refused even though the generation is already active, so nothing
	 * can have observed the interval in which the trust entry and the
	 * provider were still being installed.
	 */
	nfsd_ffv2_prototype_publish_pause();
	spin_lock(&anchor->prototype_gate_lock);
	/*
	 * The state is checked again here, and not only when this
	 * registration was admitted.  Everything between the two is
	 * sleepable -- an export lookup, a publication, a whole object read
	 * -- and a close owner may have claimed the gate during it.  If one
	 * has, nothing is published: committing the nonce or storing READY
	 * now would hand out a registration the owner has already decided to
	 * tear down, and transferring ownership of the provider or the
	 * generation would give it a second remover of each.
	 */
	if (proto->state != NFSD_FFV2_PROTOTYPE_OPEN || proto->close_claimed) {
		memzero_explicit(staged, sizeof(*staged));
		spin_unlock(&anchor->prototype_gate_lock);
		error = -EBUSY;
		goto out_published;
	}
	proto->provider = provider;
	proto->owns_provider = true;
	proto->generation = generation_id;
	proto->owns_generation = true;
	memcpy(proto->source_uuid, staged->source_uuid,
	       sizeof(proto->source_uuid));
	nonce->committed = work->record;
	nonce->state = NFSD_FFV2_NONCE_COMMITTED;
	proto->state = NFSD_FFV2_PROTOTYPE_READY;
	*bundle = *staged;
	spin_unlock(&anchor->prototype_gate_lock);

	nfsd_ffv2_registration_end(nn, &registration);
	path_put(&path);
	nfsd_ffv2_prototype_nonce_release(nn, nonce);
	nfsd_ffv2_prototype_user_put(nn);
	kfree_sensitive(work);
	return 0;

out_published:
	/*
	 * Nothing published here was ever reachable: the gate never reached
	 * READY, so no mapping and no operation can be inside any of it.
	 * The counted registration reference is still held, so a close owner
	 * waiting for the gate to fall quiet is waiting for this unwind, and
	 * none of the ownership bits were set, so it will find nothing of
	 * this registration left to remove.
	 */
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
	path_put(&path);
	if (claimed)
		nfsd_ffv2_prototype_nonce_release(nn, nonce);
	nfsd_ffv2_prototype_user_put(nn);
	kfree_sensitive(work);
	return error;
out_free:
	kfree_sensitive(work);
	return error;
}

/**
 * nfsd_ffv2_prototype_unregister - retire the object set this gate published
 * @nn: the nfsd namespace
 * @net: the caller's network namespace
 * @source_uuid: the identifier the registration returned
 * @generation: the generation the registration returned
 *
 * This closes the gate.  Retiring the object set a gate serves and closing
 * that gate are the same teardown, and giving them two implementations was
 * how the second one came to run outside the close owner's fence: it could
 * remove a provider while a replay was still being answered, and retire a
 * committed nonce while a registration naming it was still admitted.  So
 * this claims the close role like any other closer, names the registration
 * it expects to find while doing so, and then runs the same teardown.
 *
 * Anything admitted before the claim keeps the gate open until it is done,
 * because the close owner waits for the counted work to drain.  Anything
 * arriving after it is refused: the gate is CLOSING, and nothing new is
 * admitted to a closing gate.
 *
 * Return: 0 when this caller performed the teardown, -EBUSY when another
 * closer was already performing it and this one waited it out,
 * -EOPNOTSUPP when the gate is off or has nothing published, -ESTALE when
 * the pair names no registration this gate made, or -EPERM for an
 * administrator that did not enable it.
 */
int nfsd_ffv2_prototype_unregister(struct nfsd_net *nn, const struct net *net,
				   const u8 source_uuid[16], u64 generation)
{
	if (!generation)
		return -EINVAL;
	return __nfsd_ffv2_prototype_close(nn, net, source_uuid, generation);
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
						       nonce, false, &record) :
		      -EOPNOTSUPP;
	nfsd_ffv2_prototype_user_put(nn);
	return error;
}

bool nfsd_ffv2_prototype_test_nonce_reusable(struct nfsd_net *nn,
					     const u8 *nonce)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype_ctx *ctx = nfsd_ffv2_prototype_ctx_of(nn);
	struct nfsd_ffv2_prototype_nonce *record;
	unsigned long index;
	bool reusable = false;
	u64 carried;

	if (!ctx)
		return false;
	carried = get_unaligned_be64(nonce);
	if (carried > (u64)ULONG_MAX)
		return false;
	index = carried;
	spin_lock(&anchor->prototype_gate_lock);
	record = xa_load(&ctx->nonces, index);
	if (record &&
	    !crypto_memneq(record->value, nonce,
			   NFSD_FFV2_PROTOTYPE_NONCE_LEN) &&
	    record->state == NFSD_FFV2_NONCE_ISSUED && !record->busy)
		reusable = true;
	spin_unlock(&anchor->prototype_gate_lock);
	return reusable;
}

/* Backdate one challenge so its expiry can be reached without waiting. */
void nfsd_ffv2_prototype_test_nonce_age(struct nfsd_net *nn, const u8 *nonce)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_prototype_nonce *record;
	struct nfsd_ffv2_prototype_ctx *ctx;

	ctx = nfsd_ffv2_prototype_ctx_of(nn);
	if (!ctx)
		return;
	spin_lock(&anchor->prototype_gate_lock);
	record = xa_load(&ctx->nonces,
			 (unsigned long)get_unaligned_be64(nonce));
	if (record)
		record->expires = 0;
	spin_unlock(&anchor->prototype_gate_lock);
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
	/*
	 * A gate is enabled only from a cycle that is completely over: the
	 * state is off, the previous close owner has signalled and given up
	 * its role, and nobody is still parked on the completion this cycle
	 * would reinitialise.
	 */
	if (proto->state != NFSD_FFV2_PROTOTYPE_OFF || proto->close_claimed ||
	    proto->close_waiters) {
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

/*
 * The one way an administrator closes a gate.  DISABLE names nothing and
 * closes whatever is there; UNREGISTER names the registration it expects
 * to find and closes only that.  Everything after the claim is the same,
 * because a gate with nothing published and a gate whose one registration
 * is being retired are the same teardown.
 */
static int __nfsd_ffv2_prototype_close(struct nfsd_net *nn,
				       const struct net *net,
				       const u8 *source_uuid, u64 generation)
{
	u32 secid = 0;
	int claim;

	if (!ns_capable(net->user_ns, CAP_SYS_ADMIN))
		return -EPERM;
	security_cred_getsecid(current_cred(), &secid);
	claim = nfsd_ffv2_prototype_close_claim(nn, net, secid, true,
						source_uuid, generation);
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
	return __nfsd_ffv2_prototype_close(nn, net, NULL, 0);
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
	int claim = nfsd_ffv2_prototype_close_claim(nn, NULL, 0, false, NULL,
						    0);

	if (claim < 0)
		return;
	if (claim)
		nfsd_ffv2_prototype_close_finish(nn);
	else
		nfsd_ffv2_prototype_close_wait(nn);
}
