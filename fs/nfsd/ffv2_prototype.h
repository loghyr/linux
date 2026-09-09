/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NFSD_FFV2_PROTOTYPE_H
#define _NFSD_FFV2_PROTOTYPE_H

#include <linux/completion.h>
#include <linux/time64.h>
#include <linux/uidgid.h>
#include <linux/wait.h>

struct net;
struct nfsd_net;
struct nfsd_ffv2_prototype_ctx;
struct user_namespace;

/*
 * The prototype authority profile.
 *
 * An ordinary Flex Files v2 data server derives its trust from a metadata
 * server that authenticated to it.  The prototype profile substitutes an
 * administrator holding CAP_SYS_ADMIN in one reserved network namespace,
 * so that the read path can be demonstrated before that authentication
 * exists.  It is deliberately not a production shape: it is compiled out
 * by default, it claims the namespace's single authority source so no
 * metadata server can share the namespace with it, and it admits only the
 * two read operations.
 *
 * The gate is a state machine, and every transition is decided under
 * anchor->prototype_gate_lock, which is taken after nfsd_mutex and never
 * before it:
 *
 *	OFF -> ENABLING -> OPEN -> READY -> CLOSING -> OFF
 *
 * ENABLE claims the source reservation, takes the setup reference, and
 * publishes ENABLING before it does any sleepable work; that reference is
 * what stops namespace exit from tearing down a half-built gate.  The first
 * caller to observe a live gate -- a second administrator, or namespace
 * pre-exit -- claims the close role and publishes CLOSING; every later
 * caller only waits.  So one actor drains, removes and releases, exactly
 * once, and everything else joins its completion.
 *
 * The two completions are distinct on purpose.  @setup_done says the
 * enabling caller has finished and rolled back whatever it staged; it does
 * not say the namespace is quiet.  @close_done says the source reservation
 * is back, the provider is gone, and the references the gate held are
 * dropped.  Everything outside waits for @close_done, so nothing can
 * release the namespace while setup is still running.
 */
enum nfsd_ffv2_prototype_state {
	NFSD_FFV2_PROTOTYPE_OFF,
	NFSD_FFV2_PROTOTYPE_ENABLING,
	NFSD_FFV2_PROTOTYPE_OPEN,
	NFSD_FFV2_PROTOTYPE_READY,
	NFSD_FFV2_PROTOTYPE_CLOSING,
};

/* Bytes in the opaque a challenge hands out, and how long it stays valid. */
#define NFSD_FFV2_PROTOTYPE_NONCE_LEN	32
#define NFSD_FFV2_PROTOTYPE_NONCE_TTL_NS	(60ULL * NSEC_PER_SEC)

/*
 * The administrator that enabled the gate.  Registration, disable and
 * unregister must present the same identity: CAP_SYS_ADMIN is not a claim
 * to somebody else's prototype.  The user namespace is held by reference
 * for as long as the tuple is valid; the network namespace is compared by
 * pointer only and is never dereferenced through here.
 */
struct nfsd_ffv2_prototype_owner {
	kuid_t			uid;
	struct user_namespace	*userns;
	const struct net	*net;
	u32			secid;
	bool			secid_valid;
	bool			valid;
};

/*
 * Per-namespace gate state.  Every field is written under
 * anchor->prototype_gate_lock except the two completions, which are
 * signalled by their single owner and waited on without it.
 */
struct nfsd_ffv2_prototype {
	enum nfsd_ffv2_prototype_state	state;
	/*
	 * Work that must drain before teardown: a challenge or registration
	 * in progress, and each admitted operation.  Closers do not count
	 * themselves, or they would wait for their own reference.
	 */
	unsigned int			users;
	wait_queue_head_t		users_wait;
	/* Held by the enabling caller across its whole sleepable setup. */
	unsigned int			setup_ref;
	/* Set by whichever caller took the close role, so only one does. */
	bool				close_claimed;
	struct completion		setup_done;
	struct completion		close_done;
	struct nfsd_ffv2_prototype_owner owner;
	/*
	 * Objects the enabling caller staged.  A bit is cleared by whoever
	 * disposes of the object, so the setup owner's rollback and the
	 * close owner's final teardown cannot both remove one.
	 */
	bool				owns_ctx;
	bool				owns_anchor;
	bool				owns_source;
	struct nfsd_ffv2_prototype_ctx	*ctx;
	/*
	 * Callers parked on @close_done.  The next enable waits for them to
	 * leave before it reinitialises that completion, so a waiter that
	 * has been woken but not yet run cannot be sent back to sleep on a
	 * completion that has already fired.
	 */
	unsigned int			close_waiters;
};

#if IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
void nfsd_ffv2_prototype_net_init(struct nfsd_net *nn);
int nfsd_ffv2_prototype_challenge(struct nfsd_net *nn, const struct net *net,
				  u8 nonce[NFSD_FFV2_PROTOTYPE_NONCE_LEN],
				  u64 *expires);
void nfsd_ffv2_prototype_net_pre_exit(struct nfsd_net *nn);
void nfsd_ffv2_prototype_net_destroy(struct nfsd_net *nn);
int nfsd_ffv2_prototype_enable(struct nfsd_net *nn, const struct net *net);
int nfsd_ffv2_prototype_disable(struct nfsd_net *nn, const struct net *net);
enum nfsd_ffv2_prototype_state
nfsd_ffv2_prototype_state_get(struct nfsd_net *nn);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
void nfsd_ffv2_prototype_test_setup_hook(struct completion *reached,
					 struct completion *proceed);
int nfsd_ffv2_prototype_test_nonce_check(struct nfsd_net *nn,
					 const struct net *net,
					 const u8 *nonce);
void nfsd_ffv2_prototype_test_nonce_age(struct nfsd_net *nn, const u8 *nonce);
unsigned int nfsd_ffv2_prototype_test_nonce_count(struct nfsd_net *nn);
unsigned int nfsd_ffv2_prototype_test_close_waiters(struct nfsd_net *nn);
#endif
#else
static inline void nfsd_ffv2_prototype_net_init(struct nfsd_net *nn) { }
static inline void nfsd_ffv2_prototype_net_pre_exit(struct nfsd_net *nn) { }
static inline void nfsd_ffv2_prototype_net_destroy(struct nfsd_net *nn) { }
#endif

#endif /* _NFSD_FFV2_PROTOTYPE_H */
