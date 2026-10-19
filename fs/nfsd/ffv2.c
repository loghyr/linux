// SPDX-License-Identifier: GPL-2.0-only
#include <linux/completion.h>
#include <linux/fs.h>
#include <linux/lockd/bind.h>
#include <linux/mount.h>
#include <linux/nfslocalio.h>
#include <net/net_namespace.h>
#include <linux/lockdep.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/sunrpc/svc_xprt.h>
#include <linux/wait.h>
#include <linux/unaligned.h>

#include "ffv2.h"
#include "filecache.h"
#include "export.h"
#include "nfsd.h"
#include "netns.h"
#include "nfsfh.h"

static const u8 nfsd_ffv2_fh_magic[8] = {
	0xff, 'F', 'F', 'V', '2', 'F', 'H', 0,
};

int nfsd_ffv2_fh_parse(const struct knfsd_fh *fh, struct nfsd_ffv2_fh_info *info)
{
	const u8 *raw = fh->fh_raw;
	u16 header_len, total_len, inner_len;

	if (fh->fh_size < NFSD_FFV2_FH_HEADER_SIZE ||
	    fh->fh_size > NFSD_FFV2_FH_MAX)
		return -EBADMSG;
	if (memcmp(raw, nfsd_ffv2_fh_magic, sizeof(nfsd_ffv2_fh_magic)) ||
	    raw[8] != 1 || raw[9])
		return -EBADMSG;
	header_len = get_unaligned_be16(raw + 10);
	total_len = get_unaligned_be16(raw + 12);
	inner_len = get_unaligned_be16(raw + 14);
	if (header_len != NFSD_FFV2_FH_HEADER_SIZE ||
	    total_len != fh->fh_size ||
	    inner_len < 8 || inner_len > NFSD_FFV2_FH_INNER_MAX ||
	    inner_len & 3 ||
	    total_len != header_len + inner_len || raw[56] != 1)
		return -EBADMSG;

	info->generation = get_unaligned_be64(raw + 16);
	if (!info->generation)
		return -EBADMSG;
	memcpy(info->object_uuid, raw + 24, sizeof(info->object_uuid));
	memcpy(info->export_uuid, raw + 40, sizeof(info->export_uuid));
	info->inner = raw + header_len;
	info->inner_len = inner_len;
	return 0;
}

int nfsd_ffv2_fh_encode(struct knfsd_fh *fh,
			const struct nfsd_ffv2_fh_info *info)
{
	u16 total_len;

	if (!info->generation || !info->inner || info->inner_len < 8 ||
	    info->inner_len > NFSD_FFV2_FH_INNER_MAX || info->inner_len & 3 ||
	    info->inner[0] != 1)
		return -EINVAL;
	total_len = NFSD_FFV2_FH_HEADER_SIZE + info->inner_len;
	memcpy(fh->fh_raw, nfsd_ffv2_fh_magic, sizeof(nfsd_ffv2_fh_magic));
	fh->fh_raw[8] = 1;
	fh->fh_raw[9] = 0;
	put_unaligned_be16(NFSD_FFV2_FH_HEADER_SIZE, fh->fh_raw + 10);
	put_unaligned_be16(total_len, fh->fh_raw + 12);
	put_unaligned_be16(info->inner_len, fh->fh_raw + 14);
	put_unaligned_be64(info->generation, fh->fh_raw + 16);
	memcpy(fh->fh_raw + 24, info->object_uuid, sizeof(info->object_uuid));
	memcpy(fh->fh_raw + 40, info->export_uuid, sizeof(info->export_uuid));
	memcpy(fh->fh_raw + NFSD_FFV2_FH_HEADER_SIZE, info->inner,
	       info->inner_len);
	fh->fh_size = total_len;
	return 0;
}

enum nfsd_ffv2_identity_state {
	NFSD_FFV2_IDENTITY_LIVE,
	NFSD_FFV2_IDENTITY_RETIRED,
};

enum nfsd_ffv2_generation_state {
	NFSD_FFV2_GENERATION_ACTIVE,
	NFSD_FFV2_GENERATION_STOPPING,
	NFSD_FFV2_GENERATION_FINALIZING,
	NFSD_FFV2_GENERATION_STOPPED,
};

struct nfsd_ffv2_identity {
	refcount_t	ref;
	u64		generation;
	int		state;
};

struct nfsd_ffv2_generation {
	refcount_t			ref;
	struct nfsd_ffv2_identity	*identity;
	atomic_t			state;
	atomic_t			admitted;
	/* Protects callback-task records removed without the anchor lock. */
	spinlock_t			admissions_lock;
	struct list_head		admissions;
	wait_queue_head_t		admitted_wait;
	struct completion		retired;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	atomic_t			test_waiters;
#endif
	void				*payload;
	void				(*release)(void *payload);
};

enum nfsd_ffv2_reservation_state {
	NFSD_FFV2_RESERVING,
	NFSD_FFV2_RESERVATION_ACTIVE,
	NFSD_FFV2_RESERVATION_FENCING,
	NFSD_FFV2_RESERVATION_QUIESCING,
};

/*
 * The caller and registry each own a reference. nfsd_ffv2_registry_lock
 * protects membership and owner links. RCU readers retain visibility until
 * unlink's grace period completes.
 */
struct nfsd_ffv2_reservation {
	struct list_head		node;
	struct list_head		owner_node;
	refcount_t		ref;
	/* Serializes gate ownership with abort and fence. */
	struct mutex		entry_lock;
	struct path		root;
	struct inode		*inode;
	struct super_block	*sb;
	struct nfsd_ffv2_participant *owner;
	u64			owner_generation;
	enum nfsd_ffv2_reservation_state state;
	u8			store_uuid[16];
	u8			export_uuid[16];
	u8			binding_token[32];
	struct nlmsvc_ffv2_gate nlm_gate;
	struct nfsd_file_ffv2_gate file_gate;
	bool			nlm_gated;
	bool			file_gated;
};

struct nfsd_ffv2_participant_snapshot {
	struct nfsd_ffv2_participant *participant;
	struct net *net;
};

static DEFINE_MUTEX(nfsd_ffv2_registry_lock);
static DEFINE_MUTEX(nfsd_ffv2_export_policy_lock);
static LIST_HEAD(nfsd_ffv2_participants);
static LIST_HEAD(nfsd_ffv2_reservations);

static void
nfsd_ffv2_participant_put(struct nfsd_ffv2_participant *participant)
{
	if (refcount_dec_and_test(&participant->ref))
		complete(&participant->released);
}

static void
nfsd_ffv2_snapshot_put(struct nfsd_ffv2_participant_snapshot *snapshot)
{
	put_net(snapshot->net);
	nfsd_ffv2_participant_put(snapshot->participant);
}

static int
nfsd_ffv2_snapshot_participants(struct nfsd_ffv2_participant_snapshot **result,
				unsigned int *count)
{
	struct nfsd_ffv2_participant_snapshot *snapshots;
	struct nfsd_ffv2_participant *participant;
	unsigned int allocated = 0;
	unsigned int nr = 0;

	mutex_lock(&nfsd_ffv2_registry_lock);
	list_for_each_entry(participant, &nfsd_ffv2_participants, node)
		allocated++;
	mutex_unlock(&nfsd_ffv2_registry_lock);

	snapshots = kcalloc(allocated, sizeof(*snapshots), GFP_KERNEL);
	if (!snapshots && allocated)
		return -ENOMEM;

	mutex_lock(&nfsd_ffv2_registry_lock);
	list_for_each_entry(participant, &nfsd_ffv2_participants, node) {
		struct net *net;

		if (nr == allocated || !READ_ONCE(participant->attached) ||
		    !participant->net)
			continue;
		net = maybe_get_net(participant->net);
		if (!net)
			continue;
		refcount_inc(&participant->ref);
		snapshots[nr].participant = participant;
		snapshots[nr].net = net;
		nr++;
	}
	mutex_unlock(&nfsd_ffv2_registry_lock);

	*result = snapshots;
	*count = nr;
	return 0;
}

static bool
nfsd_ffv2_snapshot_conflicts(struct nfsd_ffv2_participant_snapshot *snapshots,
			     unsigned int count, struct super_block *sb,
			     struct svc_export *expected)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		struct nfsd_ffv2_participant *participant =
			snapshots[i].participant;
		struct svc_export *exp;

		mutex_lock(&participant->inventory_lock);
		list_for_each_entry(exp, &participant->inventory,
				    ex_ffv2_inventory) {
			if (exp == expected &&
			    nfsd_ffv2_export_is_transitioning(exp))
				continue;
			if (exp->ex_ffv2_path.mnt->mnt_sb == sb) {
				mutex_unlock(&participant->inventory_lock);
				return true;
			}
		}
		mutex_unlock(&participant->inventory_lock);
	}
	return false;
}

static void
nfsd_ffv2_release_snapshots(struct nfsd_ffv2_participant_snapshot *snapshots,
			    unsigned int count)
{
	while (count)
		nfsd_ffv2_snapshot_put(&snapshots[--count]);
	kfree(snapshots);
}

static void
nfsd_ffv2_reservation_put(struct nfsd_ffv2_reservation *reservation)
{
	if (!refcount_dec_and_test(&reservation->ref))
		return;
	WARN_ON_ONCE(reservation->nlm_gated || reservation->file_gated);
	iput(reservation->inode);
	path_put(&reservation->root);
	mutex_destroy(&reservation->entry_lock);
	kfree(reservation);
}

static void
nfsd_ffv2_reservation_ungate_io(struct nfsd_ffv2_reservation *reservation)
{
	if (reservation->file_gated) {
		nfsd_file_ffv2_gate_end(&reservation->file_gate);
		reservation->file_gated = false;
	}
	if (reservation->nlm_gated) {
		nlmsvc_ffv2_gate_end(&reservation->nlm_gate);
		reservation->nlm_gated = false;
	}
}

int
nfsd_ffv2_reservation_gate_io(struct nfsd_ffv2_reservation *reservation)
{
	struct nfsd_ffv2_participant_snapshot *snapshots = NULL;
	struct nfsd_file_ffv2_gate *file_gate = &reservation->file_gate;
	unsigned int count = 0;
#if IS_ENABLED(CONFIG_NFS_LOCALIO)
	unsigned int i;
#endif
	int error;

	mutex_lock(&reservation->entry_lock);
	if (READ_ONCE(reservation->state) != NFSD_FFV2_RESERVING ||
	    reservation->nlm_gated || reservation->file_gated) {
		error = -EBUSY;
		goto out_unlock;
	}
	error = nlmsvc_ffv2_gate_begin(&reservation->nlm_gate,
				       reservation->sb);
	if (error)
		goto out_unlock;
	reservation->nlm_gated = true;
	error = nfsd_file_ffv2_gate_begin(file_gate, reservation->inode);
	if (error)
		goto out_ungate;
	reservation->file_gated = true;

	error = nfsd_ffv2_snapshot_participants(&snapshots, &count);
	if (error)
		goto out_ungate;
#if IS_ENABLED(CONFIG_NFS_LOCALIO)
	for (i = 0; i < count; i++) {
		struct nfsd_net *nn = net_generic(snapshots[i].net, nfsd_net_id);

		nfs_localio_invalidate_clients(&nn->local_clients,
					       &nn->local_clients_lock);
	}
#endif
	nfsd_ffv2_release_snapshots(snapshots, count);
	snapshots = NULL;
	count = 0;
	error = nfsd_file_ffv2_gate_wait(file_gate);
	if (error)
		goto out_ungate;
	mutex_unlock(&reservation->entry_lock);
	return 0;

out_ungate:
	nfsd_ffv2_release_snapshots(snapshots, count);
	nfsd_ffv2_reservation_ungate_io(reservation);
out_unlock:
	mutex_unlock(&reservation->entry_lock);
	return error;
}

static bool nfsd_ffv2_superblock_reserved(struct super_block *sb)
{
	struct nfsd_ffv2_reservation *reservation;
	bool reserved = false;

	rcu_read_lock();
	list_for_each_entry_rcu(reservation, &nfsd_ffv2_reservations, node) {
		if (READ_ONCE(reservation->sb) == sb) {
			reserved = true;
			break;
		}
	}
	rcu_read_unlock();
	return reserved;
}

static void
nfsd_ffv2_reservation_unlink(struct nfsd_ffv2_reservation *reservation)
{
	bool linked = false;

	mutex_lock(&nfsd_ffv2_registry_lock);
	if (!list_empty(&reservation->node)) {
		list_del_rcu(&reservation->node);
		list_del_init(&reservation->owner_node);
		reservation->owner = NULL;
		linked = true;
	}
	mutex_unlock(&nfsd_ffv2_registry_lock);
	if (linked) {
		/* Keep the registry reference until reservation readers leave. */
		synchronize_rcu();
		INIT_LIST_HEAD(&reservation->node);
		nfsd_ffv2_reservation_put(reservation);
	}
}

static int __nfsd_ffv2_reservation_claim(struct nfsd_net *owner,
					 const struct path *root,
					 const u8 store_uuid[16],
					 const u8 export_uuid[16],
					 const u8 binding_token[32],
					 struct nfsd_ffv2_reservation **result,
					 bool validate_backend,
					 struct svc_export *expected)
{
	struct nfsd_ffv2_participant_snapshot *snapshots = NULL;
	struct nfsd_ffv2_reservation *reservation, *cursor;
	unsigned int count = 0;
	unsigned int i;
	int error;

	if (!owner || !root || !root->dentry || !root->mnt || !store_uuid ||
	    !export_uuid || !binding_token || !result || !d_is_dir(root->dentry) ||
	    !IS_ROOT(root->dentry))
		return -EOPNOTSUPP;
	if (validate_backend && (root->mnt->mnt_sb->s_stack_depth ||
				 !root->mnt->mnt_sb->s_export_op))
		return -EOPNOTSUPP;

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (atomic_xchg(&owner->ffv2_participant.test_reservation_alloc_failure, 0))
		return -ENOMEM;
#endif
	reservation = kzalloc_obj(*reservation, GFP_KERNEL);
	if (!reservation)
		return -ENOMEM;
	reservation->inode = igrab(d_inode(root->dentry));
	if (!reservation->inode) {
		kfree(reservation);
		return -ESTALE;
	}
	refcount_set(&reservation->ref, 1);
	mutex_init(&reservation->entry_lock);
	INIT_LIST_HEAD(&reservation->node);
	INIT_LIST_HEAD(&reservation->owner_node);
	INIT_LIST_HEAD(&reservation->file_gate.list);
	init_waitqueue_head(&reservation->file_gate.wait);
	reservation->root = *root;
	path_get(&reservation->root);
	reservation->sb = root->mnt->mnt_sb;
	reservation->state = NFSD_FFV2_RESERVING;
	memcpy(reservation->store_uuid, store_uuid,
	       sizeof(reservation->store_uuid));
	memcpy(reservation->export_uuid, export_uuid,
	       sizeof(reservation->export_uuid));
	memcpy(reservation->binding_token, binding_token,
	       sizeof(reservation->binding_token));

	mutex_lock(&nfsd_ffv2_registry_lock);
	if (!READ_ONCE(owner->ffv2_participant.attached)) {
		error = -ESHUTDOWN;
		goto out_unlock_registry;
	}
	list_for_each_entry(cursor, &nfsd_ffv2_reservations, node) {
		if (cursor->sb == reservation->sb) {
			error = -EBUSY;
			goto out_unlock_registry;
		}
	}
	refcount_inc(&reservation->ref);
	reservation->owner = &owner->ffv2_participant;
	list_add_tail(&reservation->owner_node,
		      &owner->ffv2_participant.reservations);
	list_add_tail_rcu(&reservation->node, &nfsd_ffv2_reservations);
	mutex_unlock(&nfsd_ffv2_registry_lock);

	error = nfsd_ffv2_snapshot_participants(&snapshots, &count);
	if (error)
		goto out_unlink;

	mutex_lock(&reservation->entry_lock);
	mutex_lock(&nfsd_ffv2_export_policy_lock);
	if (nfsd_ffv2_snapshot_conflicts(snapshots, count, reservation->sb,
					 expected))
		error = -EBUSY;
	else
		error = 0;
	mutex_unlock(&nfsd_ffv2_export_policy_lock);
	mutex_unlock(&reservation->entry_lock);
	for (i = 0; i < count; i++)
		WARN_ON_ONCE(snapshots[i].net !=
			     snapshots[i].participant->net);
	nfsd_ffv2_release_snapshots(snapshots, count);
	if (error)
		goto out_unlink;

	*result = reservation;
	return 0;

out_unlock_registry:
	mutex_unlock(&nfsd_ffv2_registry_lock);
	nfsd_ffv2_reservation_put(reservation);
	return error;
out_unlink:
	nfsd_ffv2_reservation_unlink(reservation);
	nfsd_ffv2_reservation_put(reservation);
	return error;
}

int nfsd_ffv2_reservation_claim(struct nfsd_net *owner, const struct path *root,
				const u8 store_uuid[16],
				const u8 export_uuid[16],
				const u8 binding_token[32],
				struct nfsd_ffv2_reservation **result)
{
	return __nfsd_ffv2_reservation_claim(owner, root, store_uuid, export_uuid,
					     binding_token, result, true, NULL);
}

static int nfsd_ffv2_claim_expected(struct nfsd_net *owner,
				    const struct path *root,
				    const u8 store_uuid[16],
				    const u8 binding_token[32],
				    struct svc_export *expected,
				    struct nfsd_ffv2_reservation **result,
				    bool validate_backend)
{
	int error;

	nfsd_ffv2_export_update_lock();
	if (!nfsd_ffv2_export_is_current_locked(expected) ||
	    !nfsd_ffv2_export_is_transitioning(expected))
		error = -ESTALE;
	else
		error = __nfsd_ffv2_reservation_claim(owner, root, store_uuid,
						      expected->ex_uuid,
						      binding_token, result,
						      validate_backend, expected);
	nfsd_ffv2_export_update_unlock();
	return error;
}

int
nfsd_ffv2_reservation_claim_expected(struct nfsd_net *owner,
				     const struct path *root,
				     const u8 store_uuid[16],
				     const u8 binding_token[32],
				     struct svc_export *expected,
				     struct nfsd_ffv2_reservation **result)
{
	return nfsd_ffv2_claim_expected(owner, root, store_uuid, binding_token,
					 expected, result, true);
}

void nfsd_ffv2_reservation_abort(struct nfsd_ffv2_reservation *reservation)
{
	mutex_lock(&reservation->entry_lock);
	mutex_lock(&nfsd_ffv2_registry_lock);
	if (!list_empty(&reservation->node))
		WRITE_ONCE(reservation->state, NFSD_FFV2_RESERVATION_QUIESCING);
	mutex_unlock(&nfsd_ffv2_registry_lock);
	nfsd_ffv2_reservation_ungate_io(reservation);
	nfsd_ffv2_reservation_unlink(reservation);
	mutex_unlock(&reservation->entry_lock);
	nfsd_ffv2_reservation_put(reservation);
}

void nfsd_ffv2_reservation_fence(struct nfsd_ffv2_reservation *reservation)
{
	mutex_lock(&reservation->entry_lock);
	mutex_lock(&nfsd_ffv2_registry_lock);
	if (!list_empty(&reservation->node))
		WRITE_ONCE(reservation->state, NFSD_FFV2_RESERVATION_FENCING);
	mutex_unlock(&nfsd_ffv2_registry_lock);
	nfsd_ffv2_reservation_ungate_io(reservation);
	nfsd_ffv2_reservation_unlink(reservation);
	mutex_unlock(&reservation->entry_lock);
	nfsd_ffv2_reservation_put(reservation);
}

bool nfsd4_ffv2_mount_crossing_allowed(const struct path *path)
{
	return !nfsd_ffv2_superblock_reserved(path->mnt->mnt_sb);
}

static void
nfsd_ffv2_fence_owned_reservations(struct nfsd_ffv2_participant *participant)
{
	struct nfsd_ffv2_reservation *reservation;

	for (;;) {
		mutex_lock(&nfsd_ffv2_registry_lock);
		if (list_empty(&participant->reservations)) {
			mutex_unlock(&nfsd_ffv2_registry_lock);
			break;
		}
		reservation = list_first_entry(&participant->reservations,
					       struct nfsd_ffv2_reservation,
					       owner_node);
		refcount_inc(&reservation->ref);
		mutex_unlock(&nfsd_ffv2_registry_lock);

		nfsd_ffv2_reservation_fence(reservation);
	}
}

static bool nfsd_ffv2_anchor_get(struct nfsd_ffv2_anchor *anchor)
{
	return refcount_inc_not_zero(&anchor->ref);
}

static void nfsd_ffv2_anchor_put(struct nfsd_ffv2_anchor *anchor)
{
	if (refcount_dec_and_test(&anchor->ref))
		complete(&anchor->released);
}

static void nfsd_ffv2_identity_put(struct nfsd_ffv2_identity *identity)
{
	if (refcount_dec_and_test(&identity->ref))
		kfree(identity);
}

static void nfsd_ffv2_generation_put(struct nfsd_ffv2_generation *generation)
{
	if (!refcount_dec_and_test(&generation->ref))
		return;

	WARN_ON_ONCE(atomic_read(&generation->admitted));
	WARN_ON_ONCE(!list_empty(&generation->admissions));
	WARN_ON_ONCE(generation->payload);
	nfsd_ffv2_identity_put(generation->identity);
	kfree(generation);
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
static atomic_t nfsd_ffv2_start_failure;

static struct nfsd_ffv2_generation *
nfsd_ffv2_generation_alloc(void *payload, void (*release)(void *))
{
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_identity *identity;

	identity = kzalloc_obj(*identity, GFP_KERNEL);
	if (!identity)
		return NULL;

	generation = kzalloc_obj(*generation, GFP_KERNEL);
	if (!generation) {
		kfree(identity);
		return NULL;
	}

	refcount_set(&identity->ref, 1);
	WRITE_ONCE(identity->state, NFSD_FFV2_IDENTITY_LIVE);
	refcount_set(&generation->ref, 1);
	generation->identity = identity;
	atomic_set(&generation->state, NFSD_FFV2_GENERATION_ACTIVE);
	atomic_set(&generation->admitted, 0);
	spin_lock_init(&generation->admissions_lock);
	INIT_LIST_HEAD(&generation->admissions);
	init_waitqueue_head(&generation->admitted_wait);
	init_completion(&generation->retired);
	atomic_set(&generation->test_waiters, 0);
	generation->payload = payload;
	generation->release = release;
	return generation;
}
#endif

static struct nfsd_ffv2_generation *
nfsd_ffv2_retire_begin_locked(struct nfsd_ffv2_anchor *anchor)
{
	struct nfsd_ffv2_generation *generation = anchor->active;

	lockdep_assert_held(&anchor->lock);
	if (generation) {
		anchor->active = NULL;
		anchor->retiring = generation;
		/* Publish the tombstone before a future binding rejects it. */
		smp_store_release(&generation->identity->state,
				  NFSD_FFV2_IDENTITY_RETIRED);
		atomic_set(&generation->state,
			   NFSD_FFV2_GENERATION_STOPPING);
	} else {
		generation = anchor->retiring;
	}
	if (generation)
		refcount_inc(&generation->ref);
	return generation;
}

static void
nfsd_ffv2_release_payload(struct nfsd_ffv2_generation *generation)
{
	void *payload = xchg(&generation->payload, NULL);

	if (payload && generation->release)
		generation->release(payload);
}

static void nfsd_ffv2_wait_admitted(struct nfsd_ffv2_generation *generation)
{
	DEFINE_WAIT(wait);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	bool reported = false;
#endif

	for (;;) {
		prepare_to_wait(&generation->admitted_wait, &wait,
				TASK_UNINTERRUPTIBLE);
		if (!atomic_read(&generation->admitted))
			break;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
		if (!reported) {
			atomic_inc(&generation->test_waiters);
			reported = true;
		}
#endif
		schedule();
	}
	finish_wait(&generation->admitted_wait, &wait);
}

static void nfsd_ffv2_retire_finish(struct nfsd_ffv2_anchor *anchor,
				    struct nfsd_ffv2_generation *generation)
{
	bool unpublished = false;

	if (!generation)
		return;

	nfsd_ffv2_wait_admitted(generation);

	if (atomic_cmpxchg(&generation->state,
			   NFSD_FFV2_GENERATION_STOPPING,
			   NFSD_FFV2_GENERATION_FINALIZING) ==
			   NFSD_FFV2_GENERATION_STOPPING) {
		nfsd_ffv2_release_payload(generation);

		mutex_lock(&anchor->lock);
		if (WARN_ON_ONCE(anchor->retiring != generation)) {
			mutex_unlock(&anchor->lock);
			goto out_complete;
		}
		anchor->retiring = NULL;
		atomic_set_release(&generation->state,
				   NFSD_FFV2_GENERATION_STOPPED);
		unpublished = true;
		mutex_unlock(&anchor->lock);

out_complete:
		complete_all(&generation->retired);
		if (unpublished)
			nfsd_ffv2_generation_put(generation);
	} else {
		wait_for_completion(&generation->retired);
	}

	nfsd_ffv2_generation_put(generation);
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
static int nfsd_ffv2_publish(struct nfsd_ffv2_anchor *anchor,
			     struct nfsd_ffv2_generation *generation,
			     u64 *generation_id)
{
	int error = 0;

	mutex_lock(&anchor->lock);
	if (anchor->net_state != NFSD_FFV2_NET_LIVE ||
	    anchor->service_state == NFSD_FFV2_SERVICE_STOPPING ||
	    anchor->service_state == NFSD_FFV2_SERVICE_DRAIN_FAILED) {
		error = -ESHUTDOWN;
	} else if (anchor->service_state == NFSD_FFV2_SERVICE_DOWN) {
		error = -ENXIO;
	} else if (anchor->active || anchor->retiring) {
		error = -EBUSY;
	} else if (!anchor->next_generation ||
		   anchor->next_generation == U64_MAX) {
		error = -EOVERFLOW;
	} else {
		generation->identity->generation = anchor->next_generation++;
		refcount_inc(&generation->ref);
		anchor->active = generation;
		if (generation_id)
			*generation_id = generation->identity->generation;
	}
	mutex_unlock(&anchor->lock);
	return error;
}
#endif

/**
 * nfsd_ffv2_net_init - initialize the namespace anchor
 * @nn: namespace with no FFv2 users
 *
 * Context: Called before the namespace is exposed. Does not sleep.
 */
void nfsd_ffv2_net_init(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	refcount_set(&anchor->ref, 1);
	init_completion(&anchor->released);
	mutex_init(&anchor->lock);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	anchor->test_destroy_waiting = NULL;
#endif
	anchor->net_state = NFSD_FFV2_NET_LIVE;
	anchor->service_state = NFSD_FFV2_SERVICE_DOWN;
	anchor->next_generation = 1;
	anchor->active = NULL;
	anchor->retiring = NULL;
}

static void nfsd_ffv2_updates_set_open(struct nfsd_ffv2_participant *p,
				       bool open)
{
	spin_lock(&p->update_lock);
	if (open && p->updates_closing)
		goto out;
	if (p->updates_open != open) {
		p->updates_open = open;
		if (!++p->update_epoch)
			++p->update_epoch;
	}
out:
	spin_unlock(&p->update_lock);
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
void nfsd_ffv2_test_try_reopen_updates(struct nfsd_net *nn)
{
	nfsd_ffv2_updates_set_open(&nn->ffv2_participant, true);
}
#endif

static void nfsd_ffv2_updates_close_permanent(struct nfsd_ffv2_participant *p)
{
	spin_lock(&p->update_lock);
	p->updates_closing = true;
	if (p->updates_open) {
		p->updates_open = false;
		if (!++p->update_epoch)
			++p->update_epoch;
	}
	spin_unlock(&p->update_lock);
}

static void nfsd_ffv2_updates_wait(struct nfsd_ffv2_participant *p)
{
	wait_event(p->update_wait, !READ_ONCE(p->update_count));
}

int nfsd_ffv2_participant_register(struct nfsd_net *nn, struct net *net)
{
	struct nfsd_ffv2_participant *p = &nn->ffv2_participant;

	INIT_LIST_HEAD(&p->node);
	INIT_LIST_HEAD(&p->reservations);
	refcount_set(&p->ref, 1);
	init_completion(&p->released);
	p->net = net;
	spin_lock_init(&p->update_lock);
	init_waitqueue_head(&p->update_wait);
	p->update_count = 0;
	p->update_epoch = 1;
	p->updates_open = true;
	p->updates_closing = false;
	mutex_init(&p->inventory_lock);
	INIT_LIST_HEAD(&p->inventory);
	init_waitqueue_head(&p->inventory_wait);
	p->inventory_count = 0;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	atomic_set(&p->test_reservation_alloc_failure, 0);
	p->test_update_validated = NULL;
	p->test_update_continue = NULL;
	p->test_inventory_wait_entered = NULL;
	p->test_inventory_wait_done = NULL;
	p->test_inventory_postwait_entered = NULL;
	p->test_inventory_postwait_continue = NULL;
	p->test_inventory_lock_entered = NULL;
	p->test_inventory_destroy_continue = NULL;
	p->test_inventory_task = NULL;
	p->test_inventory_wait_count = NULL;
	p->test_release_count_zero = NULL;
	p->test_release_continue = NULL;
#endif
	WRITE_ONCE(p->attached, true);
	mutex_lock(&nfsd_ffv2_registry_lock);
	list_add_tail(&p->node, &nfsd_ffv2_participants);
	mutex_unlock(&nfsd_ffv2_registry_lock);
	return 0;
}

void nfsd_ffv2_participant_detach_begin(struct nfsd_net *nn)
{
	struct nfsd_ffv2_participant *p = &nn->ffv2_participant;

	nfsd_ffv2_updates_close_permanent(p);
	nfsd_ffv2_updates_wait(p);
	mutex_lock(&nfsd_ffv2_registry_lock);
	WRITE_ONCE(p->attached, false);
	list_del_init(&p->node);
	mutex_unlock(&nfsd_ffv2_registry_lock);
	nfsd_ffv2_fence_owned_reservations(p);
	nfsd_ffv2_participant_put(p);
	wait_for_completion(&p->released);
}

void nfsd_ffv2_participant_detach_finish(struct nfsd_net *nn)
{
	struct nfsd_ffv2_participant *p = &nn->ffv2_participant;

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (READ_ONCE(p->test_inventory_wait_count))
		*READ_ONCE(p->test_inventory_wait_count) = p->inventory_count;
	if (READ_ONCE(p->test_inventory_wait_entered))
		complete(READ_ONCE(p->test_inventory_wait_entered));
#endif
	wait_event(p->inventory_wait, !READ_ONCE(p->inventory_count));
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (READ_ONCE(p->test_inventory_postwait_entered)) {
		get_task_struct(current);
		*READ_ONCE(p->test_inventory_task) = current;
		complete(READ_ONCE(p->test_inventory_postwait_entered));
		wait_for_completion(READ_ONCE(p->test_inventory_postwait_continue));
		complete(READ_ONCE(p->test_inventory_lock_entered));
	}
#endif
	/* The final put can publish zero before dropping inventory_lock. */
	mutex_lock(&p->inventory_lock);
	mutex_unlock(&p->inventory_lock);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (READ_ONCE(p->test_inventory_wait_done))
		complete(READ_ONCE(p->test_inventory_wait_done));
	if (READ_ONCE(p->test_inventory_destroy_continue))
		wait_for_completion(READ_ONCE(p->test_inventory_destroy_continue));
#endif
	WARN_ON_ONCE(!list_empty(&p->reservations));
	p->net = NULL;
	mutex_destroy(&p->inventory_lock);
}

static void nfsd_ffv2_export_update_put(struct nfsd_ffv2_export_update *update)
{
	struct nfsd_ffv2_participant *p = update->participant;
	bool wake;

	if (!update->admitted)
		return;
	spin_lock(&p->update_lock);
	if (WARN_ON_ONCE(!p->update_count)) {
		spin_unlock(&p->update_lock);
		return;
	}
	wake = !--p->update_count;
	update->admitted = false;
	spin_unlock(&p->update_lock);
	if (wake)
		wake_up_all(&p->update_wait);
}

int nfsd_ffv2_export_update_begin(struct svc_export *exp,
				  struct nfsd_ffv2_export_update *update)
{
	struct nfsd_net *nn = net_generic(exp->cd->net, nfsd_net_id);
	struct nfsd_ffv2_participant *p = &nn->ffv2_participant;
	int error = 0;

	memset(update, 0, sizeof(*update));
	spin_lock(&p->update_lock);
	if (!p->updates_open || !READ_ONCE(p->attached)) {
		error = -ESHUTDOWN;
	} else {
		p->update_count++;
		update->participant = p;
		update->epoch = p->update_epoch;
		update->admitted = true;
	}
	spin_unlock(&p->update_lock);
	if (error)
		return error;
	mutex_lock(&nfsd_ffv2_export_policy_lock);
	update->policy_locked = true;
	if (!test_bit(CACHE_NEGATIVE, &exp->h.flags) &&
	    nfsd_ffv2_superblock_reserved(exp->ex_path.mnt->mnt_sb)) {
		nfsd_ffv2_export_update_abort(update);
		return -EBUSY;
	}
	return 0;
}

int nfsd_ffv2_export_update_validate(struct nfsd_ffv2_export_update *update)
{
	struct nfsd_ffv2_participant *p = update->participant;
	int error = 0;

	spin_lock(&p->update_lock);
	if (!p->updates_open || p->update_epoch != update->epoch)
		error = -ESHUTDOWN;
	spin_unlock(&p->update_lock);
	return error;
}

void nfsd_ffv2_export_update_end(struct svc_export *exp,
				 struct nfsd_ffv2_export_update *update)
{
	struct nfsd_ffv2_participant *p = update->participant;

	mutex_lock(&p->inventory_lock);
	if (!test_bit(CACHE_NEGATIVE, &exp->h.flags) &&
	    !exp->ex_ffv2_listed) {
		exp->ex_ffv2_path = exp->ex_path;
		path_get(&exp->ex_ffv2_path);
		exp->ex_ffv2_participant = p;
		exp->ex_ffv2_listed = true;
		list_add_tail(&exp->ex_ffv2_inventory, &p->inventory);
		p->inventory_count++;
	}
	mutex_unlock(&p->inventory_lock);
	if (update->policy_locked) {
		mutex_unlock(&nfsd_ffv2_export_policy_lock);
		update->policy_locked = false;
	}
	nfsd_ffv2_export_update_put(update);
}

void nfsd_ffv2_export_update_abort(struct nfsd_ffv2_export_update *update)
{
	if (update->policy_locked) {
		mutex_unlock(&nfsd_ffv2_export_policy_lock);
		update->policy_locked = false;
	}
	nfsd_ffv2_export_update_put(update);
}

void nfsd_ffv2_export_release(struct svc_export *exp)
{
	struct nfsd_ffv2_participant *p = exp->ex_ffv2_participant;

	if (!p)
		return;
	mutex_lock(&p->inventory_lock);
	if (exp->ex_ffv2_listed) {
		list_del_init(&exp->ex_ffv2_inventory);
		exp->ex_ffv2_listed = false;
		exp->ex_ffv2_participant = NULL;
		p->inventory_count--;
		path_put(&exp->ex_ffv2_path);
		if (!p->inventory_count)
			wake_up_all(&p->inventory_wait);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
		if (!p->inventory_count && READ_ONCE(p->test_release_count_zero)) {
			complete(READ_ONCE(p->test_release_count_zero));
			wait_for_completion(READ_ONCE(p->test_release_continue));
		}
#endif
	}
	mutex_unlock(&p->inventory_lock);
}

/**
 * nfsd_ffv2_net_pre_exit - fence and drain a departing namespace
 * @nn: namespace whose anchor remains allocated
 *
 * Context: Sleeps. Called without nfsd_mutex before net_destroy.
 */
void nfsd_ffv2_net_pre_exit(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;

	if (WARN_ON_ONCE(!nfsd_ffv2_anchor_get(anchor)))
		return;
	if (READ_ONCE(nn->ffv2_participant.attached)) {
		nfsd_ffv2_updates_close_permanent(&nn->ffv2_participant);
		nfsd_ffv2_updates_wait(&nn->ffv2_participant);
	}
	mutex_lock(&anchor->lock);
	/* Pair with admission's lockless rejection before taking ->lock. */
	smp_store_release(&anchor->net_state, NFSD_FFV2_NET_EXITING);
	anchor->service_state = NFSD_FFV2_SERVICE_STOPPING;
	generation = nfsd_ffv2_retire_begin_locked(anchor);
	mutex_unlock(&anchor->lock);

	nfsd_ffv2_retire_finish(anchor, generation);
	nfsd_ffv2_anchor_put(anchor);
}

/**
 * nfsd_ffv2_net_destroy - release the namespace anchor
 * @nn: namespace already fenced by net_pre_exit
 *
 * Context: Sleeps until all anchor holders release their references.
 */
void nfsd_ffv2_net_destroy(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	mutex_lock(&anchor->lock);
	WARN_ON_ONCE(anchor->net_state != NFSD_FFV2_NET_EXITING);
	WARN_ON_ONCE(anchor->service_state != NFSD_FFV2_SERVICE_STOPPING);
	WARN_ON_ONCE(anchor->active);
	WARN_ON_ONCE(anchor->retiring);
	mutex_unlock(&anchor->lock);
	nfsd_ffv2_anchor_put(anchor);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (READ_ONCE(anchor->test_destroy_waiting))
		complete(READ_ONCE(anchor->test_destroy_waiting));
#endif
	wait_for_completion(&anchor->released);
	mutex_destroy(&anchor->lock);
}

/**
 * nfsd_ffv2_service_up - open service admission
 * @nn: namespace whose service is starting
 *
 * Context: Sleeps. Caller holds nfsd_mutex.
 * Return: 0 on success, -ESHUTDOWN at namespace exit, or -EAGAIN during drain.
 */
int nfsd_ffv2_service_up(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	int error = 0;

	lockdep_assert_held(&nfsd_mutex);
	if (WARN_ON_ONCE(!nfsd_ffv2_anchor_get(anchor)))
		return -ESHUTDOWN;
	mutex_lock(&anchor->lock);
	if (anchor->net_state != NFSD_FFV2_NET_LIVE)
		error = -ESHUTDOWN;
	else if (anchor->service_state == NFSD_FFV2_SERVICE_STOPPING ||
		 anchor->service_state == NFSD_FFV2_SERVICE_DRAIN_FAILED)
		error = -EAGAIN;
	else if (anchor->service_state == NFSD_FFV2_SERVICE_DOWN)
		anchor->service_state = NFSD_FFV2_SERVICE_UP;
	mutex_unlock(&anchor->lock);
	if (!error)
		nfsd_ffv2_updates_set_open(&nn->ffv2_participant, true);
	nfsd_ffv2_anchor_put(anchor);
	return error;
}

/**
 * nfsd_ffv2_service_stop_begin - close service admission before worker drain
 * @nn: namespace whose service is stopping
 *
 * Context: Sleeps. Caller holds nfsd_mutex.
 * Return: A retirement reference, or NULL when no generation needs retirement.
 * Consume it with nfsd_ffv2_service_stop_finish(),
 * nfsd_ffv2_service_stop_failed(), or nfsd_ffv2_service_stop_put().
 */
struct nfsd_ffv2_generation *
nfsd_ffv2_service_stop_begin(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation = NULL;

	lockdep_assert_held(&nfsd_mutex);
	if (WARN_ON_ONCE(!nfsd_ffv2_anchor_get(anchor)))
		return NULL;
	nfsd_ffv2_updates_set_open(&nn->ffv2_participant, false);
	mutex_lock(&anchor->lock);
	if (anchor->service_state == NFSD_FFV2_SERVICE_UP)
		anchor->service_state = NFSD_FFV2_SERVICE_STOPPING;
	else if (anchor->service_state == NFSD_FFV2_SERVICE_DRAIN_FAILED)
		anchor->service_state = NFSD_FFV2_SERVICE_STOPPING;
	if (anchor->service_state == NFSD_FFV2_SERVICE_STOPPING)
		generation = nfsd_ffv2_retire_begin_locked(anchor);
	mutex_unlock(&anchor->lock);
	nfsd_ffv2_anchor_put(anchor);
	return generation;
}

/**
 * nfsd_ffv2_service_stop_finish - drain and retire a stopped generation
 * @nn: namespace that owns the generation
 * @generation: retirement reference to consume, or NULL
 *
 * Context: Sleeps. Called after worker drain without nfsd_mutex.
 */
void nfsd_ffv2_service_stop_finish(struct nfsd_net *nn,
				   struct nfsd_ffv2_generation *generation)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	lockdep_assert_not_held(&nfsd_mutex);
	if (WARN_ON_ONCE(!nfsd_ffv2_anchor_get(anchor))) {
		if (generation)
			nfsd_ffv2_generation_put(generation);
		return;
	}
	nfsd_ffv2_updates_wait(&nn->ffv2_participant);
	nfsd_ffv2_retire_finish(anchor, generation);
	nfsd_ffv2_anchor_put(anchor);
}

/**
 * nfsd_ffv2_service_stop_failed - fence admission after failed drain
 * @nn: namespace whose workers failed to drain
 * @generation: retirement reference to consume, or NULL
 *
 * Context: Sleeps. Caller holds nfsd_mutex.
 */
void nfsd_ffv2_service_stop_failed(struct nfsd_net *nn,
				   struct nfsd_ffv2_generation *generation)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	bool reopen = false;

	lockdep_assert_held(&nfsd_mutex);
	if (WARN_ON_ONCE(!nfsd_ffv2_anchor_get(anchor)))
		goto out_put;
	mutex_lock(&anchor->lock);
	if (anchor->net_state == NFSD_FFV2_NET_LIVE &&
	    anchor->service_state == NFSD_FFV2_SERVICE_STOPPING) {
		anchor->service_state = NFSD_FFV2_SERVICE_DRAIN_FAILED;
		reopen = true;
	}
	mutex_unlock(&anchor->lock);
	if (reopen)
		nfsd_ffv2_updates_set_open(&nn->ffv2_participant, true);
	nfsd_ffv2_anchor_put(anchor);
out_put:
	nfsd_ffv2_service_stop_put(generation);
}

/**
 * nfsd_ffv2_service_stop_put - drop an unused retirement reference
 * @generation: retirement reference to consume, or NULL
 *
 * Context: Does not sleep.
 */
void nfsd_ffv2_service_stop_put(struct nfsd_ffv2_generation *generation)
{
	if (generation)
		nfsd_ffv2_generation_put(generation);
}

/**
 * nfsd_ffv2_service_down - finish service shutdown
 * @nn: namespace after payload retirement
 *
 * Context: Sleeps. Caller holds nfsd_mutex.
 */
void nfsd_ffv2_service_down(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	bool reopen = false;

	lockdep_assert_held(&nfsd_mutex);
	if (WARN_ON_ONCE(!nfsd_ffv2_anchor_get(anchor)))
		return;
	mutex_lock(&anchor->lock);
	if (anchor->net_state == NFSD_FFV2_NET_LIVE) {
		anchor->service_state = NFSD_FFV2_SERVICE_DOWN;
		reopen = true;
	}
	mutex_unlock(&anchor->lock);
	if (reopen)
		nfsd_ffv2_updates_set_open(&nn->ffv2_participant, true);
	nfsd_ffv2_anchor_put(anchor);
}

/**
 * nfsd_ffv2_requested_zero_threads - classify a service-stop request
 * @n: number of requested pool counts
 * @nthreads: array of n requested thread counts
 * @nrpools: number of existing service pools
 *
 * Context: Does not sleep.
 * Return: True for a positive request with only zero counts for existing pools.
 */
bool nfsd_ffv2_requested_zero_threads(int n, const int *nthreads,
				      unsigned int nrpools)
{
	unsigned int i;

	if (n <= 0)
		return false;
	for (i = 0; i < min_t(unsigned int, n, nrpools); i++)
		if (nthreads[i])
			return false;
	return true;
}

static int
nfsd_ffv2_admit_generation(struct nfsd_net *nn,
			   struct nfsd_ffv2_admission *admission)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	int error = 0;

	INIT_LIST_HEAD(&admission->node);
	admission->anchor = NULL;
	admission->generation = NULL;
	admission->task = NULL;
	if (!nfsd_ffv2_anchor_get(anchor))
		return -ESHUTDOWN;
	/* EXITING is published before the owner reference is released. */
	if (smp_load_acquire(&anchor->net_state) != NFSD_FFV2_NET_LIVE) {
		nfsd_ffv2_anchor_put(anchor);
		return -ESHUTDOWN;
	}

	mutex_lock(&anchor->lock);
	generation = anchor->active;
	if (anchor->net_state != NFSD_FFV2_NET_LIVE ||
	    anchor->service_state != NFSD_FFV2_SERVICE_UP || !generation) {
		error = -ESHUTDOWN;
	} else {
		refcount_inc(&generation->ref);
		atomic_inc(&generation->admitted);
		admission->anchor = anchor;
		admission->generation = generation;
		admission->task = current;
		spin_lock(&generation->admissions_lock);
		list_add(&admission->node, &generation->admissions);
		spin_unlock(&generation->admissions_lock);
	}
	mutex_unlock(&anchor->lock);
	if (error)
		nfsd_ffv2_anchor_put(anchor);
	return error;
}

/**
 * nfsd_ffv2_admit - hold the active generation for one NFSD request
 * @rqstp: current NFSD worker request with a transport
 * @admission: unused caller-owned record that remains live until completion
 *
 * Context: Sleeps. Called by the NFSD worker that owns rqstp.
 * Return: 0 with owned anchor and generation references, or a negative errno.
 */
int nfsd_ffv2_admit(struct svc_rqst *rqstp,
		    struct nfsd_ffv2_admission *admission)
{
	struct nfsd_net *nn;

	if (nfsd_current_rqst() != rqstp || !rqstp->rq_xprt)
		return -EOPNOTSUPP;
	nn = net_generic(rqstp->rq_xprt->xpt_net, nfsd_net_id);
	return nfsd_ffv2_admit_generation(nn, admission);
}

/**
 * nfsd_ffv2_complete - consume an admission once
 * @admission: admitted record or an already completed record
 *
 * Context: Does not sleep. Serial or concurrent repeat completion is harmless.
 */
void nfsd_ffv2_complete(struct nfsd_ffv2_admission *admission)
{
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_anchor *anchor;

	generation = xchg(&admission->generation, NULL);
	if (!generation)
		return;
	anchor = admission->anchor;

	spin_lock(&generation->admissions_lock);
	list_del_init(&admission->node);
	spin_unlock(&generation->admissions_lock);
	admission->anchor = NULL;
	admission->task = NULL;
	if (atomic_dec_and_test(&generation->admitted))
		wake_up_all(&generation->admitted_wait);
	nfsd_ffv2_generation_put(generation);
	nfsd_ffv2_anchor_put(anchor);
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
/**
 * nfsd_ffv2_test_publish - publish a synthetic generation
 * @nn: live namespace with its service up
 * @payload: caller-owned payload transferred only on success
 * @release: callback that consumes payload after admitted work drains
 * @generation_id: optional output for the nonzero generation number
 *
 * Context: Sleeps. Caller holds nfsd_mutex.
 * Return: 0 on publication, or a negative errno without consuming payload.
 */
int nfsd_ffv2_test_publish(struct nfsd_net *nn, void *payload,
			   void (*release)(void *), u64 *generation_id)
{
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	int error;

	lockdep_assert_held(&nfsd_mutex);
	if (!nfsd_ffv2_anchor_get(anchor))
		return -ESHUTDOWN;
	generation = nfsd_ffv2_generation_alloc(payload, release);
	if (!generation) {
		nfsd_ffv2_anchor_put(anchor);
		return -ENOMEM;
	}
	error = nfsd_ffv2_publish(anchor, generation, generation_id);
	if (error)
		generation->payload = NULL;
	nfsd_ffv2_generation_put(generation);
	nfsd_ffv2_anchor_put(anchor);
	return error;
}

/**
 * nfsd_ffv2_test_admit - admit synthetic work through the lifecycle gate
 * @nn: live namespace with a published generation
 * @admission: unused caller-owned record retained until completion
 *
 * Context: Sleeps.
 * Return: 0 with owned anchor and generation references, or a negative errno.
 */
int nfsd_ffv2_test_admit(struct nfsd_net *nn,
			 struct nfsd_ffv2_admission *admission)
{
	return nfsd_ffv2_admit_generation(nn, admission);
}

static bool
nfsd_ffv2_generation_has_task(struct nfsd_ffv2_generation *generation,
			      struct task_struct *task)
{
	struct nfsd_ffv2_admission *admission;
	bool found = false;

	spin_lock(&generation->admissions_lock);
	list_for_each_entry(admission, &generation->admissions, node) {
		if (admission->task == task) {
			found = true;
			break;
		}
	}
	spin_unlock(&generation->admissions_lock);
	return found;
}

/**
 * nfsd_ffv2_test_unregister - retire one synthetic generation
 * @nn: namespace whose anchor remains allocated
 * @generation_id: generation to retire
 *
 * Context: Sleeps. Drops and reacquires the caller-held nfsd_mutex.
 * Return: 0 after retirement, -EDEADLK if the caller is admitted, or another errno.
 */
int nfsd_ffv2_test_unregister(struct nfsd_net *nn, u64 generation_id)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	int error = 0;

	lockdep_assert_held(&nfsd_mutex);
	if (!nfsd_ffv2_anchor_get(anchor))
		return -ESHUTDOWN;
	mutex_lock(&anchor->lock);
	generation = anchor->active;
	if (!generation ||
	    generation->identity->generation != generation_id)
		generation = anchor->retiring;
	if (!generation ||
	    generation->identity->generation != generation_id) {
		error = -ENOENT;
		generation = NULL;
	} else if (nfsd_ffv2_generation_has_task(generation, current)) {
		error = -EDEADLK;
		generation = NULL;
	} else if (generation == anchor->active) {
		generation = nfsd_ffv2_retire_begin_locked(anchor);
	} else {
		refcount_inc(&generation->ref);
	}
	mutex_unlock(&anchor->lock);
	if (error) {
		nfsd_ffv2_anchor_put(anchor);
		return error;
	}
	mutex_unlock(&nfsd_mutex);
	nfsd_ffv2_retire_finish(anchor, generation);
	mutex_lock(&nfsd_mutex);
	nfsd_ffv2_anchor_put(anchor);
	return error;
}

/**
 * nfsd_ffv2_test_generation_retired - observe a generation tombstone
 * @generation: generation kept alive by the caller
 *
 * Context: Does not sleep.
 * Return: True after retirement begins.
 */
bool
nfsd_ffv2_test_generation_retired(struct nfsd_ffv2_generation *generation)
{
	/* Pair with retirement publication before dereferencing an identity. */
	return smp_load_acquire(&generation->identity->state) ==
			NFSD_FFV2_IDENTITY_RETIRED;
}

/**
 * nfsd_ffv2_test_admission_retired - observe an admitted generation tombstone
 * @admission: admission whose completion remains blocked
 *
 * Context: Does not sleep.
 * Return: True after the admitted generation begins retirement.
 */
bool
nfsd_ffv2_test_admission_retired(struct nfsd_ffv2_admission *admission)
{
	return nfsd_ffv2_test_generation_retired(admission->generation);
}

/**
 * nfsd_ffv2_test_waiters - read retirement wait entries
 * @admission: admission whose completion remains blocked
 *
 * Context: Does not sleep.
 * Return: Number of retirement callers that observed outstanding admissions.
 */
unsigned int nfsd_ffv2_test_waiters(struct nfsd_ffv2_admission *admission)
{
	return atomic_read(&admission->generation->test_waiters);
}

/**
 * nfsd_ffv2_test_anchor_refcount - read namespace anchor holders
 * @nn: namespace whose anchor remains allocated
 *
 * Context: Does not sleep.
 * Return: Snapshot of the anchor reference count.
 */
unsigned int nfsd_ffv2_test_anchor_refcount(struct nfsd_net *nn)
{
	return refcount_read(&nn->ffv2.ref);
}

/**
 * nfsd_ffv2_test_anchor_hold - hold an anchor across namespace destruction
 * @nn: namespace whose anchor remains allocated
 *
 * Context: Does not sleep.
 * Return: True if a reference was acquired; pair success with anchor_release.
 */
bool nfsd_ffv2_test_anchor_hold(struct nfsd_net *nn)
{
	return nfsd_ffv2_anchor_get(&nn->ffv2);
}

/**
 * nfsd_ffv2_test_anchor_release - drop a fixture-owned anchor reference
 * @nn: namespace pinned by anchor_hold
 *
 * Context: Does not sleep.
 */
void nfsd_ffv2_test_anchor_release(struct nfsd_net *nn)
{
	nfsd_ffv2_anchor_put(&nn->ffv2);
}

/**
 * nfsd_ffv2_test_destroy_waiting - observe namespace anchor destruction
 * @nn: namespace whose destruction has not started
 * @entered: completion kept alive until destruction returns
 *
 * Context: Does not sleep. Arm before the destruction worker starts.
 */
void nfsd_ffv2_test_destroy_waiting(struct nfsd_net *nn,
				    struct completion *entered)
{
	WRITE_ONCE(nn->ffv2.test_destroy_waiting, entered);
}

/**
 * nfsd_ffv2_test_set_start_failure - arm a test-only service-start failure
 * @fail: whether the next successful worker adjustment should fail
 *
 * Context: does not sleep.
 */
void nfsd_ffv2_test_set_start_failure(bool fail)
{
	atomic_set(&nfsd_ffv2_start_failure, fail);
}

/**
 * nfsd_ffv2_test_start_failure - consume a test-only service-start failure
 *
 * Context: does not sleep.
 * Return: true when the current worker adjustment should report failure.
 */
bool nfsd_ffv2_test_start_failure(void)
{
	return atomic_xchg(&nfsd_ffv2_start_failure, 0);
}
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
int nfsd_ffv2_test_reservation_claim(struct nfsd_net *owner,
				     const struct path *root,
				     const u8 store_uuid[16],
				     const u8 binding_token[32],
				     struct nfsd_ffv2_reservation **result)
{
	return __nfsd_ffv2_reservation_claim(owner, root, store_uuid, store_uuid,
					     binding_token, result, false, NULL);
}

int
nfsd_ffv2_test_reservation_claim_expected(struct nfsd_net *owner,
					  const struct path *root,
					  const u8 store_uuid[16],
					  const u8 binding_token[32],
					  struct svc_export *expected,
					  struct nfsd_ffv2_reservation **result)
{
	return nfsd_ffv2_claim_expected(owner, root, store_uuid, binding_token,
					 expected, result, false);
}

#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
void nfsd_ffv2_test_fail_reservation_alloc(struct nfsd_net *nn)
{
	atomic_set(&nn->ffv2_participant.test_reservation_alloc_failure, 1);
}

bool nfsd_ffv2_test_reservation_waiting(struct nfsd_ffv2_reservation *reservation)
{
	/* Observation only; no wakeup depends on this lockless check. */
	return waitqueue_active(&reservation->file_gate.wait);
}
#endif
