// SPDX-License-Identifier: GPL-2.0-only
#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/lockdep.h>
#include <linux/kthread.h>
#include <linux/refcount.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/lockd/bind.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nfslocalio.h>
#include <linux/sunrpc/svc_xprt.h>
#include <linux/wait.h>
#include <net/net_namespace.h>

#include "export.h"
#include "ffv2.h"
#include "filecache.h"
#include "nfsfh.h"
#include "nfsd.h"
#include "netns.h"
#include "vfs.h"

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
	u8		object_uuid[16];
	u8		export_uuid[16];
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
	void				*payload;
	void				(*release)(void *payload);
	bool				registry_generation;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	struct completion		*test_retire_waiting;
#endif
};

struct nfsd_ffv2_object {
	struct path		export_path;
	struct path		object_path;
	struct knfsd_fh		inner_fh;
	struct auth_domain	*client;
	u8			object_uuid[16];
	u8			export_uuid[16];
	bool			export_valid;
	bool			object_valid;
	bool			visible;
};

struct nfsd_ffv2_binding {
	refcount_t		ref;
	struct net		*net;
	struct nfsd_ffv2_object *object;
	struct nfsd_ffv2_admission admission;
};

static DEFINE_MUTEX(nfsd_ffv2_registry_lock);
static DEFINE_MUTEX(nfsd_ffv2_export_policy_lock);
static LIST_HEAD(nfsd_ffv2_participants);
static LIST_HEAD(nfsd_ffv2_reservations);

#if IS_ENABLED(CONFIG_NFSD_FFV2_LIVE_TEST) || \
	IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
static atomic_t nfsd_ffv2_fault_armed_phase = ATOMIC_INIT(NFSD_FFV2_FAULT_NONE);
static atomic_t nfsd_ffv2_fault_hit_phase = ATOMIC_INIT(NFSD_FFV2_FAULT_NONE);

bool nfsd_ffv2_fault_inject(enum nfsd_ffv2_fault_phase phase)
{
	if (atomic_cmpxchg(&nfsd_ffv2_fault_armed_phase, phase,
			   NFSD_FFV2_FAULT_NONE) != phase)
		return false;
	atomic_set(&nfsd_ffv2_fault_hit_phase, phase);
	return true;
}

void nfsd_ffv2_fault_arm(enum nfsd_ffv2_fault_phase phase)
{
	atomic_set(&nfsd_ffv2_fault_hit_phase, NFSD_FFV2_FAULT_NONE);
	atomic_set(&nfsd_ffv2_fault_armed_phase, phase);
}

enum nfsd_ffv2_fault_phase nfsd_ffv2_fault_armed(void)
{
	return atomic_read(&nfsd_ffv2_fault_armed_phase);
}

enum nfsd_ffv2_fault_phase nfsd_ffv2_fault_hit(void)
{
	return atomic_read(&nfsd_ffv2_fault_hit_phase);
}
#endif

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

enum nfsd_ffv2_reservation_state {
	NFSD_FFV2_RESERVING,
	NFSD_FFV2_RESERVATION_ACTIVE,
	NFSD_FFV2_RESERVATION_FENCING,
	NFSD_FFV2_RESERVATION_QUIESCING,
};

struct nfsd_ffv2_reservation {
	struct list_head		node;
	struct list_head		owner_node;
	refcount_t		ref;
	/* Serializes publication and rollback for this reservation. */
	struct mutex		entry_lock;
	struct path		root;
	struct inode		*inode;
	struct super_block	*sb;
	struct nfsd_ffv2_participant *owner;
	u64			owner_generation;
	enum nfsd_ffv2_reservation_state state;
	u8			store_uuid[16];
	u8			binding_token[32];
	struct nlmsvc_ffv2_gate nlm_gate;
	struct nfsd_file_ffv2_gate file_gate;
	bool			nlm_gated;
	bool			file_gated;
};

struct nfsd_ffv2_service_context {
	struct nfsd_ffv2_reservation *reservation;
	struct svc_export	*export;
	struct nfsd_ffv2_object *object;
	const struct cred	*cred;
	struct completion	export_released;
	u64			control_root;
	u64			owner_generation;
	bool			published;
	bool			object_owned;
};

struct nfsd_ffv2_participant_snapshot {
	struct nfsd_ffv2_participant *participant;
	struct net		*net;
};

static void
nfsd_ffv2_participant_put(struct nfsd_ffv2_participant *participant);
static int
nfsd_ffv2_snapshot_participants(struct nfsd_ffv2_participant_snapshot **result,
				unsigned int *count);
static void
nfsd_ffv2_release_snapshots(struct nfsd_ffv2_participant_snapshot *snapshots,
			    unsigned int count);
static int
nfsd_ffv2_export_update_admit(struct nfsd_ffv2_participant *participant,
			      struct nfsd_ffv2_export_update *update);
static void
nfsd_ffv2_export_update_put(struct nfsd_ffv2_export_update *update);
static int
nfsd_ffv2_generation_prepare(struct nfsd_net *nn, void *payload,
			     void (*release)(void *),
			     const u8 object_uuid[16],
			     const u8 export_uuid[16],
			     struct nfsd_ffv2_generation **result,
			     u64 *generation_id);
static int
nfsd_ffv2_generation_commit(struct nfsd_net *nn,
			    struct nfsd_ffv2_generation *generation);
static void
nfsd_ffv2_generation_cancel(struct nfsd_net *nn,
			    struct nfsd_ffv2_generation *generation);
static bool nfsd_ffv2_anchor_get(struct nfsd_ffv2_anchor *anchor);
static void nfsd_ffv2_anchor_put(struct nfsd_ffv2_anchor *anchor);
static int nfsd_ffv2_object_validate(struct svc_export *exp,
				     struct nfsd_ffv2_object *object);
static void
nfsd_ffv2_generation_put(struct nfsd_ffv2_generation *generation);

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

		nfsd_file_ffv2_gate_phase(file_gate, NFSD_FILE_FFV2_GATE_INVALIDATE);
		nfs_localio_invalidate_clients(&nn->local_clients,
					       &nn->local_clients_lock);
		nfsd_file_ffv2_gate_phase(file_gate, NFSD_FILE_FFV2_GATE_INVALIDATED);
	}
#endif
	nfsd_ffv2_release_snapshots(snapshots, count);
	snapshots = NULL;
	count = 0;
	nfsd_file_ffv2_gate_phase(file_gate, NFSD_FILE_FFV2_GATE_WAIT);
	error = nfsd_file_ffv2_gate_wait(file_gate);
	if (error)
		goto out_ungate;
	nfsd_file_ffv2_gate_phase(file_gate, NFSD_FILE_FFV2_GATE_DRAINED);
	mutex_unlock(&reservation->entry_lock);
	return 0;

out_ungate:
	nfsd_ffv2_release_snapshots(snapshots, count);
	if (reservation->file_gated)
		nfsd_file_ffv2_gate_phase(file_gate, NFSD_FILE_FFV2_GATE_ROLLBACK);
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

		if (nr == allocated || !READ_ONCE(participant->attached))
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

#if IS_ENABLED(CONFIG_NFSD_FFV2_LIVE_TEST)
int nfsd_ffv2_live_state_show(struct seq_file *m, void *v)
{
	struct nfsd_ffv2_participant_snapshot *snapshots;
	unsigned int count, i;
	int error;

	error = nfsd_ffv2_snapshot_participants(&snapshots, &count);
	if (error)
		return error;
	for (i = 0; i < count; i++) {
		struct nfsd_ffv2_participant *participant =
			snapshots[i].participant;
		struct nfsd_net *nn = net_generic(snapshots[i].net,
						  nfsd_net_id);
		struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
		struct nfsd_ffv2_reservation *reservation;
		unsigned int reservations = 0;
		unsigned int inventory;
		unsigned int updates;
		u64 pending = 0, active = 0, retiring = 0;
		bool registration;

		mutex_lock(&anchor->lock);
		if (anchor->pending)
			pending = anchor->pending->identity->generation;
		if (anchor->active)
			active = anchor->active->identity->generation;
		if (anchor->retiring)
			retiring = anchor->retiring->identity->generation;
		registration = anchor->registration_pending;
		mutex_unlock(&anchor->lock);

		spin_lock(&participant->update_lock);
		updates = participant->update_count;
		spin_unlock(&participant->update_lock);
		mutex_lock(&participant->inventory_lock);
		inventory = participant->inventory_count;
		mutex_unlock(&participant->inventory_lock);
		mutex_lock(&nfsd_ffv2_registry_lock);
		list_for_each_entry(reservation, &participant->reservations,
				    owner_node)
			reservations++;
		mutex_unlock(&nfsd_ffv2_registry_lock);

		seq_printf(m,
			   "netns=%u registration=%u updates=%u reservations=%u inventory=%u pending=%llu active=%llu retiring=%llu\n",
			   snapshots[i].net->ns.inum, registration, updates,
			   reservations, inventory, pending, active, retiring);
	}
	nfsd_ffv2_release_snapshots(snapshots, count);
	return 0;
}
#endif

static void
nfsd_ffv2_reservation_unlink(struct nfsd_ffv2_reservation *reservation)
{
	bool linked = false;

	mutex_lock(&nfsd_ffv2_registry_lock);
	if (!list_empty(&reservation->node)) {
		list_del_rcu(&reservation->node);
		INIT_LIST_HEAD(&reservation->node);
		list_del_init(&reservation->owner_node);
		reservation->owner = NULL;
		linked = true;
	}
	mutex_unlock(&nfsd_ffv2_registry_lock);
	if (linked) {
		synchronize_rcu();
		nfsd_ffv2_reservation_put(reservation);
	}
}

static int __nfsd_ffv2_reservation_claim(struct nfsd_net *owner,
					 const struct path *root,
					 const u8 store_uuid[16],
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
	    !binding_token || !result || !d_is_dir(root->dentry) ||
	    !IS_ROOT(root->dentry))
		return -EOPNOTSUPP;
	if (validate_backend && (root->mnt->mnt_sb->s_stack_depth ||
				 !root->mnt->mnt_sb->s_export_op))
		return -EOPNOTSUPP;

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
	reservation->root = *root;
	path_get(&reservation->root);
	reservation->sb = root->mnt->mnt_sb;
	reservation->state = NFSD_FFV2_RESERVING;
	memcpy(reservation->store_uuid, store_uuid,
	       sizeof(reservation->store_uuid));
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
				const u8 binding_token[32],
				struct nfsd_ffv2_reservation **result)
{
	return __nfsd_ffv2_reservation_claim(owner, root, store_uuid, binding_token,
					     result, true, NULL);
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
	if (reservation->file_gated)
		nfsd_file_ffv2_gate_phase(&reservation->file_gate, NFSD_FILE_FFV2_GATE_ROLLBACK);
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

static struct nfsd_ffv2_service_context *
nfsd_ffv2_service_context_alloc(struct nfsd_ffv2_reservation *reservation,
				const struct cred *cred, u64 control_root,
				u64 owner_generation)
{
	struct nfsd_ffv2_service_context *context;

	context = kzalloc_obj(*context, GFP_KERNEL);
	if (!context)
		return NULL;
	refcount_inc(&reservation->ref);
	context->reservation = reservation;
	context->cred = get_cred(cred);
	context->control_root = control_root;
	context->owner_generation = owner_generation;
	init_completion(&context->export_released);
	return context;
}

struct nfsd_ffv2_object *nfsd_ffv2_object_alloc(void)
{
	return kzalloc_obj(struct nfsd_ffv2_object, GFP_KERNEL);
}

void nfsd_ffv2_object_free(struct nfsd_ffv2_object *object)
{
	if (!object)
		return;
	if (object->object_valid)
		path_put(&object->object_path);
	if (object->export_valid)
		path_put(&object->export_path);
	if (object->client)
		auth_domain_put(object->client);
	kfree(object);
}

static void
nfsd_ffv2_service_context_prepare_export(struct nfsd_ffv2_service_context *context,
					 struct svc_export *exp)
{
	if (WARN_ON_ONCE(rcu_access_pointer(exp->ex_ffv2_context)))
		return;
	nfsd_ffv2_export_template_mark_service(exp);
	RCU_INIT_POINTER(exp->ex_ffv2_context, context);
}

static void
nfsd_ffv2_service_context_abort(struct nfsd_ffv2_service_context *context,
				struct svc_export *prepared)
{
	if (prepared && rcu_access_pointer(prepared->ex_ffv2_context) == context)
		RCU_INIT_POINTER(prepared->ex_ffv2_context, NULL);
	nfsd_ffv2_reservation_put(context->reservation);
	put_cred(context->cred);
	kfree(context);
}

static struct svc_export *
nfsd_ffv2_transition_publish(struct nfsd_net *owner,
			     struct nfsd_ffv2_export_update *transaction,
			     struct nfsd_ffv2_export_update *registration,
			     struct nfsd_ffv2_reservation *reservation,
			     struct nfsd_ffv2_service_context *context,
			     struct nfsd_ffv2_generation *generation,
			     struct svc_export *old,
			     struct svc_export *template)
{
	struct nfsd_ffv2_participant *participant = &owner->ffv2_participant;
	struct nfsd_ffv2_anchor *anchor = &owner->ffv2;
	struct svc_export *published;
	int error;

	nfsd_ffv2_export_update_lock();
	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_EXACT_CURRENT) ||
	    !nfsd_ffv2_export_is_current_locked(old) ||
	    !nfsd_ffv2_export_is_transitioning(old)) {
		error = -ESTALE;
		goto out_update;
	}
	mutex_lock(&reservation->entry_lock);
	mutex_lock(&nfsd_ffv2_export_policy_lock);
	mutex_lock(&anchor->lock);
	error = nfsd_ffv2_export_update_validate(transaction);
	if (!error && registration)
		error = nfsd_ffv2_export_update_validate(registration);
	if (error || anchor->pending != generation ||
	    anchor->net_state != NFSD_FFV2_NET_LIVE ||
	    anchor->service_state != NFSD_FFV2_SERVICE_UP ||
	    (registration && (!registration->registration_slot ||
			      !anchor->registration_pending)) ||
	    reservation->state != NFSD_FFV2_RESERVING ||
	    reservation->owner != participant ||
	    !READ_ONCE(participant->attached)) {
		if (!error)
			error = -ESHUTDOWN;
		goto out_anchor;
	}

	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_CACHE_REPLACE)) {
		error = -ENOMEM;
		goto out_anchor;
	}
	/*
	 * Registry insertion and generation activation are non-failing parts of
	 * the atomic publication below. Exercise their prepared-state unwinds at
	 * the last reversible point rather than inventing a post-replacement
	 * failure that production cannot reach.
	 */
	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_REGISTRY_INSERT)) {
		error = -ENOMEM;
		goto out_anchor;
	}
	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_GENERATION_ACTIVATE)) {
		error = -ENOMEM;
		goto out_anchor;
	}
	published = nfsd_ffv2_export_update_exact_locked(template, old);
	if (IS_ERR(published)) {
		error = PTR_ERR(published);
		goto out_anchor;
	}

	/* No fallible operation is permitted after exact cache replacement. */
	nfsd_ffv2_export_transition_commit(old);
	mutex_lock(&participant->inventory_lock);
	if (!published->ex_ffv2_listed) {
		published->ex_ffv2_path = published->ex_path;
		path_get(&published->ex_ffv2_path);
		published->ex_ffv2_participant = participant;
		published->ex_ffv2_listed = true;
		list_add_tail(&published->ex_ffv2_inventory,
			      &participant->inventory);
		participant->inventory_count++;
	}
	context->export = nfsd_export_get(published);
	context->published = true;
	published->ex_ffv2_context_released = &context->export_released;
	mutex_lock(&nfsd_ffv2_registry_lock);
	reservation->state = NFSD_FFV2_RESERVATION_ACTIVE;
	reservation->owner_generation = generation->identity->generation;
	if (context->object) {
		context->object_owned = true;
		context->object->visible = true;
	}
	anchor->pending = NULL;
	anchor->active = generation;
	if (registration) {
		anchor->registration_pending = false;
		registration->registration_slot = false;
	}
	mutex_unlock(&nfsd_ffv2_registry_lock);
	mutex_unlock(&participant->inventory_lock);
	mutex_unlock(&anchor->lock);
	mutex_unlock(&nfsd_ffv2_export_policy_lock);
	mutex_unlock(&reservation->entry_lock);
	nfsd_ffv2_export_update_unlock();
	nfsd_ffv2_reservation_put(reservation);
	return published;

out_anchor:
	mutex_unlock(&anchor->lock);
	mutex_unlock(&nfsd_ffv2_export_policy_lock);
	mutex_unlock(&reservation->entry_lock);
out_update:
	nfsd_ffv2_export_update_unlock();
	return ERR_PTR(error);
}

static int
__nfsd_ffv2_service_export_publish(struct nfsd_net *owner,
				   struct svc_export *exp,
				   const struct path *root,
				   const u8 store_uuid[16],
				   const u8 binding_token[32],
				   const struct cred *cred,
				   u64 control_root, u64 *generation_id,
				   bool validate_backend,
				   struct svc_export *expected,
				   struct nfsd_ffv2_export_update *registration,
				   struct nfsd_ffv2_object *object,
				   struct knfsd_fh *outer_fh)
{
	struct nfsd_ffv2_fh_info fh_info;
	struct nfsd_ffv2_service_context *context;
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_reservation *reservation;
	struct nfsd_ffv2_export_update transaction = {};
	struct svc_export *published;
	u64 prepared_generation;
	int error;

	if (!exp || !cred || !generation_id ||
	    exp->cd != owner->svc_export_cache)
		return -EINVAL;
	*generation_id = 0;
	error = nfsd_ffv2_export_update_admit(&owner->ffv2_participant,
					      &transaction);
	if (error)
		return error;
	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_RESERVATION_CLAIM)) {
		error = -ENOMEM;
		goto out_update;
	}
	if (expected)
		error = nfsd_ffv2_claim_expected(owner, root, store_uuid,
						 binding_token, expected,
						 &reservation, validate_backend);
	else
		error = __nfsd_ffv2_reservation_claim(owner, root, store_uuid,
						      binding_token, &reservation,
						      validate_backend, NULL);
	if (error)
		goto out_update;
	if (expected) {
		error = nfsd_ffv2_export_transition_wait(expected);
		if (error) {
			nfsd_ffv2_reservation_abort(reservation);
			goto out_reopen;
		}
		error = nfsd_ffv2_reservation_gate_io(reservation);
		if (error) {
			nfsd_ffv2_reservation_abort(reservation);
			goto out_reopen;
		}
		if (object) {
			error = nfsd_ffv2_object_validate(expected, object);
			if (error) {
				nfsd_ffv2_reservation_abort(reservation);
				goto out_reopen;
			}
		}
	}
	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_CONTEXT_ALLOC)) {
		nfsd_ffv2_reservation_abort(reservation);
		error = -ENOMEM;
		goto out_reopen;
	}
	context = nfsd_ffv2_service_context_alloc(reservation, cred,
						  control_root, 0);
	if (!context) {
		nfsd_ffv2_reservation_abort(reservation);
		error = -ENOMEM;
		goto out_reopen;
	}
	context->object = object;
	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_GENERATION_ALLOC)) {
		nfsd_ffv2_service_context_abort(context, NULL);
		nfsd_ffv2_reservation_abort(reservation);
		error = -ENOMEM;
		goto out_reopen;
	}
	error = nfsd_ffv2_generation_prepare(owner, context,
					     nfsd_ffv2_service_context_release,
					     object ? object->object_uuid : NULL,
					     object ? object->export_uuid : NULL,
					     &generation, &prepared_generation);
	if (error) {
		nfsd_ffv2_service_context_abort(context, NULL);
		nfsd_ffv2_reservation_abort(reservation);
		goto out_reopen;
	}
	if (object && outer_fh) {
		memset(&fh_info, 0, sizeof(fh_info));
		fh_info.generation = prepared_generation;
		memcpy(fh_info.object_uuid, object->object_uuid,
		       sizeof(fh_info.object_uuid));
		memcpy(fh_info.export_uuid, object->export_uuid,
		       sizeof(fh_info.export_uuid));
		fh_info.inner = object->inner_fh.fh_raw;
		fh_info.inner_len = object->inner_fh.fh_size;
		error = nfsd_ffv2_fh_encode(outer_fh, &fh_info);
		if (error) {
			nfsd_ffv2_generation_cancel(owner, generation);
			nfsd_ffv2_service_context_abort(context, NULL);
			nfsd_ffv2_reservation_abort(reservation);
			goto out_reopen;
		}
	}
	context->owner_generation = prepared_generation;
	nfsd_ffv2_service_context_prepare_export(context, exp);
	if (reservation->file_gated)
		nfsd_file_ffv2_gate_phase(&reservation->file_gate, NFSD_FILE_FFV2_GATE_PRE_PUBLISH);
	error = nfsd_ffv2_live_test_checkpoint(NFSD_FFV2_LIVE_TEST_PRE_PUBLISH,
					       expected ?: exp);
	if (error) {
		nfsd_ffv2_generation_cancel(owner, generation);
		nfsd_ffv2_service_context_abort(context, exp);
		nfsd_ffv2_reservation_abort(reservation);
		goto out_reopen;
	}
	if (expected)
		published = nfsd_ffv2_transition_publish(owner, &transaction,
							 registration,
							 reservation, context, generation,
							 expected, exp);
	else
		published = nfsd_export_cache_update(exp);
	if (IS_ERR(published)) {
		error = PTR_ERR(published);
		nfsd_ffv2_generation_cancel(owner, generation);
		nfsd_ffv2_service_context_abort(context, exp);
		nfsd_ffv2_reservation_abort(reservation);
		goto out_reopen;
	}
	nfsd_export_put(published);
	if (expected) {
		nfsd_ffv2_generation_put(generation);
		*generation_id = prepared_generation;
		goto out_update;
	}
	error = nfsd_ffv2_generation_commit(owner, generation);
	if (error) {
		nfsd_ffv2_generation_cancel(owner, generation);
		nfsd_ffv2_service_context_release(context);
		goto out_update;
	}
	nfsd_ffv2_generation_put(generation);
	*generation_id = prepared_generation;
	goto out_update;

out_reopen:
	if (expected)
		nfsd_ffv2_export_transition_abort_exact(expected);

out_update:
	nfsd_ffv2_export_update_put(&transaction);
	return error;
}

static int nfsd_ffv2_object_validate(struct svc_export *exp,
				     struct nfsd_ffv2_object *object)
{
	struct inode *inode = d_inode(object->object_path.dentry);

	if (!path_equal(&exp->ex_path, &object->export_path) ||
	    object->export_path.mnt != object->object_path.mnt ||
	    object->export_path.mnt->mnt_sb !=
					object->object_path.mnt->mnt_sb ||
	    object->export_path.dentry == object->object_path.dentry ||
	    !d_is_reg(object->object_path.dentry) ||
	    d_unlinked(object->object_path.dentry) ||
	    READ_ONCE(inode->i_nlink) != 1 ||
	    !path_is_under(&object->object_path, &exp->ex_path))
		return -ESTALE;
	return 0;
}

int nfsd_ffv2_object_register(struct nfsd_net *nn,
			      struct nfsd_ffv2_export_update *registration,
			      struct nfsd_ffv2_object *object,
			      const struct nfsd_ffv2_object_request *request,
			      struct knfsd_fh *outer_fh, u64 *generation_id)
{
	struct svc_export template, *exp;
	struct svc_fh ordinary;
	__be32 status;
	int error;

	if (!nn || !registration || !object || !request || !outer_fh ||
	    !generation_id || !request->auth_domain || !request->export_path ||
	    !request->object_path || !request->object_uuid ||
	    !request->store_uuid || !request->binding_token ||
	    !registration->admitted || !registration->registration_slot ||
	    !nn->svc_export_cache) {
		error = -EINVAL;
		goto out_free;
	}

	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_AUTH_DOMAIN)) {
		error = -ENOMEM;
		goto out_free;
	}
	object->client = auth_domain_find((char *)request->auth_domain);
	if (!object->client) {
		error = -ENOENT;
		goto out_free;
	}
	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_EXPORT_PATH)) {
		error = -EIO;
		goto out_free;
	}
	error = kern_path(request->export_path, LOOKUP_NO_SYMLINKS,
			  &object->export_path);
	if (error)
		goto out_free;
	object->export_valid = true;
	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_OBJECT_PATH)) {
		error = -EIO;
		goto out_free;
	}
	error = kern_path(request->object_path, LOOKUP_NO_SYMLINKS,
			  &object->object_path);
	if (error)
		goto out_free;
	object->object_valid = true;
	memcpy(object->object_uuid, request->object_uuid,
	       sizeof(object->object_uuid));

	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_EXPORT_LOOKUP)) {
		error = -EIO;
		goto out_free;
	}
	exp = nfsd_ffv2_export_lookup(nn->svc_export_cache, object->client,
				      &object->export_path);
	if (IS_ERR(exp)) {
		error = PTR_ERR(exp);
		goto out_free;
	}
	error = nfsd_ffv2_object_validate(exp, object);
	if (error)
		goto out_put_exp;
	memcpy(object->export_uuid, exp->ex_uuid, sizeof(object->export_uuid));

	fh_init(&ordinary, NFS4_FHSIZE);
	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_FH_COMPOSE)) {
		error = -EIO;
		goto out_put_fh;
	}
	status = fh_compose(&ordinary, exp, object->object_path.dentry, NULL);
	if (status) {
		error = -ESTALE;
		goto out_put_fh;
	}
	object->inner_fh = ordinary.fh_handle;
	if (object->inner_fh.fh_size < 8 ||
	    object->inner_fh.fh_size > NFSD_FFV2_FH_INNER_MAX ||
	    object->inner_fh.fh_size & 3) {
		error = -E2BIG;
		goto out_put_fh;
	}
	fh_put(&ordinary);

	error = nfsd_ffv2_export_transition_exact(exp);
	if (error)
		goto out_put_exp;
	error = nfsd_ffv2_live_test_checkpoint(NFSD_FFV2_LIVE_TEST_TRANSITION,
					       exp);
	if (error)
		goto out_reopen;
	error = nfsd_ffv2_object_validate(exp, object);
	if (error)
		goto out_reopen;
	if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_TEMPLATE_CLONE)) {
		error = -ENOMEM;
		goto out_reopen;
	}
	error = nfsd_ffv2_export_template_clone(&template, exp);
	if (error)
		goto out_reopen;
	error = __nfsd_ffv2_service_export_publish(nn, &template,
						   &object->export_path,
						   request->store_uuid,
						   request->binding_token,
						   current_cred(),
						   request->control_root,
						   generation_id, true, exp,
						   registration, object, outer_fh);
	nfsd_ffv2_export_template_free(&template);
	if (error)
		goto out_put_exp;
	exp_put(exp);
	return 0;

out_reopen:
	nfsd_ffv2_export_transition_abort_exact(exp);
out_put_exp:
	exp_put(exp);
out_free:
	nfsd_ffv2_object_free(object);
	return error;
out_put_fh:
	fh_put(&ordinary);
	goto out_put_exp;
}

void nfsd_ffv2_binding_get(struct nfsd_ffv2_binding *binding)
{
	refcount_inc(&binding->ref);
}

void nfsd_ffv2_binding_put(struct nfsd_ffv2_binding *binding)
{
	if (!refcount_dec_and_test(&binding->ref))
		return;
	nfsd_ffv2_complete(&binding->admission);
	put_net(binding->net);
	kfree(binding);
}

static int nfsd_ffv2_binding_admit(struct nfsd_net *nn,
				   const struct nfsd_ffv2_fh_info *info,
				   struct nfsd_ffv2_binding *binding)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_service_context *context;
	struct nfsd_ffv2_object *object;
	int error = -ESTALE;

	INIT_LIST_HEAD(&binding->admission.node);
	if (!nfsd_ffv2_anchor_get(anchor))
		return -ESHUTDOWN;
	mutex_lock(&anchor->lock);
	generation = anchor->active;
	if (!generation || !generation->registry_generation ||
	    generation->identity->generation != info->generation ||
	    memcmp(generation->identity->object_uuid, info->object_uuid,
		   sizeof(generation->identity->object_uuid)) ||
	    memcmp(generation->identity->export_uuid, info->export_uuid,
		   sizeof(generation->identity->export_uuid)))
		goto out_unlock;
	context = generation->payload;
	if (!context || !context->object)
		goto out_unlock;
	mutex_lock(&nfsd_ffv2_registry_lock);
	object = context->object;
	if (!object->visible || object->inner_fh.fh_size != info->inner_len ||
	    memcmp(object->inner_fh.fh_raw, info->inner, info->inner_len)) {
		mutex_unlock(&nfsd_ffv2_registry_lock);
		goto out_unlock;
	}
	refcount_inc(&generation->ref);
	atomic_inc(&generation->admitted);
	binding->object = object;
	binding->admission.anchor = anchor;
	binding->admission.generation = generation;
	binding->admission.task = current;
	spin_lock(&generation->admissions_lock);
	list_add(&binding->admission.node, &generation->admissions);
	spin_unlock(&generation->admissions_lock);
	mutex_unlock(&nfsd_ffv2_registry_lock);
	error = 0;
out_unlock:
	mutex_unlock(&anchor->lock);
	if (error)
		nfsd_ffv2_anchor_put(anchor);
	return error;
}

static bool nfsd_ffv2_binding_current(struct nfsd_net *nn,
				      struct nfsd_ffv2_binding *binding)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	bool valid;

	mutex_lock(&anchor->lock);
	mutex_lock(&nfsd_ffv2_registry_lock);
	valid = anchor->active == binding->admission.generation &&
		binding->object->visible;
	mutex_unlock(&nfsd_ffv2_registry_lock);
	mutex_unlock(&anchor->lock);
	return valid;
}

__be32 nfsd_ffv2_fh_map(struct svc_rqst *rqstp, struct svc_fh *fhp)
{
	struct nfsd_ffv2_binding *binding;
	struct nfsd_ffv2_fh_info info;
	struct knfsd_fh outer;
	struct nfsd_net *nn;
	struct net *net;
	__be32 status;
	int error;

	outer = fhp->fh_handle;
	error = nfsd_ffv2_fh_parse(&outer, &info);
	if (error)
		return nfserr_badhandle;
	binding = kzalloc_obj(*binding, GFP_KERNEL);
	if (!binding)
		return nfserr_jukebox;
	refcount_set(&binding->ref, 1);
	net = maybe_get_net(SVC_NET(rqstp));
	if (!net) {
		kfree(binding);
		return nfserr_stale;
	}
	binding->net = net;
	nn = net_generic(net, nfsd_net_id);
	error = nfsd_ffv2_binding_admit(nn, &info, binding);
	if (error) {
		status = nfserr_stale;
		goto out_binding;
	}

	fhp->fh_handle = binding->object->inner_fh;
	status = fh_verify_ffv2_mapped(rqstp, fhp, 0,
				       NFSD_MAY_BYPASS_GSS);
	if (status)
		goto out_fh;
	if (!fhp->fh_export->ex_uuid ||
	    memcmp(fhp->fh_export->ex_uuid, binding->object->export_uuid,
		   sizeof(binding->object->export_uuid)) ||
	    fhp->fh_export->ex_client != binding->object->client ||
	    fhp->fh_dentry != binding->object->object_path.dentry ||
	    nfsd_ffv2_object_validate(fhp->fh_export, binding->object)) {
		status = nfserr_stale;
		goto out_fh;
	}
	if (!nfsd_ffv2_binding_current(nn, binding)) {
		status = nfserr_stale;
		goto out_fh;
	}
	fhp->fh_handle = outer;
	fhp->fh_ffv2_binding = binding;
	return nfs_ok;

out_fh:
	fh_put(fhp);
	nfsd_ffv2_complete(&binding->admission);
out_binding:
	put_net(binding->net);
	kfree(binding);
	return status;
}

int nfsd_ffv2_service_export_publish(struct nfsd_net *owner,
				     struct svc_export *exp,
				     const struct path *root,
				     const u8 store_uuid[16],
				     const u8 binding_token[32],
				     const struct cred *cred, u64 control_root,
				     u64 *generation_id)
{
	return __nfsd_ffv2_service_export_publish(owner, exp, root, store_uuid,
						  binding_token, cred,
						  control_root, generation_id,
						  true, NULL, NULL, NULL, NULL);
}

void nfsd_ffv2_service_context_release(void *payload)
{
	struct nfsd_ffv2_service_context *context = payload;
	struct svc_export *exp = context->export;

	if (exp) {
		mutex_lock(&nfsd_ffv2_export_policy_lock);
		rcu_assign_pointer(exp->ex_ffv2_context, NULL);
		mutex_unlock(&nfsd_ffv2_export_policy_lock);
		synchronize_rcu();
		nfsd_ffv2_live_test_checkpoint(NFSD_FFV2_LIVE_TEST_CONTEXT_CLEAR,
					       exp);
		nfsd_export_unhash(exp);
		nfsd_export_put(exp);
		wait_for_completion(&context->export_released);
	}
	put_cred(context->cred);
	nfsd_ffv2_reservation_fence(context->reservation);
	if (context->object_owned)
		nfsd_ffv2_object_free(context->object);
	kfree(context);
}

__be32 nfsd4_ffv2_export_policy_check(struct svc_export *exp, u32 opnum)
{
	if (!nfsd_ffv2_export_is_service(exp))
		return nfs_ok;
	nfsd_ffv2_live_test_checkpoint(NFSD_FFV2_LIVE_TEST_POLICY, exp);
	switch (opnum) {
	case OP_PUTFH:
	case OP_PUTROOTFH:
	case OP_PUTPUBFH:
	case OP_SAVEFH:
	case OP_RESTOREFH:
		return nfs_ok;
	default:
		return nfserr_notsupp;
	}
}

static void
nfsd_ffv2_participant_put(struct nfsd_ffv2_participant *participant)
{
	if (refcount_dec_and_test(&participant->ref))
		complete(&participant->released);
}

static void
nfsd_ffv2_updates_set_open(struct nfsd_ffv2_participant *participant,
			   bool open)
{
	spin_lock(&participant->update_lock);
	if (participant->updates_open != open) {
		participant->updates_open = open;
		participant->update_epoch++;
		if (!participant->update_epoch)
			participant->update_epoch++;
	}
	spin_unlock(&participant->update_lock);
}

static void
nfsd_ffv2_updates_wait(struct nfsd_ffv2_participant *participant)
{
	wait_event(participant->update_wait,
		   !READ_ONCE(participant->update_count));
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

int nfsd_ffv2_participant_register(struct nfsd_net *nn, struct net *net)
{
	struct nfsd_ffv2_participant *participant = &nn->ffv2_participant;

	INIT_LIST_HEAD(&participant->node);
	INIT_LIST_HEAD(&participant->reservations);
	refcount_set(&participant->ref, 1);
	init_completion(&participant->released);
	spin_lock_init(&participant->update_lock);
	init_waitqueue_head(&participant->update_wait);
	participant->update_count = 0;
	participant->update_epoch = 1;
	participant->updates_open = true;
	mutex_init(&participant->inventory_lock);
	INIT_LIST_HEAD(&participant->inventory);
	init_waitqueue_head(&participant->inventory_wait);
	participant->inventory_count = 0;
	participant->net = net;
	WRITE_ONCE(participant->attached, true);

	mutex_lock(&nfsd_ffv2_registry_lock);
	list_add_tail(&participant->node, &nfsd_ffv2_participants);
	mutex_unlock(&nfsd_ffv2_registry_lock);
	return 0;
}

void nfsd_ffv2_participant_detach_begin(struct nfsd_net *nn)
{
	struct nfsd_ffv2_participant *participant = &nn->ffv2_participant;

	nfsd_ffv2_updates_set_open(participant, false);
	nfsd_ffv2_updates_wait(participant);
	mutex_lock(&nfsd_ffv2_registry_lock);
	WRITE_ONCE(participant->attached, false);
	if (!list_empty(&participant->node))
		list_del_init(&participant->node);
	mutex_unlock(&nfsd_ffv2_registry_lock);
	nfsd_ffv2_fence_owned_reservations(participant);

	nfsd_ffv2_participant_put(participant);
	wait_for_completion(&participant->released);
}

void nfsd_ffv2_participant_detach_finish(struct nfsd_net *nn)
{
	struct nfsd_ffv2_participant *participant = &nn->ffv2_participant;

	wait_event(participant->inventory_wait,
		   !READ_ONCE(participant->inventory_count));
	WARN_ON_ONCE(!list_empty(&participant->reservations));
	participant->net = NULL;
	mutex_destroy(&participant->inventory_lock);
}

static int
nfsd_ffv2_export_update_admit(struct nfsd_ffv2_participant *participant,
			      struct nfsd_ffv2_export_update *update)
{
	int error = 0;

	spin_lock(&participant->update_lock);
	if (!participant->updates_open || !READ_ONCE(participant->attached)) {
		error = -ESHUTDOWN;
	} else {
		participant->update_count++;
		update->participant = participant;
		update->epoch = participant->update_epoch;
		update->admitted = true;
	}
	spin_unlock(&participant->update_lock);
	return error;
}

static void
nfsd_ffv2_export_update_put(struct nfsd_ffv2_export_update *update)
{
	struct nfsd_ffv2_participant *participant = update->participant;
	bool wake = false;

	if (!update->admitted)
		return;
	spin_lock(&participant->update_lock);
	if (WARN_ON_ONCE(!participant->update_count)) {
		spin_unlock(&participant->update_lock);
		return;
	}
	participant->update_count--;
	wake = !participant->update_count;
	update->admitted = false;
	spin_unlock(&participant->update_lock);
	if (wake)
		wake_up_all(&participant->update_wait);
}

int nfsd_ffv2_registration_begin(struct nfsd_net *nn,
				 struct nfsd_ffv2_export_update *registration)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	int error;

	lockdep_assert_held(&nfsd_mutex);
	memset(registration, 0, sizeof(*registration));
	error = nfsd_ffv2_export_update_admit(&nn->ffv2_participant,
					      registration);
	if (error)
		return error;
	mutex_lock(&anchor->lock);
	if (anchor->net_state != NFSD_FFV2_NET_LIVE ||
	    anchor->service_state != NFSD_FFV2_SERVICE_UP) {
		error = -ESHUTDOWN;
	} else if (anchor->registration_pending || anchor->pending ||
		   anchor->active || anchor->retiring) {
		error = -EBUSY;
	} else {
		anchor->registration_pending = true;
		registration->registration_slot = true;
		error = 0;
	}
	mutex_unlock(&anchor->lock);
	if (error)
		nfsd_ffv2_export_update_put(registration);
	return error;
}

void nfsd_ffv2_registration_end(struct nfsd_net *nn,
				struct nfsd_ffv2_export_update *registration)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	if (registration->registration_slot) {
		mutex_lock(&anchor->lock);
		WARN_ON_ONCE(!anchor->registration_pending);
		anchor->registration_pending = false;
		registration->registration_slot = false;
		mutex_unlock(&anchor->lock);
	}
	nfsd_ffv2_export_update_put(registration);
}

int nfsd_ffv2_export_update_begin(struct svc_export *exp,
				  struct svc_export *old,
				  struct nfsd_ffv2_export_update *update)
{
	struct nfsd_net *nn = net_generic(exp->cd->net, nfsd_net_id);
	struct nfsd_ffv2_participant *participant = &nn->ffv2_participant;
	struct nfsd_ffv2_service_context *context =
		rcu_access_pointer(exp->ex_ffv2_context);
	struct nfsd_ffv2_service_context *old_context;
	int error;

	lockdep_assert_not_held(&nfsd_mutex);
	memset(update, 0, sizeof(*update));
	error = nfsd_ffv2_export_update_admit(participant, update);
	if (error)
		return error;
	if (context) {
		update->reservation = context->reservation;
		mutex_lock(&context->reservation->entry_lock);
		update->entry_locked = true;
	}
	mutex_lock(&nfsd_ffv2_export_policy_lock);
	update->policy_locked = true;
	old_context = rcu_access_pointer(old->ex_ffv2_context);
	if (!READ_ONCE(participant->attached)) {
		error = -ESHUTDOWN;
		goto out_abort;
	}
	if (old_context) {
		error = test_bit(CACHE_NEGATIVE, &exp->h.flags) ?
			-EAGAIN : -EBUSY;
		goto out_abort;
	}
	if (context &&
	    (test_bit(CACHE_NEGATIVE, &exp->h.flags) ||
	     context->reservation->sb != exp->ex_path.mnt->mnt_sb ||
	     READ_ONCE(context->reservation->state) != NFSD_FFV2_RESERVING)) {
		error = -EINVAL;
		goto out_abort;
	}
	if (!test_bit(CACHE_NEGATIVE, &exp->h.flags) && !context &&
	    nfsd_ffv2_superblock_reserved(exp->ex_path.mnt->mnt_sb)) {
		error = -EBUSY;
		goto out_abort;
	}
	return 0;

out_abort:
	nfsd_ffv2_export_update_abort(update);
	return error;
}

int nfsd_ffv2_export_update_validate(struct nfsd_ffv2_export_update *update)
{
	struct nfsd_ffv2_participant *participant = update->participant;
	int error = 0;

	spin_lock(&participant->update_lock);
	if (!participant->updates_open ||
	    participant->update_epoch != update->epoch)
		error = -ESHUTDOWN;
	spin_unlock(&participant->update_lock);
	return error;
}

int nfsd_ffv2_export_update_end(struct svc_export *exp,
				struct nfsd_ffv2_export_update *update)
{
	struct nfsd_net *nn = net_generic(exp->cd->net, nfsd_net_id);
	struct nfsd_ffv2_participant *participant = &nn->ffv2_participant;
	struct nfsd_ffv2_service_context *context =
		rcu_access_pointer(exp->ex_ffv2_context);
	struct nfsd_ffv2_reservation *reservation = update->reservation;
	bool activated = false;

	mutex_lock(&participant->inventory_lock);
	if (test_bit(CACHE_NEGATIVE, &exp->h.flags)) {
		if (exp->ex_ffv2_listed) {
			list_del_init(&exp->ex_ffv2_inventory);
			exp->ex_ffv2_listed = false;
			exp->ex_ffv2_participant = NULL;
			participant->inventory_count--;
			path_put(&exp->ex_ffv2_path);
		}
	} else if (!exp->ex_ffv2_listed) {
		exp->ex_ffv2_path = exp->ex_path;
		path_get(&exp->ex_ffv2_path);
		exp->ex_ffv2_participant = participant;
		exp->ex_ffv2_listed = true;
		list_add_tail(&exp->ex_ffv2_inventory,
			      &participant->inventory);
		participant->inventory_count++;
	}
	if (context) {
		WARN_ON_ONCE(context->published);
		context->export = nfsd_export_get(exp);
		context->published = true;
		exp->ex_ffv2_context_released = &context->export_released;
		nfsd_ffv2_export_transition_commit(exp);
	}
	mutex_unlock(&participant->inventory_lock);

	/* Revalidation must not nest the registry under sleeping policy locks. */
	if (update->policy_locked) {
		mutex_unlock(&nfsd_ffv2_export_policy_lock);
		update->policy_locked = false;
	}
	if (update->entry_locked) {
		mutex_unlock(&reservation->entry_lock);
		update->entry_locked = false;
	}
	if (context) {
		mutex_lock(&nfsd_ffv2_registry_lock);
		if (!list_empty(&reservation->node) &&
		    reservation->state == NFSD_FFV2_RESERVING &&
		    reservation->owner == participant &&
		    READ_ONCE(participant->attached)) {
			reservation->state = NFSD_FFV2_RESERVATION_ACTIVE;
			reservation->owner_generation = context->owner_generation;
			activated = true;
		}
		mutex_unlock(&nfsd_ffv2_registry_lock);
	}
	if (context && !activated) {
		mutex_lock(&nfsd_ffv2_export_policy_lock);
		rcu_assign_pointer(exp->ex_ffv2_context, NULL);
		mutex_unlock(&nfsd_ffv2_export_policy_lock);
		synchronize_rcu();
		nfsd_export_unhash(exp);
		nfsd_export_put(context->export);
		nfsd_ffv2_export_update_put(update);
		return -ESHUTDOWN;
	}
	nfsd_ffv2_export_update_put(update);
	if (activated)
		nfsd_ffv2_reservation_put(reservation);
	return 0;
}

void
nfsd_ffv2_export_update_rollback_wait(struct nfsd_ffv2_service_context *context)
{
	wait_for_completion(&context->export_released);
	context->export = NULL;
	context->published = false;
}

void nfsd_ffv2_export_update_abort(struct nfsd_ffv2_export_update *update)
{
	if (update->policy_locked) {
		mutex_unlock(&nfsd_ffv2_export_policy_lock);
		update->policy_locked = false;
	}
	if (update->entry_locked) {
		mutex_unlock(&update->reservation->entry_lock);
		update->entry_locked = false;
	}
	nfsd_ffv2_export_update_put(update);
}

void nfsd_ffv2_export_release(struct svc_export *exp)
{
	struct nfsd_ffv2_participant *participant = exp->ex_ffv2_participant;

	if (participant) {
		mutex_lock(&participant->inventory_lock);
		if (exp->ex_ffv2_listed) {
			list_del_init(&exp->ex_ffv2_inventory);
			exp->ex_ffv2_listed = false;
			exp->ex_ffv2_participant = NULL;
			participant->inventory_count--;
			path_put(&exp->ex_ffv2_path);
			if (!participant->inventory_count)
				wake_up_all(&participant->inventory_wait);
		}
		mutex_unlock(&participant->inventory_lock);
	}
	if (exp->ex_ffv2_context_released)
		complete(exp->ex_ffv2_context_released);
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
#endif

static struct nfsd_ffv2_generation *
nfsd_ffv2_generation_alloc(void *payload, void (*release)(void *),
			   const u8 object_uuid[16],
			   const u8 export_uuid[16])
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
	if (object_uuid)
		memcpy(identity->object_uuid, object_uuid,
		       sizeof(identity->object_uuid));
	if (export_uuid)
		memcpy(identity->export_uuid, export_uuid,
		       sizeof(identity->export_uuid));
	WRITE_ONCE(identity->state, NFSD_FFV2_IDENTITY_LIVE);
	refcount_set(&generation->ref, 1);
	generation->identity = identity;
	atomic_set(&generation->state, NFSD_FFV2_GENERATION_ACTIVE);
	atomic_set(&generation->admitted, 0);
	spin_lock_init(&generation->admissions_lock);
	INIT_LIST_HEAD(&generation->admissions);
	init_waitqueue_head(&generation->admitted_wait);
	init_completion(&generation->retired);
	generation->payload = payload;
	generation->release = release;
	generation->registry_generation = object_uuid && export_uuid;
	return generation;
}

static int
nfsd_ffv2_generation_prepare(struct nfsd_net *nn, void *payload,
			     void (*release)(void *),
			     const u8 object_uuid[16],
			     const u8 export_uuid[16],
			     struct nfsd_ffv2_generation **result,
			     u64 *generation_id)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	int error = 0;

	generation = nfsd_ffv2_generation_alloc(payload, release, object_uuid,
						export_uuid);
	if (!generation)
		return -ENOMEM;
	if (!nfsd_ffv2_anchor_get(anchor)) {
		error = -ESHUTDOWN;
		goto out_cancel;
	}
	mutex_lock(&anchor->lock);
	if (anchor->net_state != NFSD_FFV2_NET_LIVE ||
	    anchor->service_state == NFSD_FFV2_SERVICE_STOPPING ||
	    anchor->service_state == NFSD_FFV2_SERVICE_DRAIN_FAILED) {
		error = -ESHUTDOWN;
	} else if (anchor->service_state == NFSD_FFV2_SERVICE_DOWN) {
		error = -ENXIO;
	} else if (anchor->pending || anchor->active || anchor->retiring) {
		error = -EBUSY;
	} else if (!anchor->next_generation ||
		   anchor->next_generation == U64_MAX) {
		error = -EOVERFLOW;
	} else {
		generation->identity->generation = anchor->next_generation++;
		refcount_inc(&generation->ref);
		anchor->pending = generation;
	}
	mutex_unlock(&anchor->lock);
	nfsd_ffv2_anchor_put(anchor);
	if (error)
		goto out_cancel;
	*result = generation;
	if (generation_id)
		*generation_id = generation->identity->generation;
	return 0;

out_cancel:
	generation->payload = NULL;
	nfsd_ffv2_generation_put(generation);
	return error;
}

static int
nfsd_ffv2_generation_commit(struct nfsd_net *nn,
			    struct nfsd_ffv2_generation *generation)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	int error = 0;

	mutex_lock(&anchor->lock);
	if (anchor->pending != generation) {
		error = -ESTALE;
	} else if (anchor->net_state != NFSD_FFV2_NET_LIVE ||
		   anchor->service_state != NFSD_FFV2_SERVICE_UP) {
		error = -ESHUTDOWN;
	} else {
		anchor->pending = NULL;
		anchor->active = generation;
	}
	mutex_unlock(&anchor->lock);
	return error;
}

static void
nfsd_ffv2_generation_cancel(struct nfsd_net *nn,
			    struct nfsd_ffv2_generation *generation)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	bool pending = false;

	mutex_lock(&anchor->lock);
	if (anchor->pending == generation) {
		anchor->pending = NULL;
		pending = true;
	}
	mutex_unlock(&anchor->lock);
	generation->payload = NULL;
	if (pending)
		nfsd_ffv2_generation_put(generation);
	nfsd_ffv2_generation_put(generation);
}

static struct nfsd_ffv2_generation *
nfsd_ffv2_retire_begin_locked(struct nfsd_ffv2_anchor *anchor)
{
	struct nfsd_ffv2_generation *generation = anchor->active;

	lockdep_assert_held(&anchor->lock);
	if (generation) {
		struct nfsd_ffv2_service_context *context;

		if (generation->registry_generation) {
			context = generation->payload;
			mutex_lock(&nfsd_ffv2_registry_lock);
			if (context && context->object)
				context->object->visible = false;
			mutex_unlock(&nfsd_ffv2_registry_lock);
		}
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

static bool
nfsd_ffv2_retire_admissions_drained(struct nfsd_ffv2_generation *generation)
{
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	struct completion *waiting =
		READ_ONCE(generation->test_retire_waiting);

	if (waiting) {
		complete_all(waiting);
		if (kthread_should_stop())
			return true;
	}
#endif
	return atomic_read(&generation->admitted) == 0;
}

static void nfsd_ffv2_retire_finish(struct nfsd_ffv2_anchor *anchor,
				    struct nfsd_ffv2_generation *generation,
				    bool wait)
{
	bool unpublished = false;

	if (!generation)
		return;

	if (wait) {
		wait_event(generation->admitted_wait,
			   nfsd_ffv2_retire_admissions_drained(generation));
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
		if (READ_ONCE(generation->test_retire_waiting)) {
			WRITE_ONCE(generation->test_retire_waiting, NULL);
			if (kthread_should_stop())
				goto out_put;
		}
#endif
	} else if (WARN_ON_ONCE(atomic_read(&generation->admitted))) {
		goto out_put;
	}

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
	} else if (wait) {
		wait_for_completion(&generation->retired);
	}

out_put:
	nfsd_ffv2_generation_put(generation);
}

void nfsd_ffv2_net_init(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	refcount_set(&anchor->ref, 1);
	init_completion(&anchor->released);
	mutex_init(&anchor->lock);
	anchor->net_state = NFSD_FFV2_NET_LIVE;
	anchor->service_state = NFSD_FFV2_SERVICE_DOWN;
	anchor->next_generation = 1;
	anchor->pending = NULL;
	anchor->active = NULL;
	anchor->retiring = NULL;
	anchor->registration_pending = false;
}

void nfsd_ffv2_net_pre_exit(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;

	if (WARN_ON_ONCE(!nfsd_ffv2_anchor_get(anchor)))
		return;
	nfsd_ffv2_updates_set_open(&nn->ffv2_participant, false);
	nfsd_ffv2_updates_wait(&nn->ffv2_participant);
	mutex_lock(&anchor->lock);
	/* Pair with admission's lockless rejection before taking ->lock. */
	smp_store_release(&anchor->net_state, NFSD_FFV2_NET_EXITING);
	anchor->service_state = NFSD_FFV2_SERVICE_STOPPING;
	generation = nfsd_ffv2_retire_begin_locked(anchor);
	mutex_unlock(&anchor->lock);

	nfsd_ffv2_retire_finish(anchor, generation, true);
	nfsd_ffv2_anchor_put(anchor);
}

void nfsd_ffv2_net_destroy(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	mutex_lock(&anchor->lock);
	WARN_ON_ONCE(anchor->net_state != NFSD_FFV2_NET_EXITING);
	WARN_ON_ONCE(anchor->service_state != NFSD_FFV2_SERVICE_STOPPING);
	WARN_ON_ONCE(anchor->active);
	WARN_ON_ONCE(anchor->retiring);
	WARN_ON_ONCE(anchor->pending);
	WARN_ON_ONCE(anchor->registration_pending);
	mutex_unlock(&anchor->lock);
	nfsd_ffv2_anchor_put(anchor);
	wait_for_completion(&anchor->released);
	mutex_destroy(&anchor->lock);
}

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
	nfsd_ffv2_retire_finish(anchor, generation, true);
	nfsd_ffv2_anchor_put(anchor);
}

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

void nfsd_ffv2_service_stop_put(struct nfsd_ffv2_generation *generation)
{
	if (generation)
		nfsd_ffv2_generation_put(generation);
}

void nfsd_ffv2_service_down(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	lockdep_assert_held(&nfsd_mutex);
	if (WARN_ON_ONCE(!nfsd_ffv2_anchor_get(anchor)))
		return;
	mutex_lock(&anchor->lock);
	if (anchor->net_state == NFSD_FFV2_NET_LIVE)
		anchor->service_state = NFSD_FFV2_SERVICE_DOWN;
	mutex_unlock(&anchor->lock);
	nfsd_ffv2_anchor_put(anchor);
}

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

int nfsd_ffv2_register(struct nfsd_net *nn)
{
	lockdep_assert_held(&nfsd_mutex);
	(void)nn;
	return -EOPNOTSUPP;
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

int nfsd_ffv2_admit(struct svc_rqst *rqstp,
		    struct nfsd_ffv2_admission *admission)
{
	struct nfsd_net *nn;

	if (nfsd_current_rqst() != rqstp || !rqstp->rq_xprt)
		return -EOPNOTSUPP;
	nn = net_generic(rqstp->rq_xprt->xpt_net, nfsd_net_id);
	return nfsd_ffv2_admit_generation(nn, admission);
}

void nfsd_ffv2_complete(struct nfsd_ffv2_admission *admission)
{
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_anchor *anchor;

	/* Completion owns and consumes the admission exactly once. */
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

int nfsd_ffv2_service_generation_retire(struct nfsd_net *nn,
					u64 generation_id)
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
	nfsd_ffv2_retire_finish(anchor, generation, true);
	mutex_lock(&nfsd_mutex);
	nfsd_ffv2_anchor_put(anchor);
	return error;
}

int nfsd_ffv2_object_unregister(struct nfsd_net *nn, u64 generation_id,
				const u8 object_uuid[16])
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	int error = 0;

	lockdep_assert_held(&nfsd_mutex);
	if (!generation_id || !object_uuid)
		return -EINVAL;
	mutex_lock(&anchor->lock);
	generation = anchor->active;
	if (!generation ||
	    generation->identity->generation != generation_id)
		generation = anchor->retiring;
	if (!generation ||
	    generation->identity->generation != generation_id ||
	    memcmp(generation->identity->object_uuid, object_uuid,
		   sizeof(generation->identity->object_uuid)))
		error = -ENOENT;
	mutex_unlock(&anchor->lock);
	if (error)
		return error;
	return nfsd_ffv2_service_generation_retire(nn, generation_id);
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
int nfsd_ffv2_test_reservation_claim(struct nfsd_net *owner,
				     const struct path *root,
				     const u8 store_uuid[16],
				     const u8 binding_token[32],
				     struct nfsd_ffv2_reservation **result)
{
	return __nfsd_ffv2_reservation_claim(owner, root, store_uuid,
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

int
nfsd_ffv2_test_service_export_publish(struct nfsd_net *owner,
				      struct svc_export *exp,
				      const struct path *root,
				      const u8 store_uuid[16],
				      const u8 binding_token[32],
				      const struct cred *cred,
				      u64 control_root, u64 *generation_id)
{
	return __nfsd_ffv2_service_export_publish(owner, exp, root, store_uuid,
						  binding_token, cred,
						  control_root, generation_id,
						  false, NULL, NULL, NULL, NULL);
}

int nfsd_ffv2_test_transition_publish(struct nfsd_net *owner,
				      struct nfsd_ffv2_export_update *registration,
				      struct nfsd_ffv2_object *object,
				      struct knfsd_fh *outer_fh,
				      struct svc_export *template,
				      struct svc_export *expected,
				      const struct path *root,
				      const u8 store_uuid[16],
				      const u8 binding_token[32],
				      const struct cred *cred,
				      u64 control_root, u64 *generation_id)
{
	return __nfsd_ffv2_service_export_publish(owner, template, root,
						  store_uuid, binding_token,
						  cred, control_root,
						  generation_id, false,
						  expected, registration, object,
						  outer_fh);
}

int nfsd_ffv2_test_object_init(struct nfsd_ffv2_object *object,
			       struct auth_domain *client,
			       const struct path *export_path,
			       const struct path *object_path, const u8 *inner,
			       u16 inner_len, const u8 object_uuid[16],
			       const u8 export_uuid[16])
{
	if (!object || !client || !export_path || !object_path || !inner ||
	    inner_len < 8 ||
	    inner_len > NFSD_FFV2_FH_INNER_MAX || inner_len & 3)
		return -EINVAL;
	kref_get(&client->ref);
	object->client = client;
	object->export_path = *export_path;
	path_get(&object->export_path);
	object->export_valid = true;
	object->object_path = *object_path;
	path_get(&object->object_path);
	object->object_valid = true;
	object->inner_fh.fh_size = inner_len;
	memcpy(object->inner_fh.fh_raw, inner, inner_len);
	memcpy(object->object_uuid, object_uuid, sizeof(object->object_uuid));
	memcpy(object->export_uuid, export_uuid, sizeof(object->export_uuid));
	return 0;
}

struct nfsd_ffv2_binding *
nfsd_ffv2_test_binding_create(struct nfsd_net *nn,
			      const struct nfsd_ffv2_fh_info *info)
{
	struct nfsd_ffv2_binding *binding;
	int error;

	binding = kzalloc_obj(*binding, GFP_KERNEL);
	if (!binding)
		return ERR_PTR(-ENOMEM);
	refcount_set(&binding->ref, 1);
	binding->net = maybe_get_net(nn->ffv2_participant.net);
	if (!binding->net) {
		kfree(binding);
		return ERR_PTR(-ESHUTDOWN);
	}
	error = nfsd_ffv2_binding_admit(nn, info, binding);
	if (error) {
		put_net(binding->net);
		kfree(binding);
		return ERR_PTR(error);
	}
	return binding;
}

int nfsd_ffv2_test_publish(struct nfsd_net *nn, void *payload,
			   void (*release)(void *), u64 *generation_id)
{
	struct nfsd_ffv2_generation *generation;
	int error;

	lockdep_assert_held(&nfsd_mutex);
	error = nfsd_ffv2_generation_prepare(nn, payload, release, NULL, NULL,
					     &generation, generation_id);
	if (error)
		return error;
	error = nfsd_ffv2_generation_commit(nn, generation);
	if (error) {
		nfsd_ffv2_generation_cancel(nn, generation);
		return error;
	}
	nfsd_ffv2_generation_put(generation);
	return 0;
}

int nfsd_ffv2_test_admit(struct nfsd_net *nn,
			 struct nfsd_ffv2_admission *admission)
{
	return nfsd_ffv2_admit_generation(nn, admission);
}

void nfsd_ffv2_test_complete(struct nfsd_ffv2_admission *admission)
{
	nfsd_ffv2_complete(admission);
}

int nfsd_ffv2_test_unregister(struct nfsd_net *nn, u64 generation_id)
{
	return nfsd_ffv2_service_generation_retire(nn, generation_id);
}

int nfsd_ffv2_test_retire_waiting(struct nfsd_net *nn, u64 generation_id,
				  struct completion *waiting)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	int error = -ENOENT;

	mutex_lock(&anchor->lock);
	generation = anchor->active;
	if (generation && generation->identity->generation == generation_id) {
		WRITE_ONCE(generation->test_retire_waiting, waiting);
		error = 0;
	}
	mutex_unlock(&anchor->lock);
	return error;
}

bool
nfsd_ffv2_test_generation_retired(struct nfsd_ffv2_generation *generation)
{
	/* Pair with retirement publication before dereferencing an identity. */
	return smp_load_acquire(&generation->identity->state) ==
			NFSD_FFV2_IDENTITY_RETIRED;
}

bool
nfsd_ffv2_test_admission_retired(struct nfsd_ffv2_admission *admission)
{
	return nfsd_ffv2_test_generation_retired(admission->generation);
}

unsigned int nfsd_ffv2_test_refcount(struct nfsd_ffv2_admission *admission)
{
	return refcount_read(&admission->generation->ref);
}

unsigned int nfsd_ffv2_test_anchor_refcount(struct nfsd_net *nn)
{
	return refcount_read(&nn->ffv2.ref);
}

/**
 * nfsd_ffv2_test_set_start_failure - arm a test-only service-start failure
 * @fail: whether the next successful worker adjustment should fail
 */
void nfsd_ffv2_test_set_start_failure(bool fail)
{
	atomic_set(&nfsd_ffv2_start_failure, fail);
}

/**
 * nfsd_ffv2_test_start_failure - consume a test-only service-start failure
 *
 * Return: true when the current worker adjustment should report failure.
 */
bool nfsd_ffv2_test_start_failure(void)
{
	return atomic_xchg(&nfsd_ffv2_start_failure, 0);
}

void nfsd_ffv2_test_fault_arm(enum nfsd_ffv2_fault_phase phase)
{
	nfsd_ffv2_fault_arm(phase);
}
#endif
