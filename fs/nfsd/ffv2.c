// SPDX-License-Identifier: GPL-2.0-only
#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/lockdep.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/lockd/bind.h>
#include <linux/mount.h>
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
	void				*payload;
	void				(*release)(void *payload);
};

static DEFINE_MUTEX(nfsd_ffv2_registry_lock);
static DEFINE_MUTEX(nfsd_ffv2_export_policy_lock);
static LIST_HEAD(nfsd_ffv2_participants);
static LIST_HEAD(nfsd_ffv2_reservations);

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
	    inner_len < 4 || inner_len > NFSD_FFV2_FH_INNER_MAX ||
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

	if (!info->generation || !info->inner || info->inner_len < 4 ||
	    info->inner_len > NFSD_FFV2_FH_INNER_MAX || info->inner[0] != 1)
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
	const struct cred	*cred;
	struct completion	export_released;
	u64			control_root;
	u64			owner_generation;
	bool			published;
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
			     struct nfsd_ffv2_generation **result,
			     u64 *generation_id);
static int
nfsd_ffv2_generation_commit(struct nfsd_net *nn,
			    struct nfsd_ffv2_generation *generation);
static void
nfsd_ffv2_generation_cancel(struct nfsd_net *nn,
			    struct nfsd_ffv2_generation *generation);
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
	error = nfsd_file_ffv2_gate_begin(&reservation->file_gate,
					  reservation->sb);
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
	error = nfsd_file_ffv2_gate_wait(&reservation->file_gate);
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
			     unsigned int count, struct super_block *sb)
{
	unsigned int i;

	for (i = 0; i < count; i++) {
		struct nfsd_ffv2_participant *participant =
			snapshots[i].participant;
		struct svc_export *exp;

		mutex_lock(&participant->inventory_lock);
		list_for_each_entry(exp, &participant->inventory,
				    ex_ffv2_inventory) {
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
					 bool validate_backend)
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
	if (nfsd_ffv2_snapshot_conflicts(snapshots, count, reservation->sb))
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
					     result, true);
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

static void
nfsd_ffv2_service_context_prepare_export(struct nfsd_ffv2_service_context *context,
					 struct svc_export *exp)
{
	if (WARN_ON_ONCE(rcu_access_pointer(exp->ex_ffv2_context)))
		return;
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

static int
__nfsd_ffv2_service_export_publish(struct nfsd_net *owner,
				   struct svc_export *exp,
				   const struct path *root,
				   const u8 store_uuid[16],
				   const u8 binding_token[32],
				   const struct cred *cred,
				   u64 control_root, u64 *generation_id,
				   bool validate_backend)
{
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
	error = __nfsd_ffv2_reservation_claim(owner, root, store_uuid,
					      binding_token, &reservation,
					      validate_backend);
	if (error)
		goto out_update;
	context = nfsd_ffv2_service_context_alloc(reservation, cred,
						  control_root, 0);
	if (!context) {
		nfsd_ffv2_reservation_abort(reservation);
		error = -ENOMEM;
		goto out_update;
	}
	error = nfsd_ffv2_generation_prepare(owner, context,
					     nfsd_ffv2_service_context_release,
					     &generation, &prepared_generation);
	if (error) {
		nfsd_ffv2_service_context_abort(context, NULL);
		nfsd_ffv2_reservation_abort(reservation);
		goto out_update;
	}
	context->owner_generation = prepared_generation;
	nfsd_ffv2_service_context_prepare_export(context, exp);
	published = nfsd_export_cache_update(exp);
	if (IS_ERR(published)) {
		error = PTR_ERR(published);
		nfsd_ffv2_generation_cancel(owner, generation);
		nfsd_ffv2_service_context_abort(context, exp);
		nfsd_ffv2_reservation_abort(reservation);
		goto out_update;
	}
	nfsd_export_put(published);
	error = nfsd_ffv2_generation_commit(owner, generation);
	if (error) {
		nfsd_ffv2_generation_cancel(owner, generation);
		nfsd_ffv2_service_context_release(context);
		goto out_update;
	}
	nfsd_ffv2_generation_put(generation);
	*generation_id = prepared_generation;

out_update:
	nfsd_ffv2_export_update_put(&transaction);
	return error;
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
						  true);
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
		nfsd_export_unhash(exp);
		nfsd_export_put(exp);
		wait_for_completion(&context->export_released);
	}
	put_cred(context->cred);
	nfsd_ffv2_reservation_fence(context->reservation);
	kfree(context);
}

__be32 nfsd4_ffv2_export_policy_check(struct svc_export *exp, u32 opnum)
{
	bool service_context;

	(void)opnum;
	rcu_read_lock();
	service_context = rcu_access_pointer(exp->ex_ffv2_context);
	rcu_read_unlock();
	return service_context ? nfserr_notsupp : nfs_ok;
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

	mutex_lock(&nfsd_ffv2_registry_lock);
	WRITE_ONCE(participant->attached, false);
	if (!list_empty(&participant->node))
		list_del_init(&participant->node);
	mutex_unlock(&nfsd_ffv2_registry_lock);
	nfsd_ffv2_updates_set_open(participant, false);
	nfsd_ffv2_updates_wait(participant);
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
	generation->payload = payload;
	generation->release = release;
	return generation;
}

static int
nfsd_ffv2_generation_prepare(struct nfsd_net *nn, void *payload,
			     void (*release)(void *),
			     struct nfsd_ffv2_generation **result,
			     u64 *generation_id)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	int error = 0;

	generation = nfsd_ffv2_generation_alloc(payload, release);
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

static void nfsd_ffv2_retire_finish(struct nfsd_ffv2_anchor *anchor,
				    struct nfsd_ffv2_generation *generation,
				    bool wait)
{
	bool unpublished = false;

	if (!generation)
		return;

	if (wait) {
		wait_event(generation->admitted_wait,
			   atomic_read(&generation->admitted) == 0);
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

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
int nfsd_ffv2_test_reservation_claim(struct nfsd_net *owner,
				     const struct path *root,
				     const u8 store_uuid[16],
				     const u8 binding_token[32],
				     struct nfsd_ffv2_reservation **result)
{
	return __nfsd_ffv2_reservation_claim(owner, root, store_uuid,
					     binding_token, result, false);
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
						  false);
}

int nfsd_ffv2_test_publish(struct nfsd_net *nn, void *payload,
			   void (*release)(void *), u64 *generation_id)
{
	struct nfsd_ffv2_generation *generation;
	int error;

	lockdep_assert_held(&nfsd_mutex);
	error = nfsd_ffv2_generation_prepare(nn, payload, release,
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
#endif
