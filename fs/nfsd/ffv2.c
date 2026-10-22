// SPDX-License-Identifier: GPL-2.0-only
#include <linux/cred.h>
#include <linux/crc32.h>
#include <linux/namei.h>
#include <linux/rhashtable.h>
#include <linux/workqueue.h>
#include <linux/sunrpc/gss_api.h>
#include <linux/sunrpc/auth_gss.h>
#include <linux/sunrpc/msg_prot.h>
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
#include "ffv2_store.h"
#include "ffv2_trust.h"
#include "filecache.h"
#include "export.h"
#include "nfsd.h"
#include "netns.h"
#include "nfsfh.h"
#include "state.h"
#include "vfs.h"
#include "xdr4.h"

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

struct nfsd_ffv2_provider {
	const struct nfsd_ffv2_provider_ops *ops;
	void *data;
	u32 chunk_size;
	refcount_t ref;
	struct completion gone;
};

/* Drop a callback's reference, releasing a removal waiting on the last. */
static void nfsd_ffv2_provider_put(struct nfsd_ffv2_provider *provider)
{
	if (refcount_dec_and_test(&provider->ref))
		complete(&provider->gone);
}

static bool nfsd_ffv2_provider_shutdown(struct nfsd_net *nn);

enum nfsd_ffv2_unregister_kind {
	NFSD_FFV2_UNREGISTER_NONE,
	NFSD_FFV2_UNREGISTER_OBJECT,
	NFSD_FFV2_UNREGISTER_PROTOTYPE,
};

struct nfsd_ffv2_object {
	/* Bytes in one chunk of this object; zero when it is not known. */
	u32 chunk_size;
	struct path export_path;
	struct path object_path;
	struct knfsd_fh inner_fh;
	struct auth_domain *client;
	u8 object_uuid[16];
	u8 export_uuid[16];
	bool export_valid;
	bool object_valid;
	bool visible;
};

struct nfsd_ffv2_trust_key {
	stateid_t stateid;
	u8 object_uuid[16];
	u64 authority_epoch;
};

enum nfsd_ffv2_trust_state {
	NFSD_FFV2_TRUST_LIVE,
	NFSD_FFV2_TRUST_REPLACED,
	NFSD_FFV2_TRUST_REVOKED,
};

struct nfsd_ffv2_trust_entry {
	struct rhash_head node;
	struct rcu_head rcu;
	/* Off-list staging for entries dropped outside the update mutex. */
	struct list_head dispose;
	refcount_t ref;
	struct nfsd_ffv2_trust_key key;
	u64 generation_id;
	clientid_t pnfs_clientid;
	u32 client_id;
	u32 iomode;
	u32 profile_mask;
	enum nfsd_ffv2_caller_class actor;
	struct timespec64 expires;
	char *principal;
	size_t principal_len;
	atomic_t state;
	struct nfsd_ffv2_authority *authority;
	struct nfsd_ffv2_object *object;
	struct nfsd_ffv2_trust_registry *registry;
};

struct nfsd_ffv2_trust_registry {
	/* Completes the final wake before the enclosing context can disappear. */
	spinlock_t drain_lock;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	struct nfsd_net *test_nn;
#endif
	struct rhashtable table;
	/* Serializes install, renewal, revoke, and retirement. */
	struct mutex update_lock;
	unsigned int entries;
	/*
	 * Closeable admission count: one per live entry, plus one per
	 * in-flight install.  An RCU grace period does not cover a
	 * reference taken before it began, so destruction waits on this
	 * rather than on RCU alone.  The drain predicate takes only
	 * drain_lock: wait_event() evaluates its condition with the task
	 * already set !TASK_RUNNING, where a sleeping mutex is illegal.
	 */
	atomic_t admissions;
	wait_queue_head_t drain_wait;
	size_t principal_bytes;
	bool live;
};

struct nfsd_ffv2_object_set {
	u32 count;
	struct nfsd_ffv2_object *objects[NFSD_FFV2_MAX_OBJECTS];
};

struct nfsd_ffv2_service_context {
	struct nfsd_ffv2_trust_registry trust;
	/*
	 * The namespace this context was published in.  Non-owning: the
	 * generation this context is the payload of is drained by that
	 * namespace's own exit fence, so the pointer cannot outlive it.
	 */
	struct nfsd_net *nn;
	struct nfsd_ffv2_reservation *reservation;
	struct svc_export *export;
	struct nfsd_ffv2_object_set objects;
	struct nfsd_ffv2_authority *authority;
	const struct cred *cred;
	struct completion export_released;
	u64 control_root;
	u64 owner_generation;
	bool published;
	bool objects_owned;
	/*
	 * Set when publication transferred the namespace's MDS source
	 * reservation to this context.  The reservation then lives as long as
	 * the generation does and is released once, here, at retirement.
	 */
	bool source_claimed;
};

static struct nfsd_ffv2_object *nfsd_ffv2_object_set_find(const struct nfsd_ffv2_object_set *set,
							  const u8 object_uuid[16])
{
	struct nfsd_ffv2_object *found = NULL;
	u32 i;

	for (i = 0; i < set->count; i++) {
		struct nfsd_ffv2_object *object = set->objects[i];

		if (!object || memcmp(object->object_uuid, object_uuid, 16))
			continue;
		if (found)
			return NULL;
		found = object;
	}
	return found;
}

static void nfsd_ffv2_object_set_free(struct nfsd_ffv2_object_set *set)
{
	while (set->count) {
		struct nfsd_ffv2_object *object = set->objects[--set->count];

		set->objects[set->count] = NULL;
		nfsd_ffv2_object_free(object);
	}
}

enum nfsd_ffv2_authority_state {
	NFSD_FFV2_AUTHORITY_PREPARED,
	NFSD_FFV2_AUTHORITY_PUBLISHED,
	NFSD_FFV2_AUTHORITY_DEAD,
};

struct nfsd_ffv2_authority {
	refcount_t ref;
	struct nfsd_net *nn;
	struct nfs4_sessionid sessionid;
	clientid_t clientid;
	u64 epoch;
	u64 generation_id;
	struct svc_cred machine_cred;
	u32 exchange_flags;
	/* Leaf lock, nested under ->client_lock or the publication locks. */
	spinlock_t state_lock;
	enum nfsd_ffv2_authority_state state;
	bool linked;
	struct list_head session_link;
};

static const struct rhashtable_params nfsd_ffv2_trust_params = {
	.key_len = sizeof(struct nfsd_ffv2_trust_key),
	.key_offset = offsetof(struct nfsd_ffv2_trust_entry, key),
	.head_offset = offsetof(struct nfsd_ffv2_trust_entry, node),
	.automatic_shrinking = true,
};

static_assert(sizeof(struct nfsd_ffv2_trust_key) == sizeof(stateid_t) + 16 + sizeof(u64));

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
	u8 unregister_uuid[16];
	enum nfsd_ffv2_unregister_kind unregister_kind;
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
	bool registry_generation;
	void				*payload;
	void				(*release)(void *payload);
};

struct nfsd_ffv2_binding {
	refcount_t ref;
	struct net *net;
	struct nfsd_ffv2_admission admission;
	/* The admission, not just a generation reference, protects this object. */
	struct nfsd_ffv2_object *object;
	bool prototype_admitted;
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

static bool
nfsd_ffv2_generation_has_task(struct nfsd_ffv2_generation *generation, struct task_struct *task);
static void nfsd_ffv2_service_context_release(void *payload);
static void nfsd_ffv2_authority_put(struct nfsd_ffv2_authority *authority);
static void nfsd_ffv2_authority_detach(struct nfsd_ffv2_authority *authority);
static bool nfsd_ffv2_authority_publish(struct nfsd_ffv2_authority *authority, u64 generation_id);
static int
nfsd_ffv2_trust_registry_init(struct nfsd_ffv2_trust_registry *registry, struct nfsd_net *nn);
static void nfsd_ffv2_trust_registry_destroy(struct nfsd_ffv2_trust_registry *registry);

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
bool nfsd_ffv2_test_registration_fault(struct nfsd_net *nn,
				       enum nfsd_ffv2_test_registration_fault fault)
{
	struct nfsd_ffv2_registration_test *test = &nn->ffv2.test_registration;

	if (atomic_cmpxchg(&test->fault, fault, NFSD_FFV2_TEST_NONE) != fault)
		return false;
	atomic_set(&test->hit, fault);
	return true;
}
#endif

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

static int nfsd_ffv2_source_claim_locked(struct nfsd_net *nn, enum nfsd_ffv2_source want)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	int error;

	spin_lock(&anchor->prototype_gate_lock);
	error = nfsd_ffv2_source_claim_gated(anchor, want);
	spin_unlock(&anchor->prototype_gate_lock);
	return error;
}

static void nfsd_ffv2_source_release(struct nfsd_net *nn, enum nfsd_ffv2_source held)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	if (held == NFSD_FFV2_SOURCE_NONE)
		return;
	spin_lock(&anchor->prototype_gate_lock);
	if (!WARN_ON_ONCE(anchor->source != held))
		anchor->source = NFSD_FFV2_SOURCE_NONE;
	spin_unlock(&anchor->prototype_gate_lock);
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
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	atomic_set(&generation->test_waiters, 0);
#endif
	generation->payload = payload;
	generation->release = release;
	return generation;
}

static int nfsd_ffv2_generation_prepare(struct nfsd_net *nn, void *payload, void (*release)(void *),
					enum nfsd_ffv2_unregister_kind unregister_kind,
					const u8 unregister_uuid[16],
					struct nfsd_ffv2_generation **result, u64 *generation_id)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	int error = 0;

	generation = nfsd_ffv2_generation_alloc(payload, release);
	if (!generation)
		return -ENOMEM;
	generation->identity->unregister_kind = unregister_kind;
	memcpy(generation->identity->unregister_uuid, unregister_uuid, 16);
	generation->registry_generation = true;
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
	} else if (!anchor->next_generation || anchor->next_generation == U64_MAX) {
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

static void
nfsd_ffv2_generation_cancel(struct nfsd_net *nn, struct nfsd_ffv2_generation *generation)
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
		if (generation->registry_generation) {
			struct nfsd_ffv2_service_context *context = generation->payload;

			u32 i;

			for (i = 0; i < context->objects.count; i++)
				context->objects.objects[i]->visible = false;
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

	RCU_INIT_POINTER(anchor->provider, NULL);
	refcount_set(&anchor->ref, 1);
	init_completion(&anchor->released);
	mutex_init(&anchor->lock);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	anchor->test_destroy_waiting = NULL;
	memset(&anchor->test_registration, 0, sizeof(anchor->test_registration));
#endif
	anchor->net_state = NFSD_FFV2_NET_LIVE;
	anchor->service_state = NFSD_FFV2_SERVICE_DOWN;
	anchor->next_generation = 1;
	anchor->pending = NULL;
	anchor->registration_pending = false;
	spin_lock_init(&anchor->prototype_gate_lock);
	nfsd_ffv2_prototype_net_init(nn);
	anchor->source = NFSD_FFV2_SOURCE_NONE;
	spin_lock_init(&anchor->authority_lock);
	init_waitqueue_head(&anchor->authority_wait);
	anchor->next_authority_epoch = 1;
	anchor->authority_work = 0;
	anchor->authority_work_open = true;
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

static int nfsd_ffv2_export_update_admit(struct nfsd_ffv2_participant *participant,
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

int nfsd_ffv2_export_update_begin(struct svc_export *exp,
				  struct nfsd_ffv2_export_update *update)
{
	struct nfsd_net *nn = net_generic(exp->cd->net, nfsd_net_id);
	struct nfsd_ffv2_participant *p = &nn->ffv2_participant;
	int error = 0;

	memset(update, 0, sizeof(*update));
	error = nfsd_ffv2_export_update_admit(p, update);
	if (error)
		return error;
	mutex_lock(&nfsd_ffv2_export_policy_lock);
	update->policy_locked = true;
	if (rcu_access_pointer(exp->ex_ffv2_context) ||
	    exp->ex_ffv2_access_state == NFSD_FFV2_EXPORT_SERVICE) {
		nfsd_ffv2_export_update_abort(update);
		return -EINVAL;
	}
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
		goto out_complete;
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
out_complete:
	if (exp->ex_ffv2_context_released)
		complete(exp->ex_ffv2_context_released);
}

static bool nfsd_ffv2_authority_work_idle(struct nfsd_ffv2_anchor *anchor)
{
	bool idle;

	spin_lock(&anchor->authority_lock);
	idle = !anchor->authority_work;
	spin_unlock(&anchor->authority_lock);
	return idle;
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
	nfsd_ffv2_prototype_net_pre_exit(nn);
	if (READ_ONCE(nn->ffv2_participant.attached)) {
		nfsd_ffv2_updates_close_permanent(&nn->ffv2_participant);
		nfsd_ffv2_updates_wait(&nn->ffv2_participant);
	}
	spin_lock(&anchor->authority_lock);
	anchor->authority_work_open = false;
	spin_unlock(&anchor->authority_lock);
	mutex_lock(&anchor->lock);
	/* Pair with admission's lockless rejection before taking ->lock. */
	smp_store_release(&anchor->net_state, NFSD_FFV2_NET_EXITING);
	anchor->service_state = NFSD_FFV2_SERVICE_STOPPING;
	generation = nfsd_ffv2_retire_begin_locked(anchor);
	mutex_unlock(&anchor->lock);

	nfsd_ffv2_provider_shutdown(nn);
	nfsd_ffv2_retire_finish(anchor, generation);
	wait_event(anchor->authority_wait, nfsd_ffv2_authority_work_idle(anchor));
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
	WARN_ON_ONCE(anchor->pending);
	WARN_ON_ONCE(anchor->registration_pending);
	WARN_ON_ONCE(anchor->source != NFSD_FFV2_SOURCE_NONE);
	WARN_ON_ONCE(anchor->active);
	WARN_ON_ONCE(anchor->retiring);
	mutex_unlock(&anchor->lock);
	nfsd_ffv2_anchor_put(anchor);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (READ_ONCE(anchor->test_destroy_waiting))
		complete(READ_ONCE(anchor->test_destroy_waiting));
#endif
	wait_for_completion(&anchor->released);
	nfsd_ffv2_prototype_net_destroy(nn);
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

static bool nfsd_ffv2_authority_published(struct nfsd_ffv2_authority *authority, u64 *epoch)
{
	bool published;

	spin_lock(&authority->state_lock);
	published = authority->state == NFSD_FFV2_AUTHORITY_PUBLISHED;
	if (published && epoch)
		*epoch = authority->epoch;
	spin_unlock(&authority->state_lock);
	return published;
}

static int
nfsd_ffv2_admit_generation(struct nfsd_net *nn,
			   struct nfsd_ffv2_admission *admission,
			   struct nfsd_ffv2_generation *expected,
			   struct nfsd_ffv2_authority *authority)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	int error = 0;

	INIT_LIST_HEAD(&admission->node);
	admission->anchor = NULL;
	admission->generation = NULL;
	admission->task = NULL;
	admission->provider = NULL;
	admission->provider_result = NULL;
	admission->provider_result_release = NULL;
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
	} else if (expected && generation != expected) {
		error = -ESTALE;
	} else if (authority &&
		   !nfsd_ffv2_authority_published(authority, NULL)) {
		error = -ESTALE;
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
	return nfsd_ffv2_admit_generation(nn, admission, NULL, NULL);
}

/**
 * nfsd_ffv2_complete - consume an admission once
 * @admission: admitted record or an already completed record
 *
 * Context: May sleep when releasing a provider result. Call without spinlocks.
 * Call after the last callback. Concurrent completion consumes ownership
 * once; keep the admission allocated until the completing task returns.
 */
void nfsd_ffv2_complete(struct nfsd_ffv2_admission *admission)
{
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_anchor *anchor;

	generation = xchg(&admission->generation, NULL);
	if (!generation)
		return;
	anchor = admission->anchor;

	if (admission->provider_result_release) {
		admission->provider_result_release(admission->provider_result);
		admission->provider_result_release = NULL;
		admission->provider_result = NULL;
	}
	if (admission->provider) {
		nfsd_ffv2_provider_put(admission->provider);
		admission->provider = NULL;
	}
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
	return nfsd_ffv2_admit_generation(nn, admission, NULL, NULL);
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

static const struct nfsd_ffv2_op_profile nfsd_ffv2_op_profiles[] = {
	[OP_CHUNK_READ] = {
		.callers	= NFSD_FFV2_CALLERS(DATA_CLIENT),
		.iomode		= NFSD_FFV2_IOMODE_READ_OR_RW,
		.profile_bit	= NFSD_FFV2_PROFILE_READ_DATA,
	},
	[OP_CHUNK_HEADER_READ] = {
		.callers	= NFSD_FFV2_CALLERS(DATA_CLIENT),
		.iomode		= NFSD_FFV2_IOMODE_READ_OR_RW,
		.profile_bit	= NFSD_FFV2_PROFILE_READ_METADATA,
	},
	[OP_CHUNK_WRITE] = {
		.callers	= NFSD_FFV2_CALLERS(DATA_CLIENT),
		.iomode		= NFSD_FFV2_IOMODE_RW_ONLY,
		.profile_bit	= NFSD_FFV2_PROFILE_WRITE_DATA,
		.writer_identity = true,
	},
	[OP_CHUNK_COMMIT] = {
		.callers	= NFSD_FFV2_CALLERS(DATA_CLIENT),
		.iomode		= NFSD_FFV2_IOMODE_RW_ONLY,
		.profile_bit	= NFSD_FFV2_PROFILE_WRITE_LIFECYCLE,
		.writer_identity = true,
	},
	[OP_CHUNK_FINALIZE] = {
		.callers	= NFSD_FFV2_CALLERS(DATA_CLIENT),
		.iomode		= NFSD_FFV2_IOMODE_RW_ONLY,
		.profile_bit	= NFSD_FFV2_PROFILE_WRITE_LIFECYCLE,
		.writer_identity = true,
	},
	[OP_CHUNK_ROLLBACK] = {
		.callers	= NFSD_FFV2_CALLERS(DATA_CLIENT),
		.iomode		= NFSD_FFV2_IOMODE_RW_ONLY,
		.profile_bit	= NFSD_FFV2_PROFILE_WRITE_LIFECYCLE,
		.writer_identity = true,
	},
	[OP_CHUNK_WRITE_REPAIR] = {
		.callers	= NFSD_FFV2_CALLERS(REPAIR_ACTOR),
		.iomode		= NFSD_FFV2_IOMODE_RW_ONLY,
		.profile_bit	= NFSD_FFV2_PROFILE_REPAIR_WRITE,
		.writer_identity = true,
	},
	[OP_CHUNK_REPAIRED] = {
		.callers	= NFSD_FFV2_CALLERS(REPAIR_ACTOR),
		.iomode		= NFSD_FFV2_IOMODE_RW_ONLY,
		.profile_bit	= NFSD_FFV2_PROFILE_REPORT_REPAIRED,
		.writer_identity = true,
	},
	[OP_CHUNK_LOCK] = {
		.callers	= NFSD_FFV2_CALLERS(DATA_CLIENT) |
				  NFSD_FFV2_CALLERS(REPAIR_ACTOR),
		.iomode		= NFSD_FFV2_IOMODE_RW_ONLY,
		.profile_bit	= NFSD_FFV2_PROFILE_LOCK_CONTROL,
	},
	[OP_CHUNK_UNLOCK] = {
		.callers	= NFSD_FFV2_CALLERS(DATA_CLIENT) |
				  NFSD_FFV2_CALLERS(REPAIR_ACTOR),
		.iomode		= NFSD_FFV2_IOMODE_RW_ONLY,
		.profile_bit	= NFSD_FFV2_PROFILE_LOCK_CONTROL,
	},
	[OP_CHUNK_ERROR] = {
		.callers	= NFSD_FFV2_CALLERS(DATA_CLIENT),
		.iomode		= NFSD_FFV2_IOMODE_READ_OR_RW,
		.profile_bit	= NFSD_FFV2_PROFILE_REPORT_ERROR,
	},
	[OP_TRUST_STATEID] = {
		.callers	= NFSD_FFV2_CALLERS(MDS_CONTROL),
		.iomode		= NFSD_FFV2_IOMODE_ANY,
	},
	[OP_REVOKE_STATEID] = {
		.callers	= NFSD_FFV2_CALLERS(MDS_CONTROL),
		.iomode		= NFSD_FFV2_IOMODE_ANY,
	},
	[OP_BULK_REVOKE_STATEID] = {
		.callers	= NFSD_FFV2_CALLERS(MDS_CONTROL),
		.iomode		= NFSD_FFV2_IOMODE_ANY,
		/* Takes only a clientid4; it names no file. */
		.no_filehandle	= true,
	},
};

/**
 * nfsd_ffv2_op_profile - describe one operation's authorization requirements
 * @opnum: NFSv4 operation number
 *
 * Returns the operation's profile, or NULL when the operation has none and
 * therefore cannot be authorized.
 */
const struct nfsd_ffv2_op_profile *nfsd_ffv2_op_profile(u32 opnum)
{
	const struct nfsd_ffv2_op_profile *profile;

	if (opnum >= ARRAY_SIZE(nfsd_ffv2_op_profiles))
		return NULL;
	profile = &nfsd_ffv2_op_profiles[opnum];
	if (!profile->callers)
		return NULL;
	return profile;
}

/**
 * nfsd_ffv2_op_no_filehandle - does this operation name no file?
 * @opnum: NFSv4 operation number
 *
 * Returns true for a control operation whose arguments contain no
 * filehandle, such as BULK_REVOKE_STATEID.
 */
bool nfsd_ffv2_op_no_filehandle(u32 opnum)
{
	const struct nfsd_ffv2_op_profile *profile;

	profile = nfsd_ffv2_op_profile(opnum);
	return profile && profile->no_filehandle;
}

static bool
nfsd_ffv2_generation_has_task(struct nfsd_ffv2_generation *generation, struct task_struct *task)
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

int nfsd_ffv2_service_generation_retire(struct nfsd_net *nn, u64 generation_id)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	int error = 0;

	lockdep_assert_held(&nfsd_mutex);
	if (!nfsd_ffv2_anchor_get(anchor))
		return -ESHUTDOWN;
	mutex_lock(&anchor->lock);
	generation = anchor->active;
	if (!generation || generation->identity->generation != generation_id)
		generation = anchor->retiring;
	if (!generation || generation->identity->generation != generation_id) {
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

int nfsd_ffv2_object_unregister(struct nfsd_net *nn, u64 generation_id, const u8 object_uuid[16])
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	int error = 0;

	lockdep_assert_held(&nfsd_mutex);
	if (!generation_id || !object_uuid)
		return -EINVAL;
	mutex_lock(&anchor->lock);
	generation = anchor->active;
	if (!generation || generation->identity->generation != generation_id)
		generation = anchor->retiring;
	if (!generation || generation->identity->generation != generation_id ||
	    generation->identity->unregister_kind != NFSD_FFV2_UNREGISTER_OBJECT ||
	    memcmp(generation->identity->unregister_uuid, object_uuid,
		   sizeof(generation->identity->unregister_uuid)))
		error = -ENOENT;
	mutex_unlock(&anchor->lock);
	if (error)
		return error;
	return nfsd_ffv2_service_generation_retire(nn, generation_id);
}

struct nfsd_ffv2_authority_retire {
	struct work_struct work;
	struct nfsd_ffv2_authority *authority;
	u64 generation_id;
};

static bool nfsd_ffv2_cred_integrity_protected(const struct svc_cred *cred)
{
	u32 service;

	if (!cred->cr_gss_mech)
		return false;
	service = gss_pseudoflavor_to_service(cred->cr_gss_mech, cred->cr_flavor);
	return service == RPC_GSS_SVC_INTEGRITY || service == RPC_GSS_SVC_PRIVACY;
}

/**
 * nfsd_ffv2_authority_qualify - may this client act as an MDS control root?
 * @clp: the client owning the located session
 *
 * The administrator selects the session.  NFSD sets its PNFS-MDS flag
 * according to the local pNFS configuration; the flag does not attest a
 * peer MDS role.  Qualification also requires an active machine credential
 * established with RPCSEC_GSS integrity or privacy and a principal.
 *
 * Returns 0 when the client qualifies, or -EACCES.
 */
static int nfsd_ffv2_authority_qualify(const struct nfs4_client *clp)
{
	if (clp->cl_minorversion < 1)
		return -EACCES;
	if (!(clp->cl_exchange_flags & EXCHGID4_FLAG_USE_PNFS_MDS))
		return -EACCES;
	if (!clp->cl_mach_cred)
		return -EACCES;
	if (!nfsd_ffv2_cred_integrity_protected(&clp->cl_cred))
		return -EACCES;
	if (!clp->cl_cred.cr_raw_principal && !clp->cl_cred.cr_principal)
		return -EACCES;
	return 0;
}

void nfsd_ffv2_session_init(struct nfsd4_session *session)
{
	INIT_LIST_HEAD(&session->se_ffv2_authorities);
}

void nfsd_ffv2_session_free(struct nfsd4_session *session)
{
	WARN_ON_ONCE(!list_empty(&session->se_ffv2_authorities));
}

static void nfsd_ffv2_authority_free(struct nfsd_ffv2_authority *authority)
{
	free_svc_cred(&authority->machine_cred);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	atomic_dec(&authority->nn->ffv2.test_registration.authorities);
#endif
	kfree(authority);
}

static void nfsd_ffv2_authority_get(struct nfsd_ffv2_authority *authority)
{
	refcount_inc(&authority->ref);
}

static void nfsd_ffv2_authority_put(struct nfsd_ffv2_authority *authority)
{
	if (authority && refcount_dec_and_test(&authority->ref))
		nfsd_ffv2_authority_free(authority);
}

static bool nfsd_ffv2_authority_work_admit(struct nfsd_ffv2_anchor *anchor)
{
	bool admitted = false;

	spin_lock(&anchor->authority_lock);
	if (anchor->authority_work_open) {
		anchor->authority_work++;
		admitted = true;
	}
	spin_unlock(&anchor->authority_lock);
	return admitted;
}

static void nfsd_ffv2_authority_work_done(struct nfsd_ffv2_anchor *anchor)
{
	spin_lock(&anchor->authority_lock);
	if (!WARN_ON_ONCE(!anchor->authority_work) && --anchor->authority_work == 0)
		wake_up_all(&anchor->authority_wait);
	spin_unlock(&anchor->authority_lock);
}

static void nfsd_ffv2_authority_retire_work(struct work_struct *work)
{
	struct nfsd_ffv2_authority_retire *retire =
		container_of(work, struct nfsd_ffv2_authority_retire, work);
	struct nfsd_ffv2_authority *authority = retire->authority;
	struct nfsd_ffv2_anchor *anchor = &authority->nn->ffv2;

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (READ_ONCE(anchor->test_registration.work_entered)) {
		complete(READ_ONCE(anchor->test_registration.work_entered));
		wait_for_completion(READ_ONCE(anchor->test_registration.work_continue));
	}
#endif
	/* service_generation_retire owns the unlock-around-wait protocol. */
	mutex_lock(&nfsd_mutex);
	nfsd_ffv2_service_generation_retire(authority->nn, retire->generation_id);
	mutex_unlock(&nfsd_mutex);
	nfsd_ffv2_authority_put(authority);
	kfree(retire);
	/* Signals pre-exit last, once ->nn is no longer used here. */
	nfsd_ffv2_authority_work_done(anchor);
}

static void
nfsd_ffv2_authority_retire_queue(struct nfsd_ffv2_authority *authority, u64 generation_id)
{
	struct nfsd_ffv2_anchor *anchor = &authority->nn->ffv2;
	struct nfsd_ffv2_authority_retire *retire;

	if (!nfsd_ffv2_authority_work_admit(anchor))
		return;
	retire = nfsd_ffv2_test_registration_fault(authority->nn, NFSD_FFV2_TEST_WORK_ALLOC) ?
			 NULL :
			 kzalloc_obj(*retire, GFP_ATOMIC);
	if (!retire) {
		/*
		 * Service stop and namespace exit still retire this
		 * generation; only the prompt out-of-line retirement is lost.
		 */
		nfsd_ffv2_authority_work_done(anchor);
		return;
	}
	nfsd_ffv2_authority_get(authority);
	retire->authority = authority;
	retire->generation_id = generation_id;
	INIT_WORK(&retire->work, nfsd_ffv2_authority_retire_work);
	queue_work(system_dfl_wq, &retire->work);
}

static struct nfsd_ffv2_authority *
nfsd_ffv2_authority_kill_locked(struct nfsd_ffv2_authority *authority, u64 *retire_generation)
{
	struct nfsd_ffv2_authority *dropped = NULL;

	spin_lock(&authority->state_lock);
	if (retire_generation && authority->state == NFSD_FFV2_AUTHORITY_PUBLISHED)
		*retire_generation = authority->generation_id;
	authority->state = NFSD_FFV2_AUTHORITY_DEAD;
	if (authority->linked) {
		authority->linked = false;
		list_del_init(&authority->session_link);
		dropped = authority;
	}
	spin_unlock(&authority->state_lock);
	return dropped;
}

/**
 * nfsd_ffv2_session_dead_locked - kill every authority derived from a session
 * @session: the session being removed
 *
 * Runs from every path that removes a session: DESTROY_SESSION, client
 * expiry, administrative expiry, and namespace session-table teardown.
 * Published authorities queue counted retirement work. The worker drains
 * without client_lock.
 *
 * Caller holds nn->client_lock.
 */
void nfsd_ffv2_session_dead_locked(struct nfsd4_session *session)
{
	struct nfsd_ffv2_authority *authority, *tmp;

	list_for_each_entry_safe(authority, tmp, &session->se_ffv2_authorities, session_link) {
		u64 retire_generation = 0;
		struct nfsd_ffv2_authority *dropped;

		dropped = nfsd_ffv2_authority_kill_locked(authority, &retire_generation);
		if (retire_generation)
			nfsd_ffv2_authority_retire_queue(authority, retire_generation);
		nfsd_ffv2_authority_put(dropped);
	}
}

/**
 * nfsd_ffv2_authority_detach - retire one authority from any context
 * @authority: the authority to kill
 *
 * The single idempotent detach used by registration cancellation, generation
 * retirement and replacement, service stop, and namespace pre-exit.
 *
 * Caller holds no anchor, session, or FFv2 lock.
 */
static void nfsd_ffv2_authority_detach(struct nfsd_ffv2_authority *authority)
{
	struct nfsd_net *nn = authority->nn;
	struct nfsd_ffv2_authority *dropped;

	spin_lock(&nn->client_lock);
	dropped = nfsd_ffv2_authority_kill_locked(authority, NULL);
	spin_unlock(&nn->client_lock);
	nfsd_ffv2_authority_put(dropped);
}

/**
 * nfsd_ffv2_authority_publish - consume a prepared authority at publication
 * @authority: the prepared authority
 * @generation_id: nonzero identifier of the generation being published
 *
 * Returns true when the authority was still prepared. Exact export
 * replacement may still refuse, in which case cancellation must detach the
 * authority. Returns false if session death won before publication.
 *
 * May be called with the FFv2 publication locks held: ->state_lock is a leaf
 * and nothing waits under it.
 */
static bool nfsd_ffv2_authority_publish(struct nfsd_ffv2_authority *authority, u64 generation_id)
{
	bool published = false;

	spin_lock(&authority->state_lock);
	if (authority->state == NFSD_FFV2_AUTHORITY_PREPARED) {
		authority->state = NFSD_FFV2_AUTHORITY_PUBLISHED;
		authority->generation_id = generation_id;
		published = true;
	}
	spin_unlock(&authority->state_lock);
	return published;
}

static int nfsd_ffv2_authority_epoch(struct nfsd_ffv2_anchor *anchor, u64 *epoch)
{
	int error = 0;

	spin_lock(&anchor->authority_lock);
	if (!anchor->next_authority_epoch || anchor->next_authority_epoch == U64_MAX)
		error = -EOVERFLOW;
	else
		*epoch = anchor->next_authority_epoch++;
	spin_unlock(&anchor->authority_lock);
	return error;
}

/**
 * nfsd_ffv2_authority_register - derive an authority from a session locator
 * @nn: nfsd namespace receiving the registration
 * @net: the registering request's own network namespace
 * @sessionid: exact 16-byte session locator, the only caller-supplied input
 * @result: returns the prepared authority on success
 *
 * Resolves the locator in @net and derives the authority from the live
 * session and its owning client.  A session in another namespace is not
 * visible in @net's table and is reported like an unknown locator.
 *
 * Returns 0 with a prepared, linked authority, or a negative errno.
 */
int nfsd_ffv2_authority_register(struct nfsd_net *nn, struct net *net,
				 const u8 sessionid[NFS4_MAX_SESSIONID_LEN],
				 struct nfsd_ffv2_authority **result)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_authority *authority;
	struct nfsd4_session *session;
	struct nfs4_client *clp;
	u32 exchange_flags;
	clientid_t clientid;
	int error;

	spin_lock(&nn->client_lock);
	session = nfsd4_session_lookup_get(net, sessionid);
	if (!session) {
		spin_unlock(&nn->client_lock);
		return -ENOENT;
	}
	clp = session->se_client;
	exchange_flags = clp->cl_exchange_flags;
	clientid = clp->cl_clientid;
	error = nfsd_ffv2_authority_qualify(clp);
	spin_unlock(&nn->client_lock);
	if (error)
		goto out_put_session;

	/*
	 * The session reference pins the client, so the establishing
	 * credential stays valid for the deep copy taken outside the lock.
	 */
	if (nfsd_ffv2_test_registration_fault(nn, NFSD_FFV2_TEST_AUTH_ALLOC)) {
		error = -ENOMEM;
		goto out_put_session;
	}
	authority = kzalloc_obj(*authority, GFP_KERNEL);
	if (!authority) {
		error = -ENOMEM;
		goto out_put_session;
	}
	refcount_set(&authority->ref, 1);
	spin_lock_init(&authority->state_lock);
	INIT_LIST_HEAD(&authority->session_link);
	authority->nn = nn;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	atomic_inc(&nn->ffv2.test_registration.authorities);
#endif
	authority->state = NFSD_FFV2_AUTHORITY_PREPARED;
	memcpy(&authority->sessionid.data, sessionid, NFS4_MAX_SESSIONID_LEN);
	authority->clientid = clientid;
	authority->exchange_flags = exchange_flags;

	error = nfsd4_ffv2_copy_cred(nn, &authority->machine_cred, &clp->cl_cred);
	if (error)
		goto out_free;
	error = nfsd_ffv2_authority_epoch(anchor, &authority->epoch);
	if (error)
		goto out_free;

	/*
	 * Link only while the session is still live.  A session that died
	 * during the copy has already run its detach hook and would never run
	 * it again for a late link.
	 */
	spin_lock(&nn->client_lock);
	if (nfsd_ffv2_test_registration_fault(nn, NFSD_FFV2_TEST_AUTH_LINK_DEATH)) {
		nfsd_ffv2_session_dead_locked(session);
		session->se_dead = true;
	}
	if (nfsd4_session_is_live_locked(session)) {
		refcount_inc(&authority->ref);
		authority->linked = true;
		list_add(&authority->session_link, &session->se_ffv2_authorities);
	} else {
		error = -ENOENT;
	}
	spin_unlock(&nn->client_lock);
	if (error)
		goto out_free;

	nfsd4_session_put_ref(session);
	*result = authority;
	return 0;

out_free:
	nfsd_ffv2_authority_put(authority);
out_put_session:
	nfsd4_session_put_ref(session);
	return error;
}

static void nfsd_ffv2_trust_admission_put(struct nfsd_ffv2_trust_registry *registry)
{
	spin_lock(&registry->drain_lock);
	if (atomic_dec_and_test(&registry->admissions))
		wake_up_all(&registry->drain_wait);
	spin_unlock(&registry->drain_lock);
}

static void nfsd_ffv2_trust_entry_free(struct rcu_head *rcu)
{
	struct nfsd_ffv2_trust_entry *entry = container_of(rcu, struct nfsd_ffv2_trust_entry, rcu);

	kfree_sensitive(entry->principal);
	kfree(entry);
}

static void nfsd_ffv2_trust_entry_put(struct nfsd_ffv2_trust_entry *entry)
{
	struct nfsd_ffv2_trust_registry *registry;
	struct nfsd_ffv2_authority *authority;
	size_t bytes;

	if (!entry || !refcount_dec_and_test(&entry->ref))
		return;

	registry = entry->registry;
	authority = entry->authority;
	bytes = entry->principal_len;
	entry->authority = NULL;
	/* The registry admission still protects the authority's namespace. */
	nfsd_ffv2_authority_put(authority);

	/*
	 * Retained bytes are returned only at final free, so a replacement
	 * cannot transiently exceed the budget while both entries exist.
	 * The same critical section retires this entry from the drain count
	 * and wakes a waiting destroy, which is why destruction cannot
	 * complete while any reference remains.
	 */
	if (registry) {
		if (bytes) {
			mutex_lock(&registry->update_lock);
			if (!WARN_ON_ONCE(registry->principal_bytes < bytes))
				registry->principal_bytes -= bytes;
			mutex_unlock(&registry->update_lock);
		}
		/*
		 * Released after the mutex, so a destroy woken by this drop
		 * cannot destroy the mutex while it is still held here.
		 */
		nfsd_ffv2_trust_admission_put(registry);
	}
	call_rcu(&entry->rcu, nfsd_ffv2_trust_entry_free);
}

/**
 * nfsd_ffv2_trust_registry_init - prepare one generation's trust registry
 * @registry: registry embedded in the generation payload
 * @nn: namespace owning the enclosing context
 */
static int
nfsd_ffv2_trust_registry_init(struct nfsd_ffv2_trust_registry *registry, struct nfsd_net *nn)
{
	int error;

	spin_lock_init(&registry->drain_lock);
	mutex_init(&registry->update_lock);
	init_waitqueue_head(&registry->drain_wait);
	registry->entries = 0;
	atomic_set(&registry->admissions, 0);
	registry->principal_bytes = 0;
	error = nfsd_ffv2_test_registration_fault(nn, NFSD_FFV2_TEST_HASH_INIT) ?
		-ENOMEM : rhashtable_init(&registry->table, &nfsd_ffv2_trust_params);
	if (error) {
		mutex_destroy(&registry->update_lock);
		return error;
	}
	registry->live = true;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	registry->test_nn = nn;
	atomic_inc(&nn->ffv2.test_registration.registries);
#endif
	return 0;
}

static bool
nfsd_ffv2_trust_unhash_locked(struct nfsd_ffv2_trust_registry *reg,
			      struct nfsd_ffv2_trust_entry *entry, enum nfsd_ffv2_trust_state state)
{
	lockdep_assert_held(&reg->update_lock);

	if (rhashtable_remove_fast(&reg->table, &entry->node, nfsd_ffv2_trust_params))
		return false;
	/* Publish the terminal state before the entry becomes unreachable. */
	atomic_set_release(&entry->state, state);
	if (!WARN_ON_ONCE(!reg->entries))
		reg->entries--;
	return true;
}

/**
 * nfsd_ffv2_trust_retire - unhash and revoke every entry in a registry
 * @registry: registry being torn down with its generation
 *
 * Removes lookup visibility for all entries, marks them revoked, and waits
 * for the RCU lookup window with no registry, anchor, or service lock held.
 * Outstanding entry references keep their memory alive until released.
 */
static void nfsd_ffv2_trust_retire(struct nfsd_ffv2_trust_registry *registry)
{
	struct nfsd_ffv2_trust_entry *entry;
	struct rhashtable_iter iter;
	LIST_HEAD(doomed);

	if (!registry->live)
		return;

	mutex_lock(&registry->update_lock);
	registry->live = false;
	rhashtable_walk_enter(&registry->table, &iter);
	rhashtable_walk_start(&iter);
	while ((entry = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(entry))
			continue;
		if (nfsd_ffv2_trust_unhash_locked(registry, entry, NFSD_FFV2_TRUST_REVOKED))
			/* Carries the table reference, dropped below. */
			list_add_tail(&entry->dispose, &doomed);
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	mutex_unlock(&registry->update_lock);

	/* No registry, anchor, or service lock is held across this wait. */
	synchronize_rcu();
	while (!list_empty(&doomed)) {
		entry = list_first_entry(&doomed, struct nfsd_ffv2_trust_entry, dispose);
		list_del(&entry->dispose);
		nfsd_ffv2_trust_entry_put(entry);
	}
}

static bool nfsd_ffv2_trust_registry_idle(struct nfsd_ffv2_trust_registry *registry)
{
	bool idle;

	spin_lock(&registry->drain_lock);
	idle = !atomic_read(&registry->admissions);
	spin_unlock(&registry->drain_lock);
	return idle;
}

/**
 * nfsd_ffv2_trust_registry_destroy - drain and free a registry
 * @registry: registry whose generation has retired
 *
 * Waits for every outstanding entry reference, not only for an RCU grace
 * period: a request may hold a reference it acquired before retirement
 * began, and releasing it takes this registry's mutex.  Destroying the
 * mutex before that release would be a use-after-free.
 *
 * Caller holds no registry, anchor, or service lock.
 */
static void nfsd_ffv2_trust_registry_destroy(struct nfsd_ffv2_trust_registry *registry)
{
	nfsd_ffv2_trust_retire(registry);
	/* Pair with the final count drop and wake before freeing the waitqueue. */
	wait_event(registry->drain_wait, nfsd_ffv2_trust_registry_idle(registry));
	WARN_ON_ONCE(registry->entries);
	WARN_ON_ONCE(registry->principal_bytes);
	rhashtable_destroy(&registry->table);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	atomic_dec(&registry->test_nn->ffv2.test_registration.registries);
#endif
	mutex_destroy(&registry->update_lock);
}

static void nfsd_ffv2_trust_key_init(struct nfsd_ffv2_trust_key *key, const stateid_t *stateid,
				     const u8 object_uuid[16], u64 authority_epoch)
{
	/* Hashed as raw bytes, so every byte must be initialised. */
	memset(key, 0, sizeof(*key));
	key->stateid = *stateid;
	memcpy(key->object_uuid, object_uuid, 16);
	key->authority_epoch = authority_epoch;
}

static struct nfsd_ffv2_trust_entry *
nfsd_ffv2_trust_lookup(struct nfsd_ffv2_trust_registry *registry, const stateid_t *stateid,
		       const u8 object_uuid[16], u64 authority_epoch)
{
	struct nfsd_ffv2_trust_entry *entry;
	struct nfsd_ffv2_trust_key key;

	nfsd_ffv2_trust_key_init(&key, stateid, object_uuid, authority_epoch);

	rcu_read_lock();
	entry = rhashtable_lookup(&registry->table, &key, nfsd_ffv2_trust_params);
	/* A replaced or revoked entry must not start a new operation. */
	if (entry && atomic_read_acquire(&entry->state) != NFSD_FFV2_TRUST_LIVE)
		entry = NULL;
	if (entry && !refcount_inc_not_zero(&entry->ref))
		entry = NULL;
	rcu_read_unlock();
	return entry;
}

static __be32 nfsd_ffv2_trust_validate(const struct nfsd_ffv2_trust_entry *entry, u64 generation_id,
				       const u8 object_uuid[16], u64 authority_epoch,
				       u32 profile_bit, const char *principal)
{
	struct timespec64 now;

	if (atomic_read_acquire(&entry->state) != NFSD_FFV2_TRUST_LIVE)
		return nfserr_bad_stateid;
	if (entry->generation_id != generation_id)
		return nfserr_bad_stateid;
	if (entry->key.authority_epoch != authority_epoch)
		return nfserr_bad_stateid;
	if (memcmp(entry->key.object_uuid, object_uuid, 16))
		return nfserr_bad_stateid;
	/* Exactly one named bit; never inferred from iomode alone. */
	if (!profile_bit || hweight32(profile_bit) != 1)
		return nfserr_bad_stateid;
	if (!(entry->profile_mask & profile_bit))
		return nfserr_bad_stateid;

	ktime_get_real_ts64(&now);
	if (timespec64_compare(&entry->expires, &now) <= 0)
		return nfserr_bad_stateid;

	if (entry->principal) {
		if (!principal || strcmp(entry->principal, principal))
			return nfserr_acces;
	}
	return nfs_ok;
}

int nfsd_ffv2_registration_begin(struct nfsd_net *nn, struct nfsd_ffv2_export_update *registration)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	int error;

	lockdep_assert_held(&nfsd_mutex);
	memset(registration, 0, sizeof(*registration));
	error = nfsd_ffv2_source_claim_locked(nn, NFSD_FFV2_SOURCE_MDS);
	if (error)
		return error;
	registration->source_claimed = true;
	error = nfsd_ffv2_export_update_admit(&nn->ffv2_participant, registration);
	if (error)
		goto out_source;
	mutex_lock(&anchor->lock);
	if (anchor->net_state != NFSD_FFV2_NET_LIVE ||
	    anchor->service_state != NFSD_FFV2_SERVICE_UP) {
		error = -ESHUTDOWN;
	} else if (anchor->registration_pending || anchor->pending || anchor->active ||
		   anchor->retiring) {
		error = -EBUSY;
	} else {
		anchor->registration_pending = true;
		registration->registration_slot = true;
		error = 0;
	}
	mutex_unlock(&anchor->lock);
	if (!error)
		return 0;
out_source:
	nfsd_ffv2_source_release(nn, NFSD_FFV2_SOURCE_MDS);
	nfsd_ffv2_export_update_put(registration);
	return error;
}

void nfsd_ffv2_registration_end(struct nfsd_net *nn, struct nfsd_ffv2_export_update *registration)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	bool unpublished = registration->registration_slot;

	if (registration->registration_slot) {
		mutex_lock(&anchor->lock);
		WARN_ON_ONCE(!anchor->registration_pending);
		anchor->registration_pending = false;
		registration->registration_slot = false;
		mutex_unlock(&anchor->lock);
	}
	if (registration->authority) {
		nfsd_ffv2_authority_detach(registration->authority);
		nfsd_ffv2_authority_put(registration->authority);
		registration->authority = NULL;
	}
	if (unpublished && registration->source_claimed)
		nfsd_ffv2_source_release(nn, NFSD_FFV2_SOURCE_MDS);
	nfsd_ffv2_export_update_put(registration);
}

static struct nfsd_ffv2_service_context *
nfsd_ffv2_service_context_alloc(struct nfsd_net *nn, struct nfsd_ffv2_reservation *reservation,
				const struct cred *cred, u64 control_root, u64 owner_generation)
{
	struct nfsd_ffv2_service_context *context;

	if (nfsd_ffv2_test_registration_fault(nn, NFSD_FFV2_TEST_CONTEXT_ALLOC))
		return NULL;
	context = kzalloc_obj(*context, GFP_KERNEL);
	if (!context)
		return NULL;
	if (nfsd_ffv2_trust_registry_init(&context->trust, nn)) {
		kfree(context);
		return NULL;
	}
	refcount_inc(&reservation->ref);
	context->nn = nn;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	atomic_inc(&nn->ffv2.test_registration.contexts);
#endif
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

static void nfsd_ffv2_service_context_prepare_export(struct nfsd_ffv2_service_context *context,
						     struct svc_export *exp)
{
	if (WARN_ON_ONCE(rcu_access_pointer(exp->ex_ffv2_context)))
		return;
	nfsd_ffv2_export_template_mark_service(exp);
	RCU_INIT_POINTER(exp->ex_ffv2_context, context);
}

static void nfsd_ffv2_service_context_abort(struct nfsd_ffv2_service_context *context,
					    struct svc_export *prepared)
{
	if (prepared && rcu_access_pointer(prepared->ex_ffv2_context) == context)
		RCU_INIT_POINTER(prepared->ex_ffv2_context, NULL);
	nfsd_ffv2_trust_registry_destroy(&context->trust);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	atomic_dec(&context->nn->ffv2.test_registration.contexts);
#endif
	nfsd_ffv2_reservation_put(context->reservation);
	put_cred(context->cred);
	kfree(context);
}

static struct svc_export *
nfsd_ffv2_transition_publish(struct nfsd_net *owner, struct nfsd_ffv2_export_update *transaction,
			     struct nfsd_ffv2_export_update *registration,
			     struct nfsd_ffv2_reservation *reservation,
			     struct nfsd_ffv2_service_context *context,
			     struct nfsd_ffv2_generation *generation, struct svc_export *old,
			     struct svc_export *template)
{
	struct nfsd_ffv2_participant *participant = &owner->ffv2_participant;
	struct nfsd_ffv2_anchor *anchor = &owner->ffv2;
	struct svc_export *published;
	int error;

	if (nfsd_ffv2_test_registration_fault(owner, NFSD_FFV2_TEST_AUTH_PUBLISH_DEATH))
		nfsd_ffv2_authority_detach(registration->authority);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (READ_ONCE(owner->ffv2.test_registration.before_publish)) {
		complete(READ_ONCE(owner->ffv2.test_registration.before_publish));
		wait_for_completion(READ_ONCE(owner->ffv2.test_registration.publish_continue));
	}
#endif
	nfsd_ffv2_export_update_lock();

	if (!nfsd_ffv2_export_is_current_locked(old) || !nfsd_ffv2_export_is_transitioning(old)) {
		error = -ESTALE;
		goto out_update;
	}
	mutex_lock(&reservation->entry_lock);
	mutex_lock(&nfsd_ffv2_export_policy_lock);
	mutex_lock(&anchor->lock);
	error = nfsd_ffv2_export_update_validate(transaction);
	if (!error)
		error = nfsd_ffv2_export_update_validate(registration);
	if (error || anchor->pending != generation || anchor->net_state != NFSD_FFV2_NET_LIVE ||
	    anchor->service_state != NFSD_FFV2_SERVICE_UP ||
	    (!registration->registration_slot || !anchor->registration_pending) ||
	    reservation->state != NFSD_FFV2_RESERVING || reservation->owner != participant ||
	    !READ_ONCE(participant->attached)) {
		if (!error)
			error = -ESHUTDOWN;
		goto out_anchor;
	}

	/*
	 * Last reversible point for the authority: consume PREPARED into
	 * PUBLISHED, or abort here because the session died first.  Session
	 * death takes the same leaf lock, so exactly one of the two
	 * linearizations wins and no generation is published with an
	 * authority that was already dead.
	 */
	if (!nfsd_ffv2_authority_publish(registration->authority,
					 generation->identity->generation)) {
		error = -ENOENT;
		goto out_anchor;
	}
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (nfsd_ffv2_test_registration_fault(owner, NFSD_FFV2_TEST_EXACT_REPLACE))
		nfsd_ffv2_test_fail_export_alloc();
#endif
	published = nfsd_ffv2_export_update_exact_locked(template, old);
	if (IS_ERR(published)) {
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
		if (registration->authority->state == NFSD_FFV2_AUTHORITY_PUBLISHED)
			atomic_inc(&owner->ffv2.test_registration.published_refusals);
#endif
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
		list_add_tail(&published->ex_ffv2_inventory, &participant->inventory);
		participant->inventory_count++;
	}
	context->export = exp_get(published);
	context->published = true;
	published->ex_ffv2_context_released = &context->export_released;
	mutex_lock(&nfsd_ffv2_registry_lock);
	reservation->state = NFSD_FFV2_RESERVATION_ACTIVE;
	reservation->owner_generation = generation->identity->generation;
	context->objects_owned = true;
	{
		u32 i;

		for (i = 0; i < context->objects.count; i++)
			context->objects.objects[i]->visible = true;
	}
	anchor->pending = NULL;
	anchor->active = generation;
	anchor->registration_pending = false;
	registration->registration_slot = false;
	/* The generation payload now owns the authority. */
	context->authority = registration->authority;
	registration->authority = NULL;
	/* ...and the source reservation the registration claimed. */
	context->source_claimed = registration->source_claimed;
	registration->source_claimed = false;
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

static int nfsd_ffv2_object_validate(struct svc_export *exp, struct nfsd_ffv2_object *object)
{
	struct inode *inode = d_inode(object->object_path.dentry);

	if (!path_equal(&exp->ex_path, &object->export_path) ||
	    object->export_path.mnt != object->object_path.mnt ||
	    object->export_path.mnt->mnt_sb != object->object_path.mnt->mnt_sb ||
	    object->export_path.dentry == object->object_path.dentry ||
	    !d_is_reg(object->object_path.dentry) || d_unlinked(object->object_path.dentry) ||
	    READ_ONCE(inode->i_nlink) != 1 || !path_is_under(&object->object_path, &exp->ex_path))
		return -ESTALE;
	return 0;
}

static int nfsd_ffv2_set_publish(struct nfsd_net *nn, struct nfsd_ffv2_export_update *registration,
				 struct nfsd_ffv2_object_set *objects, struct svc_export *exp,
				 const u8 store_uuid[16], const u8 binding_token[32],
				 const struct cred *cred, u64 control_root, bool validate_backend,
				 enum nfsd_ffv2_unregister_kind kind, const u8 unregister_uuid[16],
				 struct knfsd_fh *outer_fh, u64 *generation_id)
{
	struct nfsd_ffv2_export_update transaction = {};
	struct nfsd_ffv2_service_context *context;
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_reservation *reservation;
	struct svc_export template, *published;
	struct nfsd_ffv2_fh_info info = {};
	u64 id;
	u32 i;
	int error;

	*generation_id = 0;
	error = nfsd_ffv2_export_transition_exact(exp);
	if (error)
		goto out_object;
	for (i = 0; i < objects->count; i++) {
		error = nfsd_ffv2_object_validate(exp, objects->objects[i]);
		if (error)
			break;
	}
	if (error)
		goto out_reopen;
	if (nfsd_ffv2_test_registration_fault(nn, NFSD_FFV2_TEST_TEMPLATE)) {
		error = -ENOMEM;
		goto out_reopen;
	}
	error = nfsd_ffv2_export_template_clone(&template, exp);
	if (error)
		goto out_reopen;
	error = nfsd_ffv2_export_update_admit(&nn->ffv2_participant, &transaction);
	if (error)
		goto out_template;
	if (nfsd_ffv2_test_registration_fault(nn, NFSD_FFV2_TEST_RESERVATION)) {
		error = -ENOMEM;
		goto out_update;
	}
	error = nfsd_ffv2_claim_expected(nn, &objects->objects[0]->export_path, store_uuid,
					 binding_token, exp, &reservation, validate_backend);
	if (error)
		goto out_update;
	error = nfsd_ffv2_export_transition_wait(exp);
	if (!error)
		error = nfsd_ffv2_reservation_gate_io(reservation);
	if (!error)
		for (i = 0; i < objects->count; i++) {
			error = nfsd_ffv2_object_validate(exp, objects->objects[i]);
			if (error)
				break;
		}
	if (error)
		goto out_reservation;
	context = nfsd_ffv2_service_context_alloc(nn, reservation, cred, control_root, 0);
	if (!context) {
		error = -ENOMEM;
		goto out_reservation;
	}
	context->objects = *objects;
	if (nfsd_ffv2_test_registration_fault(nn, NFSD_FFV2_TEST_GENERATION)) {
		error = -ENOMEM;
		goto out_context;
	}
	error = nfsd_ffv2_generation_prepare(nn, context, nfsd_ffv2_service_context_release, kind,
					     unregister_uuid, &generation, &id);
	if (error)
		goto out_context;
	for (i = 0; i < objects->count; i++) {
		struct nfsd_ffv2_object *object = objects->objects[i];

		info.generation = id;
		memcpy(info.object_uuid, object->object_uuid, sizeof(info.object_uuid));
		memcpy(info.export_uuid, object->export_uuid, sizeof(info.export_uuid));
		info.inner = object->inner_fh.fh_raw;
		info.inner_len = object->inner_fh.fh_size;
		if (nfsd_ffv2_test_registration_fault(nn, NFSD_FFV2_TEST_ENCODE)) {
			error = -ENOMEM;
			goto out_generation;
		}
		error = nfsd_ffv2_fh_encode(&outer_fh[i], &info);
		if (error)
			goto out_generation;
	}
	context->owner_generation = id;
	nfsd_ffv2_service_context_prepare_export(context, &template);
	published = nfsd_ffv2_transition_publish(nn, &transaction, registration, reservation,
						 context, generation, exp, &template);
	if (IS_ERR(published)) {
		error = PTR_ERR(published);
		goto out_generation;
	}
	exp_put(published);
	nfsd_ffv2_generation_put(generation);
	*generation_id = id;
	nfsd_ffv2_export_update_put(&transaction);
	nfsd_ffv2_export_template_free(&template);
	return 0;

out_generation:
	nfsd_ffv2_generation_cancel(nn, generation);
out_context:
	nfsd_ffv2_service_context_abort(context, &template);
out_reservation:
	nfsd_ffv2_reservation_abort(reservation);
out_update:
	nfsd_ffv2_export_update_put(&transaction);
out_template:
	nfsd_ffv2_export_template_free(&template);
out_reopen:
	nfsd_ffv2_export_transition_abort_exact(exp);
out_object:
	nfsd_ffv2_object_set_free(objects);
	return error;
}

static int nfsd_ffv2_object_publish(struct nfsd_net *nn,
				    struct nfsd_ffv2_export_update *registration,
				    struct nfsd_ffv2_object *object, struct svc_export *exp,
				    const u8 store_uuid[16], const u8 binding_token[32],
				    const struct cred *cred, u64 control_root,
				    struct knfsd_fh *outer_fh, u64 *generation_id)
{
	struct nfsd_ffv2_object_set objects = { .count = 1, .objects = { object } };

	return nfsd_ffv2_set_publish(nn, registration, &objects, exp, store_uuid, binding_token,
				     cred, control_root, true, NFSD_FFV2_UNREGISTER_OBJECT,
				     object->object_uuid, outer_fh, generation_id);
}

int nfsd_ffv2_object_register(struct nfsd_net *nn, struct nfsd_ffv2_export_update *registration,
			      struct nfsd_ffv2_object *object,
			      const struct nfsd_ffv2_object_request *request,
			      struct knfsd_fh *outer_fh, u64 *generation_id)
{
	struct svc_fh ordinary;
	struct svc_export *exp;
	__be32 status;
	int error;

	if (!nn || !registration || !object || !request || !outer_fh || !generation_id ||
	    !request->auth_domain || !request->export_path || !request->object_path ||
	    !request->object_uuid || !request->store_uuid || !request->binding_token ||
	    !registration->admitted || !registration->registration_slot ||
	    !registration->authority || !nn->svc_export_cache) {
		error = -EINVAL;
		goto out_free;
	}
	if (nfsd_ffv2_test_registration_fault(nn, NFSD_FFV2_TEST_AUTH_DOMAIN)) {
		error = -ENOMEM;
		goto out_free;
	}
	object->client = auth_domain_find((char *)request->auth_domain);
	if (!object->client) {
		error = -ENOENT;
		goto out_free;
	}

	if (nfsd_ffv2_test_registration_fault(nn, NFSD_FFV2_TEST_EXPORT_PATH)) {
		error = -EIO;
		goto out_free;
	}
	error = kern_path(request->export_path, LOOKUP_NO_SYMLINKS, &object->export_path);
	if (error)
		goto out_free;
	object->export_valid = true;

	if (nfsd_ffv2_test_registration_fault(nn, NFSD_FFV2_TEST_OBJECT_PATH)) {
		error = -EIO;
		goto out_free;
	}
	error = kern_path(request->object_path, LOOKUP_NO_SYMLINKS, &object->object_path);
	if (error)
		goto out_free;
	object->object_valid = true;
	memcpy(object->object_uuid, request->object_uuid, sizeof(object->object_uuid));

	if (nfsd_ffv2_test_registration_fault(nn, NFSD_FFV2_TEST_EXPORT_LOOKUP)) {
		error = -EIO;
		goto out_free;
	}
	exp = nfsd_ffv2_export_lookup(nn->svc_export_cache, object->client, &object->export_path);
	if (IS_ERR(exp)) {
		error = PTR_ERR(exp);
		goto out_free;
	}
	error = nfsd_ffv2_object_validate(exp, object);
	if (error)
		goto out_put_exp;
	memcpy(object->export_uuid, exp->ex_uuid, sizeof(object->export_uuid));

	fh_init(&ordinary, NFS4_FHSIZE);

	if (nfsd_ffv2_test_registration_fault(nn, NFSD_FFV2_TEST_FH_COMPOSE)) {
		error = -EIO;
		goto out_put_fh;
	}
	status = fh_compose(&ordinary, exp, object->object_path.dentry, NULL);
	if (status) {
		error = -ESTALE;
		goto out_put_fh;
	}
	object->inner_fh = ordinary.fh_handle;
	if (object->inner_fh.fh_size < 8 || object->inner_fh.fh_size > NFSD_FFV2_FH_INNER_MAX ||
	    object->inner_fh.fh_size & 3 || object->inner_fh.fh_raw[0] != 1) {
		error = -E2BIG;
		goto out_put_fh;
	}
	fh_put(&ordinary);

	error = nfsd_ffv2_object_publish(nn, registration, object, exp, request->store_uuid,
					 request->binding_token, current_cred(),
					 request->control_root, outer_fh, generation_id);
	/* The object is consumed either way; only the export is left. */
	exp_put(exp);
	return error;

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
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	atomic_dec(&binding->admission.anchor->test_registration.bindings);
#endif
	nfsd_ffv2_complete(&binding->admission);
	if (binding->prototype_admitted)
		nfsd_ffv2_prototype_op_release(net_generic(binding->net, nfsd_net_id));
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
	binding->admission.provider = NULL;
	binding->admission.provider_result = NULL;
	binding->admission.provider_result_release = NULL;
	if (!nfsd_ffv2_anchor_get(anchor))
		return -ESHUTDOWN;
	mutex_lock(&anchor->lock);
	generation = anchor->active;
	if (anchor->net_state != NFSD_FFV2_NET_LIVE ||
	    anchor->service_state != NFSD_FFV2_SERVICE_UP ||
	    !generation || !generation->registry_generation ||
	    generation->identity->generation != info->generation)
		goto out_unlock;
	context = generation->payload;
	object = nfsd_ffv2_object_set_find(&context->objects, info->object_uuid);
	if (!object || !object->visible ||
	    memcmp(object->export_uuid, info->export_uuid, sizeof(object->export_uuid)) ||
	    memcmp(object->object_uuid, info->object_uuid, sizeof(object->object_uuid)) ||
	    object->inner_fh.fh_size != info->inner_len ||
	    memcmp(object->inner_fh.fh_raw, info->inner, info->inner_len))
		goto out_unlock;
	error = nfsd_ffv2_prototype_op_admit(nn, &binding->prototype_admitted);
	if (error)
		goto out_unlock;
	/* Retirement cannot unpublish or free the payload under anchor->lock. */
	refcount_inc(&generation->ref);
	atomic_inc(&generation->admitted);
	binding->object = object;
	binding->admission.anchor = anchor;
	binding->admission.generation = generation;
	binding->admission.task = current;
	spin_lock(&generation->admissions_lock);
	list_add(&binding->admission.node, &generation->admissions);
	spin_unlock(&generation->admissions_lock);
	error = 0;
out_unlock:
	mutex_unlock(&anchor->lock);
	if (error)
		nfsd_ffv2_anchor_put(anchor);
	return error;
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
unsigned int nfsd_ffv2_test_binding_refs(struct nfsd_ffv2_binding *binding)
{
	return refcount_read(&binding->ref);
}

bool nfsd_ffv2_test_binding_waiting(struct nfsd_ffv2_binding *binding)
{
	/* The retained binding keeps this wait queue and its owner alive. */
	return waitqueue_active(&binding->admission.generation->admitted_wait) &&
	       atomic_read(&binding->admission.generation->test_waiters);
}
#endif

static bool nfsd_ffv2_binding_current(struct nfsd_net *nn,
				      struct nfsd_ffv2_binding *binding)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	bool valid;

	mutex_lock(&anchor->lock);
	valid = anchor->active == binding->admission.generation &&
		binding->object->visible;
	mutex_unlock(&anchor->lock);
	return valid;
}

static bool nfsd_ffv2_read_status_valid(__be32 status)
{
	return status == nfs_ok || status == nfserr_payload_not_atomic ||
	       status == nfserr_noent || status == nfserr_payload_lost;
}

static bool nfsd_ffv2_checksum_valid(const struct nfsd_ffv2_checksum *checksum)
{
	return checksum->cs_algorithm == NFSD_FFV2_CHECKSUM_ALG_CRC32 &&
	       checksum->cs_len == NFSD_FFV2_CHECKSUM_CRC32_LEN;
}

static bool
nfsd_ffv2_read_chunks_valid(u32 count, u32 chunk_size,
			    const struct nfsd_ffv2_read_chunk *chunks)
{
	u64 total = 0;
	u32 i;

	for (i = 0; i < count; i++) {
		const struct nfsd_ffv2_read_chunk *chunk = &chunks[i];

		if (!nfsd_ffv2_read_status_valid(chunk->cr_status))
			return false;
		if (!nfsd_ffv2_checksum_valid(&chunk->cr_checksum))
			return false;
		if (chunk->cr_status == nfserr_noent) {
			u32 crc;

			if (!chunk->cr_effective_len ||
			    chunk->cr_effective_len > chunk_size ||
			    !chunk->cr_chunk ||
			    memchr_inv(chunk->cr_chunk, 0,
				       chunk->cr_effective_len) ||
			    chunk->cr_owner.co_cohort_id ||
			    chunk->cr_owner.co_client_id ||
			    chunk->cr_owner.co_id ||
			    chunk->cr_guard.cg_gen_id ||
			    chunk->cr_guard.cg_client_id !=
				    NFSD_FFV2_GUARD_CLIENT_ID_NONE ||
			    chunk->cr_payload_id || chunk->cr_locked)
				return false;
			crc = crc32_le(~0U, chunk->cr_chunk,
				       chunk->cr_effective_len) ^
			      ~0U;
			if (get_unaligned_be32(chunk->cr_checksum.cs_value) !=
			    crc)
				return false;
			total += chunk->cr_effective_len;
			if (total > NFSD_FFV2_MAX_PAYLOAD_BYTES)
				return false;
			continue;
		}
		if (chunk->cr_status != nfs_ok) {
			if (chunk->cr_effective_len)
				return false;
			continue;
		}
		if (chunk->cr_effective_len > chunk_size ||
		    chunk->cr_effective_len > NFSD_FFV2_MAX_PAYLOAD_BYTES)
			return false;
		if (chunk->cr_effective_len && !chunk->cr_chunk)
			return false;
		total += chunk->cr_effective_len;
	}
	return total <= NFSD_FFV2_MAX_PAYLOAD_BYTES;
}

static bool
nfsd_ffv2_header_entries_valid(u32 count,
			       const struct nfsd_ffv2_chunk_result *result)
{
	u32 i;

	for (i = 0; i < count; i++) {
		const struct nfsd_ffv2_chunk_guard *guard;
		const struct nfsd_ffv2_retained *pred;

		if (!nfsd_ffv2_read_status_valid(result->header.status[i]))
			return false;
		pred = &result->header.predecessors[i];
		switch (pred->disposition) {
		case NFSD_FFV2_RETAINED_ABSENT:
		case NFSD_FFV2_RETAINED_PRESENT:
		case NFSD_FFV2_RETAINED_ERRORED:
			break;
		default:
			return false;
		}

		if (result->header.status[i] != nfserr_noent)
			continue;
		guard = &result->header.guards[i];
		if (guard->cg_gen_id ||
		    guard->cg_client_id != NFSD_FFV2_GUARD_CLIENT_ID_NONE)
			return false;
		if (pred->disposition != NFSD_FFV2_RETAINED_ABSENT)
			return false;
	}
	return true;
}

static bool
nfsd_ffv2_result_valid(u32 opnum, u32 chunk_size,
		       const struct nfsd_ffv2_chunk_request *request,
		       const struct nfsd_ffv2_chunk_result *result)
{
	if (result->count > request->count)
		return false;
	if (result->count < request->count && !result->eof)
		return false;
	if (!result->count)
		return true;
	if (opnum == OP_CHUNK_READ)
		return result->read.chunks &&
		       nfsd_ffv2_read_chunks_valid(result->count, chunk_size,
						   result->read.chunks);
	if (!result->header.status || !result->header.locked ||
	    !result->header.owners || !result->header.guards ||
	    !result->header.predecessors)
		return false;
	return nfsd_ffv2_header_entries_valid(result->count, result);
}

static u32 nfsd_ffv2_read_bound(u32 count, u32 chunk_size)
{
	u64 payload, padding, total;

	if (check_mul_overflow((u64)count, (u64)NFSD4_FFV2_READ_ENT_WORDS,
			       &total))
		return U32_MAX;
	if (check_add_overflow(total, (u64)NFSD4_FFV2_READ_FIXED_WORDS, &total))
		return U32_MAX;
	if (check_mul_overflow(total, (u64)XDR_UNIT, &total))
		return U32_MAX;
	if (check_mul_overflow((u64)count, (u64)chunk_size, &payload))
		return U32_MAX;
	payload = min_t(u64, payload, NFSD_FFV2_MAX_PAYLOAD_BYTES);
	if (check_mul_overflow((u64)count, (u64)(XDR_UNIT - 1), &padding))
		return U32_MAX;

	if (check_add_overflow(total, payload, &total) ||
	    check_add_overflow(total, padding, &total))
		return U32_MAX;
	return total > U32_MAX ? U32_MAX : (u32)total;
}

/* Unpublish before waiting for RCU readers and admitted result owners. */
static struct nfsd_ffv2_provider *
nfsd_ffv2_provider_unpublish(struct nfsd_net *nn)
{
	struct nfsd_ffv2_provider *provider;

	mutex_lock(&nfsd_ffv2_registry_lock);
	provider = rcu_dereference_protected(nn->ffv2.provider,
					     lockdep_is_held(&nfsd_ffv2_registry_lock));
	rcu_assign_pointer(nn->ffv2.provider, NULL);
	mutex_unlock(&nfsd_ffv2_registry_lock);
	return provider;
}

static void nfsd_ffv2_provider_drain(struct nfsd_net *nn,
				     struct nfsd_ffv2_provider *provider)
{
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	struct completion **waiting =
		READ_ONCE(nn->ffv2.test_registration.provider_drain_wait);
#endif

	synchronize_rcu();
	nfsd_ffv2_provider_put(provider);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (waiting) {
		/* Pairs with the observer's acquire while it holds a provider ref. */
		smp_store_release(waiting, &provider->gone);
	}
#endif
	wait_for_completion(&provider->gone);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (waiting) {
		/* The observer cannot dereference the completion after withdrawal. */
		smp_store_release(waiting, NULL);
	}
#endif
	kfree(provider);
}

static bool nfsd_ffv2_provider_shutdown(struct nfsd_net *nn)
{
	struct nfsd_ffv2_provider *provider = nfsd_ffv2_provider_unpublish(nn);

	if (!provider)
		return false;
	nfsd_ffv2_provider_drain(nn, provider);
	return true;
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
void nfsd_ffv2_test_provider_drain_hook(struct nfsd_net *nn,
					struct completion **waiting)
{
	WRITE_ONCE(nn->ffv2.test_registration.provider_drain_wait, waiting);
}

void nfsd_ffv2_test_read_copy_fault(struct nfsd_net *nn, unsigned int stage)
{
	WRITE_ONCE(nn->ffv2.test_registration.read_copy_fault, stage);
}

void nfsd_ffv2_test_object_geometry(struct svc_fh *fhp, u32 chunk_size)
{
	fhp->fh_ffv2_binding->object->chunk_size = chunk_size;
}

#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST) || IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
int nfsd_ffv2_provider_install(struct nfsd_net *nn,
			       const struct nfsd_ffv2_provider_ops *ops,
			       void *data, u32 chunk_size)
{
	struct nfsd_ffv2_provider *provider;
	struct nfsd_ffv2_anchor *anchor;

	if (!nn || !ops || !ops->chunk_read || !ops->chunk_header_read)
		return -EINVAL;
	if (!chunk_size || chunk_size > NFSD_FFV2_MAX_PAYLOAD_BYTES)
		return -EINVAL;
	anchor = &nn->ffv2;
	provider = kzalloc_obj(*provider, GFP_KERNEL);
	if (!provider)
		return -ENOMEM;
	provider->ops = ops;
	provider->data = data;
	provider->chunk_size = chunk_size;
	refcount_set(&provider->ref, 1);
	init_completion(&provider->gone);
	mutex_lock(&anchor->lock);
	if (anchor->net_state != NFSD_FFV2_NET_LIVE) {
		mutex_unlock(&anchor->lock);
		kfree(provider);
		return -ESHUTDOWN;
	}
	mutex_lock(&nfsd_ffv2_registry_lock);
	if (rcu_dereference_protected(nn->ffv2.provider,
				      lockdep_is_held(&nfsd_ffv2_registry_lock))) {
		mutex_unlock(&nfsd_ffv2_registry_lock);
		mutex_unlock(&anchor->lock);
		kfree(provider);
		return -EBUSY;
	}
	rcu_assign_pointer(nn->ffv2.provider, provider);
	mutex_unlock(&nfsd_ffv2_registry_lock);
	mutex_unlock(&anchor->lock);
	return 0;
}

/**
 * nfsd_ffv2_provider_remove - remove @nn's provider
 * @nn: the namespace whose boundary is being closed
 *
 * Takes the provider out of the registry, then waits for the callbacks and
 * admissions still holding it, so no request can be running in provider
 * code once this returns and the caller may free its operations vector and
 * state.  A caller that must keep an admission alive across the removal
 * cannot use this, because the wait is for that admission.
 *
 * Context: Sleeps. Caller holds no admission that would prevent drain.
 */
void nfsd_ffv2_provider_remove(struct nfsd_net *nn)
{
	nfsd_ffv2_provider_shutdown(nn);
}
#endif

static __be32
nfsd_ffv2_provider_dispatch(struct nfsd_net *nn, u32 opnum,
			    const struct nfsd_ffv2_object *object,
			    const struct nfsd_ffv2_chunk_request *request,
			    struct nfsd_ffv2_chunk_result *result, u32 available,
			    struct nfsd_ffv2_admission *admission)
{
	struct nfsd_ffv2_provider *provider;
	bool pinned = admission->provider;
	__be32 status;

	if (pinned) {
		provider = admission->provider;
	} else {
		rcu_read_lock();
		provider = rcu_dereference(nn->ffv2.provider);
		if (!provider || !refcount_inc_not_zero(&provider->ref)) {
			rcu_read_unlock();
			return nfserr_notsupp;
		}
		rcu_read_unlock();
	}
	if (request->count > (opnum == OP_CHUNK_READ ?
				      4096 :
				      NFSD_FFV2_CHUNK_HEADER_READ_MAX) ||
	    request->offset > U64_MAX - request->count) {
		if (!pinned)
			nfsd_ffv2_provider_put(provider);
		return nfserr_inval;
	}
	if (opnum == OP_CHUNK_HEADER_READ &&
	    (u64)(8 + (u64)request->count * 9) * XDR_UNIT > available) {
		if (!pinned)
			nfsd_ffv2_provider_put(provider);
		return nfserr_toosmall;
	}
	if (object->chunk_size && object->chunk_size != provider->chunk_size) {
		if (!pinned)
			nfsd_ffv2_provider_put(provider);
		return nfserr_serverfault;
	}
	if (opnum == OP_CHUNK_READ &&
	    nfsd_ffv2_read_bound(request->count, provider->chunk_size) >
		    available) {
		if (!pinned)
			nfsd_ffv2_provider_put(provider);
		return nfserr_toosmall;
	}

	memset(result, 0, sizeof(*result));
	if (opnum == OP_CHUNK_READ)
		status = provider->ops->chunk_read(provider->data, object,
						   request, result);
	else
		status = provider->ops->chunk_header_read(provider->data, object, request, result);
	/* The admission pins borrowed data even after a callback error. */
	if (!pinned)
		admission->provider = provider;
	if (!!result->private != !!result->release) {
		status = nfserr_serverfault;
	} else if (result->release) {
		if (!admission->provider_result) {
			admission->provider_result = result->private;
			admission->provider_result_release = result->release;
		} else {
			/* A later callback cannot replace an outstanding owner. */
			if (result->private != admission->provider_result)
				result->release(result->private);
			status = nfserr_serverfault;
		}
	}

	return status;
}

/**
 * nfsd_ffv2_provider_probe - borrow one namespace's provider result
 * @rqstp: current request
 * @fhp: mapped filehandle already authorized for this operation
 * @opnum: CHUNK_READ or CHUNK_HEADER_READ
 * @request: chunk range
 * @result: borrowed data, valid until admission completion
 * @available: encoded response capacity in bytes
 * @admission: execution admission held by the current task
 *
 * Context: Sleeps. Call after ordered validation, without spinlocks.
 * Return: NFS status. No provider returns NFS4ERR_NOTSUPP.
 */
__be32 nfsd_ffv2_provider_probe(struct svc_rqst *rqstp, struct svc_fh *fhp,
				u32 opnum,
				const struct nfsd_ffv2_chunk_request *request,
				struct nfsd_ffv2_chunk_result *result,
				u32 available,
				struct nfsd_ffv2_admission *admission)
{
	struct nfsd_ffv2_binding *binding = fhp->fh_ffv2_binding;
	struct nfsd_net *nn;
	__be32 status;

	if (!admission || !admission->generation || admission->task != current)
		return nfserr_serverfault;
	if (opnum != OP_CHUNK_READ && opnum != OP_CHUNK_HEADER_READ)
		return nfserr_notsupp;
	if (!binding || binding->net != SVC_NET(rqstp) ||
	    binding->admission.generation != admission->generation)
		return nfserr_stale;
	nn = net_generic(binding->net, nfsd_net_id);
	if (!nfsd_ffv2_binding_current(nn, binding))
		return nfserr_stale;
	status = nfsd_ffv2_provider_dispatch(nn, opnum, binding->object,
					     request, result, available,
					     admission);
	/* Adopt cleanup ownership before rejecting malformed returned fields. */
	if (status == nfs_ok &&
	    !nfsd_ffv2_result_valid(opnum, admission->provider->chunk_size,
				    request, result))
		return nfserr_serverfault;
	return status;
}

__be32 nfsd_ffv2_provider_admit_mutation(struct svc_rqst *rqstp, u32 opnum,
					 struct nfsd_ffv2_admission *admission)
{
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);
	struct nfsd_ffv2_provider *provider;

	if (!admission || !admission->generation || admission->task != current)
		return nfserr_serverfault;
	if (!admission->provider) {
		rcu_read_lock();
		provider = rcu_dereference(nn->ffv2.provider);
		if (!provider || !refcount_inc_not_zero(&provider->ref)) {
			rcu_read_unlock();
			return nfserr_notsupp;
		}
		rcu_read_unlock();
		admission->provider = provider;
	}
	provider = admission->provider;
	switch (opnum) {
	case OP_CHUNK_WRITE:
		return provider->ops->chunk_write ? nfs_ok : nfserr_notsupp;
	case OP_CHUNK_FINALIZE:
		return provider->ops->chunk_finalize ? nfs_ok : nfserr_notsupp;
	case OP_CHUNK_COMMIT:
		return provider->ops->chunk_commit ? nfs_ok : nfserr_notsupp;
	default:
		return nfserr_notsupp;
	}
}

static __be32
nfsd_ffv2_provider_mutation_dispatch(struct nfsd_net *nn, u32 opnum,
				     const struct nfsd_ffv2_object *object, const void *request,
				     struct nfsd_ffv2_mutation_result *result,
				     struct nfsd_ffv2_admission *admission)
{
	struct nfsd_ffv2_provider *provider = admission->provider;
	__be32 status;

	memset(result, 0, sizeof(*result));
	switch (opnum) {
	case OP_CHUNK_WRITE:
		status = provider->ops->chunk_write ?
				 provider->ops->chunk_write(provider->data, object, request,
							    result) :
				 nfserr_notsupp;
		break;
	case OP_CHUNK_FINALIZE:
		status = provider->ops->chunk_finalize ?
				 provider->ops->chunk_finalize(provider->data, object, request,
							       result) :
				 nfserr_notsupp;
		break;
	case OP_CHUNK_COMMIT:
		status = provider->ops->chunk_commit ?
				 provider->ops->chunk_commit(provider->data, object, request,
							     result) :
				 nfserr_notsupp;
		break;
	default:
		status = nfserr_notsupp;
		break;
	}
	/* Completion owns callback state even on refusal or malformed results. */
	if (!!result->private != !!result->release) {
		status = nfserr_serverfault;
	} else if (result->release) {
		if (!admission->provider_result) {
			admission->provider_result = result->private;
			admission->provider_result_release = result->release;
		} else {
			if (result->private != admission->provider_result)
				result->release(result->private);
			status = nfserr_serverfault;
		}
	}

	return status;
}

static bool nfsd_ffv2_mutation_result_valid(u32 opnum, const void *request,
					    const struct nfsd_ffv2_mutation_result *result)
{
	const struct nfsd_ffv2_chunk_owner *owner;

	if (result->status != nfs_ok && result->status != nfserr_chunk_guarded &&
	    result->status != nfserr_nospc && result->status != nfserr_jukebox &&
	    result->status != nfserr_seq_false_retry && result->status != nfserr_stale_stateid &&
	    result->status != nfserr_io && result->status != nfserr_inval &&
	    result->status != nfserr_serverfault)
		return false;
	if (result->count != 1 || (result->status != nfs_ok && result->activated))
		return false;
	if (opnum == OP_CHUNK_WRITE) {
		const struct nfsd_ffv2_write_request *write = request;

		if ((result->activated && (!write->activate_if_empty || !write->stability)) ||
		    result->stability > NFS_FILE_SYNC ||
		    (result->status == nfs_ok && result->stability < write->stability))
			return false;
		if (result->bytes > write->payload_len ||
		    (result->status == nfs_ok && result->bytes != write->payload_len) ||
		    (result->status != nfs_ok && result->bytes))
			return false;
		owner = &write->owner;
	} else {
		const struct nfsd_ffv2_lifecycle_request *lifecycle = request;

		if (result->bytes || result->activated || result->stability > NFS_FILE_SYNC)
			return false;
		owner = &lifecycle->owner;
	}
	return owner->co_cohort_id == result->owner.co_cohort_id &&
	       owner->co_client_id == result->owner.co_client_id &&
	       owner->co_id == result->owner.co_id;
}

__be32 nfsd_ffv2_provider_mutate(struct svc_rqst *rqstp, struct svc_fh *fhp, u32 opnum,
				 const void *request, struct nfsd_ffv2_mutation_result *result,
				 struct nfsd_ffv2_admission *admission)
{
	struct nfsd_ffv2_binding *binding = fhp->fh_ffv2_binding;
	struct nfsd_net *nn;
	__be32 status;

	if (!request || !result || !admission || !admission->generation ||
	    admission->task != current)
		return nfserr_serverfault;
	if (opnum != OP_CHUNK_WRITE && opnum != OP_CHUNK_FINALIZE && opnum != OP_CHUNK_COMMIT)
		return nfserr_notsupp;
	if (!binding || binding->net != SVC_NET(rqstp) ||
	    binding->admission.generation != admission->generation)
		return nfserr_stale;
	nn = net_generic(binding->net, nfsd_net_id);
	if (!nfsd_ffv2_binding_current(nn, binding))
		return nfserr_stale;
	status = nfsd_ffv2_provider_admit_mutation(rqstp, opnum, admission);
	if (status)
		return status;
	status = nfsd_ffv2_provider_mutation_dispatch(nn, opnum, binding->object, request, result,
						      admission);
	if (status != nfs_ok)
		return status;
	if (nfsd_ffv2_mutation_result_valid(opnum, request, result))
		return nfs_ok;
	return nfserr_serverfault;
}

static bool nfsd_ffv2_mapped_target_valid(struct svc_fh *fhp,
					  struct nfsd_ffv2_binding *binding)
{
	struct nfsd_ffv2_service_context *context = binding->admission.generation->payload;

	return fhp->fh_export == context->export && fhp->fh_export->ex_uuid &&
	       !memcmp(fhp->fh_export->ex_uuid, binding->object->export_uuid,
		       sizeof(binding->object->export_uuid)) &&
	       fhp->fh_export->ex_client == binding->object->client &&
	       fhp->fh_dentry == binding->object->object_path.dentry &&
	       !nfsd_ffv2_object_validate(fhp->fh_export, binding->object);
}

__be32 nfsd_ffv2_fh_map(struct svc_rqst *rqstp, struct svc_fh *fhp)
{
	struct nfsd_ffv2_binding *binding;
	struct nfsd_ffv2_fh_info info;
	struct knfsd_fh outer = fhp->fh_handle;
	struct nfsd_net *nn = net_generic(SVC_NET(rqstp), nfsd_net_id);
	struct net *net;
	__be32 status;

	if (nfsd_ffv2_fh_parse(&outer, &info))
		return nfserr_badhandle;
	if (nfsd_ffv2_test_registration_fault(nn, NFSD_FFV2_TEST_MAP_ALLOC))
		return nfserr_jukebox;
	binding = kzalloc_obj(*binding, GFP_KERNEL);
	if (!binding)
		return nfserr_jukebox;
	refcount_set(&binding->ref, 1);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	atomic_inc(&nn->ffv2.test_registration.bindings);
#endif
	net = nfsd_ffv2_test_registration_fault(nn, NFSD_FFV2_TEST_MAP_NET) ?
		NULL : maybe_get_net(SVC_NET(rqstp));
	if (!net) {
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
		atomic_dec(&nn->ffv2.test_registration.bindings);
#endif
		kfree(binding);
		return nfserr_stale;
	}
	binding->net = net;
	if (nfsd_ffv2_binding_admit(nn, &info, binding)) {
		status = nfserr_stale;
		goto out_net;
	}

	fhp->fh_handle = binding->object->inner_fh;
	status = fh_verify_ffv2_mapped(rqstp, fhp, 0, NFSD_MAY_BYPASS_GSS);
	if (status)
		goto out_fh;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (READ_ONCE(nn->ffv2.test_registration.map_verified)) {
		complete(READ_ONCE(nn->ffv2.test_registration.map_verified));
		wait_for_completion(READ_ONCE(nn->ffv2.test_registration.map_continue));
	}
#endif
	if (!nfsd_ffv2_mapped_target_valid(fhp, binding) ||
	    !nfsd_ffv2_binding_current(nn, binding)) {
		status = nfserr_stale;
		goto out_fh;
	}
	fhp->fh_handle = outer;
	fhp->fh_ffv2_binding = binding;
	return nfs_ok;

out_fh:
	fh_put(fhp);
	nfsd_ffv2_complete(&binding->admission);
	if (binding->prototype_admitted)
		nfsd_ffv2_prototype_op_release(nn);
out_net:
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	atomic_dec(&nn->ffv2.test_registration.bindings);
#endif
	put_net(net);
	kfree(binding);
	return status;
}

__be32 nfsd4_ffv2_export_policy_check(struct svc_export *exp, u32 opnum)
{
	if (!nfsd_ffv2_export_is_service(exp))
		return nfs_ok;
	switch (opnum) {
	case OP_PUTFH:
	case OP_PUTROOTFH:
	case OP_PUTPUBFH:
	case OP_SAVEFH:
	case OP_RESTOREFH:
	case OP_CHUNK_COMMIT:
	case OP_CHUNK_FINALIZE:
	case OP_CHUNK_HEADER_READ:
	case OP_CHUNK_READ:
	case OP_CHUNK_WRITE:
		return nfs_ok;
	default:
		return nfserr_notsupp;
	}
}

static void nfsd_ffv2_service_context_release(void *payload)
{
	struct nfsd_ffv2_service_context *context = payload;
	struct svc_export *exp = context->export;

	if (exp) {
		mutex_lock(&nfsd_ffv2_export_policy_lock);
		rcu_assign_pointer(exp->ex_ffv2_context, NULL);
		mutex_unlock(&nfsd_ffv2_export_policy_lock);
		synchronize_rcu();
		nfsd_export_unhash(exp);
		exp_put(exp);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
		if (READ_ONCE(context->nn->ffv2.test_registration.export_wait))
			complete(READ_ONCE(context->nn->ffv2.test_registration.export_wait));
#endif
		wait_for_completion(&context->export_released);
	}
	/*
	 * Retire trust before the object is freed: entries hold a non-owning
	 * object pointer that stays valid only while the generation does.
	 * This waits, so it must run with no anchor or registry lock held.
	 */
	nfsd_ffv2_trust_registry_destroy(&context->trust);
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	atomic_dec(&context->nn->ffv2.test_registration.contexts);
#endif
	if (context->authority) {
		nfsd_ffv2_authority_detach(context->authority);
		nfsd_ffv2_authority_put(context->authority);
	}
	put_cred(context->cred);
	nfsd_ffv2_reservation_fence(context->reservation);
	if (context->objects_owned)
		nfsd_ffv2_object_set_free(&context->objects);
	/*
	 * Last: the namespace may admit another authority source only once
	 * this generation's objects and trust are gone.
	 */
	if (context->source_claimed)
		nfsd_ffv2_source_release(context->nn, NFSD_FFV2_SOURCE_MDS);
	kfree(context);
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
int nfsd_ffv2_test_authority_state(struct nfsd_ffv2_authority *authority)
{
	return READ_ONCE(authority->state);
}

bool nfsd_ffv2_test_authority_copy(struct nfsd_ffv2_authority *authority,
				   const struct svc_cred *cred)
{
	return authority->machine_cred.cr_principal != cred->cr_principal &&
	       authority->machine_cred.cr_raw_principal != cred->cr_raw_principal &&
	       authority->machine_cred.cr_targ_princ != cred->cr_targ_princ &&
	       !strcmp(authority->machine_cred.cr_principal, cred->cr_principal) &&
	       !strcmp(authority->machine_cred.cr_raw_principal, cred->cr_raw_principal) &&
	       !strcmp(authority->machine_cred.cr_targ_princ, cred->cr_targ_princ) &&
	       authority->machine_cred.cr_group_info == cred->cr_group_info &&
	       authority->machine_cred.cr_gss_mech == cred->cr_gss_mech;
}

void nfsd_ffv2_test_wrong_unregister_kind(struct nfsd_net *nn, bool wrong)
{
	mutex_lock(&nn->ffv2.lock);
	nn->ffv2.active->identity->unregister_kind = wrong ? NFSD_FFV2_UNREGISTER_NONE :
							     NFSD_FFV2_UNREGISTER_OBJECT;
	mutex_unlock(&nn->ffv2.lock);
}

void *nfsd_ffv2_test_trust_hold(struct nfsd_net *nn)
{
	struct nfsd_ffv2_service_context *context;
	struct nfsd_ffv2_trust_entry *entry;
	struct nfsd_ffv2_admission admission = {};
	int error;

	entry = kzalloc_obj(*entry, GFP_KERNEL);
	if (!entry)
		return NULL;
	error = nfsd_ffv2_admit_generation(nn, &admission, NULL, NULL);
	if (error) {
		kfree(entry);
		return NULL;
	}
	context = admission.generation->payload;
	entry->registry = &context->trust;
	entry->object = context->objects.objects[0];
	entry->authority = context->authority;
	nfsd_ffv2_authority_get(entry->authority);
	refcount_set(&entry->ref, 2);
	atomic_set(&entry->state, NFSD_FFV2_TRUST_LIVE);
	mutex_lock(&context->trust.update_lock);
	error = rhashtable_insert_fast(&context->trust.table, &entry->node, nfsd_ffv2_trust_params);
	if (!error) {
		context->trust.entries++;
		atomic_inc(&context->trust.admissions);
	}
	mutex_unlock(&context->trust.update_lock);
	if (error) {
		nfsd_ffv2_authority_put(entry->authority);
		kfree(entry);
		nfsd_ffv2_complete(&admission);
		return NULL;
	}
	nfsd_ffv2_complete(&admission);
	return entry;
}

void nfsd_ffv2_test_trust_put(void *entry)
{
	nfsd_ffv2_trust_entry_put(entry);
}
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
bool nfsd_ffv2_test_export_waiting(struct svc_export *exp)
{
	return exp->ex_ffv2_context_released && swait_active(&exp->ex_ffv2_context_released->wait);
}

bool nfsd_ffv2_test_trust_waiting(void *held)
{
	struct nfsd_ffv2_trust_entry *entry = held;

	/* The held entry keeps the registry and its waitqueue alive. */
	return waitqueue_active(&entry->registry->drain_wait);
}
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
void nfsd_ffv2_test_work_drain(struct nfsd_net *nn)
{
	wait_event(nn->ffv2.authority_wait, nfsd_ffv2_authority_work_idle(&nn->ffv2));
}

int nfsd_ffv2_test_active_authority_state(struct nfsd_net *nn)
{
	struct nfsd_ffv2_service_context *context;
	int state = -ENOENT;

	mutex_lock(&nn->ffv2.lock);
	if (nn->ffv2.active) {
		context = nn->ffv2.active->payload;
		spin_lock(&context->authority->state_lock);
		state = context->authority->state;
		spin_unlock(&context->authority->state_lock);
	}
	mutex_unlock(&nn->ffv2.lock);
	return state;
}
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
bool nfsd_ffv2_test_work_waiting(struct nfsd_net *nn)
{
	/* The fixture owns this namespace until every worker has joined. */
	return waitqueue_active(&nn->ffv2.authority_wait);
}
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST) || IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
static bool nfsd_ffv2_trust_admission_get(struct nfsd_ffv2_trust_registry *registry)
{
	bool admitted = false;

	mutex_lock(&registry->update_lock);
	if (registry->live) {
		atomic_inc(&registry->admissions);
		admitted = true;
	}
	mutex_unlock(&registry->update_lock);
	return admitted;
}

static __be32 nfsd_ffv2_trust_charge_locked(struct nfsd_ffv2_trust_registry *r,
					    size_t principal_len, bool new_entry)
{
	size_t bytes;

	lockdep_assert_held(&r->update_lock);

	if (new_entry && r->entries >= NFSD_FFV2_TRUST_ENTRIES_MAX)
		return nfserr_delay;
	if (check_add_overflow(r->principal_bytes, principal_len, &bytes))
		return nfserr_delay;
	if (bytes > NFSD_FFV2_TRUST_BYTES_MAX)
		return nfserr_delay;
	r->principal_bytes = bytes;
	if (new_entry)
		r->entries++;
	return nfs_ok;
}

static struct nfsd_ffv2_trust_entry *
nfsd_ffv2_trust_entry_alloc(struct nfsd_ffv2_trust_registry *registry,
			    struct nfsd_ffv2_authority *authority, struct nfsd_ffv2_object *object,
			    u64 generation_id, const struct nfsd_ffv2_trust_request *request,
			    u64 authority_epoch, size_t principal_len)
{
	struct nfsd_ffv2_trust_entry *entry;

	entry = nfsd_ffv2_test_registration_fault(registry->test_nn, NFSD_FFV2_TEST_TRUST_ALLOC) ?
			NULL :
			kzalloc_obj(*entry, GFP_KERNEL);
	if (!entry)
		return NULL;
	if (principal_len) {
		entry->principal =
			nfsd_ffv2_test_registration_fault(registry->test_nn,
							  NFSD_FFV2_TEST_TRUST_PRINCIPAL) ?
				NULL :
				kmemdup_nul(request->principal, principal_len, GFP_KERNEL);
		if (!entry->principal) {
			kfree(entry);
			return NULL;
		}
		entry->principal_len = principal_len;
	}
	refcount_set(&entry->ref, 1);
	INIT_LIST_HEAD(&entry->dispose);
	/*
	 * The entry owns an admission from allocation until its final
	 * release, so a request holding a reference blocks destruction.
	 * The caller's install admission guarantees the registry is open.
	 */
	atomic_inc(&registry->admissions);
	nfsd_ffv2_trust_key_init(&entry->key, &request->stateid, request->object_uuid,
				 authority_epoch);
	entry->generation_id = generation_id;
	entry->pnfs_clientid = request->pnfs_clientid;
	entry->client_id = request->client_id;
	entry->actor = request->actor;
	entry->iomode = request->iomode;
	entry->profile_mask = request->profile_mask;
	entry->expires = request->expires;
	entry->object = object;
	entry->registry = registry;
	atomic_set(&entry->state, NFSD_FFV2_TRUST_LIVE);
	nfsd_ffv2_authority_get(authority);
	entry->authority = authority;
	return entry;
}

static bool nfsd_ffv2_trust_renewable(const struct nfsd_ffv2_trust_entry *old,
				      const struct nfsd_ffv2_trust_request *req)
{
	return old->pnfs_clientid.cl_boot == req->pnfs_clientid.cl_boot &&
	       old->pnfs_clientid.cl_id == req->pnfs_clientid.cl_id &&
	       old->client_id == req->client_id && old->iomode == req->iomode &&
	       old->actor == req->actor;
}

static __be32 nfsd_ffv2_trust_install(struct nfsd_ffv2_trust_registry *registry,
				      struct nfsd_ffv2_authority *authority,
				      struct nfsd_ffv2_object *object, u64 generation_id,
				      const struct nfsd_ffv2_trust_request *request)
{
	struct nfsd_ffv2_trust_entry *entry, *old, *replaced = NULL;
	struct nfsd_ffv2_trust_key key;
	size_t principal_len = 0;
	u64 authority_epoch;
	__be32 status;
	int error;

	if (request->iomode != IOMODE_READ && request->iomode != IOMODE_RW)
		return nfserr_inval;
	if (request->expires.tv_nsec < 0 || request->expires.tv_nsec >= NSEC_PER_SEC)
		return nfserr_inval;
	if (request->profile_mask & ~NFSD_FFV2_PROFILE_ALL)
		return nfserr_inval;
	/* Only a data client or a repair actor can hold a trust entry. */
	if (request->actor != NFSD_FFV2_CALLER_DATA_CLIENT &&
	    request->actor != NFSD_FFV2_CALLER_REPAIR_ACTOR)
		return nfserr_inval;
	if (request->principal) {
		principal_len = strnlen(request->principal, NFSD_FFV2_TRUST_PRINCIPAL_MAX + 1);
		if (principal_len > NFSD_FFV2_TRUST_PRINCIPAL_MAX)
			return nfserr_inval;
	}
	if (!nfsd_ffv2_authority_published(authority, &authority_epoch))
		return nfserr_bad_stateid;

	/* Holds the registry open for the whole operation. */
	if (!nfsd_ffv2_trust_admission_get(registry))
		return nfserr_stale;

	entry = nfsd_ffv2_trust_entry_alloc(registry, authority, object, generation_id, request,
					    authority_epoch, principal_len);
	if (!entry) {
		nfsd_ffv2_trust_admission_put(registry);
		return nfserr_delay;
	}

	nfsd_ffv2_trust_key_init(&key, &request->stateid, request->object_uuid, authority_epoch);

	mutex_lock(&registry->update_lock);
	if (!registry->live) {
		status = nfserr_stale;
		goto out_unlock;
	}
	old = rhashtable_lookup_fast(&registry->table, &key, nfsd_ffv2_trust_params);
	if (old && !nfsd_ffv2_trust_renewable(old, request)) {
		status = nfserr_bad_stateid;
		goto out_unlock;
	}
	status = nfsd_ffv2_trust_charge_locked(registry, principal_len, !old);
	if (status != nfs_ok)
		goto out_unlock;

	if (old) {
		/*
		 * Replace atomically.  This cannot allocate, so renewal has
		 * no failure path that could leave the caller's live stateid
		 * unhashed while the operation reports a retryable error.
		 */
		if (nfsd_ffv2_test_registration_fault(registry->test_nn,
						      NFSD_FFV2_TEST_TRUST_REPLACE))
			error = -ENOMEM;
		else
			error = rhashtable_replace_fast(&registry->table, &old->node, &entry->node,
							nfsd_ffv2_trust_params);
		if (!error) {
			/* The old entry stops answering new lookups; its
			 * existing readers finish, and its bytes return at
			 * its own final free.
			 */
			atomic_set_release(&old->state, NFSD_FFV2_TRUST_REPLACED);
			replaced = old;
		}
	} else {
		if (nfsd_ffv2_test_registration_fault(registry->test_nn,
						      NFSD_FFV2_TEST_TRUST_INSERT))
			error = -ENOMEM;
		else
			error = rhashtable_insert_fast(&registry->table, &entry->node,
						       nfsd_ffv2_trust_params);
	}
	if (error) {
		/* The old entry, if any, is still hashed and still LIVE. */
		if (!old && !WARN_ON_ONCE(!registry->entries))
			registry->entries--;
		if (!WARN_ON_ONCE(registry->principal_bytes < principal_len))
			registry->principal_bytes -= principal_len;
		status = nfserr_delay;
		goto out_unlock;
	}
	mutex_unlock(&registry->update_lock);
	nfsd_ffv2_trust_entry_put(replaced);
	nfsd_ffv2_trust_admission_put(registry);
	return nfs_ok;

out_unlock:
	mutex_unlock(&registry->update_lock);
	nfsd_ffv2_trust_entry_put(replaced);
	/* Releases the entry's own admission through the normal path. */
	entry->principal_len = 0;
	nfsd_ffv2_trust_entry_put(entry);
	nfsd_ffv2_trust_admission_put(registry);
	return status;
}

#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
static bool nfsd_ffv2_trust_revoke(struct nfsd_ffv2_trust_registry *registry,
				   const stateid_t *stateid, const u8 object_uuid[16],
				   u64 authority_epoch)
{
	struct nfsd_ffv2_trust_entry *entry;
	struct nfsd_ffv2_trust_key key;
	bool removed = false;

	nfsd_ffv2_trust_key_init(&key, stateid, object_uuid, authority_epoch);

	mutex_lock(&registry->update_lock);
	entry = rhashtable_lookup_fast(&registry->table, &key, nfsd_ffv2_trust_params);
	if (entry)
		removed = nfsd_ffv2_trust_unhash_locked(registry, entry, NFSD_FFV2_TRUST_REVOKED);
	mutex_unlock(&registry->update_lock);

	/* Drops the table reference now that the mutex is released. */
	if (removed)
		nfsd_ffv2_trust_entry_put(entry);
	return removed;
}
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
static void nfsd_ffv2_test_policy_pause(struct nfsd_net *nn, bool execution)
{
	struct nfsd_ffv2_registration_test *test = &nn->ffv2.test_registration;
	struct completion *entered, *resume;

	entered = execution ? READ_ONCE(test->execute_entered) :
			      READ_ONCE(test->validation_entered);
	resume = execution ? READ_ONCE(test->execute_continue) :
			     READ_ONCE(test->validation_continue);
	if (entered) {
		complete(entered);
		wait_for_completion(resume);
	}
}
#endif

static bool nfsd_ffv2_authority_matches_session(struct nfsd_ffv2_authority *authority,
						struct nfsd4_session *session)
{
	struct nfs4_client *clp;
	bool match;

	if (!session)
		return false;
	clp = session->se_client;
	if (!clp)
		return false;

	spin_lock(&authority->state_lock);
	match = authority->state == NFSD_FFV2_AUTHORITY_PUBLISHED &&
		!memcmp(authority->sessionid.data, session->se_sessionid.data,
			NFS4_MAX_SESSIONID_LEN) &&
		authority->clientid.cl_boot == clp->cl_clientid.cl_boot &&
		authority->clientid.cl_id == clp->cl_clientid.cl_id;
	spin_unlock(&authority->state_lock);
	return match;
}

static bool nfsd_ffv2_stateid_is_anonymous(const stateid_t *stateid)
{
	static const stateid_t anonymous = {};

	return !memcmp(stateid, &anonymous, sizeof(*stateid));
}

static bool nfsd_ffv2_trust_entry_has_writer(const struct nfsd_ffv2_trust_entry *entry,
					     struct nfsd4_session *session)
{
	struct nfs4_client *clp;

	if (!session)
		return false;
	clp = session->se_client;
	if (!clp)
		return false;
	return entry->pnfs_clientid.cl_boot == clp->cl_clientid.cl_boot &&
	       entry->pnfs_clientid.cl_id == clp->cl_clientid.cl_id;
}

static __be32 nfsd_ffv2_trust_check_policy(const struct nfsd_ffv2_trust_entry *entry,
					   const struct nfsd_ffv2_op_profile *profile,
					   struct nfsd4_session *session,
					   const struct nfsd_ffv2_actor_id *actor)
{
	u32 iomode = entry->iomode;

	/*
	 * The caller class comes from the entry the metadata server
	 * installed, so an ordinary writer cannot present itself as a repair
	 * actor by choosing a repair operation, and a repair actor cannot
	 * use an ordinary writer's profile.
	 */
	if (!(profile->callers & BIT(entry->actor)))
		return nfserr_bad_stateid;

	switch (profile->iomode) {
	case NFSD_FFV2_IOMODE_RW_ONLY:
		if (iomode != IOMODE_RW)
			return nfserr_bad_stateid;
		break;
	case NFSD_FFV2_IOMODE_READ_OR_RW:
		if (iomode != IOMODE_READ && iomode != IOMODE_RW)
			return nfserr_bad_stateid;
		break;
	case NFSD_FFV2_IOMODE_ANY:
		break;
	}

	/*
	 * A writer or repair actor must name itself on the wire, and that
	 * name must be the one the entry was issued to.  A data request need
	 * not use the MDS session, so the connection cannot supply this.
	 */
	if (profile->writer_identity) {
		if (!actor || !actor->present)
			return nfserr_bad_stateid;
		if (actor->client_id != entry->client_id)
			return nfserr_bad_stateid;
		if (!nfsd_ffv2_trust_entry_has_writer(entry, session))
			return nfserr_bad_stateid;
	}
	return nfs_ok;
}

static struct nfsd_ffv2_generation *nfsd_ffv2_active_generation_get(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;

	mutex_lock(&anchor->lock);
	generation = anchor->active;
	if (generation && generation->registry_generation)
		refcount_inc(&generation->ref);
	else
		generation = NULL;
	mutex_unlock(&anchor->lock);
	return generation;
}

__be32 nfsd_ffv2_validate_operation(struct svc_rqst *rqstp, struct svc_fh *fhp,
				    struct nfsd4_session *session, u32 opnum,
				    const stateid_t *stateid,
				    const struct nfsd_ffv2_actor_id *actor,
				    struct nfsd_ffv2_admission *admission)
{
	const struct nfsd_ffv2_op_profile *profile;
	struct nfsd_ffv2_service_context *context;
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_generation *owned = NULL;
	struct nfsd_ffv2_admission validation = {};
	struct nfsd_ffv2_authority *authority;
	struct nfsd_ffv2_object *object;
	struct nfsd_ffv2_binding *binding;
	struct nfsd_ffv2_trust_entry *entry;
	struct nfsd_net *nn;
	u64 epoch;
	__be32 status;

	/* An operation with no profile cannot be authorized at all. */
	profile = nfsd_ffv2_op_profile(opnum);
	if (!profile)
		return nfserr_notsupp;

	/*
	 * Binding and generation identity precede any state lookup.  A
	 * control operation that names no file, such as BULK_REVOKE_STATEID,
	 * resolves the active generation directly instead, taking a
	 * reference before acquiring its payload validation admission.
	 * It still passes the same authority checks, so this is not a way
	 * around them.
	 */
	binding = fhp ? fhp->fh_ffv2_binding : NULL;
	if (!binding) {
		if (!profile->no_filehandle || !rqstp->rq_xprt)
			return nfserr_stale;
		nn = net_generic(rqstp->rq_xprt->xpt_net, nfsd_net_id);
		owned = nfsd_ffv2_active_generation_get(nn);
		if (!owned)
			return nfserr_stale;
		generation = owned;
	} else {
		if (binding->net != SVC_NET(rqstp))
			return nfserr_stale;
		nn = net_generic(binding->net, nfsd_net_id);
		if (!nfsd_ffv2_binding_current(nn, binding))
			return nfserr_stale;
		generation = binding->admission.generation;
		if (!generation)
			return nfserr_stale;
	}
	/*
	 * A filehandle binding already admits the generation for its lifetime.
	 * A filehandle-less request has only a generation kref so far, which
	 * does not keep retirement from releasing its payload.  Admit it for
	 * validation before reading any context-derived state.  This is not
	 * authorization to execute: the regular admission below still checks
	 * the generation and authority after all policy checks have passed.
	 */
	if (owned && nfsd_ffv2_admit_generation(nn, &validation, generation, NULL)) {
		status = nfserr_stale;
		goto out;
	}
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	if (owned)
		nfsd_ffv2_test_policy_pause(nn, false);
#endif

	context = generation->payload;
	/* A handleless operation cannot select an ambiguous object. */
	object = binding				? binding->object :
		 context && context->objects.count == 1 ? context->objects.objects[0] :
							  NULL;
	if (!context || !object) {
		status = nfserr_stale;
		goto out;
	}
	authority = context->authority;
	if (!authority) {
		status = nfserr_perm;
		goto out;
	}

	if (profile->callers & NFSD_FFV2_CALLERS(MDS_CONTROL)) {
		/*
		 * Control operations must arrive on the exact registered
		 * session, still carrying the machine credential and GSS
		 * profile the authority was derived from.
		 */
		status = nfserr_perm;
		if (!nfsd_ffv2_authority_matches_session(authority, session))
			goto out;
		if (nfsd_ffv2_authority_qualify(session->se_client))
			goto out;
		if ((session->se_client->cl_cred.cr_raw_principal &&
		     !rqstp->rq_cred.cr_raw_principal) ||
		    !nfsd4_mach_creds_match(session->se_client, rqstp))
			goto out;

		/*
		 * The service-root capability probe is recognized only after
		 * authority validation, and only for the exact anonymous
		 * tuple.  It never creates or consults a trust entry.
		 */
		if (opnum == OP_TRUST_STATEID && stateid &&
		    nfsd_ffv2_stateid_is_anonymous(stateid)) {
			status = nfserr_inval;
			goto out;
		}
		/*
		 * A control operation selecting a target client must name
		 * one; the selection is carried to the operation itself.
		 */
		if (opnum == OP_BULK_REVOKE_STATEID && (!actor || !actor->target_present)) {
			status = nfserr_inval;
			goto out;
		}
		status = nfs_ok;
		goto admit;
	}

	/*
	 * Data and repair operations need not use the MDS session, but their
	 * trust entry must be rooted in the published authority epoch.
	 */
	status = nfserr_bad_stateid;
	if (!stateid || nfsd_ffv2_stateid_is_anonymous(stateid))
		goto out;
	if (!nfsd_ffv2_authority_published(authority, &epoch))
		goto out;

	entry = nfsd_ffv2_trust_lookup(&context->trust, stateid, object->object_uuid, epoch);
	if (!entry)
		goto out;

	status = nfsd_ffv2_trust_validate(entry, generation->identity->generation,
					  object->object_uuid, epoch, profile->profile_bit,
					  rqstp->rq_cred.cr_principal);
	if (status == nfs_ok)
		status = nfsd_ffv2_trust_check_policy(entry, profile, session, actor);
	nfsd_ffv2_trust_entry_put(entry);
	if (status != nfs_ok)
		goto out;

admit:
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	nfsd_ffv2_test_policy_pause(nn, true);
#endif
	/*
	 * Execution admission is the fence: it revalidates the generation
	 * identity and the authority state under the anchor lock, and its
	 * reference is what retirement and namespace exit drain before
	 * tearing anything down.  The caller releases it on every path.
	 */
	if (nfsd_ffv2_admit_generation(nn, admission, generation, authority))
		status = nfserr_stale;
out:
	nfsd_ffv2_complete(&validation);
	if (owned)
		nfsd_ffv2_generation_put(owned);
	return status;
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
__be32 nfsd_ffv2_trust_install_active(struct nfsd_net *nn,
				      const struct nfsd_ffv2_trust_request *req)
{
	struct nfsd_ffv2_service_context *context;
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_admission validation = {};
	__be32 status = nfserr_stale;
	struct nfsd_ffv2_object *object;

	generation = nfsd_ffv2_active_generation_get(nn);
	if (!generation)
		return status;
	if (nfsd_ffv2_admit_generation(nn, &validation, generation, NULL))
		goto out;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	nfsd_ffv2_test_policy_pause(nn, false);
#endif
	context = generation->payload;
	object = context ? nfsd_ffv2_object_set_find(&context->objects, req->object_uuid) : NULL;
	if (!object || !context->authority)
		goto out;
	status = nfsd_ffv2_trust_install(&context->trust, context->authority, object,
					 generation->identity->generation, req);
out:
	nfsd_ffv2_complete(&validation);
	nfsd_ffv2_generation_put(generation);
	return status;
}
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
__be32 nfsd_ffv2_test_trust_update(struct nfsd_net *nn, const struct nfsd_ffv2_trust_request *req,
				   bool revoke)
{
	struct nfsd_ffv2_service_context *context;
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_admission validation = {};
	__be32 status = nfserr_stale;
	u64 epoch;

	generation = nfsd_ffv2_active_generation_get(nn);
	if (!generation)
		return status;
	if (nfsd_ffv2_admit_generation(nn, &validation, generation, NULL))
		goto out;
	nfsd_ffv2_test_policy_pause(nn, false);
	context = generation->payload;
	if (!context || !context->objects.count || !context->authority ||
	    memcmp(context->objects.objects[0]->object_uuid, req->object_uuid, 16))
		goto out;
	if (revoke) {
		if (!nfsd_ffv2_authority_published(context->authority, &epoch)) {
			status = nfserr_bad_stateid;
			goto out;
		}
		nfsd_ffv2_trust_revoke(&context->trust, &req->stateid, req->object_uuid, epoch);
		status = nfs_ok;
	} else {
		status = nfsd_ffv2_trust_install(&context->trust, context->authority,
						 context->objects.objects[0],
						 generation->identity->generation, req);
	}
out:
	nfsd_ffv2_complete(&validation);
	nfsd_ffv2_generation_put(generation);
	return status;
}
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
static bool nfsd_ffv2_test_trust_select(struct nfsd_net *nn, struct nfsd_ffv2_admission *admission)
{
	if (nfsd_ffv2_admit_generation(nn, admission, NULL, NULL))
		return false;
	if (!admission->generation->registry_generation) {
		nfsd_ffv2_complete(admission);
		return false;
	}
	return true;
}

void *nfsd_ffv2_test_trust_get(struct nfsd_net *nn, const stateid_t *stateid)
{
	struct nfsd_ffv2_admission admission = {};
	struct nfsd_ffv2_service_context *context;
	struct nfsd_ffv2_trust_entry *entry = NULL;
	u64 epoch;

	if (!nfsd_ffv2_test_trust_select(nn, &admission))
		return NULL;
	context = admission.generation->payload;
	if (nfsd_ffv2_authority_published(context->authority, &epoch))
		entry = nfsd_ffv2_trust_lookup(&context->trust, stateid,
					       context->objects.objects[0]->object_uuid, epoch);
	nfsd_ffv2_complete(&admission);
	return entry;
}

bool nfsd_ffv2_test_trust_snapshot(struct nfsd_net *nn, struct nfsd_ffv2_trust_stats *stats)
{
	struct nfsd_ffv2_admission admission = {};
	struct nfsd_ffv2_service_context *context;

	if (!nfsd_ffv2_test_trust_select(nn, &admission))
		return false;
	context = admission.generation->payload;
	mutex_lock(&context->trust.update_lock);
	stats->entries = context->trust.entries;
	stats->bytes = context->trust.principal_bytes;
	stats->holds = atomic_read(&context->trust.admissions);
	mutex_unlock(&context->trust.update_lock);
	stats->generation = admission.generation->identity->generation;
	stats->epoch = context->authority->epoch;
	nfsd_ffv2_complete(&admission);
	return true;
}

__be32 nfsd_ffv2_test_entry_validate(void *entry, u64 generation, const u8 object_uuid[16],
				     u64 epoch, u32 profile, const char *principal)
{
	return nfsd_ffv2_trust_validate(entry, generation, object_uuid, epoch, profile, principal);
}

unsigned int nfsd_ffv2_test_admitted(struct nfsd_ffv2_admission *observer)
{
	return atomic_read(&observer->generation->admitted);
}
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
bool nfsd_ffv2_anchor_hold(struct nfsd_net *nn)
{
	return nfsd_ffv2_anchor_get(&nn->ffv2);
}
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
void nfsd_ffv2_anchor_release(struct nfsd_net *nn)
{
	nfsd_ffv2_anchor_put(&nn->ffv2);
}
#endif

int nfsd_ffv2_source_claim_gated(struct nfsd_ffv2_anchor *anchor, enum nfsd_ffv2_source want)
{
	lockdep_assert_held(&nfsd_mutex);
	lockdep_assert_held(&anchor->prototype_gate_lock);
	if (want == NFSD_FFV2_SOURCE_NONE)
		return -EINVAL;
	if (anchor->source != NFSD_FFV2_SOURCE_NONE)
		return -EBUSY;
	anchor->source = want;
	return 0;
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
void nfsd_ffv2_source_release_gated(struct nfsd_ffv2_anchor *anchor, enum nfsd_ffv2_source held)
{
	lockdep_assert_held(&nfsd_mutex);
	lockdep_assert_held(&anchor->prototype_gate_lock);
	if (!WARN_ON_ONCE(anchor->source != held))
		anchor->source = NFSD_FFV2_SOURCE_NONE;
}
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
enum nfsd_ffv2_source nfsd_ffv2_source_get(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	enum nfsd_ffv2_source source;

	spin_lock(&anchor->prototype_gate_lock);
	source = anchor->source;
	spin_unlock(&anchor->prototype_gate_lock);
	return source;
}
#endif

int nfsd_ffv2_reservation_store_root(struct nfsd_ffv2_reservation *reservation, struct path *root,
				     u8 store_uuid[16], u8 export_uuid[16], u8 binding_token[32])
{
	int error = 0;

	if (!reservation || !root || !store_uuid || !export_uuid || !binding_token)
		return -EINVAL;
	mutex_lock(&reservation->entry_lock);
	if (reservation->state != NFSD_FFV2_RESERVING &&
	    reservation->state != NFSD_FFV2_RESERVATION_ACTIVE) {
		error = -ESHUTDOWN;
		goto out_unlock;
	}
	*root = reservation->root;
	path_get(root);
	refcount_inc(&reservation->ref);
	memcpy(store_uuid, reservation->store_uuid, sizeof(reservation->store_uuid));
	memcpy(export_uuid, reservation->export_uuid, sizeof(reservation->export_uuid));
	memcpy(binding_token, reservation->binding_token, sizeof(reservation->binding_token));
out_unlock:
	mutex_unlock(&reservation->entry_lock);
	return error;
}

int nfsd_ffv2_reservation_store_begin(struct nfsd_ffv2_reservation *reservation)
{
	mutex_lock(&reservation->entry_lock);
	if (reservation->state == NFSD_FFV2_RESERVING ||
	    reservation->state == NFSD_FFV2_RESERVATION_ACTIVE)
		return 0;
	mutex_unlock(&reservation->entry_lock);
	return -ESHUTDOWN;
}

void nfsd_ffv2_reservation_store_end(struct nfsd_ffv2_reservation *reservation)
{
	mutex_unlock(&reservation->entry_lock);
}

void nfsd_ffv2_reservation_store_put(struct nfsd_ffv2_reservation *reservation)
{
	nfsd_ffv2_reservation_put(reservation);
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
int nfsd_ffv2_authority_prototype_create(struct nfsd_net *nn, struct nfsd_ffv2_authority **result)
{
	struct nfsd_ffv2_authority *authority;
	int error;

	if (nfsd_ffv2_prototype_test_event(nn, NFSD_FFV2_TEST_PROTO_AUTH_ALLOC))
		return -ENOMEM;
	authority = kzalloc_obj(*authority, GFP_KERNEL);
	if (!authority)
		return -ENOMEM;
	refcount_set(&authority->ref, 1);
	spin_lock_init(&authority->state_lock);
	INIT_LIST_HEAD(&authority->session_link);
	authority->nn = nn;
#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
	atomic_inc(&nn->ffv2.test_registration.authorities);
#endif
	authority->state = NFSD_FFV2_AUTHORITY_PREPARED;
	error = nfsd_ffv2_authority_epoch(&nn->ffv2, &authority->epoch);
	if (error) {
		nfsd_ffv2_authority_put(authority);
		return error;
	}
	*result = authority;
	return 0;
}

static bool nfsd_ffv2_member_identity_duplicate(const u8 first_persisted[32],
						const struct knfsd_fh *first_inner,
						const struct inode *first_inode,
						const u8 second_persisted[32],
						const struct knfsd_fh *second_inner,
						const struct inode *second_inode)
{
	return !memcmp(first_persisted, second_persisted, 32) || first_inode == second_inode ||
	       (first_inner->fh_size == second_inner->fh_size &&
		!memcmp(first_inner->fh_raw, second_inner->fh_raw, first_inner->fh_size)) ||
	       !memcmp(first_persisted + 16, second_persisted + 16, 16);
}

int nfsd_ffv2_object_register_fhs(struct nfsd_net *nn, struct nfsd_ffv2_export_update *registration,
				  struct svc_fh *fhps, const u8 persisted_handles[][32], u32 count,
				  u32 chunk_size, const u8 store_uuid[16],
				  const u8 binding_token[32], const struct cred *cred,
				  bool validate_backend, const u8 unregister_uuid[16],
				  u8 object_uuids[][16], struct knfsd_fh *outer_fhs,
				  u64 *generation_id)
{
	struct nfsd_ffv2_object_set objects = {};
	struct svc_export *exp = NULL;
	u32 i, j;
	int error = -EINVAL;

	if (!fhps)
		return -EINVAL;
	if (!nn || !registration || !persisted_handles || !count || count > NFSD_FFV2_MAX_OBJECTS ||
	    !chunk_size || chunk_size > NFSD_FFV2_MAX_PAYLOAD_BYTES || !store_uuid ||
	    !binding_token || !cred || !unregister_uuid || !object_uuids || !outer_fhs ||
	    !generation_id)
		goto out_fhs;
	for (i = 0; i < count; i++) {
		struct nfsd_ffv2_object *object;
		struct svc_export *member_exp = fhps[i].fh_export;

		if (!member_exp || !member_exp->ex_uuid || !fhps[i].fh_dentry ||
		    memcmp(persisted_handles[i], member_exp->ex_uuid, 16)) {
			error = -EXDEV;
			goto out_fhs;
		}
		if (!exp) {
			exp = exp_get(member_exp);
		} else if (member_exp != exp) {
			error = -EXDEV;
			goto out_fhs;
		}
		if ((fhps[i].fh_handle.fh_size < 8 ||
		     fhps[i].fh_handle.fh_size > NFSD_FFV2_FH_INNER_MAX ||
		     fhps[i].fh_handle.fh_size & 3 || fhps[i].fh_handle.fh_raw[0] != 1)) {
			error = -E2BIG;
			goto out_fhs;
		}
		for (j = 0; j < i; j++) {
			if (nfsd_ffv2_member_identity_duplicate(persisted_handles[i],
								&fhps[i].fh_handle,
								d_inode(fhps[i].fh_dentry),
								persisted_handles[j],
								&fhps[j].fh_handle,
								d_inode(fhps[j].fh_dentry))) {
				error = -EEXIST;
				goto out_fhs;
			}
		}
		object = nfsd_ffv2_prototype_test_member(nn, NFSD_FFV2_TEST_PROTO_OBJECT_ALLOC, i) ?
				 NULL :
				 nfsd_ffv2_object_alloc();
		if (!object) {
			error = -ENOMEM;
			goto out_fhs;
		}
		object->chunk_size = chunk_size;
		kref_get(&member_exp->ex_client->ref);
		object->client = member_exp->ex_client;
		object->export_path = member_exp->ex_path;
		path_get(&object->export_path);
		object->export_valid = true;
		object->object_path.mnt = member_exp->ex_path.mnt;
		object->object_path.dentry = fhps[i].fh_dentry;
		path_get(&object->object_path);
		object->object_valid = true;
		object->inner_fh = fhps[i].fh_handle;
		memcpy(object->object_uuid, persisted_handles[i] + 16, 16);
		memcpy(object_uuids[i], object->object_uuid, 16);
		memcpy(object->export_uuid, member_exp->ex_uuid, 16);
		objects.objects[objects.count++] = object;
	}
	error = 0;
out_fhs:
	for (i = 0; i < min_t(u32, count, NFSD_FFV2_MAX_OBJECTS); i++)
		fh_put(&fhps[i]);
	if (error) {
		nfsd_ffv2_object_set_free(&objects);
		if (exp)
			exp_put(exp);
		return error;
	}
	error = nfsd_ffv2_set_publish(nn, registration, &objects, exp, store_uuid, binding_token,
				      cred, 0, validate_backend, NFSD_FFV2_UNREGISTER_PROTOTYPE,
				      unregister_uuid, outer_fhs, generation_id);
	exp_put(exp);
	return error;
}

bool nfsd_ffv2_prototype_generation_matches(struct nfsd_net *nn, const u8 source_uuid[16],
					    u64 generation_id)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;
	bool matches;

	lockdep_assert_held(&anchor->lock);
	generation = anchor->active;

	matches = anchor->net_state == NFSD_FFV2_NET_LIVE &&
		  anchor->service_state == NFSD_FFV2_SERVICE_UP && generation &&
		  generation->identity->generation == generation_id &&
		  generation->identity->unregister_kind == NFSD_FFV2_UNREGISTER_PROTOTYPE &&
		  !memcmp(generation->identity->unregister_uuid, source_uuid, 16);

	return matches;
}

int nfsd_ffv2_registration_begin_prototype(struct nfsd_net *nn,
					   struct nfsd_ffv2_export_update *registration)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	int error;

	lockdep_assert_held(&nfsd_mutex);
	memset(registration, 0, sizeof(*registration));
	error = nfsd_ffv2_export_update_admit(&nn->ffv2_participant, registration);
	if (error)
		return error;
	mutex_lock(&anchor->lock);
	if (anchor->net_state != NFSD_FFV2_NET_LIVE ||
	    anchor->service_state != NFSD_FFV2_SERVICE_UP) {
		error = -ESHUTDOWN;
	} else if (anchor->registration_pending || anchor->pending || anchor->active ||
		   anchor->retiring) {
		error = -EBUSY;
	} else {
		anchor->registration_pending = true;
		registration->registration_slot = true;
	}
	mutex_unlock(&anchor->lock);
	if (error)
		nfsd_ffv2_export_update_put(registration);
	return error;
}

/**
 * nfsd_ffv2_store_open_generation - acquire a store from an exact generation
 * @nn: namespace owning the generation
 * @generation_id: currently published generation
 * @result: receives an independently owned store on success
 *
 * A generation reference does not retain its payload. Hold a validation
 * admission until store-open has acquired its own reservation and file refs.
 *
 * Context: Sleeps. Caller holds no FFv2 lock.
 * Return: Zero on success, or a negative errno.
 */
int nfsd_ffv2_store_open_generation(struct nfsd_net *nn, u64 generation_id,
				    struct nfsd_ffv2_store **result)
{
	struct nfsd_ffv2_service_context *context;
	struct nfsd_ffv2_generation *generation;
	struct nfsd_ffv2_admission validation = {};
	int error = -ESTALE;

	*result = NULL;
	generation = nfsd_ffv2_active_generation_get(nn);
	if (!generation)
		return error;
	if (generation->identity->generation != generation_id)
		goto out;
	error = nfsd_ffv2_admit_generation(nn, &validation, generation, NULL);
	if (error)
		goto out;
	error = nfsd_ffv2_prototype_test_event(nn, NFSD_FFV2_TEST_PROTO_STORE_OPEN);
	if (!error) {
		context = generation->payload;
		error = nfsd_ffv2_store_open(nn, context->reservation, result);
	}
	nfsd_ffv2_complete(&validation);
out:
	nfsd_ffv2_generation_put(generation);
	return error;
}

const u8 *nfsd_ffv2_object_uuid(const struct nfsd_ffv2_object *object)
{
	return object->object_uuid;
}
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST) && IS_ENABLED(CONFIG_NFSD_FFV2_PROTOTYPE_AUTH)
int nfsd_ffv2_test_prototype_handle(struct nfsd_net *nn, u32 index, struct knfsd_fh *fh)
{
	struct nfsd_ffv2_fh_info info = {};
	struct nfsd_ffv2_service_context *context;
	struct nfsd_ffv2_object *object;
	int error = -ENOENT;

	mutex_lock(&nn->ffv2.lock);
	if (!nn->ffv2.active)
		goto out;
	context = nn->ffv2.active->payload;
	if (index >= context->objects.count)
		goto out;
	object = context->objects.objects[index];
	info.generation = nn->ffv2.active->identity->generation;
	memcpy(info.object_uuid, object->object_uuid, 16);
	memcpy(info.export_uuid, object->export_uuid, 16);
	info.inner = object->inner_fh.fh_raw;
	info.inner_len = object->inner_fh.fh_size;
	error = nfsd_ffv2_fh_encode(fh, &info);
out:
	mutex_unlock(&nn->ffv2.lock);
	return error;
}

unsigned int nfsd_ffv2_test_active_admissions(struct nfsd_net *nn)
{
	unsigned int count;

	mutex_lock(&nn->ffv2.lock);
	count = nn->ffv2.active ? atomic_read(&nn->ffv2.active->admitted) : 0;
	mutex_unlock(&nn->ffv2.lock);
	return count;
}
#endif
