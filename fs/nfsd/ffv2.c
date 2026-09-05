// SPDX-License-Identifier: GPL-2.0-only
#include <linux/completion.h>
#include <linux/cred.h>
#include <linux/lockdep.h>
#include <linux/kthread.h>
#include <linux/overflow.h>
#include <linux/refcount.h>
#include <linux/rhashtable.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <linux/fs.h>
#include <linux/fs_context.h>
#include <linux/lockd/bind.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nfslocalio.h>
#include <linux/sunrpc/gss_api.h>
#include <linux/sunrpc/auth_gss.h>
#include <linux/sunrpc/msg_prot.h>
#include <linux/sunrpc/svc_xprt.h>
#include <linux/wait.h>
#include <net/net_namespace.h>

#include "export.h"
#include "ffv2.h"
#include "ffv2_trust.h"
#include "filecache.h"
#include "nfsfh.h"
#include "nfsd.h"
#include "netns.h"
#include "state.h"
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
	/* Bytes in one chunk of this object; zero when it is not known. */
	u32			chunk_size;
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

struct nfsd_ffv2_provider_probe_counters {
	atomic64_t	read;
	atomic64_t	header_read;
	atomic64_t	mapped;
	atomic64_t	stale;
	atomic64_t	fail_closed;
	/* Callbacks actually entered, so a test can tell one from none. */
	atomic64_t	callbacks;
	/* Results the boundary refused to hand back. */
	atomic64_t	malformed;
	atomic64_t	last_generation;
};

static struct nfsd_ffv2_provider_probe_counters nfsd_ffv2_probe_counters;

/* Providers retired by the namespace-exit fence rather than by removal. */
static atomic64_t nfsd_ffv2_provider_fenced = ATOMIC64_INIT(0);

/*
 * A published read-only provider: the callbacks and the opaque state they
 * run against, held in one object so a request can never pair one with the
 * other's replacement.  The reference count protects this container, which
 * is what lets removal know when the last callback has left; the installer
 * owns the operations vector and the state it published and must keep them
 * alive until removal returns.
 *
 * One of these is published per namespace, in nn->ffv2.provider.  There is
 * no way to install one outside a KUnit build, so in an ordinary build
 * every namespace has none and every mapped request still terminates in
 * NFS4ERR_NOTSUPP.
 */
struct nfsd_ffv2_provider {
	const struct nfsd_ffv2_provider_ops	*ops;
	void					*data;
	/*
	 * The one chunk size this provider serves.  Declaring it asserts
	 * that every object it answers for has exactly this size, which the
	 * boundary checks rather than trusts.  It is a homogeneous test
	 * provider's value: a server whose objects differ needs the size
	 * per object, which is where it belongs.
	 */
	u32					chunk_size;
	refcount_t				ref;
	struct completion			gone;
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

/*
 * Trusted stateid registry.
 *
 * The key is the exact bytes the metadata server issued: the whole 16-byte
 * stateid including its seqid, the logical object, and the epoch of the
 * authority that installed it.  nfsd performs no seqid arithmetic on an
 * MDS-issued value, so a new seqid is a distinct entry rather than an
 * update of an existing one.
 *
 * Entries are immutable once published.  Renewal allocates a complete
 * replacement and swaps it under the update mutex, which lets a reader that
 * already validated the old entry finish while new lookups miss it.
 */

/* Contiguous and padding-free so it can be hashed as raw bytes. */
struct nfsd_ffv2_trust_key {
	stateid_t	stateid;
	u8		object_uuid[16];
	u64		authority_epoch;
};

static_assert(sizeof(struct nfsd_ffv2_trust_key) ==
	      sizeof(stateid_t) + 16 + sizeof(u64),
	      "trust key must not carry padding");

enum nfsd_ffv2_trust_state {
	NFSD_FFV2_TRUST_LIVE,
	NFSD_FFV2_TRUST_REPLACED,
	NFSD_FFV2_TRUST_REVOKED,
};

struct nfsd_ffv2_trust_entry {
	struct rhash_head		node;
	struct rcu_head			rcu;
	/* Off-list staging for entries dropped outside the update mutex. */
	struct list_head		dispose;
	refcount_t			ref;
	struct nfsd_ffv2_trust_key	key;
	u64				generation_id;
	clientid_t			pnfs_clientid;
	u32				client_id;
	u32				iomode;
	u32				profile_mask;
	enum nfsd_ffv2_caller_class	actor;
	struct timespec64		expires;
	char				*principal;
	size_t				principal_len;
	atomic_t			state;
	struct nfsd_ffv2_authority	*authority;
	struct nfsd_ffv2_object		*object;
	struct nfsd_ffv2_trust_registry *registry;
};

static const struct rhashtable_params nfsd_ffv2_trust_params = {
	.key_len	= sizeof(struct nfsd_ffv2_trust_key),
	.key_offset	= offsetof(struct nfsd_ffv2_trust_entry, key),
	.head_offset	= offsetof(struct nfsd_ffv2_trust_entry, node),
	.automatic_shrinking = true,
};

struct nfsd_ffv2_trust_registry {
	struct rhashtable	table;
	/* Serializes install, renewal, revoke, and retirement. */
	struct mutex		update_lock;
	unsigned int		entries;
	/*
	 * Closeable admission count: one per live entry, plus one per
	 * in-flight install.  An RCU grace period does not cover a
	 * reference taken before it began, so destruction waits on this
	 * rather than on RCU alone.  It is atomic so the drain predicate
	 * takes no lock: wait_event() evaluates its condition with the
	 * task already set !TASK_RUNNING, where blocking is illegal.
	 */
	atomic_t		admissions;
	wait_queue_head_t	drain_wait;
	size_t			principal_bytes;
	bool			live;
};

struct nfsd_ffv2_service_context {
	struct nfsd_ffv2_trust_registry trust;
	struct nfsd_ffv2_reservation *reservation;
	struct svc_export	*export;
	struct nfsd_ffv2_object *object;
	struct nfsd_ffv2_authority *authority;
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
nfsd_ffv2_admit_generation(struct nfsd_net *nn,
			   struct nfsd_ffv2_admission *admission,
			   struct nfsd_ffv2_generation *expected,
			   struct nfsd_ffv2_authority *authority);
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
		struct svc_export *exp;
		unsigned int reservations = 0;
		unsigned int contexts = 0;
		unsigned int inventory;
		unsigned int service = 0;
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
		list_for_each_entry(exp, &participant->inventory,
				    ex_ffv2_inventory) {
			if (nfsd_ffv2_export_is_service(exp))
				service++;
			if (rcu_access_pointer(exp->ex_ffv2_context))
				contexts++;
		}
		mutex_unlock(&participant->inventory_lock);
		mutex_lock(&nfsd_ffv2_registry_lock);
		list_for_each_entry(reservation, &participant->reservations,
				    owner_node)
			reservations++;
		mutex_unlock(&nfsd_ffv2_registry_lock);

		seq_printf(m,
			   "netns=%u registration=%u updates=%u reservations=%u inventory=%u service=%u contexts=%u pending=%llu active=%llu retiring=%llu\n",
			   snapshots[i].net->ns.inum, registration, updates,
			   reservations, inventory, service, contexts, pending,
			   active, retiring);
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
		list_del_init(&reservation->owner_node);
		reservation->owner = NULL;
		linked = true;
	}
	mutex_unlock(&nfsd_ffv2_registry_lock);
	if (linked) {
		synchronize_rcu();
		INIT_LIST_HEAD(&reservation->node);
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
	if (nfsd_ffv2_trust_registry_init(&context->trust)) {
		kfree(context);
		return NULL;
	}
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
	/*
	 * Last reversible point for the authority: consume PREPARED into
	 * PUBLISHED, or abort here because the session died first.  Session
	 * death takes the same leaf lock, so exactly one of the two
	 * linearizations wins and no generation is published with an
	 * authority that was already dead.
	 */
	if (registration && registration->authority &&
	    !nfsd_ffv2_authority_publish(registration->authority,
					 generation->identity->generation)) {
		error = -ENOENT;
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
		/* The generation payload now owns the authority. */
		context->authority = registration->authority;
		registration->authority = NULL;
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
		goto out_reopen;
	}
	if (expected)
		error = nfsd_ffv2_claim_expected(owner, root, store_uuid,
						 binding_token, expected,
						 &reservation, validate_backend);
	else
		error = __nfsd_ffv2_reservation_claim(owner, root, store_uuid,
						      binding_token, &reservation,
						      validate_backend, NULL);
	if (error && expected)
		goto out_reopen;
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
	/*
	 * A chunk cannot be larger than the whole payload one operation may
	 * carry, so a larger claim is refused here rather than bounding a
	 * reply with it later.
	 */
	if (request->chunk_size > NFSD_FFV2_MAX_PAYLOAD_BYTES) {
		error = -EINVAL;
		goto out_free;
	}
	object->chunk_size = request->chunk_size;

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

/* Statuses a CHUNK_READ result may report per chunk. */
static bool nfsd_ffv2_read_status_valid(__be32 status)
{
	/*
	 * NFS4ERR_NOENT is excluded rather than absent from the protocol: an
	 * EMPTY chunk must be returned as a synthetic payload zero-filled to
	 * the layout's chunk size, and no chunk size reaches this boundary,
	 * so neither the length nor the fill can be checked here.
	 */
	return status == nfs_ok ||
	       status == nfserr_payload_not_atomic ||
	       status == nfserr_payload_lost;
}

/* Statuses a CHUNK_HEADER_READ result may report per chunk. */
static bool nfsd_ffv2_header_status_valid(__be32 status)
{
	/*
	 * NFS4ERR_CHUNK_LOCKED is not among them: lock state is reported
	 * separately in the locked array so that a locked chunk still
	 * surfaces its lifecycle state and owner.
	 */
	return status == nfs_ok ||
	       status == nfserr_payload_not_atomic ||
	       status == nfserr_noent ||
	       status == nfserr_payload_lost;
}

/* A checksum this server can encode and the client can verify. */
static bool nfsd_ffv2_checksum_valid(const struct nfsd_ffv2_checksum *checksum)
{
	return checksum->cs_algorithm == NFSD_FFV2_CHECKSUM_ALG_CRC32 &&
	       checksum->cs_len == NFSD_FFV2_CHECKSUM_CRC32_LEN;
}

/*
 * Per-chunk checks for a read result.  The payload bound is aggregate, so
 * the running total is carried across elements: bounding each chunk alone
 * would admit a full count of chunks each just under the limit.
 */
static bool nfsd_ffv2_read_chunks_valid(u32 count, u32 chunk_size,
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
		/* Only a committed chunk carries bytes. */
		if (chunk->cr_status != nfs_ok) {
			if (chunk->cr_effective_len)
				return false;
			continue;
		}
		/*
		 * No chunk is larger than the size its provider serves, and
		 * none is larger than one operation's whole payload.  The
		 * first is what the reply was admitted against, so a longer
		 * one would not fit the room reserved for it.
		 */
		if (chunk->cr_effective_len > chunk_size ||
		    chunk->cr_effective_len > NFSD_FFV2_MAX_PAYLOAD_BYTES)
			return false;
		/*
		 * A length without a pointer would be copied through NULL.
		 * A pointer without a length is harmless and permitted.
		 */
		if (chunk->cr_effective_len && !chunk->cr_chunk)
			return false;
		total += chunk->cr_effective_len;
	}
	/*
	 * Each element is bounded and the count is bounded, so the sum
	 * cannot overflow the accumulator; only the total needs testing.
	 */
	return total <= NFSD_FFV2_MAX_PAYLOAD_BYTES;
}

/* Per-chunk checks for a header result. */
static bool nfsd_ffv2_header_entries_valid(u32 count,
					   const struct nfsd_ffv2_chunk_result *result)
{
	u32 i;

	for (i = 0; i < count; i++) {
		const struct nfsd_ffv2_chunk_guard *guard;
		const struct nfsd_ffv2_retained *pred;

		if (!nfsd_ffv2_header_status_valid(result->header.status[i]))
			return false;

		/* The discriminant selects a union arm on the wire. */
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
		/*
		 * An EMPTY chunk reports the all-zeros guard and holds no
		 * retained predecessor.  Its owner is unspecified, so it is
		 * deliberately not checked; a terminally lost chunk is a
		 * different case and constrains neither.
		 */
		guard = &result->header.guards[i];
		if (guard->cg_gen_id ||
		    guard->cg_client_id != NFSD_FFV2_GUARD_CLIENT_ID_NONE)
			return false;
		if (pred->disposition != NFSD_FFV2_RETAINED_ABSENT)
			return false;
	}
	return true;
}

/*
 * A provider may answer with fewer chunks than were asked for, but only at
 * the end of what it holds, and never with more.  Every array an encoder
 * would walk has to be there when it says it produced something, and every
 * length, status and metadata invariant an encoder would rely on is checked
 * here, on the way out of the boundary, so the encoder can trust the result
 * rather than re-deriving whether a provider is well behaved.
 */
static bool nfsd_ffv2_result_valid(u32 opnum, u32 chunk_size,
				   const struct nfsd_ffv2_chunk_request *request,
				   const struct nfsd_ffv2_chunk_result *result)
{
	if (result->count > request->count)
		return false;
	/*
	 * Shortness is only ever end-of-range here: a shortfall for response
	 * capacity is applied by bounding the request before it is made, so
	 * a short answer that does not report EOF has no defined meaning and
	 * would leave a client resuming at the offset it started from.
	 */
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

/* Drop a callback's reference, releasing a removal waiting on the last. */
static void nfsd_ffv2_provider_put(struct nfsd_ffv2_provider *provider)
{
	if (refcount_dec_and_test(&provider->ref))
		complete(&provider->gone);
}

/*
 * Unpublish @nn's provider, wait out an RCU grace period so no further
 * callback can find it, drop the publication reference, and wait for the
 * last callback or admission reference before freeing the container.
 *
 * Return: true when a provider was published and has now been retired.
 */
static bool nfsd_ffv2_provider_shutdown(struct nfsd_net *nn)
{
	struct nfsd_ffv2_provider *provider;

	mutex_lock(&nfsd_ffv2_registry_lock);
	provider = rcu_dereference_protected(nn->ffv2.provider,
					     lockdep_is_held(&nfsd_ffv2_registry_lock));
	rcu_assign_pointer(nn->ffv2.provider, NULL);
	mutex_unlock(&nfsd_ffv2_registry_lock);
	if (!provider)
		return false;

	/* No further callback can find it; drain the ones that did. */
	synchronize_rcu();
	nfsd_ffv2_provider_put(provider);
	wait_for_completion(&provider->gone);
	kfree(provider);
	return true;
}

/*
 * Run the read-only provider installed for @nn, if one exists.  The
 * published provider is looked up under RCU and a reference on it is taken
 * there and held across the callback, so removal cannot free the container
 * a request is still inside, and cannot return while the installer's
 * operations vector and state are still in use.
 *
 * Returns nfserr_notsupp with no callback made when that namespace has no
 * provider installed, which is every namespace in an ordinary build.
 */
/*
 * The largest CHUNK_READ reply @count chunks of @chunk_size can produce.
 * The aggregate limit bounds the concatenated payload, so it caps that
 * product alone; each payload is a separately counted opaque, so its
 * padding is a term of its own and is not absorbed by the cap.  With no
 * chunks there is no payload and no padding, so the metadata stands alone.
 *
 * Returns U32_MAX if the arithmetic would overflow, which no response
 * buffer can hold and so rejects the request.
 */
static u32 nfsd_ffv2_read_bound(u32 count, u32 chunk_size)
{
	u64 payload, padding, total;

	if (check_mul_overflow((u64)count, (u64)NFSD4_FFV2_READ_ENT_WORDS,
			       &total))
		return U32_MAX;
	if (check_add_overflow(total, (u64)NFSD4_FFV2_READ_FIXED_WORDS,
			       &total))
		return U32_MAX;
	if (check_mul_overflow(total, (u64)XDR_UNIT, &total))
		return U32_MAX;
	if (!count)
		return total > U32_MAX ? U32_MAX : (u32)total;

	/*
	 * An overflow here is not a reply the aggregate limit would have
	 * bounded, it is arithmetic that says nothing: reject rather than
	 * substitute a number that happens to be smaller.
	 */
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

static __be32
nfsd_ffv2_provider_dispatch(struct nfsd_net *nn, u32 opnum,
			    const struct nfsd_ffv2_object *object,
			    const struct nfsd_ffv2_chunk_request *request,
			    struct nfsd_ffv2_chunk_result *result,
			    u32 available,
			    struct nfsd_ffv2_admission *admission)
{
	struct nfsd_ffv2_provider *provider;
	bool pinned = admission->provider;
	__be32 status;

	/*
	 * An admission owns one provider for its whole life.  A later call
	 * on the same admission uses it rather than looking again: choosing
	 * again could answer from a replacement whose storage this admission
	 * does not hold, and the result would borrow from something nothing
	 * keeps alive.
	 */
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

	/*
	 * Selection, the size the bound is computed from, and the callback
	 * are one decision on one reference: a provider installed after this
	 * point does not answer this request, and the size that admitted it
	 * is the size the answering provider declared.  A provider that
	 * declares one size for objects of another is refused rather than
	 * asked, because the bound would describe a different object.
	 */
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
	atomic64_inc(&nfsd_ffv2_probe_counters.callbacks);
	if (opnum == OP_CHUNK_READ)
		status = provider->ops->chunk_read(provider->data, object,
						   request, result);
	else
		status = provider->ops->chunk_header_read(provider->data,
							  object, request,
							  result);

	/*
	 * A result borrows provider storage, so the reference outlives the
	 * callback: it moves to the execution admission and is dropped when
	 * that completes, which is after every consumer of the result.
	 * Nothing borrows storage from a failed call.  A reference already
	 * owned by the admission stays owned by it and is not dropped here.
	 */
	if (!pinned) {
		if (status != nfs_ok)
			nfsd_ffv2_provider_put(provider);
		else
			admission->provider = provider;
	}
	return status;
}

/**
 * nfsd_ffv2_provider_probe - cross the FFv2 provider boundary
 * @rqstp: the request being served
 * @fhp: current filehandle, which must be a mapped FFv2 binding
 * @opnum: CHUNK_READ or CHUNK_HEADER_READ
 * @request: the chunk range the operation asked for
 * @result: receives the provider's result on success
 * @available: bytes the reply may occupy, from the caller's response buffer
 * @admission: the caller's execution admission, which takes a reference on
 *	the provider so the result's borrowed storage outlives the callback.
 *	Required: there is no result-safe way to cross the boundary without
 *	one
 *
 * The caller has already passed the ordered authority, trusted stateid,
 * and operation-profile checks, and holds an execution admission.  This
 * revalidates the binding against the currently active generation and then
 * consults the provider.
 *
 * What remains missing for a full provider is durable logical identity,
 * the store and write-ahead log behind mutating operations, and escrow
 * ownership; no mutating entry point exists here.
 *
 * Return: the provider's status, NFS4ERR_STALE when the binding no longer
 * names the active generation, NFS4ERR_NOTSUPP when no provider is
 * installed, or NFS4ERR_SERVERFAULT for a malformed provider result or a
 * caller with no execution admission.
 */
__be32 nfsd_ffv2_provider_probe(struct svc_rqst *rqstp, struct svc_fh *fhp,
				u32 opnum,
				const struct nfsd_ffv2_chunk_request *request,
				struct nfsd_ffv2_chunk_result *result,
				u32 available,
				struct nfsd_ffv2_admission *admission)
{
	struct nfsd_ffv2_binding *binding = fhp->fh_ffv2_binding;
	struct nfsd_ffv2_generation *generation;
	struct nfsd_net *nn;
	__be32 status;

	/*
	 * The admission is what a successful result's borrowed storage is
	 * bounded by, so there is no correct way to cross this boundary
	 * without one.  Refuse rather than hand back pointers nothing holds
	 * a reference for; a caller reaching here without an admission is a
	 * kernel bug, not a client one.
	 */
	if (WARN_ON_ONCE(!admission))
		return nfserr_serverfault;

	if (opnum == OP_CHUNK_READ)
		atomic64_inc(&nfsd_ffv2_probe_counters.read);
	else if (opnum == OP_CHUNK_HEADER_READ)
		atomic64_inc(&nfsd_ffv2_probe_counters.header_read);
	else
		return nfserr_notsupp;

	if (!binding || binding->net != SVC_NET(rqstp))
		goto stale;
	nn = net_generic(binding->net, nfsd_net_id);
	if (!nfsd_ffv2_binding_current(nn, binding))
		goto stale;

	generation = binding->admission.generation;
	if (!generation)
		goto stale;
	atomic64_set(&nfsd_ffv2_probe_counters.last_generation,
		     generation->identity->generation);
	atomic64_inc(&nfsd_ffv2_probe_counters.mapped);

	status = nfsd_ffv2_provider_dispatch(nn, opnum, binding->object,
					     request, result, available,
					     admission);
	if (status == nfserr_notsupp) {
		atomic64_inc(&nfsd_ffv2_probe_counters.fail_closed);
		return status;
	}
	if (status == nfs_ok &&
	    !nfsd_ffv2_result_valid(opnum,
				    admission->provider ?
				    admission->provider->chunk_size : 0,
				    request, result)) {
		memset(result, 0, sizeof(*result));
		/* Nothing borrows storage from a refused result. */
		if (admission && admission->provider) {
			nfsd_ffv2_provider_put(admission->provider);
			admission->provider = NULL;
		}
		atomic64_inc(&nfsd_ffv2_probe_counters.malformed);
		return nfserr_serverfault;
	}
	return status;

stale:
	atomic64_inc(&nfsd_ffv2_probe_counters.stale);
	return nfserr_stale;
}

int nfsd_ffv2_provider_probe_show(struct seq_file *m, void *v)
{
	seq_printf(m,
		   "read=%lld header_read=%lld mapped=%lld stale=%lld fail_closed=%lld callbacks=%lld malformed=%lld last_generation=%lld\n",
		   atomic64_read(&nfsd_ffv2_probe_counters.read),
		   atomic64_read(&nfsd_ffv2_probe_counters.header_read),
		   atomic64_read(&nfsd_ffv2_probe_counters.mapped),
		   atomic64_read(&nfsd_ffv2_probe_counters.stale),
		   atomic64_read(&nfsd_ffv2_probe_counters.fail_closed),
		   atomic64_read(&nfsd_ffv2_probe_counters.callbacks),
		   atomic64_read(&nfsd_ffv2_probe_counters.malformed),
		   atomic64_read(&nfsd_ffv2_probe_counters.last_generation));
	return 0;
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
	/*
	 * Retire trust before the object is freed: entries hold a non-owning
	 * object pointer that stays valid only while the generation does.
	 * This waits, so it must run with no anchor or registry lock held.
	 */
	nfsd_ffv2_trust_registry_destroy(&context->trust);
	if (context->authority) {
		nfsd_ffv2_authority_detach(context->authority);
		nfsd_ffv2_authority_put(context->authority);
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
	case OP_CHUNK_HEADER_READ:
	case OP_CHUNK_READ:
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
	/*
	 * Registration cancellation: an authority that never reached
	 * publication is detached here through the common helper.  After a
	 * successful publication the generation payload owns it and this is a
	 * no-op.
	 */
	if (registration->authority) {
		nfsd_ffv2_authority_detach(registration->authority);
		nfsd_ffv2_authority_put(registration->authority);
		registration->authority = NULL;
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

enum nfsd_ffv2_authority_state {
	NFSD_FFV2_AUTHORITY_PREPARED,
	NFSD_FFV2_AUTHORITY_PUBLISHED,
	NFSD_FFV2_AUTHORITY_DEAD,
};

/*
 * Control authority derived from one live NFSv4.1 or later MDS session.
 * Every identity field is read from the session and its client under
 * ->client_lock, so a caller cannot assert an identity it does not already
 * hold on the wire.  The object never pins the network namespace: ->nn is a
 * non-owning pointer valid only while the pernet anchor drains authorities.
 */
struct nfsd_ffv2_authority {
	refcount_t			ref;
	struct nfsd_net			*nn;
	struct nfs4_sessionid		sessionid;
	clientid_t			clientid;
	u64				epoch;
	u64				generation_id;
	struct svc_cred			machine_cred;
	u32				exchange_flags;
	/* Leaf lock, nested under ->client_lock or the publication locks. */
	spinlock_t			state_lock;
	enum nfsd_ffv2_authority_state	state;
	bool				linked;
	struct list_head		session_link;
};

/*
 * FFv2 MDS control authority.
 *
 * A registering caller names one session locator and nothing else.  Every
 * identity fact recorded below is read from the live session and its owning
 * client, so a caller cannot assert an MDS identity it does not already hold
 * on the wire.  The object never takes get_net(): ->nn stays valid only while
 * the pernet anchor still drains authorities, which pre-exit guarantees.
 */

static bool nfsd_ffv2_cred_integrity_protected(const struct svc_cred *cred)
{
	u32 service;

	if (!cred->cr_gss_mech)
		return false;
	service = gss_pseudoflavor_to_service(cred->cr_gss_mech,
					      cred->cr_flavor);
	return service == RPC_GSS_SVC_INTEGRITY ||
	       service == RPC_GSS_SVC_PRIVACY;
}

/**
 * nfsd_ffv2_authority_qualify - may this client act as an MDS control root?
 * @clp: the client owning the located session
 *
 * The self-declared PNFS-MDS flag is necessary but not sufficient: the
 * client must also hold an active machine credential established with
 * RPCSEC_GSS integrity or privacy and present a principal.  AUTH_SYS and an
 * unreviewed transport identity are deliberately not accepted here.
 *
 * Returns 0 when the client qualifies, or -EACCES.
 */
int nfsd_ffv2_authority_qualify(const struct nfs4_client *clp)
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
	kfree(authority);
}

void nfsd_ffv2_authority_get(struct nfsd_ffv2_authority *authority)
{
	refcount_inc(&authority->ref);
}

void nfsd_ffv2_authority_put(struct nfsd_ffv2_authority *authority)
{
	if (authority && refcount_dec_and_test(&authority->ref))
		nfsd_ffv2_authority_free(authority);
}

/* Admit one authority retirement work item.  Returns false once closed. */
static bool nfsd_ffv2_authority_work_admit(struct nfsd_ffv2_anchor *anchor)
{
	bool admitted = false;

	spin_lock(&anchor->authority_tokens_lock);
	if (anchor->authority_work_open) {
		anchor->authority_work++;
		admitted = true;
	}
	spin_unlock(&anchor->authority_tokens_lock);
	return admitted;
}

static void nfsd_ffv2_authority_work_done(struct nfsd_ffv2_anchor *anchor)
{
	spin_lock(&anchor->authority_tokens_lock);
	if (!WARN_ON_ONCE(!anchor->authority_work) &&
	    --anchor->authority_work == 0)
		wake_up_all(&anchor->authority_wait);
	spin_unlock(&anchor->authority_tokens_lock);
}

struct nfsd_ffv2_authority_retire {
	struct work_struct		work;
	struct nfsd_ffv2_authority	*authority;
	u64				generation_id;
};

static void nfsd_ffv2_authority_retire_work(struct work_struct *work)
{
	struct nfsd_ffv2_authority_retire *retire =
		container_of(work, struct nfsd_ffv2_authority_retire, work);
	struct nfsd_ffv2_authority *authority = retire->authority;
	struct nfsd_ffv2_anchor *anchor = &authority->nn->ffv2;

	/* service_generation_retire owns the unlock-around-wait protocol. */
	mutex_lock(&nfsd_mutex);
	nfsd_ffv2_service_generation_retire(authority->nn,
					    retire->generation_id);
	mutex_unlock(&nfsd_mutex);
	nfsd_ffv2_authority_put(authority);
	kfree(retire);
	/* Signals pre-exit last, once ->nn is no longer used here. */
	nfsd_ffv2_authority_work_done(anchor);
}

/*
 * Queue exact-generation retirement for an authority whose session just
 * died.  Retirement waits for users, so it must not run under
 * ->client_lock; the work item runs it with no lock held.  Admission is
 * taken before the item is published and released by the worker, so pre-exit
 * cannot free the anchor underneath it.
 *
 * Caller holds nn->client_lock.
 */
static void
nfsd_ffv2_authority_retire_queue(struct nfsd_ffv2_authority *authority,
				 u64 generation_id)
{
	struct nfsd_ffv2_anchor *anchor = &authority->nn->ffv2;
	struct nfsd_ffv2_authority_retire *retire;

	if (!nfsd_ffv2_authority_work_admit(anchor))
		return;
	retire = kzalloc_obj(*retire, GFP_ATOMIC);
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
	queue_work(system_wq, &retire->work);
}

/*
 * Kill one authority and unlink it from its session.  Returns the session
 * list reference when this call performed the unlink, so the caller can drop
 * that reference once it has released its locks.  Repeated calls are no-ops,
 * so concurrent retirement and session death cannot double drop.
 *
 * Caller holds nn->client_lock; ->state_lock nests inside it.
 */
static struct nfsd_ffv2_authority *
nfsd_ffv2_authority_kill_locked(struct nfsd_ffv2_authority *authority,
				u64 *retire_generation)
{
	struct nfsd_ffv2_authority *dropped = NULL;

	spin_lock(&authority->state_lock);
	if (retire_generation &&
	    authority->state == NFSD_FFV2_AUTHORITY_PUBLISHED)
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
 * Releasing the authority here takes no further lock and queues no work.
 *
 * Caller holds nn->client_lock.
 */
void nfsd_ffv2_session_dead_locked(struct nfsd4_session *session)
{
	struct nfsd_ffv2_authority *authority, *tmp;

	list_for_each_entry_safe(authority, tmp,
				 &session->se_ffv2_authorities, session_link) {
		u64 retire_generation = 0;
		struct nfsd_ffv2_authority *dropped;

		dropped = nfsd_ffv2_authority_kill_locked(authority,
							  &retire_generation);
		if (retire_generation)
			nfsd_ffv2_authority_retire_queue(authority,
							 retire_generation);
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
void nfsd_ffv2_authority_detach(struct nfsd_ffv2_authority *authority)
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
 * Returns true when the authority was still prepared, meaning the caller may
 * proceed with the non-failing generation commit.  Returns false when the
 * session died first, so the caller must abort before replacing the exact
 * export.  Session death takes the same lock, so these are the only two
 * linearizations.
 *
 * May be called with the FFv2 publication locks held: ->state_lock is a leaf
 * and nothing waits under it.
 */
bool nfsd_ffv2_authority_publish(struct nfsd_ffv2_authority *authority,
				 u64 generation_id)
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

/*
 * Caller holds the anchor lock; the authority leaf nests inside it, which
 * is the documented order for publication and admission.
 */
static bool
nfsd_ffv2_authority_published_locked(struct nfsd_ffv2_authority *authority)
{
	bool published;

	spin_lock(&authority->state_lock);
	published = authority->state == NFSD_FFV2_AUTHORITY_PUBLISHED;
	spin_unlock(&authority->state_lock);
	return published;
}

/**
 * nfsd_ffv2_authority_published - read a published authority's epoch
 * @authority: authority to query
 * @epoch: receives the issuer epoch when published
 *
 * Returns true only while the authority is PUBLISHED, so a caller cannot
 * bind new state to a prepared or dead issuer.
 */
bool nfsd_ffv2_authority_published(struct nfsd_ffv2_authority *authority,
				   u64 *epoch)
{
	bool published;

	spin_lock(&authority->state_lock);
	published = authority->state == NFSD_FFV2_AUTHORITY_PUBLISHED;
	if (published)
		*epoch = authority->epoch;
	spin_unlock(&authority->state_lock);
	return published;
}

/*
 * Allocate one epoch from the per-namespace counter.  The counter never
 * wraps and never reissues zero or a prior value: exhaustion fails closed so
 * that no generation is published with a reused epoch.
 */
static int nfsd_ffv2_authority_epoch(struct nfsd_ffv2_anchor *anchor,
				     u64 *epoch)
{
	int error = 0;

	spin_lock(&anchor->authority_tokens_lock);
	if (!anchor->next_authority_epoch ||
	    anchor->next_authority_epoch == U64_MAX)
		error = -EOVERFLOW;
	else
		*epoch = anchor->next_authority_epoch++;
	spin_unlock(&anchor->authority_tokens_lock);
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
	authority = kzalloc_obj(*authority, GFP_KERNEL);
	if (!authority) {
		error = -ENOMEM;
		goto out_put_session;
	}
	refcount_set(&authority->ref, 1);
	spin_lock_init(&authority->state_lock);
	INIT_LIST_HEAD(&authority->session_link);
	authority->nn = nn;
	authority->state = NFSD_FFV2_AUTHORITY_PREPARED;
	memcpy(&authority->sessionid.data, sessionid,
	       NFS4_MAX_SESSIONID_LEN);
	authority->clientid = clientid;
	authority->exchange_flags = exchange_flags;

	error = nfsd4_copy_cred(&authority->machine_cred, &clp->cl_cred);
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
	if (nfsd4_session_is_live_locked(session)) {
		refcount_inc(&authority->ref);
		authority->linked = true;
		list_add(&authority->session_link,
			 &session->se_ffv2_authorities);
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

/**
 * nfsd_ffv2_authority_token_get - admit one temporary authority token
 * @authority: authority the caller wants to use
 *
 * A token holder may use the non-owning ->nn pointer until it releases the
 * admission.  Only a published authority may be admitted.  Returns 0, or
 * -ESHUTDOWN once the gate or authority has closed.
 */
int nfsd_ffv2_authority_token_get(struct nfsd_ffv2_authority *authority)
{
	struct nfsd_ffv2_anchor *anchor = &authority->nn->ffv2;
	int error = -ESHUTDOWN;

	spin_lock(&anchor->authority_tokens_lock);
	if (anchor->authority_tokens_open) {
		spin_lock(&authority->state_lock);
		if (authority->state != NFSD_FFV2_AUTHORITY_PUBLISHED ||
		    !authority->generation_id)
			goto out_state;
		anchor->authority_tokens++;
		refcount_inc(&authority->ref);
		error = 0;
out_state:
		spin_unlock(&authority->state_lock);
	}
	spin_unlock(&anchor->authority_tokens_lock);
	return error;
}

/**
 * nfsd_ffv2_authority_token_put - release one temporary authority token
 * @authority: authority whose token is being released
 */
void nfsd_ffv2_authority_token_put(struct nfsd_ffv2_authority *authority)
{
	struct nfsd_ffv2_anchor *anchor = &authority->nn->ffv2;

	nfsd_ffv2_authority_put(authority);
	spin_lock(&anchor->authority_tokens_lock);
	if (!WARN_ON_ONCE(!anchor->authority_tokens) &&
	    --anchor->authority_tokens == 0)
		wake_up_all(&anchor->authority_wait);
	spin_unlock(&anchor->authority_tokens_lock);
}

static void
nfsd_ffv2_authority_admissions_close(struct nfsd_ffv2_anchor *anchor)
{
	spin_lock(&anchor->authority_tokens_lock);
	anchor->authority_tokens_open = false;
	anchor->authority_work_open = false;
	spin_unlock(&anchor->authority_tokens_lock);
}

static bool
nfsd_ffv2_authority_admissions_idle(struct nfsd_ffv2_anchor *anchor)
{
	bool idle;

	spin_lock(&anchor->authority_tokens_lock);
	idle = !anchor->authority_tokens && !anchor->authority_work;
	spin_unlock(&anchor->authority_tokens_lock);
	return idle;
}

/*
 * Wait for every admitted authority token and retirement work item to drain.
 * No FFv2, anchor, or session lock is held here, and no authority pins the
 * namespace, so this cannot deadlock against a token holder.
 */
static void
nfsd_ffv2_authority_admissions_drain(struct nfsd_ffv2_anchor *anchor)
{
	wait_event(anchor->authority_wait,
		   nfsd_ffv2_authority_admissions_idle(anchor));
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
/*
 * Build a prepared authority linked to @session without a live NFS client.
 * The epoch allocation and session linkage are the production paths; only
 * the session lookup and credential copy are bypassed.
 */
struct nfsd_ffv2_authority *
nfsd_ffv2_test_authority_create(struct nfsd_net *nn,
				struct nfsd4_session *session)
{
	struct nfsd_ffv2_authority *authority;

	authority = kzalloc_obj(*authority, GFP_KERNEL);
	if (!authority)
		return NULL;
	refcount_set(&authority->ref, 1);
	spin_lock_init(&authority->state_lock);
	INIT_LIST_HEAD(&authority->session_link);
	authority->nn = nn;
	authority->state = NFSD_FFV2_AUTHORITY_PREPARED;
	if (nfsd_ffv2_authority_epoch(&nn->ffv2, &authority->epoch)) {
		kfree(authority);
		return NULL;
	}
	spin_lock(&nn->client_lock);
	refcount_inc(&authority->ref);
	authority->linked = true;
	list_add(&authority->session_link, &session->se_ffv2_authorities);
	spin_unlock(&nn->client_lock);
	return authority;
}

u64 nfsd_ffv2_test_authority_epoch(const struct nfsd_ffv2_authority *authority)
{
	return authority->epoch;
}

u64 nfsd_ffv2_test_authority_gen(const struct nfsd_ffv2_authority *authority)
{
	return authority->generation_id;
}

bool nfsd_ffv2_test_authority_dead(const struct nfsd_ffv2_authority *authority)
{
	return READ_ONCE(authority->state) == NFSD_FFV2_AUTHORITY_DEAD;
}

bool
nfsd_ffv2_test_authority_published(const struct nfsd_ffv2_authority *authority)
{
	return READ_ONCE(authority->state) == NFSD_FFV2_AUTHORITY_PUBLISHED;
}

bool
nfsd_ffv2_test_authority_linked(const struct nfsd_ffv2_authority *authority)
{
	return READ_ONCE(authority->linked);
}

int nfsd_ffv2_test_authority_epoch_alloc(struct nfsd_net *nn, u64 *epoch)
{
	return nfsd_ffv2_authority_epoch(&nn->ffv2, epoch);
}

void nfsd_ffv2_test_authority_epoch_set(struct nfsd_net *nn, u64 next)
{
	spin_lock(&nn->ffv2.authority_tokens_lock);
	nn->ffv2.next_authority_epoch = next;
	spin_unlock(&nn->ffv2.authority_tokens_lock);
}

bool nfsd_ffv2_test_authority_work_admit(struct nfsd_net *nn)
{
	return nfsd_ffv2_authority_work_admit(&nn->ffv2);
}

void nfsd_ffv2_test_authority_work_done(struct nfsd_net *nn)
{
	nfsd_ffv2_authority_work_done(&nn->ffv2);
}

void nfsd_ffv2_test_authority_admissions_close(struct nfsd_net *nn)
{
	nfsd_ffv2_authority_admissions_close(&nn->ffv2);
}

bool nfsd_ffv2_test_authority_admissions_idle(struct nfsd_net *nn)
{
	return nfsd_ffv2_authority_admissions_idle(&nn->ffv2);
}
#endif /* CONFIG_NFSD_FFV2_KUNIT_TEST */

/* Trusted stateid registry implementation. */

/*
 * Take one registry admission.  Fails once retirement has closed the
 * registry, which is what prevents a new install from racing destruction.
 */
static bool
nfsd_ffv2_trust_admission_get(struct nfsd_ffv2_trust_registry *registry)
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

static void
nfsd_ffv2_trust_admission_put(struct nfsd_ffv2_trust_registry *registry)
{
	if (atomic_dec_and_test(&registry->admissions))
		wake_up_all(&registry->drain_wait);
}

static void nfsd_ffv2_trust_entry_free(struct rcu_head *rcu)
{
	struct nfsd_ffv2_trust_entry *entry =
		container_of(rcu, struct nfsd_ffv2_trust_entry, rcu);

	kfree_sensitive(entry->principal);
	kfree(entry);
}

/*
 * Release the caller's reference.  The principal and the authority
 * reference are held until the last reader drops out, so a reader that
 * validated the entry before revocation can always finish.
 */
void nfsd_ffv2_trust_entry_put(struct nfsd_ffv2_trust_entry *entry)
{
	struct nfsd_ffv2_trust_registry *registry;
	struct nfsd_ffv2_authority *authority;
	size_t bytes;

	if (!entry || !refcount_dec_and_test(&entry->ref))
		return;

	registry = entry->registry;
	authority = entry->authority;
	bytes = entry->principal_len;

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
	entry->authority = NULL;
	call_rcu(&entry->rcu, nfsd_ffv2_trust_entry_free);
	nfsd_ffv2_authority_put(authority);
}

/**
 * nfsd_ffv2_trust_registry_init - prepare one generation's trust registry
 * @registry: registry embedded in the generation payload
 */
int nfsd_ffv2_trust_registry_init(struct nfsd_ffv2_trust_registry *registry)
{
	int error;

	mutex_init(&registry->update_lock);
	init_waitqueue_head(&registry->drain_wait);
	registry->entries = 0;
	atomic_set(&registry->admissions, 0);
	registry->principal_bytes = 0;
	error = rhashtable_init(&registry->table, &nfsd_ffv2_trust_params);
	if (error) {
		mutex_destroy(&registry->update_lock);
		return error;
	}
	registry->live = true;
	return 0;
}

/*
 * Remove one entry from lookup.  On success the table's reference becomes
 * the caller's, to be dropped once the update mutex is released: releasing
 * it takes that same mutex to return the principal budget.
 */
static bool nfsd_ffv2_trust_unhash_locked(struct nfsd_ffv2_trust_registry *reg,
					  struct nfsd_ffv2_trust_entry *entry,
					  enum nfsd_ffv2_trust_state state)
{
	lockdep_assert_held(&reg->update_lock);

	if (rhashtable_remove_fast(&reg->table, &entry->node,
				   nfsd_ffv2_trust_params))
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
void nfsd_ffv2_trust_retire(struct nfsd_ffv2_trust_registry *registry)
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
		if (nfsd_ffv2_trust_unhash_locked(registry, entry,
						  NFSD_FFV2_TRUST_REVOKED))
			/* Carries the table reference, dropped below. */
			list_add_tail(&entry->dispose, &doomed);
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	mutex_unlock(&registry->update_lock);

	/* No registry, anchor, or service lock is held across this wait. */
	synchronize_rcu();
	while (!list_empty(&doomed)) {
		entry = list_first_entry(&doomed, struct nfsd_ffv2_trust_entry,
					 dispose);
		list_del(&entry->dispose);
		nfsd_ffv2_trust_entry_put(entry);
	}
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
void nfsd_ffv2_trust_registry_destroy(struct nfsd_ffv2_trust_registry *registry)
{
	nfsd_ffv2_trust_retire(registry);
	/* Lockless predicate: wait_event() forbids blocking in its test. */
	wait_event(registry->drain_wait,
		   !atomic_read(&registry->admissions));
	WARN_ON_ONCE(registry->entries);
	WARN_ON_ONCE(registry->principal_bytes);
	rhashtable_destroy(&registry->table);
	mutex_destroy(&registry->update_lock);
}

static void nfsd_ffv2_trust_key_init(struct nfsd_ffv2_trust_key *key,
				     const stateid_t *stateid,
				     const u8 object_uuid[16],
				     u64 authority_epoch)
{
	/* Hashed as raw bytes, so every byte must be initialised. */
	memset(key, 0, sizeof(*key));
	key->stateid = *stateid;
	memcpy(key->object_uuid, object_uuid, 16);
	key->authority_epoch = authority_epoch;
}

/**
 * nfsd_ffv2_trust_lookup - find a live entry and take a reference
 * @registry: generation's registry
 * @stateid: exact 16-byte stateid as issued, including seqid
 * @object_uuid: logical object the entry is bound to
 * @authority_epoch: epoch of the issuing authority
 *
 * Returns a referenced entry, or NULL.  The caller must revalidate with
 * nfsd_ffv2_trust_validate() after leaving the RCU section, and must drop
 * the reference with nfsd_ffv2_trust_entry_put().
 */
struct nfsd_ffv2_trust_entry *
nfsd_ffv2_trust_lookup(struct nfsd_ffv2_trust_registry *registry,
		       const stateid_t *stateid, const u8 object_uuid[16],
		       u64 authority_epoch)
{
	struct nfsd_ffv2_trust_entry *entry;
	struct nfsd_ffv2_trust_key key;

	nfsd_ffv2_trust_key_init(&key, stateid, object_uuid, authority_epoch);

	rcu_read_lock();
	entry = rhashtable_lookup(&registry->table, &key,
				  nfsd_ffv2_trust_params);
	/* A replaced or revoked entry must not start a new operation. */
	if (entry && atomic_read_acquire(&entry->state) != NFSD_FFV2_TRUST_LIVE)
		entry = NULL;
	if (entry && !refcount_inc_not_zero(&entry->ref))
		entry = NULL;
	rcu_read_unlock();
	return entry;
}

/**
 * nfsd_ffv2_trust_validate - revalidate a referenced entry outside RCU
 * @entry: referenced entry from nfsd_ffv2_trust_lookup()
 * @generation_id: generation the request resolved to
 * @object_uuid: object the request resolved to
 * @authority_epoch: epoch the request resolved to
 * @profile_bit: the single profile bit this operation requires
 * @principal: authenticated request principal, or NULL for none
 *
 * Returns nfs_ok, or the exact wire status for the first failing check.
 */
__be32 nfsd_ffv2_trust_validate(const struct nfsd_ffv2_trust_entry *entry,
				u64 generation_id, const u8 object_uuid[16],
				u64 authority_epoch, u32 profile_bit,
				const char *principal)
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

/*
 * Charge one principal against the per-generation and per-issuer budgets.
 * A replacement does not change the entry count, only the retained bytes.
 */
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
			    struct nfsd_ffv2_authority *authority,
			    struct nfsd_ffv2_object *object,
			    u64 generation_id,
			    const struct nfsd_ffv2_trust_request *request,
			    u64 authority_epoch, size_t principal_len)
{
	struct nfsd_ffv2_trust_entry *entry;

	entry = kzalloc_obj(*entry, GFP_KERNEL);
	if (!entry)
		return NULL;
	if (principal_len) {
		entry->principal = kmemdup_nul(request->principal,
					       principal_len, GFP_KERNEL);
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
	nfsd_ffv2_trust_key_init(&entry->key, &request->stateid,
				 request->object_uuid, authority_epoch);
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

/* An exact key may be renewed only when the whole target identity matches. */
static bool nfsd_ffv2_trust_renewable(const struct nfsd_ffv2_trust_entry *old,
				      const struct nfsd_ffv2_trust_request *req)
{
	return old->pnfs_clientid.cl_boot == req->pnfs_clientid.cl_boot &&
	       old->pnfs_clientid.cl_id == req->pnfs_clientid.cl_id &&
	       old->client_id == req->client_id &&
	       old->iomode == req->iomode &&
	       old->actor == req->actor;
}

/**
 * nfsd_ffv2_trust_install - create or renew one trusted stateid
 * @registry: generation's registry
 * @authority: issuing MDS authority, must be published
 * @object: generation-owned object the entry binds to
 * @generation_id: owning generation
 * @request: immutable description of the registration
 *
 * Allocates the complete replacement before taking the update mutex, so a
 * failure never disturbs a live entry.  Returns nfs_ok, or the wire status.
 */
__be32 nfsd_ffv2_trust_install(struct nfsd_ffv2_trust_registry *registry,
			       struct nfsd_ffv2_authority *authority,
			       struct nfsd_ffv2_object *object,
			       u64 generation_id,
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
	if (request->expires.tv_nsec < 0 ||
	    request->expires.tv_nsec >= NSEC_PER_SEC)
		return nfserr_inval;
	if (request->profile_mask & ~NFSD_FFV2_PROFILE_ALL)
		return nfserr_inval;
	/* Only a data client or a repair actor can hold a trust entry. */
	if (request->actor != NFSD_FFV2_CALLER_DATA_CLIENT &&
	    request->actor != NFSD_FFV2_CALLER_REPAIR_ACTOR)
		return nfserr_inval;
	if (request->principal) {
		principal_len = strnlen(request->principal,
					NFSD_FFV2_TRUST_PRINCIPAL_MAX + 1);
		if (principal_len > NFSD_FFV2_TRUST_PRINCIPAL_MAX)
			return nfserr_inval;
	}
	if (!nfsd_ffv2_authority_published(authority, &authority_epoch))
		return nfserr_bad_stateid;

	/* Holds the registry open for the whole operation. */
	if (!nfsd_ffv2_trust_admission_get(registry))
		return nfserr_stale;

	entry = nfsd_ffv2_trust_entry_alloc(registry, authority, object,
					    generation_id, request,
					    authority_epoch, principal_len);
	if (!entry) {
		nfsd_ffv2_trust_admission_put(registry);
		return nfserr_delay;
	}

	nfsd_ffv2_trust_key_init(&key, &request->stateid, request->object_uuid,
				 authority_epoch);

	mutex_lock(&registry->update_lock);
	if (!registry->live) {
		status = nfserr_stale;
		goto out_unlock;
	}
	old = rhashtable_lookup_fast(&registry->table, &key,
				     nfsd_ffv2_trust_params);
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
		if (nfsd_ffv2_fault_inject(NFSD_FFV2_FAULT_TRUST_REPLACE))
			error = -ENOMEM;
		else
			error = rhashtable_replace_fast(&registry->table,
							&old->node,
							&entry->node,
							nfsd_ffv2_trust_params);
		if (!error) {
			/* The old entry stops answering new lookups; its
			 * existing readers finish, and its bytes return at
			 * its own final free.
			 */
			atomic_set_release(&old->state,
					   NFSD_FFV2_TRUST_REPLACED);
			replaced = old;
		}
	} else {
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

/**
 * nfsd_ffv2_trust_revoke - remove one exact entry from lookup
 * @registry: generation's registry
 * @stateid: exact stateid to revoke
 * @object_uuid: object the entry is bound to
 * @authority_epoch: epoch of the requesting issuer
 *
 * Returns true when an entry was removed.  A miss, including an entry owned
 * by a different issuer, is not an error to the caller.
 */
bool nfsd_ffv2_trust_revoke(struct nfsd_ffv2_trust_registry *registry,
			    const stateid_t *stateid, const u8 object_uuid[16],
			    u64 authority_epoch)
{
	struct nfsd_ffv2_trust_entry *entry;
	struct nfsd_ffv2_trust_key key;
	bool removed = false;

	nfsd_ffv2_trust_key_init(&key, stateid, object_uuid, authority_epoch);

	mutex_lock(&registry->update_lock);
	entry = rhashtable_lookup_fast(&registry->table, &key,
				       nfsd_ffv2_trust_params);
	if (entry)
		removed = nfsd_ffv2_trust_unhash_locked(registry, entry,
							NFSD_FFV2_TRUST_REVOKED);
	mutex_unlock(&registry->update_lock);

	/* Drops the table reference now that the mutex is released. */
	if (removed)
		nfsd_ffv2_trust_entry_put(entry);
	return removed;
}

/**
 * nfsd_ffv2_trust_bulk_revoke - revoke one issuer's entries
 * @registry: generation's registry
 * @authority_epoch: only entries installed by this issuer are considered
 * @target: pNFS client to select, or NULL for all of this issuer's entries
 *
 * Never touches an entry owned by another metadata server.  Returns the
 * number of entries removed.
 */
unsigned int
nfsd_ffv2_trust_bulk_revoke(struct nfsd_ffv2_trust_registry *registry,
			    u64 authority_epoch,
			    const clientid_t *target)
{
	struct nfsd_ffv2_trust_entry *entry;
	struct rhashtable_iter iter;
	unsigned int removed = 0;
	LIST_HEAD(doomed);

	mutex_lock(&registry->update_lock);
	rhashtable_walk_enter(&registry->table, &iter);
	rhashtable_walk_start(&iter);
	while ((entry = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(entry))
			continue;
		if (entry->key.authority_epoch != authority_epoch)
			continue;
		if (target &&
		    (entry->pnfs_clientid.cl_boot != target->cl_boot ||
		     entry->pnfs_clientid.cl_id != target->cl_id))
			continue;
		if (!nfsd_ffv2_trust_unhash_locked(registry, entry,
						   NFSD_FFV2_TRUST_REVOKED))
			continue;
		list_add_tail(&entry->dispose, &doomed);
		removed++;
	}
	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	mutex_unlock(&registry->update_lock);

	while (!list_empty(&doomed)) {
		entry = list_first_entry(&doomed, struct nfsd_ffv2_trust_entry,
					 dispose);
		list_del(&entry->dispose);
		nfsd_ffv2_trust_entry_put(entry);
	}
	return removed;
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
struct nfsd_ffv2_trust_registry *nfsd_ffv2_test_trust_registry_alloc(void)
{
	struct nfsd_ffv2_trust_registry *registry;

	registry = kzalloc_obj(*registry, GFP_KERNEL);
	if (!registry)
		return NULL;
	if (nfsd_ffv2_trust_registry_init(registry)) {
		kfree(registry);
		return NULL;
	}
	return registry;
}

void nfsd_ffv2_test_trust_registry_free(struct nfsd_ffv2_trust_registry *reg)
{
	nfsd_ffv2_trust_registry_destroy(reg);
	kfree(reg);
}

unsigned int
nfsd_ffv2_test_trust_entries(const struct nfsd_ffv2_trust_registry *registry)
{
	return registry->entries;
}

size_t
nfsd_ffv2_test_trust_bytes(const struct nfsd_ffv2_trust_registry *registry)
{
	return registry->principal_bytes;
}

bool nfsd_ffv2_test_trust_replaced(const struct nfsd_ffv2_trust_entry *entry)
{
	return atomic_read(&entry->state) == NFSD_FFV2_TRUST_REPLACED;
}

bool nfsd_ffv2_test_trust_revoked(const struct nfsd_ffv2_trust_entry *entry)
{
	return atomic_read(&entry->state) == NFSD_FFV2_TRUST_REVOKED;
}

u32 nfsd_ffv2_test_trust_iomode(const struct nfsd_ffv2_trust_entry *entry)
{
	return entry->iomode;
}

enum nfsd_ffv2_caller_class
nfsd_ffv2_test_trust_actor(const struct nfsd_ffv2_trust_entry *entry)
{
	return entry->actor;
}
#endif /* CONFIG_NFSD_FFV2_KUNIT_TEST */

/**
 * nfsd_ffv2_authority_matches_session - is this the exact registered session?
 * @authority: published authority to compare against
 * @session: session the request arrived on
 *
 * Compares the whole session locator and the owning clientid, so a client
 * that copied a machine credential onto a different session cannot present
 * itself as the metadata server.
 */
static bool
nfsd_ffv2_authority_matches_session(struct nfsd_ffv2_authority *authority,
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

/* Is this the anonymous capability-probe tuple rather than a real stateid? */
static bool nfsd_ffv2_stateid_is_anonymous(const stateid_t *stateid)
{
	static const stateid_t anonymous = {};

	return !memcmp(stateid, &anonymous, sizeof(*stateid));
}

/*
 * FFv2 operation profiles.
 *
 * Each operation names one caller class, one profile bit, and its iomode
 * requirement.  An operation absent from this table has no profile and
 * cannot be authorized, which is what keeps values outside the frozen
 * 78..91 range, including the escrow family, unreachable.
 */
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
	/*
	 * The lifecycle operations name a chunk_owner4 array that the
	 * decoder counts but does not retain; enabling their dispatch
	 * requires retaining those identities first.
	 */
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

/* Entry accessors used by the ordered validation gate. */
static u32
nfsd_ffv2_trust_entry_iomode(const struct nfsd_ffv2_trust_entry *entry)
{
	return entry->iomode;
}

/*
 * Does this entry name the requesting client as its writer?  With no
 * session the answer is no: a writer must be identifiable.
 */
static bool
nfsd_ffv2_trust_entry_has_writer(const struct nfsd_ffv2_trust_entry *entry,
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

/*
 * Iomode and writer policy, checked after the entry's own validation so a
 * caller cannot substitute a read entry for a write operation, or act as a
 * writer or repair actor it is not.
 */
static __be32
nfsd_ffv2_trust_check_policy(const struct nfsd_ffv2_trust_entry *entry,
			     const struct nfsd_ffv2_op_profile *profile,
			     struct nfsd4_session *session,
			     const struct nfsd_ffv2_actor_id *actor)
{
	u32 iomode = nfsd_ffv2_trust_entry_iomode(entry);

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

/*
 * Drop a generation reference taken for a filehandle-less operation.  A
 * request that used a mapped binding owns no such reference.
 */
static void nfsd_ffv2_generation_put_owned(struct nfsd_ffv2_generation *owned)
{
	if (owned)
		nfsd_ffv2_generation_put(owned);
}

/*
 * Take a reference to the generation a filehandle-less control operation
 * applies to.  The reference is acquired under the anchor lock, because
 * retirement takes that lock to move the generation off ->active and then
 * releases it: an unreferenced pointer read here could be freed before it
 * was dereferenced.  The caller owns the reference and must drop it on
 * every path.
 */
static struct nfsd_ffv2_generation *
nfsd_ffv2_active_generation_get(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;

	mutex_lock(&anchor->lock);
	generation = anchor->active;
	if (generation)
		refcount_inc(&generation->ref);
	mutex_unlock(&anchor->lock);
	return generation;
}

/**
 * nfsd_ffv2_validate_operation - ordered FFv2 authorization gate
 * @rqstp: the request being authorized
 * @fhp: current filehandle, which must already be a mapped FFv2 binding
 * @session: session the request arrived on, or NULL
 * @opnum: FFv2 operation number
 * @stateid: stateid the operation presented, or NULL when it has none
 * @actor: writer or repair-actor identity the request named, or NULL
 * @admission: receives the execution admission the caller must release
 *
 * Runs every authorization check in the design's precedence before any
 * provider admission could be taken.  The caller has already resolved
 * decode and SEQUENCE status; this function covers binding, authority,
 * trusted stateid, operation profile, principal and writer policy, and
 * generation liveness.
 *
 * Returns the exact wire status for the first failing check, or nfs_ok
 * when the request is fully authorized.  A fully authorized request still
 * terminates in NFS4ERR_NOTSUPP at its caller: no provider exists.
 */
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
	struct nfsd_ffv2_authority *authority;
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
	 * reference so retirement cannot free it underneath this request.
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

	context = generation->payload;
	if (!context || !context->object) {
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
		if (!nfsd4_mach_creds_match(session->se_client, rqstp))
			goto out;

		/*
		 * The service-root capability probe is recognised only after
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
		if (opnum == OP_BULK_REVOKE_STATEID &&
		    (!actor || !actor->target_present)) {
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

	entry = nfsd_ffv2_trust_lookup(&context->trust, stateid,
				       context->object->object_uuid, epoch);
	if (!entry)
		goto out;

	status = nfsd_ffv2_trust_validate(entry,
					  generation->identity->generation,
					  context->object->object_uuid, epoch,
					  profile->profile_bit,
					  rqstp->rq_cred.cr_principal);
	if (status == nfs_ok)
		status = nfsd_ffv2_trust_check_policy(entry, profile, session,
						      actor);
	nfsd_ffv2_trust_entry_put(entry);
	if (status != nfs_ok)
		goto out;

admit:
	/*
	 * Execution admission is the fence: it revalidates the generation
	 * identity and the authority state under the anchor lock, and its
	 * reference is what retirement and namespace exit drain before
	 * tearing anything down.  The caller releases it on every path.
	 */
	if (nfsd_ffv2_admit_generation(nn, admission, generation, authority))
		status = nfserr_stale;
out:
	nfsd_ffv2_generation_put_owned(owned);
	return status;
}

#if IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
/*
 * Take and drop a filehandle-less generation reference the way the gate
 * does, so a test can prove retirement waits for it.
 */
struct nfsd_ffv2_generation *
nfsd_ffv2_test_active_generation_get(struct nfsd_net *nn)
{
	return nfsd_ffv2_active_generation_get(nn);
}

void nfsd_ffv2_test_generation_put(struct nfsd_ffv2_generation *generation)
{
	nfsd_ffv2_generation_put_owned(generation);
}

unsigned int
nfsd_ffv2_test_generation_refcount(struct nfsd_ffv2_generation *generation)
{
	return refcount_read(&generation->ref);
}

/*
 * Install a trust entry into the active generation's registry, the way the
 * TRUST_STATEID handler will once it exists.  @authority selects the
 * issuer: NULL uses the generation's own, and any other published
 * authority roots the entry in a different issuer epoch, which is how a
 * test builds a stale-issuer negative that the gate must not find.
 */
__be32
nfsd_ffv2_test_trust_install_active(struct nfsd_net *nn,
				    struct nfsd_ffv2_authority *authority,
				    const struct nfsd_ffv2_trust_request *req)
{
	struct nfsd_ffv2_service_context *context;
	struct nfsd_ffv2_generation *generation;
	__be32 status;

	generation = nfsd_ffv2_active_generation_get(nn);
	if (!generation)
		return nfserr_stale;
	context = generation->payload;
	if (!context || !context->object || !context->authority) {
		nfsd_ffv2_generation_put_owned(generation);
		return nfserr_stale;
	}
	status = nfsd_ffv2_trust_install(&context->trust,
					 authority ? authority :
						     context->authority,
					 context->object,
					 generation->identity->generation, req);
	nfsd_ffv2_generation_put_owned(generation);
	return status;
}

/* Revoke one entry from the active generation's registry. */
bool nfsd_ffv2_test_trust_revoke_active(struct nfsd_net *nn,
					const stateid_t *stateid)
{
	struct nfsd_ffv2_service_context *context;
	struct nfsd_ffv2_generation *generation;
	bool revoked = false;
	u64 epoch;

	generation = nfsd_ffv2_active_generation_get(nn);
	if (!generation)
		return false;
	context = generation->payload;
	if (context && context->object && context->authority &&
	    nfsd_ffv2_authority_published(context->authority, &epoch))
		revoked = nfsd_ffv2_trust_revoke(&context->trust, stateid,
						 context->object->object_uuid,
						 epoch);
	nfsd_ffv2_generation_put_owned(generation);
	return revoked;
}

/* The object a mapped binding resolved to, so a fixture can match it. */
const struct nfsd_ffv2_object *
nfsd_ffv2_test_binding_object(const struct nfsd_ffv2_binding *binding)
{
	return binding ? binding->object : NULL;
}

/* The object UUID the active generation was published with. */
bool nfsd_ffv2_test_active_object_uuid(struct nfsd_net *nn, u8 uuid[16])
{
	struct nfsd_ffv2_service_context *context;
	struct nfsd_ffv2_generation *generation;
	bool found = false;

	generation = nfsd_ffv2_active_generation_get(nn);
	if (!generation)
		return false;
	context = generation->payload;
	if (context && context->object) {
		memcpy(uuid, context->object->object_uuid, 16);
		found = true;
	}
	nfsd_ffv2_generation_put_owned(generation);
	return found;
}

/*
 * Provider entry accounting, so a test can prove that a fail-closed result
 * was reached without the provider boundary ever being crossed.
 */
u64 nfsd_ffv2_test_provider_entries(void)
{
	return atomic64_read(&nfsd_ffv2_probe_counters.mapped) +
	       atomic64_read(&nfsd_ffv2_probe_counters.fail_closed);
}

/* Callbacks entered, so a test can distinguish one call from none. */
u64 nfsd_ffv2_test_provider_callbacks(void)
{
	return atomic64_read(&nfsd_ffv2_probe_counters.callbacks);
}

/**
 * nfsd_ffv2_test_provider_install - install a namespace's read-only provider
 * @nn: the namespace the provider serves
 * @ops: read-only callbacks, which must both be supplied
 * @data: opaque provider state passed back to each callback
 *
 * Only one provider may be installed per namespace.  The callbacks and the
 * state are published together, so a callback always runs against the
 * state its own operations vector was installed with.
 *
 * Return: 0, -EINVAL for a missing namespace or an incomplete operations
 * vector, -ENOMEM, -ESHUTDOWN once @nn has begun exiting, or -EBUSY when
 * @nn already has one installed.
 */
int nfsd_ffv2_test_provider_install(struct nfsd_net *nn,
				    const struct nfsd_ffv2_provider_ops *ops,
				    void *data, u32 chunk_size)
{
	struct nfsd_ffv2_provider *provider;
	struct nfsd_ffv2_anchor *anchor;

	if (!nn || !ops || !ops->chunk_read || !ops->chunk_header_read)
		return -EINVAL;
	/*
	 * A provider must say how large its chunks are, because nothing else
	 * at this boundary does, and a reply cannot be bounded without it.
	 * Zero is not "unknown" here: it would admit no payload at all.
	 */
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

	/*
	 * Publication is part of the namespace's lifecycle, not merely of
	 * the registry: taking the anchor lock and requiring NET_LIVE is
	 * what makes installation and namespace exit one transaction.  A
	 * provider published before exit closes that state is drained by the
	 * exit fence; one attempted after it never publishes at all.
	 */
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
 * nfsd_ffv2_test_provider_remove - remove @nn's read-only provider
 * @nn: the namespace whose boundary is being closed
 *
 * Closes the boundary first, then waits for the last callback reference to
 * be dropped, so no request can be running in provider code once this
 * returns and the caller may free its operations vector and state.
 */
void nfsd_ffv2_test_provider_remove(struct nfsd_net *nn)
{
	nfsd_ffv2_provider_shutdown(nn);
}

/* Providers the namespace-exit fence had to retire, for a test to see. */
u64 nfsd_ffv2_test_provider_fenced(void)
{
	return atomic64_read(&nfsd_ffv2_provider_fenced);
}

__be32 nfsd_ffv2_test_validate_operation(struct svc_rqst *rqstp,
					 struct svc_fh *fhp,
					 struct nfsd4_session *session,
					 u32 opnum, const stateid_t *stateid,
					 const struct nfsd_ffv2_actor_id *actor,
					 struct nfsd_ffv2_admission *admission)
{
	return nfsd_ffv2_validate_operation(rqstp, fhp, session, opnum,
					    stateid, actor, admission);
}
#endif

void nfsd_ffv2_net_init(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;

	refcount_set(&anchor->ref, 1);
	init_completion(&anchor->released);
	mutex_init(&anchor->lock);
	anchor->net_state = NFSD_FFV2_NET_LIVE;
	anchor->service_state = NFSD_FFV2_SERVICE_DOWN;
	RCU_INIT_POINTER(anchor->provider, NULL);
	anchor->next_generation = 1;
	anchor->pending = NULL;
	anchor->active = NULL;
	anchor->retiring = NULL;
	anchor->registration_pending = false;
	spin_lock_init(&anchor->authority_tokens_lock);
	init_waitqueue_head(&anchor->authority_wait);
	anchor->next_authority_epoch = 1;
	anchor->authority_tokens = 0;
	anchor->authority_work = 0;
	anchor->authority_tokens_open = true;
	anchor->authority_work_open = true;
}

void nfsd_ffv2_net_pre_exit(struct nfsd_net *nn)
{
	struct nfsd_ffv2_anchor *anchor = &nn->ffv2;
	struct nfsd_ffv2_generation *generation;

	if (WARN_ON_ONCE(!nfsd_ffv2_anchor_get(anchor)))
		return;
	nfsd_ffv2_updates_set_open(&nn->ffv2_participant, false);
	nfsd_ffv2_updates_wait(&nn->ffv2_participant);
	/*
	 * Close new authority-token and retirement-work admission before the
	 * generation retires, so nothing new can reach ->nn afterwards.
	 */
	nfsd_ffv2_authority_admissions_close(anchor);
	mutex_lock(&anchor->lock);
	/* Pair with admission's lockless rejection before taking ->lock. */
	smp_store_release(&anchor->net_state, NFSD_FFV2_NET_EXITING);
	anchor->service_state = NFSD_FFV2_SERVICE_STOPPING;
	generation = nfsd_ffv2_retire_begin_locked(anchor);
	mutex_unlock(&anchor->lock);

	/*
	 * Close the provider boundary now that installation is refused: an
	 * installer takes the same lock and requires NET_LIVE, so one that
	 * published before the store above is drained here and one that
	 * arrives after it never publishes.  A namespace must not depend on
	 * its installer removing a provider -- no callback and no
	 * result-holding admission may outlive it -- and the WARN in
	 * nfsd_ffv2_net_destroy() means this fence was missed.
	 */
	if (nfsd_ffv2_provider_shutdown(nn))
		atomic64_inc(&nfsd_ffv2_provider_fenced);

	nfsd_ffv2_retire_finish(anchor, generation, true);
	/*
	 * Drain every admitted token and worker before the session tables and
	 * the anchor go away: the non-owning ->nn pointer must not outlive its
	 * last user.
	 */
	nfsd_ffv2_authority_admissions_drain(anchor);
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
	/*
	 * A provider is namespace-scoped and only a KUnit build can install
	 * one; a namespace reaching teardown while one is still published
	 * means a test left it behind, which would outlive the anchor the
	 * callbacks are fenced by.
	 */
	WARN_ON_ONCE(rcu_access_pointer(anchor->provider));
	mutex_unlock(&anchor->lock);
	WARN_ON_ONCE(!nfsd_ffv2_authority_admissions_idle(anchor));
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
		/*
		 * The generation was replaced between validation and here,
		 * so the work this request authorized no longer applies.
		 */
		error = -ESTALE;
	} else if (authority &&
		   !nfsd_ffv2_authority_published_locked(authority)) {
		/*
		 * Authority teardown is the linearization point: once it is
		 * no longer published, nothing new may be admitted against
		 * it even while its generation is briefly still active.
		 */
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

int nfsd_ffv2_admit(struct svc_rqst *rqstp,
		    struct nfsd_ffv2_admission *admission)
{
	struct nfsd_net *nn;

	if (nfsd_current_rqst() != rqstp || !rqstp->rq_xprt)
		return -EOPNOTSUPP;
	nn = net_generic(rqstp->rq_xprt->xpt_net, nfsd_net_id);
	return nfsd_ffv2_admit_generation(nn, admission, NULL, NULL);
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
	/*
	 * Last: the result this request may still have been reading borrows
	 * provider storage, and provider removal is waiting on this.
	 */
	if (admission->provider) {
		nfsd_ffv2_provider_put(admission->provider);
		admission->provider = NULL;
	}
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
	return nfsd_ffv2_admit_generation(nn, admission, NULL, NULL);
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
