/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NFSD_FFV2_H
#define _NFSD_FFV2_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/nfs4.h>
#include <linux/refcount.h>
#include <linux/completion.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

struct net;
struct nfsd_net;
struct nfsd_ffv2_generation;
struct nfsd_ffv2_object;
struct nfsd_ffv2_binding;
struct nfsd_ffv2_reservation;
struct nfsd_ffv2_service_context;
struct cred;
struct path;
struct seq_file;
struct svc_rqst;
struct svc_fh;
struct svc_export;
struct svc_xprt;
struct task_struct;
struct knfsd_fh;
struct dentry;
struct nfsd4_session;
struct nfs4_client;
struct nfsd_ffv2_authority;

#define NFSD_FFV2_FH_HEADER_SIZE	56
#define NFSD_FFV2_FH_INNER_MAX	72
#define NFSD_FFV2_FH_MAX		128

struct nfsd_ffv2_fh_info {
	u64		generation;
	u8		object_uuid[16];
	u8		export_uuid[16];
	const u8	*inner;
	u16		inner_len;
};

struct nfsd_ffv2_object_request {
	const char	*auth_domain;
	const char	*export_path;
	const char	*object_path;
	const u8	*object_uuid;
	const u8	*store_uuid;
	const u8	*binding_token;
	u64		control_root;
	/*
	 * Bytes in one chunk of this object, or zero when the registrar does
	 * not know.  The value belongs to the layout: it is a per-mirror
	 * parameter, so it is recorded per object rather than once for a
	 * server, and every chunk of a shard carries it except the last,
	 * which may be shorter.
	 */
	u32		chunk_size;
};

struct nfsd_ffv2_participant {
	struct list_head		node;
	struct list_head		reservations;
	refcount_t		ref;
	struct completion	released;
	/* Serializes export-update admission with service stop. */
	spinlock_t		update_lock;
	wait_queue_head_t	update_wait;
	unsigned int		update_count;
	u64			update_epoch;
	bool			updates_open;
	/* Protects the complete live-export inventory. */
	struct mutex		inventory_lock;
	struct list_head		inventory;
	wait_queue_head_t	inventory_wait;
	unsigned int		inventory_count;
	struct net		*net;
	bool			attached;
};

struct nfsd_ffv2_export_update {
	struct nfsd_ffv2_participant *participant;
	struct nfsd_ffv2_reservation *reservation;
	u64				epoch;
	bool				admitted;
	bool				entry_locked;
	bool				policy_locked;
	bool				registration_slot;
	/* Prepared authority owned by the caller until publication. */
	struct nfsd_ffv2_authority	*authority;
};

enum nfsd_ffv2_net_state {
	NFSD_FFV2_NET_LIVE,
	NFSD_FFV2_NET_EXITING,
};

enum nfsd_ffv2_service_state {
	NFSD_FFV2_SERVICE_DOWN,
	NFSD_FFV2_SERVICE_UP,
	NFSD_FFV2_SERVICE_STOPPING,
	NFSD_FFV2_SERVICE_DRAIN_FAILED,
};

/* Opaque outside ffv2.c: the published provider and its reference. */
struct nfsd_ffv2_provider;

struct nfsd_ffv2_anchor {
	/* Keeps the embedded anchor alive across admitted callbacks. */
	refcount_t			ref;
	/*
	 * The read-only provider installed for this namespace, if any.
	 * FFv2 generation, binding, and authority state is per-namespace, so
	 * provider selection is too: a request is served only by the
	 * provider installed for the namespace its binding belongs to.
	 */
	struct nfsd_ffv2_provider __rcu	*provider;
	struct completion		released;
	/* Serializes service state, generation publication, and admission. */
	struct mutex			lock;
	enum nfsd_ffv2_net_state	net_state;
	enum nfsd_ffv2_service_state	service_state;
	u64				next_generation;
	struct nfsd_ffv2_generation	*pending;
	struct nfsd_ffv2_generation	*active;
	struct nfsd_ffv2_generation	*retiring;
	bool				registration_pending;
	/*
	 * Authority epoch allocation and the closeable authority-token and
	 * retirement-work admissions.  One lock covers both gates and the
	 * per-net token count so the gates cannot invert against each other.
	 */
	u64				next_authority_epoch;
	/* Protects both admission gates and the per-net token count. */
	spinlock_t			authority_tokens_lock;
	wait_queue_head_t		authority_wait;
	unsigned int			authority_tokens;
	unsigned int			authority_work;
	bool				authority_tokens_open;
	bool				authority_work_open;
};

void nfsd_ffv2_net_init(struct nfsd_net *nn);
void nfsd_ffv2_net_pre_exit(struct nfsd_net *nn);
void nfsd_ffv2_net_destroy(struct nfsd_net *nn);
int nfsd_ffv2_participant_register(struct nfsd_net *nn, struct net *net);
void nfsd_ffv2_participant_detach_begin(struct nfsd_net *nn);
void nfsd_ffv2_participant_detach_finish(struct nfsd_net *nn);
int nfsd_ffv2_export_update_begin(struct svc_export *exp,
				  struct svc_export *old,
				  struct nfsd_ffv2_export_update *update);
int nfsd_ffv2_export_update_validate(struct nfsd_ffv2_export_update *update);
int nfsd_ffv2_export_update_end(struct svc_export *exp,
				struct nfsd_ffv2_export_update *update);
void nfsd_ffv2_export_update_abort(struct nfsd_ffv2_export_update *update);
int nfsd_ffv2_registration_begin(struct nfsd_net *nn,
				 struct nfsd_ffv2_export_update *registration);
void nfsd_ffv2_registration_end(struct nfsd_net *nn,
				struct nfsd_ffv2_export_update *registration);
struct nfsd_ffv2_object *nfsd_ffv2_object_alloc(void);
void nfsd_ffv2_object_free(struct nfsd_ffv2_object *object);
int nfsd_ffv2_object_register(struct nfsd_net *nn,
			      struct nfsd_ffv2_export_update *registration,
			      struct nfsd_ffv2_object *object,
			      const struct nfsd_ffv2_object_request *request,
			      struct knfsd_fh *outer_fh, u64 *generation_id);
int nfsd_ffv2_object_unregister(struct nfsd_net *nn, u64 generation_id,
				const u8 object_uuid[16]);
void
nfsd_ffv2_export_update_rollback_wait(struct nfsd_ffv2_service_context *context);
void nfsd_ffv2_export_release(struct svc_export *exp);
int nfsd_ffv2_reservation_claim(struct nfsd_net *owner, const struct path *root,
				const u8 store_uuid[16],
				const u8 binding_token[32],
				struct nfsd_ffv2_reservation **result);
int nfsd_ffv2_reservation_gate_io(struct nfsd_ffv2_reservation *reservation);
int nfsd_ffv2_reservation_claim_expected(struct nfsd_net *owner,
					 const struct path *root,
					 const u8 store_uuid[16],
					 const u8 binding_token[32],
					 struct svc_export *expected,
					 struct nfsd_ffv2_reservation **result);
void nfsd_ffv2_reservation_abort(struct nfsd_ffv2_reservation *reservation);
void nfsd_ffv2_reservation_fence(struct nfsd_ffv2_reservation *reservation);
bool nfsd4_ffv2_mount_crossing_allowed(const struct path *path);
int nfsd_ffv2_service_export_publish(struct nfsd_net *owner,
				     struct svc_export *exp,
				     const struct path *root,
				     const u8 store_uuid[16],
				     const u8 binding_token[32],
				     const struct cred *cred, u64 control_root,
				     u64 *generation_id);
int nfsd_ffv2_service_generation_retire(struct nfsd_net *nn,
					u64 generation_id);
void nfsd_ffv2_service_context_release(void *payload);
__be32 nfsd4_ffv2_export_policy_check(struct svc_export *exp, u32 opnum);
int nfsd_ffv2_service_up(struct nfsd_net *nn);
struct nfsd_ffv2_generation *
nfsd_ffv2_service_stop_begin(struct nfsd_net *nn);
void nfsd_ffv2_service_stop_finish(struct nfsd_net *nn,
				   struct nfsd_ffv2_generation *generation);
void nfsd_ffv2_service_stop_failed(struct nfsd_net *nn,
				   struct nfsd_ffv2_generation *generation);
void nfsd_ffv2_service_stop_put(struct nfsd_ffv2_generation *generation);
void nfsd_ffv2_service_down(struct nfsd_net *nn);
bool nfsd_ffv2_requested_zero_threads(int n, const int *nthreads,
				      unsigned int nrpools);
int nfsd_ffv2_register(struct nfsd_net *nn);
int nfsd_ffv2_authority_register(struct nfsd_net *nn, struct net *net,
				 const u8 sessionid[NFS4_MAX_SESSIONID_LEN],
				 struct nfsd_ffv2_authority **result);
void nfsd_ffv2_authority_get(struct nfsd_ffv2_authority *authority);
void nfsd_ffv2_authority_put(struct nfsd_ffv2_authority *authority);
void nfsd_ffv2_authority_detach(struct nfsd_ffv2_authority *authority);
bool nfsd_ffv2_authority_publish(struct nfsd_ffv2_authority *authority,
				 u64 generation_id);
void nfsd_ffv2_session_init(struct nfsd4_session *session);
void nfsd_ffv2_session_dead_locked(struct nfsd4_session *session);
void nfsd_ffv2_session_free(struct nfsd4_session *session);
int nfsd_ffv2_authority_token_get(struct nfsd_ffv2_authority *authority);
void nfsd_ffv2_authority_token_put(struct nfsd_ffv2_authority *authority);
int nfsd_ffv2_authority_qualify(const struct nfs4_client *clp);
bool nfsd_ffv2_authority_published(struct nfsd_ffv2_authority *authority,
				   u64 *epoch);

int nfsd_ffv2_fh_parse(const struct knfsd_fh *fh, struct nfsd_ffv2_fh_info *info);
int nfsd_ffv2_fh_encode(struct knfsd_fh *fh,
			const struct nfsd_ffv2_fh_info *info);
__be32 nfsd_ffv2_fh_map(struct svc_rqst *rqstp, struct svc_fh *fhp);
void nfsd_ffv2_binding_get(struct nfsd_ffv2_binding *binding);
void nfsd_ffv2_binding_put(struct nfsd_ffv2_binding *binding);
/*
 * Read-only chunk request and result shapes.
 *
 * These mirror CHUNK_READ4args/CHUNK_READ4resok and
 * CHUNK_HEADER_READ4args/CHUNK_HEADER_READ4resok in the aggregate Flex
 * Files v2 draft, so that the encoder a later slice adds is a direct field
 * mapping rather than a translation.  The stateid is not repeated here:
 * the ordered gate has already validated it before a provider is reached.
 */
#define NFSD_FFV2_CHUNK_HEADER_READ_MAX	1024
#define NFSD_FFV2_CHECKSUM_VALUE_MAX	64

/*
 * checksum_algorithm4 values.  Only CRC32 is wired: the client's verifier
 * accepts nothing else, so a result naming another algorithm could not be
 * consumed even if it were encoded.
 */
#define NFSD_FFV2_CHECKSUM_ALG_NONE	0
#define NFSD_FFV2_CHECKSUM_ALG_CRC32	1

/* Length CRC32 always produces, in bytes. */
#define NFSD_FFV2_CHECKSUM_CRC32_LEN	4

/*
 * Aggregate bound on the concatenated payload bytes a CHUNK_READ reply may
 * carry.  Bounds the total rather than any single chunk: a per-element check
 * alone would admit a full count of chunks each just under the limit.
 */
#define NFSD_FFV2_MAX_PAYLOAD_BYTES	4194304U

/*
 * Reserved chunk_guard4 client identity.  An EMPTY chunk reports the
 * all-zeros guard pair, which uses this value rather than a real client.
 */
#define NFSD_FFV2_GUARD_CLIENT_ID_NONE	0U

/*
 * XDR words a CHUNK_READ reply costs apart from its payloads: the operation
 * number and status, the eof flag and the outer array's length; and, per
 * chunk, a tagged checksum, the effective length, the owner triple, the
 * guard pair, the payload identifier, the lock flags, the status, and the
 * payload's own length.  The boundary sizes a reply with these before the
 * provider runs, and the encoder emits them.
 */
#define NFSD4_FFV2_READ_FIXED_WORDS	(2 + 1 + 1)
#define NFSD4_FFV2_READ_ENT_WORDS	14

/* chunk_owner4: the committed generation a chunk belongs to. */
struct nfsd_ffv2_chunk_owner {
	u64	co_cohort_id;
	u32	co_client_id;
	u32	co_id;
};

/* chunk_guard4: the per-chunk compare-and-swap state. */
struct nfsd_ffv2_chunk_guard {
	u32	cg_gen_id;
	u32	cg_client_id;
};

/* checksum4: a tagged checksum over the chunk header and payload. */
struct nfsd_ffv2_checksum {
	u32	cs_algorithm;
	u32	cs_len;
	u8	cs_value[NFSD_FFV2_CHECKSUM_VALUE_MAX];
};

/* retained_generation_disposition4 */
enum nfsd_ffv2_retained_disposition {
	NFSD_FFV2_RETAINED_ABSENT,
	NFSD_FFV2_RETAINED_PRESENT,
	NFSD_FFV2_RETAINED_ERRORED,
};

/* optional_retained4: a predecessor generation, when one is retained. */
struct nfsd_ffv2_retained {
	enum nfsd_ffv2_retained_disposition disposition;
	struct nfsd_ffv2_chunk_owner	rp_owner;
};

/* read_chunk4 */
struct nfsd_ffv2_read_chunk {
	struct nfsd_ffv2_checksum	cr_checksum;
	u32				cr_effective_len;
	struct nfsd_ffv2_chunk_owner	cr_owner;
	struct nfsd_ffv2_chunk_guard	cr_guard;
	u32				cr_payload_id;
	u32				cr_locked;
	__be32				cr_status;
	const u8			*cr_chunk;
};

/*
 * A chunk range.  @offset is a chunk index, not a byte offset, and @count
 * is a chunk count: CHUNK_READ works in the layout's chunk coordinate
 * system rather than the byte coordinate system READ uses.
 */
struct nfsd_ffv2_chunk_request {
	u64	offset;
	u32	count;
};

/*
 * One read result.  A provider may return fewer chunks than were asked
 * for, but only when it has run out of chunks in the requested range, and
 * a short result MUST then set @eof: shortness has no other defined cause
 * at this boundary, and a short result without @eof leaves a client
 * resuming at the offset it started from.  @count is what it actually
 * produced; it is never more, and the
 * arrays an encoder walks are present whenever @count is non-zero, both
 * checked at the boundary before this is handed back.  Every pointer here
 * is borrowed from provider-owned storage and stays valid only while the
 * caller's execution admission is held: the admission carries a reference
 * on the provider that produced the result, so provider removal cannot
 * complete, and the storage cannot be freed, until the admission does.
 * That admission is also what retirement and namespace exit drain.  A
 * caller that must outlive its admission -- a wire encoder, once one
 * exists -- has to copy what it needs or hold the admission through
 * encoding.
 *
 * Lifetime is necessary but not sufficient: the storage a successful
 * result points at must also be immutable and not reused for another
 * operation until this operation's admission completes.  Callbacks can
 * run concurrently on one provider, so a shared scratch array that the
 * next call overwrites would corrupt a result whose reference is still
 * perfectly valid.  A provider that cannot promise that has to return
 * per-operation storage.
 */
struct nfsd_ffv2_chunk_result {
	bool	eof;
	u32	count;
	union {
		/* CHUNK_READ4resok */
		struct {
			const struct nfsd_ffv2_read_chunk *chunks;
		} read;
		/* CHUNK_HEADER_READ4resok: five co-indexed arrays. */
		struct {
			const __be32			   *status;
			const u32			   *locked;
			const struct nfsd_ffv2_chunk_owner *owners;
			const struct nfsd_ffv2_chunk_guard *guards;
			const struct nfsd_ffv2_retained	   *predecessors;
		} header;
	};
};

/*
 * The read-only half of the provider boundary.  A callback runs only after
 * the ordered gate has authorized the request and taken an execution
 * admission, and only for an operation whose profile names it.  No
 * mutating entry point exists yet, and no provider is installed in an
 * ordinary build.
 *
 * Callbacks are synchronous and may sleep.  @object, @request and @result
 * are the caller's, valid only for the duration of the call: a provider
 * must not retain any of them, and must answer before it returns.  The
 * storage a result points at is the provider's own and must stay valid
 * until the caller releases the execution admission it holds.  An
 * asynchronous provider needs a different interface, not this one.
 */
struct nfsd_ffv2_provider_ops {
	__be32 (*chunk_read)(void *provider,
			     const struct nfsd_ffv2_object *object,
			     const struct nfsd_ffv2_chunk_request *request,
			     struct nfsd_ffv2_chunk_result *result);
	__be32 (*chunk_header_read)(void *provider,
				    const struct nfsd_ffv2_object *object,
				    const struct nfsd_ffv2_chunk_request *request,
				    struct nfsd_ffv2_chunk_result *result);
};

struct nfsd_ffv2_admission {
	struct list_head			node;
	struct nfsd_ffv2_anchor		*anchor;
	struct nfsd_ffv2_generation	*generation;
	struct task_struct		*task;
	/*
	 * The provider a callback ran against, held from the callback until
	 * this admission completes.  A result borrows provider storage, so
	 * the storage has to outlive every consumer of the result, and this
	 * admission is what those consumers are bounded by.
	 */
	struct nfsd_ffv2_provider	*provider;
};

__be32 nfsd_ffv2_provider_probe(struct svc_rqst *rqstp, struct svc_fh *fhp,
				u32 opnum,
				const struct nfsd_ffv2_chunk_request *request,
				struct nfsd_ffv2_chunk_result *result,
				u32 available,
				struct nfsd_ffv2_admission *admission);
int nfsd_ffv2_provider_probe_show(struct seq_file *m, void *v);

int nfsd_ffv2_admit(struct svc_rqst *rqstp,
		    struct nfsd_ffv2_admission *admission);
void nfsd_ffv2_complete(struct nfsd_ffv2_admission *admission);

enum nfsd_ffv2_live_test_stage {
	NFSD_FFV2_LIVE_TEST_NONE,
	NFSD_FFV2_LIVE_TEST_TRANSITION,
	NFSD_FFV2_LIVE_TEST_PRE_PUBLISH,
	NFSD_FFV2_LIVE_TEST_POLICY,
	NFSD_FFV2_LIVE_TEST_CONTEXT_CLEAR,
};

enum nfsd_ffv2_fault_phase {
	NFSD_FFV2_FAULT_NONE,
	NFSD_FFV2_FAULT_REPLY_SKB,
	NFSD_FFV2_FAULT_OBJECT_ALLOC,
	NFSD_FFV2_FAULT_AUTH_DOMAIN,
	NFSD_FFV2_FAULT_EXPORT_PATH,
	NFSD_FFV2_FAULT_OBJECT_PATH,
	NFSD_FFV2_FAULT_EXPORT_LOOKUP,
	NFSD_FFV2_FAULT_FH_COMPOSE,
	NFSD_FFV2_FAULT_RESERVATION_CLAIM,
	NFSD_FFV2_FAULT_CONTEXT_ALLOC,
	NFSD_FFV2_FAULT_GENERATION_ALLOC,
	NFSD_FFV2_FAULT_TEMPLATE_CLONE,
	NFSD_FFV2_FAULT_EXACT_CURRENT,
	NFSD_FFV2_FAULT_CACHE_REPLACE,
	NFSD_FFV2_FAULT_REGISTRY_INSERT,
	NFSD_FFV2_FAULT_GENERATION_ACTIVATE,
	NFSD_FFV2_FAULT_REPLY_BUILD,
	NFSD_FFV2_FAULT_TRUST_REPLACE,
};

#if IS_ENABLED(CONFIG_NFSD_FFV2_LIVE_TEST) || \
	IS_ENABLED(CONFIG_NFSD_FFV2_KUNIT_TEST)
bool nfsd_ffv2_fault_inject(enum nfsd_ffv2_fault_phase phase);
void nfsd_ffv2_fault_arm(enum nfsd_ffv2_fault_phase phase);
enum nfsd_ffv2_fault_phase nfsd_ffv2_fault_armed(void);
enum nfsd_ffv2_fault_phase nfsd_ffv2_fault_hit(void);
#else
static inline bool
nfsd_ffv2_fault_inject(enum nfsd_ffv2_fault_phase phase)
{
	return false;
}
#endif

#if IS_ENABLED(CONFIG_NFSD_FFV2_LIVE_TEST)
int nfsd_ffv2_live_test_checkpoint(enum nfsd_ffv2_live_test_stage stage,
				   struct svc_export *exp);
int nfsd_ffv2_live_state_show(struct seq_file *m, void *v);
void nfsd_ffv2_live_test_debugfs_init(struct dentry *parent);
void nfsd_ffv2_live_test_exit(void);
#else
static inline int
nfsd_ffv2_live_test_checkpoint(enum nfsd_ffv2_live_test_stage stage,
			       struct svc_export *exp)
{
	return 0;
}

static inline void nfsd_ffv2_live_test_debugfs_init(struct dentry *parent) { }
static inline void nfsd_ffv2_live_test_exit(void) { }
#endif

int nfsd_ffv2_test_publish(struct nfsd_net *nn, void *payload,
			   void (*release)(void *), u64 *generation);
int nfsd_ffv2_test_admit(struct nfsd_net *nn,
			 struct nfsd_ffv2_admission *admission);
void nfsd_ffv2_test_complete(struct nfsd_ffv2_admission *admission);
int nfsd_ffv2_test_unregister(struct nfsd_net *nn, u64 generation);
int nfsd_ffv2_test_retire_waiting(struct nfsd_net *nn, u64 generation,
				  struct completion *waiting);
int nfsd_ffv2_test_reservation_claim(struct nfsd_net *owner,
				     const struct path *root,
				     const u8 store_uuid[16],
				     const u8 binding_token[32],
				     struct nfsd_ffv2_reservation **result);
int nfsd_ffv2_test_reservation_claim_expected(struct nfsd_net *owner,
					      const struct path *root,
					      const u8 store_uuid[16],
					      const u8 binding_token[32],
					      struct svc_export *expected,
					      struct nfsd_ffv2_reservation **result);
int
nfsd_ffv2_test_service_export_publish(struct nfsd_net *owner,
				      struct svc_export *exp,
				      const struct path *root,
				      const u8 store_uuid[16],
				      const u8 binding_token[32],
				      const struct cred *cred,
				      u64 control_root, u64 *generation_id);
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
				      u64 control_root, u64 *generation_id);
int nfsd_ffv2_test_object_init(struct nfsd_ffv2_object *object,
			       struct auth_domain *client,
			       const struct path *export_path,
			       const struct path *object_path, const u8 *inner,
			       u16 inner_len, const u8 object_uuid[16],
			       const u8 export_uuid[16]);
struct nfsd_ffv2_binding *
nfsd_ffv2_test_binding_create(struct nfsd_net *nn,
			      const struct nfsd_ffv2_fh_info *info);
bool nfsd_ffv2_test_generation_retired(struct nfsd_ffv2_generation *generation);
bool nfsd_ffv2_test_admission_retired(struct nfsd_ffv2_admission *admission);
unsigned int nfsd_ffv2_test_refcount(struct nfsd_ffv2_admission *admission);
unsigned int nfsd_ffv2_test_anchor_refcount(struct nfsd_net *nn);
void nfsd_ffv2_test_worker(struct svc_rqst *rqstp, struct svc_xprt *xprt);
void nfsd_ffv2_test_set_start_failure(bool fail);
bool nfsd_ffv2_test_start_failure(void);
void nfsd_ffv2_test_fault_arm(enum nfsd_ffv2_fault_phase phase);
struct nfsd_ffv2_authority *
nfsd_ffv2_test_authority_create(struct nfsd_net *nn,
				struct nfsd4_session *session);
u64 nfsd_ffv2_test_authority_epoch(const struct nfsd_ffv2_authority *authority);
u64 nfsd_ffv2_test_authority_gen(const struct nfsd_ffv2_authority *authority);
bool nfsd_ffv2_test_authority_dead(const struct nfsd_ffv2_authority *authority);
bool
nfsd_ffv2_test_authority_published(const struct nfsd_ffv2_authority *authority);
bool
nfsd_ffv2_test_authority_linked(const struct nfsd_ffv2_authority *authority);
int nfsd_ffv2_test_authority_epoch_alloc(struct nfsd_net *nn, u64 *epoch);
void nfsd_ffv2_test_authority_epoch_set(struct nfsd_net *nn, u64 next);
bool nfsd_ffv2_test_authority_work_admit(struct nfsd_net *nn);
void nfsd_ffv2_test_authority_work_done(struct nfsd_net *nn);
void nfsd_ffv2_test_authority_admissions_close(struct nfsd_net *nn);
bool nfsd_ffv2_test_authority_admissions_idle(struct nfsd_net *nn);

/*
 * Install or remove @nn's read-only provider.  Both are defined inside the
 * CONFIG_NFSD_FFV2_KUNIT_TEST guard in ffv2.c, so neither symbol exists in
 * ffv2.o in an ordinary build, and there is no netlink, debugfs, or
 * syscall path to them in any build.  Removal takes the provider out of the
 * registry and then waits for the callbacks and admissions already holding
 * it; the installer owns the operations vector and the state throughout and
 * may free them once removal returns.
 *
 * A caller that must keep an admission alive across the removal cannot use
 * this one, because the wait is for that admission.  Unpublish and drain
 * separately instead.
 */
int nfsd_ffv2_test_provider_install(struct nfsd_net *nn,
				    const struct nfsd_ffv2_provider_ops *ops,
				    void *data, u32 chunk_size);
void nfsd_ffv2_test_provider_remove(struct nfsd_net *nn);
/*
 * Removal in two steps, for a test that must keep an admission alive while
 * the registry slot is reused.  The handle must be drained once the
 * admission has completed, or the provider is leaked.
 */
void nfsd_ffv2_test_fh_set_chunk_size(struct svc_fh *fhp, u32 chunk_size);
void *nfsd_ffv2_test_provider_unpublish(struct nfsd_net *nn);
void nfsd_ffv2_test_provider_drain(void *handle);
u64 nfsd_ffv2_test_provider_fenced(void);
void nfsd_ffv2_test_release_counters(u64 *admissions, u64 *providers);

/*
 * What the server built for the last compound reply, as values: the head's
 * length, the reply's page length and page count, and how far the reply's
 * page cursor advanced.  Recorded before the transport takes the pages, and
 * holding no pointer to any of them.
 */
struct nfsd_ffv2_reply_shape {
	u32	head_len;
	u32	page_len;
	u32	page_base;
	u32	pages_used;
	u32	pages_available;
	u64	admissions_released;
	u64	providers_released;
	u32	ops_released;
	u32	sequence;
	bool	valid;
};

/*
 * What the server's export authentication produced for the last request it
 * dispatched, as values only: the program coordinates, whether a client
 * domain was selected, that domain's name, and how many supplementary
 * groups the credential carries once svc_set_client() has run.  Recorded
 * after authentication succeeds and before the procedure runs, holding no
 * reference to the domain or to the credential.
 */
struct nfsd_ffv2_auth_record {
	u32	prog;
	u32	vers;
	u32	proc;
	u32	ngroups;
	u32	sequence;
	char	domain[64];
	bool	have_client;
	bool	valid;
};

void nfsd_ffv2_test_auth_record(struct nfsd_ffv2_auth_record *rec);
void nfsd_ffv2_test_auth_record_reset(void);

void nfsd_ffv2_test_reply_shape(struct nfsd_ffv2_reply_shape *shape);
void nfsd_ffv2_test_reply_shape_reset(void);
u64 nfsd_ffv2_test_provider_callbacks(void);
const struct nfsd_ffv2_object *
nfsd_ffv2_test_binding_object(const struct nfsd_ffv2_binding *binding);

/*
 * Encode one read reply into @xdr from an operation's own response object.
 * Both are defined inside the CONFIG_NFSD_FFV2_KUNIT_TEST guard in
 * nfs4xdr.c, so neither symbol exists in an ordinary build.  They exist
 * because the wire shape cannot otherwise be examined: KUnit cannot build
 * a compound with a response buffer, and a reply that is structurally
 * right can still be wrong on the wire.
 */
/* Words one read_chunk4 costs apart from its payload; see nfs4proc.c. */
#define NFSD4_FFV2_TEST_READ_ENT_WORDS	14

struct xdr_stream;
union nfsd4_op_u;
__be32 nfsd_ffv2_test_encode_chunk_read(struct xdr_stream *xdr,
					union nfsd4_op_u *u);
__be32 nfsd_ffv2_test_encode_chunk_header_read(struct xdr_stream *xdr,
					       union nfsd4_op_u *u);

/*
 * Run and release one operation through its own table entry, so a test can
 * drive the production handler with a response buffer of its choosing.
 * Defined inside the same guard in nfs4proc.c.
 */
struct nfsd4_compound_state;
__be32 nfsd_ffv2_test_run_op(struct svc_rqst *rqstp,
			     struct nfsd4_compound_state *cstate, u32 opnum,
			     union nfsd4_op_u *u);
void nfsd_ffv2_test_release_op(u32 opnum, union nfsd4_op_u *u);

#endif /* _NFSD_FFV2_H */
