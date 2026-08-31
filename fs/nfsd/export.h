/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 1995-1997 Olaf Kirch <okir@monad.swb.de>
 */
#ifndef NFSD_EXPORT_H
#define NFSD_EXPORT_H

#include <linux/sunrpc/cache.h>
#include <linux/percpu_counter.h>
#include <uapi/linux/nfsd/export.h>
#include <linux/nfs4.h>

struct knfsd_fh;
struct svc_fh;
struct svc_rqst;
struct nfsd_ffv2_service_context;

/*
 * FS Locations
 */

#define MAX_FS_LOCATIONS	128

struct nfsd4_fs_location {
	char *hosts; /* colon separated list of hosts */
	char *path;  /* slash separated list of path components */
};

struct nfsd4_fs_locations {
	uint32_t locations_count;
	struct nfsd4_fs_location *locations;
/* If we're not actually serving this data ourselves (only providing a
 * list of replicas that do serve it) then we set "migrated": */
	int migrated;
};

/*
 * We keep an array of pseudoflavors with the export, in order from most
 * to least preferred.  For the foreseeable future, we don't expect more
 * than the eight pseudoflavors null, unix, krb5, krb5i, krb5p, skpm3,
 * spkm3i, and spkm3p (and using all 8 at once should be rare).
 */
#define MAX_SECINFO_LIST	8
#define EX_UUID_LEN		16

struct exp_flavor_info {
	u32	pseudoflavor;
	u32	flags;
};

/* Per-export stats */
enum {
	EXP_STATS_FH_STALE,
	EXP_STATS_IO_READ,
	EXP_STATS_IO_WRITE,
	EXP_STATS_COUNTERS_NUM
};

struct export_stats {
	time64_t		start_time;
	struct percpu_counter	counter[EXP_STATS_COUNTERS_NUM];
};

enum nfsd_ffv2_export_access_state {
	NFSD_FFV2_EXPORT_OPEN,
	NFSD_FFV2_EXPORT_TRANSITIONING,
	NFSD_FFV2_EXPORT_SERVICE,
};

struct svc_export {
	struct cache_head	h;
	struct auth_domain *	ex_client;
	int			ex_flags;
	int			ex_fsid;
	struct path		ex_path;
	kuid_t			ex_anon_uid;
	kgid_t			ex_anon_gid;
	unsigned char *		ex_uuid; /* 16 byte fsid */
	struct nfsd4_fs_locations ex_fslocs;
	uint32_t		ex_nflavors;
	struct exp_flavor_info	ex_flavors[MAX_SECINFO_LIST];
	u32			ex_layout_types;
	struct nfsd4_deviceid_map *ex_devid_map;
	struct cache_detail	*cd;
	struct rcu_head		ex_rcu;
	unsigned long		ex_xprtsec_modes;
	struct export_stats	*ex_stats;
	struct list_head	ex_ffv2_inventory;
	struct path		ex_ffv2_path;
	struct nfsd_ffv2_participant *ex_ffv2_participant;
	bool			ex_ffv2_listed;
	struct nfsd_ffv2_service_context __rcu *ex_ffv2_context;
	struct completion	*ex_ffv2_context_released;
	spinlock_t		ex_ffv2_access_lock; /* protects state and count */
	wait_queue_head_t	ex_ffv2_access_wait;
	enum nfsd_ffv2_export_access_state ex_ffv2_access_state;
	unsigned int		ex_ffv2_access_count;
};

struct svc_export *nfsd_export_cache_update(struct svc_export *new);
struct svc_export *
nfsd_ffv2_export_select(struct cache_detail *cd, struct auth_domain *client,
			const struct path *path);
bool nfsd_ffv2_export_is_current(struct svc_export *exp);
bool nfsd_ffv2_export_transition_abort_exact(struct svc_export *exp);
void nfsd_ffv2_export_update_lock(void);
void nfsd_ffv2_export_update_unlock(void);
bool nfsd_ffv2_export_is_current_locked(struct svc_export *exp);
struct svc_export *
nfsd_ffv2_export_update_exact_locked(struct svc_export *new,
				     struct svc_export *old);
int nfsd_ffv2_export_template_clone(struct svc_export *template,
				    struct svc_export *source);
void nfsd_ffv2_export_template_free(struct svc_export *template);
int nfsd_ffv2_export_access_get(struct svc_export *exp);
int nfsd_ffv2_export_access_clone(struct svc_export *exp);
void nfsd_ffv2_export_access_put(struct svc_export *exp);
int nfsd_ffv2_export_transition_begin(struct svc_export *exp);
int nfsd_ffv2_export_transition_wait(struct svc_export *exp);
bool nfsd_ffv2_export_is_transitioning(struct svc_export *exp);
void nfsd_ffv2_export_transition_abort(struct svc_export *exp);
void nfsd_ffv2_export_transition_commit(struct svc_export *exp);
struct svc_export *nfsd_ffv2_test_export_lookup(struct svc_export *key);
struct svc_export *
nfsd_ffv2_test_export_update_exact(struct svc_export *new,
				   struct svc_export *old);
void nfsd_ffv2_test_fail_export_alloc(bool fail);

/* an "export key" (expkey) maps a filehandlefragement to an
 * svc_export for a given client.  There can be several per export,
 * for the different fsid types.
 */
struct svc_expkey {
	struct cache_head	h;

	struct auth_domain *	ek_client;
	u8			ek_fsidtype;
	u32			ek_fsid[6];

	struct path		ek_path;
	struct rcu_head		ek_rcu;
};

#define EX_ISSYNC(exp)		(!((exp)->ex_flags & NFSEXP_ASYNC))
#define EX_NOHIDE(exp)		((exp)->ex_flags & NFSEXP_NOHIDE)
#define EX_WGATHER(exp)		((exp)->ex_flags & NFSEXP_GATHERED_WRITES)

struct svc_cred;
int nfsexp_flags(struct svc_cred *cred, struct svc_export *exp);
__be32 check_xprtsec_policy(struct svc_export *exp, struct svc_rqst *rqstp);
__be32 check_security_flavor(struct svc_export *exp, struct svc_rqst *rqstp,
			     bool may_bypass_gss);
__be32 check_nfsd_access(struct svc_export *exp, struct svc_rqst *rqstp,
			 bool may_bypass_gss);

/*
 * Function declarations
 */
int			nfsd_export_init(struct net *);
void			nfsd_export_shutdown(struct net *);
void			nfsd_export_flush(struct net *);
struct svc_export *	rqst_exp_get_by_name(struct svc_rqst *,
					     const struct path *);
struct svc_export *	rqst_exp_parent(struct svc_rqst *,
					struct path *);
struct svc_export *	rqst_find_fsidzero_export(struct svc_rqst *);
int			exp_rootfh(struct net *, struct auth_domain *,
					char *path, struct knfsd_fh *, int maxsize);
__be32			exp_pseudoroot(struct svc_rqst *, struct svc_fh *);

static inline void exp_put(struct svc_export *exp)
{
	cache_put(&exp->h, exp->cd);
}

static inline struct svc_export *exp_get(struct svc_export *exp)
{
	cache_get(&exp->h);
	return exp;
}

struct svc_export *nfsd_export_get(struct svc_export *exp);
void nfsd_export_put(struct svc_export *exp);
void nfsd_export_unhash(struct svc_export *exp);
struct svc_export *rqst_exp_find(struct cache_req *reqp, struct net *net,
				 struct auth_domain *cl, struct auth_domain *gsscl,
				 int fsid_type, u32 *fsidv);

#endif /* NFSD_EXPORT_H */
