// SPDX-License-Identifier: GPL-2.0-only
#ifdef CONFIG_NFSD_FFV2_LIVE_TEST

#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/hex.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <net/net_namespace.h>

#include "nfsd.h"
#include "export.h"
#include "ffv2.h"
#include "ffv2_store.h"
#include "filecache.h"
#include "netns.h"

struct nfsd_ffv2_live_test_state {
	/* Serializes one-shot pause ownership and its observations. */
	struct mutex		lock;
	wait_queue_head_t	wait;
	enum nfsd_ffv2_live_test_stage armed;
	enum nfsd_ffv2_live_test_stage reached;
	bool			blocked;
	bool			service;
	bool			context;
};

static struct nfsd_ffv2_live_test_state nfsd_ffv2_live_test = {
	.lock = __MUTEX_INITIALIZER(nfsd_ffv2_live_test.lock),
	.wait = __WAIT_QUEUE_HEAD_INITIALIZER(nfsd_ffv2_live_test.wait),
};

static const char *
nfsd_ffv2_live_test_stage_name(enum nfsd_ffv2_live_test_stage stage)
{
	switch (stage) {
	case NFSD_FFV2_LIVE_TEST_TRANSITION:
		return "transition";
	case NFSD_FFV2_LIVE_TEST_PRE_PUBLISH:
		return "pre_publish";
	case NFSD_FFV2_LIVE_TEST_POLICY:
		return "policy";
	case NFSD_FFV2_LIVE_TEST_CONTEXT_CLEAR:
		return "context_clear";
	case NFSD_FFV2_LIVE_TEST_NONE:
	default:
		return "none";
	}
}

static enum nfsd_ffv2_live_test_stage
nfsd_ffv2_live_test_parse_stage(const char *name)
{
	if (!strcmp(name, "transition"))
		return NFSD_FFV2_LIVE_TEST_TRANSITION;
	if (!strcmp(name, "pre_publish"))
		return NFSD_FFV2_LIVE_TEST_PRE_PUBLISH;
	if (!strcmp(name, "policy"))
		return NFSD_FFV2_LIVE_TEST_POLICY;
	if (!strcmp(name, "context_clear"))
		return NFSD_FFV2_LIVE_TEST_CONTEXT_CLEAR;
	return NFSD_FFV2_LIVE_TEST_NONE;
}

static const char *
nfsd_ffv2_fault_phase_name(enum nfsd_ffv2_fault_phase phase)
{
	switch (phase) {
	case NFSD_FFV2_FAULT_REPLY_SKB:
		return "reply_skb";
	case NFSD_FFV2_FAULT_OBJECT_ALLOC:
		return "object_alloc";
	case NFSD_FFV2_FAULT_AUTH_DOMAIN:
		return "auth_domain";
	case NFSD_FFV2_FAULT_EXPORT_PATH:
		return "export_path";
	case NFSD_FFV2_FAULT_OBJECT_PATH:
		return "object_path";
	case NFSD_FFV2_FAULT_EXPORT_LOOKUP:
		return "export_lookup";
	case NFSD_FFV2_FAULT_FH_COMPOSE:
		return "fh_compose";
	case NFSD_FFV2_FAULT_RESERVATION_CLAIM:
		return "reservation_claim";
	case NFSD_FFV2_FAULT_CONTEXT_ALLOC:
		return "context_alloc";
	case NFSD_FFV2_FAULT_GENERATION_ALLOC:
		return "generation_alloc";
	case NFSD_FFV2_FAULT_TEMPLATE_CLONE:
		return "template_clone";
	case NFSD_FFV2_FAULT_EXACT_CURRENT:
		return "exact_current";
	case NFSD_FFV2_FAULT_CACHE_REPLACE:
		return "cache_replace";
	case NFSD_FFV2_FAULT_REGISTRY_INSERT:
		return "registry_insert";
	case NFSD_FFV2_FAULT_GENERATION_ACTIVATE:
		return "generation_activate";
	case NFSD_FFV2_FAULT_REPLY_BUILD:
		return "reply_build";
	case NFSD_FFV2_FAULT_NONE:
	default:
		return "none";
	}
}

static enum nfsd_ffv2_fault_phase
nfsd_ffv2_fault_phase_parse(const char *name)
{
	enum nfsd_ffv2_fault_phase phase;

	for (phase = NFSD_FFV2_FAULT_REPLY_SKB;
	     phase <= NFSD_FFV2_FAULT_REPLY_BUILD; phase++)
		if (!strcmp(name, nfsd_ffv2_fault_phase_name(phase)))
			return phase;
	return NFSD_FFV2_FAULT_NONE;
}

static const char *
nfsd_ffv2_fault_visibility(enum nfsd_ffv2_fault_phase phase)
{
	switch (phase) {
	case NFSD_FFV2_FAULT_REPLY_BUILD:
		return "published";
	case NFSD_FFV2_FAULT_CONTEXT_ALLOC:
	case NFSD_FFV2_FAULT_GENERATION_ALLOC:
	case NFSD_FFV2_FAULT_EXACT_CURRENT:
	case NFSD_FFV2_FAULT_CACHE_REPLACE:
	case NFSD_FFV2_FAULT_REGISTRY_INSERT:
	case NFSD_FFV2_FAULT_GENERATION_ACTIVATE:
		return "transaction";
	default:
		return "pre_transaction";
	}
}

int nfsd_ffv2_live_test_checkpoint(enum nfsd_ffv2_live_test_stage stage,
				   struct svc_export *exp)
{
	struct nfsd_ffv2_live_test_state *state = &nfsd_ffv2_live_test;
	bool pause = false;

	mutex_lock(&state->lock);
	if (state->armed == stage) {
		state->armed = NFSD_FFV2_LIVE_TEST_NONE;
		state->reached = stage;
		state->blocked = true;
		state->service = nfsd_ffv2_export_is_service(exp);
		rcu_read_lock();
		state->context = rcu_access_pointer(exp->ex_ffv2_context);
		rcu_read_unlock();
		pause = true;
	}
	mutex_unlock(&state->lock);
	if (!pause)
		return 0;

	wake_up_all(&state->wait);
	return wait_event_interruptible(state->wait,
					!READ_ONCE(state->blocked));
}

static ssize_t nfsd_ffv2_live_test_read(struct file *file, char __user *buf,
					size_t len, loff_t *ppos)
{
	struct nfsd_ffv2_live_test_state *state = &nfsd_ffv2_live_test;
	enum nfsd_ffv2_fault_phase armed, hit;
	char output[256];
	int size;

	mutex_lock(&state->lock);
	armed = nfsd_ffv2_fault_armed();
	hit = nfsd_ffv2_fault_hit();
	size = scnprintf(output, sizeof(output),
			 "armed=%s reached=%s blocked=%u service=%u context=%u fault_armed=%s fault_hit=%s visibility=%s\n",
			 nfsd_ffv2_live_test_stage_name(state->armed),
			 nfsd_ffv2_live_test_stage_name(state->reached),
			 state->blocked, state->service, state->context,
			 nfsd_ffv2_fault_phase_name(armed),
			 nfsd_ffv2_fault_phase_name(hit),
			 nfsd_ffv2_fault_visibility(armed != NFSD_FFV2_FAULT_NONE ?
						    armed : hit));
	mutex_unlock(&state->lock);
	return simple_read_from_buffer(buf, len, ppos, output, size);
}

static ssize_t nfsd_ffv2_live_test_write(struct file *file,
					 const char __user *buf, size_t len,
					 loff_t *ppos)
{
	struct nfsd_ffv2_live_test_state *state = &nfsd_ffv2_live_test;
	enum nfsd_ffv2_live_test_stage stage;
	char input[48];
	char *command;
	bool wake = false;

	if (!len || len >= sizeof(input))
		return -EINVAL;
	if (copy_from_user(input, buf, len))
		return -EFAULT;
	input[len] = '\0';
	command = strim(input);

	mutex_lock(&state->lock);
	if (!strcmp(command, "continue")) {
		state->blocked = false;
		wake = true;
	} else if (!strcmp(command, "clear")) {
		state->armed = NFSD_FFV2_LIVE_TEST_NONE;
		state->reached = NFSD_FFV2_LIVE_TEST_NONE;
		state->blocked = false;
		state->service = false;
		state->context = false;
		nfsd_ffv2_fault_arm(NFSD_FFV2_FAULT_NONE);
		wake = true;
	} else if (str_has_prefix(command, "fail ")) {
		enum nfsd_ffv2_fault_phase phase;

		phase = nfsd_ffv2_fault_phase_parse(command + 5);
		if (phase == NFSD_FFV2_FAULT_NONE) {
			mutex_unlock(&state->lock);
			return -EINVAL;
		}
		nfsd_ffv2_fault_arm(phase);
	} else if (str_has_prefix(command, "pause ")) {
		stage = nfsd_ffv2_live_test_parse_stage(command + 6);
		if (stage == NFSD_FFV2_LIVE_TEST_NONE) {
			mutex_unlock(&state->lock);
			return -EINVAL;
		}
		if (state->blocked) {
			mutex_unlock(&state->lock);
			return -EBUSY;
		}
		state->armed = stage;
		state->reached = NFSD_FFV2_LIVE_TEST_NONE;
	} else {
		mutex_unlock(&state->lock);
		return -EINVAL;
	}
	mutex_unlock(&state->lock);
	if (wake)
		wake_up_all(&state->wait);
	return len;
}

static const struct file_operations nfsd_ffv2_live_test_fops = {
	.owner = THIS_MODULE,
	.read = nfsd_ffv2_live_test_read,
	.write = nfsd_ffv2_live_test_write,
	.llseek = default_llseek,
};

static int nfsd_ffv2_file_gate_diag_open(struct inode *inode,
					 struct file *file)
{
	return single_open(file, nfsd_file_ffv2_gate_diag_show, NULL);
}

static const struct file_operations nfsd_ffv2_file_gate_diag_fops = {
	.owner = THIS_MODULE,
	.open = nfsd_ffv2_file_gate_diag_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int nfsd_ffv2_live_state_open(struct inode *inode, struct file *file)
{
	return single_open(file, nfsd_ffv2_live_state_show, NULL);
}

static const struct file_operations nfsd_ffv2_live_state_fops = {
	.owner = THIS_MODULE,
	.open = nfsd_ffv2_live_state_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int nfsd_ffv2_provider_probe_open(struct inode *inode,
					 struct file *file)
{
	return single_open(file, nfsd_ffv2_provider_probe_show, NULL);
}

static const struct file_operations nfsd_ffv2_provider_probe_fops = {
	.owner = THIS_MODULE,
	.open = nfsd_ffv2_provider_probe_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

struct nfsd_ffv2_store_test_state {
	/* Serializes a run and its result. */
	struct mutex lock;
	int result;
	u64 generation;
};

static struct nfsd_ffv2_store_test_state nfsd_ffv2_store_test = {
	.lock = __MUTEX_INITIALIZER(nfsd_ffv2_store_test.lock),
};

static int nfsd_ffv2_store_reopen_test(const char *name,
				       const u8 store_uuid[16],
				       const u8 export_uuid[16],
				       const u8 binding_token[32], u64 *generation)
{
	struct nfsd_net *nn = net_generic(&init_net, nfsd_net_id);
	struct nfsd_ffv2_reservation *reservation = NULL;
	struct nfsd_ffv2_store *store = NULL;
	struct nfsd_ffv2_super_record next;
	struct path root;
	int error;

	error = kern_path(name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &root);
	if (error)
		return error;
	error = nfsd_ffv2_reservation_claim(nn, &root, store_uuid, export_uuid,
					    binding_token, &reservation);
	path_put(&root);
	if (error)
		return error;
	error = nfsd_ffv2_store_open(reservation, &store);
	if (error)
		goto out_abort;
	error = nfsd_ffv2_store_get_super(store, &next);
	if (error)
		goto out_close;
	if (next.payload_durable_bytes) {
		struct nfsd_ffv2_super_record regressing = next;

		regressing.generation++;
		regressing.payload_durable_bytes--;
		error = nfsd_ffv2_store_checkpoint(store, &regressing);
		if (error != -EINVAL)
			goto out_close;
		error = 0;
	}
	next.generation++;
	error = nfsd_ffv2_store_checkpoint(store, &next);
out_close:
	nfsd_ffv2_store_close(store);
	store = NULL;
	if (error)
		goto out_abort;
	error = nfsd_ffv2_store_open(reservation, &store);
	if (!error) {
		struct nfsd_ffv2_super_record reopened;

		error = nfsd_ffv2_store_get_super(store, &reopened);
		if (!error && reopened.generation != next.generation + 1)
			error = -EBADMSG;
	}
	if (!error)
		*generation = next.generation + 1;
	nfsd_ffv2_store_close(store);
out_abort:
	nfsd_ffv2_reservation_abort(reservation);
	return error;
}

static int nfsd_ffv2_store_failure_test(const char *name,
					const u8 store_uuid[16],
					const u8 export_uuid[16],
					const u8 binding_token[32])
{
	struct nfsd_net *nn = net_generic(&init_net, nfsd_net_id);
	struct nfsd_ffv2_reservation *reservation = NULL;
	struct nfsd_ffv2_store *store = NULL;
	struct nfsd_ffv2_super_record next;
	struct nfsd_ffv2_payload_record record = {
		.object_id = (1ULL << 40) | 1,
		.content_len = NFSD_FFV2_PAYLOAD_ALIGN,
	};
	u8 *bytes;
	u64 offset;
	struct path root;
	int error;

	error = kern_path(name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &root);
	if (error)
		return error;
	error = nfsd_ffv2_reservation_claim(nn, &root, store_uuid, export_uuid,
					    binding_token, &reservation);
	path_put(&root);
	if (error)
		return error;
	error = nfsd_ffv2_store_open(reservation, &store);
	if (error)
		goto out_abort;
	bytes = kzalloc(NFSD_FFV2_PAYLOAD_ALIGN, GFP_KERNEL);
	if (!bytes) {
		error = -ENOMEM;
		goto out_close;
	}
	memcpy(record.store_uuid, store_uuid, sizeof(record.store_uuid));
	record.content = bytes;
	nfsd_ffv2_store_test_fail_next_io(store);
	error = nfsd_ffv2_store_append_payload(store, &record, &offset);
	if (error != -EIO)
		goto out_free;
	error = nfsd_ffv2_store_append_payload(store, &record, &offset);
	if (error != -EIO)
		goto out_free;
	error = nfsd_ffv2_store_get_super(store, &next);
	if (error)
		goto out_free;
	next.generation++;
	error = nfsd_ffv2_store_checkpoint(store, &next);
	if (error == -EIO)
		error = 0;
out_free:
	kfree(bytes);
out_close:
	nfsd_ffv2_store_close(store);
out_abort:
	nfsd_ffv2_reservation_abort(reservation);
	return error;
}

static int ffv2_store_raw_checkpoint_test(const char *name,
					  const u8 store_uuid[16],
					  const u8 export_uuid[16],
					  const u8 binding_token[32])
{
	struct nfsd_net *nn = net_generic(&init_net, nfsd_net_id);
	struct nfsd_ffv2_reservation *reservation = NULL;
	struct nfsd_ffv2_store *store = NULL;
	struct nfsd_ffv2_super_record next;
	struct nfsd_ffv2_payload_record record = {
		.content_len = NFSD_FFV2_PAYLOAD_ALIGN,
	};
	u8 *bytes;
	u64 durable, offset;
	struct path root;
	int error;

	error = kern_path(name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &root);
	if (error)
		return error;
	error = nfsd_ffv2_reservation_claim(nn, &root, store_uuid, export_uuid,
					    binding_token, &reservation);
	path_put(&root);
	if (error)
		return error;
	error = nfsd_ffv2_store_open(reservation, &store);
	if (error)
		goto out_abort;
	error = nfsd_ffv2_store_get_super(store, &next);
	if (error)
		goto out_close;
	durable = next.payload_durable_bytes;
	record.object_id = (next.ds_incarnation << 40) | 1;
	memcpy(record.store_uuid, store_uuid, sizeof(record.store_uuid));
	bytes = kzalloc(NFSD_FFV2_PAYLOAD_ALIGN, GFP_KERNEL);
	if (!bytes) {
		error = -ENOMEM;
		goto out_close;
	}
	record.content = bytes;
	error = nfsd_ffv2_store_append_payload(store, &record, &offset);
	if (!error) {
		next.generation++;
		error = nfsd_ffv2_store_checkpoint(store, &next);
	}
	kfree(bytes);
	if (error)
		goto out_close;
	nfsd_ffv2_store_close(store);
	store = NULL;
	error = nfsd_ffv2_store_open(reservation, &store);
	if (!error) {
		error = nfsd_ffv2_store_get_super(store, &next);
		if (!error && next.payload_durable_bytes != durable)
			error = -EBADMSG;
		if (!error && nfsd_ffv2_store_test_payload_size(store) != durable)
			error = -EBADMSG;
	}
out_close:
	nfsd_ffv2_store_close(store);
out_abort:
	nfsd_ffv2_reservation_abort(reservation);
	return error;
}

static ssize_t nfsd_ffv2_store_test_read(struct file *file, char __user *buf,
					 size_t len, loff_t *ppos)
{
	struct nfsd_ffv2_store_test_state *state = &nfsd_ffv2_store_test;
	char output[96];
	int size;

	mutex_lock(&state->lock);
	size = scnprintf(output, sizeof(output), "result=%d generation=%llu\n",
			 state->result, state->generation);
	mutex_unlock(&state->lock);
	return simple_read_from_buffer(buf, len, ppos, output, size);
}

static ssize_t nfsd_ffv2_store_test_write(struct file *file,
					  const char __user *buf, size_t len,
					  loff_t *ppos)
{
	struct nfsd_ffv2_store_test_state *state = &nfsd_ffv2_store_test;
	char *input;
	char *path, *store, *export, *token, *mode;
	u8 store_uuid[16], export_uuid[16], binding_token[32];
	u64 generation = 0;
	int error;

	if (!len || len >= PATH_MAX + 138)
		return -EINVAL;
	input = memdup_user_nul(buf, len);
	if (IS_ERR(input))
		return PTR_ERR(input);
	path = strim(input);
	store = strchr(path, ' ');
	if (!store) {
		error = -EINVAL;
		goto out;
	}
	*store++ = '\0';
	export = strchr(store, ' ');
	if (!export) {
		error = -EINVAL;
		goto out;
	}
	*export++ = '\0';
	token = strchr(export, ' ');
	if (!token) {
		error = -EINVAL;
		goto out;
	}
	*token++ = '\0';
	mode = strchr(token, ' ');
	if (mode)
		*mode++ = '\0';
	if (strlen(store) != 32 || strlen(export) != 32 ||
	    strlen(token) != 64) {
		error = -EINVAL;
		goto out;
	}
	error = hex2bin(store_uuid, store, sizeof(store_uuid));
	if (error)
		goto out;
	error = hex2bin(export_uuid, export, sizeof(export_uuid));
	if (error)
		goto out;
	error = hex2bin(binding_token, token, sizeof(binding_token));
	if (error)
		goto out;
	if (mode && !strcmp(mode, "fail"))
		error = nfsd_ffv2_store_failure_test(path, store_uuid,
						     export_uuid, binding_token);
	else if (mode && !strcmp(mode, "raw"))
		error = ffv2_store_raw_checkpoint_test(path, store_uuid,
						       export_uuid, binding_token);
	else if (!mode)
		error = nfsd_ffv2_store_reopen_test(path, store_uuid, export_uuid,
						    binding_token, &generation);
	else
		error = -EINVAL;
	mutex_lock(&state->lock);
	state->result = error;
	state->generation = generation;
	mutex_unlock(&state->lock);
out:
	kfree(input);
	return error ? error : len;
}

static const struct file_operations nfsd_ffv2_store_test_fops = {
	.owner = THIS_MODULE,
	.read = nfsd_ffv2_store_test_read,
	.write = nfsd_ffv2_store_test_write,
	.llseek = default_llseek,
};

void nfsd_ffv2_live_test_debugfs_init(struct dentry *parent)
{
	debugfs_create_file("ffv2-live-test", 0600, parent, NULL,
			    &nfsd_ffv2_live_test_fops);
	debugfs_create_file("ffv2-file-gates", 0400, parent, NULL,
			    &nfsd_ffv2_file_gate_diag_fops);
	debugfs_create_file("ffv2-live-state", 0400, parent, NULL,
			    &nfsd_ffv2_live_state_fops);
	debugfs_create_file("ffv2-provider-probe", 0400, parent, NULL,
			    &nfsd_ffv2_provider_probe_fops);
	debugfs_create_file("ffv2-store-test", 0600, parent, NULL,
			    &nfsd_ffv2_store_test_fops);
}

void nfsd_ffv2_live_test_exit(void)
{
	mutex_lock(&nfsd_ffv2_live_test.lock);
	nfsd_ffv2_live_test.blocked = false;
	mutex_unlock(&nfsd_ffv2_live_test.lock);
	wake_up_all(&nfsd_ffv2_live_test.wait);
}

#endif /* CONFIG_NFSD_FFV2_LIVE_TEST */
