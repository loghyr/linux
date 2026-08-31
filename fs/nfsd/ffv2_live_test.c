// SPDX-License-Identifier: GPL-2.0-only
#ifdef CONFIG_NFSD_FFV2_LIVE_TEST

#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "export.h"
#include "ffv2.h"

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
	char output[160];
	int size;

	mutex_lock(&state->lock);
	size = scnprintf(output, sizeof(output),
			 "armed=%s reached=%s blocked=%u service=%u context=%u\n",
			 nfsd_ffv2_live_test_stage_name(state->armed),
			 nfsd_ffv2_live_test_stage_name(state->reached),
			 state->blocked, state->service, state->context);
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
		wake = true;
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

void nfsd_ffv2_live_test_debugfs_init(struct dentry *parent)
{
	debugfs_create_file("ffv2-live-test", 0600, parent, NULL,
			    &nfsd_ffv2_live_test_fops);
}

void nfsd_ffv2_live_test_exit(void)
{
	mutex_lock(&nfsd_ffv2_live_test.lock);
	nfsd_ffv2_live_test.blocked = false;
	mutex_unlock(&nfsd_ffv2_live_test.lock);
	wake_up_all(&nfsd_ffv2_live_test.wait);
}

#endif /* CONFIG_NFSD_FFV2_LIVE_TEST */
