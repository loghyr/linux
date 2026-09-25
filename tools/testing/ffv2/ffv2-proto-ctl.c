// SPDX-License-Identifier: GPL-2.0-only
/*
 * Drive the nfsd Flex Files v2 prototype authority gate from userspace.
 *
 * The gate is a demonstrator: it lets an administrator holding
 * CAP_SYS_ADMIN in one reserved network namespace stand in for the
 * metadata server that would otherwise authenticate to this data server.
 * This program issues the generic-netlink commands that gate defines and
 * prints what a registration published, so a test client can present it.
 *
 * It speaks only the nfsd family's own commands and carries no protocol
 * of its own.  Nothing here is a deployment tool.
 */
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <linux/nfsd_netlink.h>

#define NLMSG_BUF_SIZE	8192

struct ffv2_nl {
	int	fd;
	uint16_t family;
	uint32_t seq;
	uint8_t	buf[NLMSG_BUF_SIZE];
};

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

static void print_hex(const char *name, const void *data, size_t len)
{
	const uint8_t *p = data;
	size_t i;

	printf("%s=", name);
	for (i = 0; i < len; i++)
		printf("%02x", p[i]);
	printf("\n");
}

/* One hex digit, or -1.  sscanf("%2x") would accept "0g" as a single 0. */
static int hex_digit(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static size_t parse_hex(const char *text, uint8_t *out, size_t max)
{
	size_t len = strlen(text);
	size_t i;

	if (!len || len % 2 || len / 2 > max)
		die("bad hex string of %zu characters", len);
	for (i = 0; i < len / 2; i++) {
		int hi = hex_digit(text[2 * i]);
		int lo = hex_digit(text[2 * i + 1]);

		if (hi < 0 || lo < 0)
			die("bad hex digit in \"%s\"", text);
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return len / 2;
}

/* One netlink message under construction in @nl's buffer. */
static struct nlmsghdr *nl_start(struct ffv2_nl *nl, uint16_t type, uint8_t cmd)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)nl->buf;
	struct genlmsghdr *gnlh;

	memset(nl->buf, 0, sizeof(nl->buf));
	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = ++nl->seq;
	gnlh = NLMSG_DATA(nlh);
	gnlh->cmd = cmd;
	gnlh->version = NFSD_FAMILY_VERSION;
	return nlh;
}

static void nl_put(struct ffv2_nl *nl, uint16_t type, const void *data,
		   uint16_t len)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)nl->buf;
	struct nlattr *nla;

	if (NLMSG_ALIGN(nlh->nlmsg_len) + NLA_HDRLEN + NLA_ALIGN(len) >
	    sizeof(nl->buf))
		die("netlink request too large");
	nla = (struct nlattr *)(nl->buf + NLMSG_ALIGN(nlh->nlmsg_len));
	nla->nla_type = type;
	nla->nla_len = NLA_HDRLEN + len;
	memcpy((uint8_t *)nla + NLA_HDRLEN, data, len);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(nla->nla_len);
}

static void nl_put_u32(struct ffv2_nl *nl, uint16_t type, uint32_t value)
{
	nl_put(nl, type, &value, sizeof(value));
}

static void nl_put_u64(struct ffv2_nl *nl, uint16_t type, uint64_t value)
{
	nl_put(nl, type, &value, sizeof(value));
}

static void nl_put_str(struct ffv2_nl *nl, uint16_t type, const char *value)
{
	nl_put(nl, type, value, (uint16_t)(strlen(value) + 1));
}

static struct nlattr *nl_nest_start(struct ffv2_nl *nl, uint16_t type)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)nl->buf;
	struct nlattr *nla;

	if (NLMSG_ALIGN(nlh->nlmsg_len) + NLA_HDRLEN > sizeof(nl->buf))
		die("netlink request too large");
	nla = (struct nlattr *)(nl->buf + NLMSG_ALIGN(nlh->nlmsg_len));
	nla->nla_type = type | NLA_F_NESTED;
	nla->nla_len = NLA_HDRLEN;
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(NLA_HDRLEN);
	return nla;
}

static void nl_nest_end(struct ffv2_nl *nl, struct nlattr *nla)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)nl->buf;

	nla->nla_len = (uint8_t *)nl->buf + nlh->nlmsg_len - (uint8_t *)nla;
}

/*
 * Send the staged message and collect the reply.  A DONE or an ACK ends the
 * exchange; an error reply is reported with the errno the kernel chose, so
 * a refused registration is distinguishable from a broken request.
 */
static size_t nl_talk(struct ffv2_nl *nl, uint8_t *reply, size_t reply_size)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)nl->buf;
	uint8_t in[NLMSG_BUF_SIZE];
	size_t payload = 0;
	ssize_t got;

	if (send(nl->fd, nl->buf, nlh->nlmsg_len, 0) < 0)
		die("netlink send: %s", strerror(errno));
	for (;;) {
		struct nlmsghdr *rep;

		got = recv(nl->fd, in, sizeof(in), 0);
		if (got < 0)
			die("netlink recv: %s", strerror(errno));
		for (rep = (struct nlmsghdr *)in; NLMSG_OK(rep, (size_t)got);
		     rep = NLMSG_NEXT(rep, got)) {
			if (rep->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = NLMSG_DATA(rep);

				if (err->error)
					die("netlink command failed: %s",
					    strerror(-err->error));
				return payload;
			}
			if (rep->nlmsg_type == NLMSG_DONE)
				return payload;
			payload = rep->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
			if (payload > reply_size)
				die("netlink reply too large");
			memcpy(reply,
			       (uint8_t *)NLMSG_DATA(rep) + GENL_HDRLEN,
			       payload);
		}
	}
}

static const struct nlattr *nl_find(const uint8_t *reply, size_t len,
				    uint16_t type)
{
	size_t off = 0;

	while (off + NLA_HDRLEN <= len) {
		const struct nlattr *nla = (const struct nlattr *)(reply + off);

		if (nla->nla_len < NLA_HDRLEN || off + nla->nla_len > len)
			return NULL;
		if ((nla->nla_type & NLA_TYPE_MASK) == type)
			return nla;
		off += NLA_ALIGN(nla->nla_len);
	}
	return NULL;
}

static const void *nl_data(const struct nlattr *nla, size_t *len)
{
	*len = nla->nla_len - NLA_HDRLEN;
	return (const uint8_t *)nla + NLA_HDRLEN;
}

static void nl_open(struct ffv2_nl *nl)
{
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	uint8_t reply[NLMSG_BUF_SIZE];
	const struct nlattr *nla;
	size_t len, attrlen;

	nl->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (nl->fd < 0)
		die("netlink socket: %s", strerror(errno));
	if (bind(nl->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		die("netlink bind: %s", strerror(errno));

	nl_start(nl, GENL_ID_CTRL, CTRL_CMD_GETFAMILY);
	nl_put_str(nl, CTRL_ATTR_FAMILY_NAME, NFSD_FAMILY_NAME);
	len = nl_talk(nl, reply, sizeof(reply));
	nla = nl_find(reply, len, CTRL_ATTR_FAMILY_ID);
	if (!nla)
		die("no %s generic-netlink family; is nfsd loaded?",
		    NFSD_FAMILY_NAME);
	{
		const void *value = nl_data(nla, &attrlen);

		if (attrlen != sizeof(nl->family))
			die("family id is %zu bytes, not %zu", attrlen,
			    sizeof(nl->family));
		memcpy(&nl->family, value, sizeof(nl->family));
	}
}

static void cmd_enable(struct ffv2_nl *nl)
{
	uint8_t reply[NLMSG_BUF_SIZE];

	nl_start(nl, nl->family, NFSD_CMD_FFV2_PROTOTYPE_ENABLE);
	nl_talk(nl, reply, sizeof(reply));
	printf("PROTO-ENABLE=ok\n");
}

static void cmd_disable(struct ffv2_nl *nl)
{
	uint8_t reply[NLMSG_BUF_SIZE];

	nl_start(nl, nl->family, NFSD_CMD_FFV2_PROTOTYPE_DISABLE);
	nl_talk(nl, reply, sizeof(reply));
	printf("PROTO-DISABLE=ok\n");
}

/*
 * A registration presents a nonce the gate issued, so the challenge and the
 * registration are one command here: the nonce is never useful on its own.
 */
/* Append one "KEY=hex" line to the bundle a client reads. */
static void bundle_hex(FILE *f, const char *key, const void *data, size_t len)
{
	const uint8_t *p = data;
	size_t i;

	if (!f)
		return;
	fprintf(f, "%s=", key);
	for (i = 0; i < len; i++)
		fprintf(f, "%02x", p[i]);
	fprintf(f, "\n");
}

/*
 * A registration presents a nonce the gate issued, so the challenge and the
 * registration are one command here: the nonce is never useful on its own.
 *
 * The bundle this writes is the only thing a client should read.  In
 * particular the stateid is written in XDR wire order, because the
 * attribute the kernel hands back holds its sequence id in host order and
 * the difference between the two is invisible in hex: leaving the choice
 * to whoever wired up the harness is leaving a byte-reversed stateid to be
 * discovered as a refused read.
 */
static void cmd_register(struct ffv2_nl *nl, const char *domain,
			 const char *handle_hex, uint32_t chunk_size,
			 uint32_t data_count, const char *store_uuid_hex,
			 const char *binding_token_hex,
			 const char *persisted_handle_hex, uint32_t writer_id,
			 uint64_t pnfs_clientid, const char *bundle_path,
			 const char *run)
{
	uint8_t reply[NLMSG_BUF_SIZE];
	uint8_t handle[128];
	uint8_t nonce[32];
	uint8_t store_uuid[16];
	uint8_t binding_token[32];
	uint8_t persisted_handle[32];
	uint8_t wire[16];
	const struct nlattr *nla;
	size_t handle_len, len, attrlen;
	size_t object_len;
	size_t mapped_len = 0, uuid_len = 0;
	uint8_t mapped[128], uuid[16];
	const void *value;
	const void *object_data;
	uint64_t generation;
	uint32_t seqid;
	FILE *bundle = NULL;

	nl_start(nl, nl->family, NFSD_CMD_FFV2_PROTOTYPE_CHALLENGE);
	len = nl_talk(nl, reply, sizeof(reply));
	nla = nl_find(reply, len, NFSD_A_FFV2_PROTOTYPE_NONCE);
	if (!nla)
		die("challenge returned no nonce");
	value = nl_data(nla, &attrlen);
	if (attrlen != sizeof(nonce))
		die("challenge nonce is %zu bytes", attrlen);
	memcpy(nonce, value, sizeof(nonce));
	print_hex("PROTO-NONCE", nonce, sizeof(nonce));

	handle_len = parse_hex(handle_hex, handle, sizeof(handle));
	if (!handle_len)
		die("the ordinary filehandle is empty");
	if (parse_hex(store_uuid_hex, store_uuid, sizeof(store_uuid)) !=
	    sizeof(store_uuid))
		die("store uuid must be 16 bytes");
	if (parse_hex(binding_token_hex, binding_token,
		      sizeof(binding_token)) != sizeof(binding_token))
		die("binding token must be 32 bytes");
	if (parse_hex(persisted_handle_hex, persisted_handle,
		      sizeof(persisted_handle)) != sizeof(persisted_handle))
		die("persisted handle must be 32 bytes");
	nl_start(nl, nl->family, NFSD_CMD_FFV2_PROTOTYPE_REGISTER);
	nl_put(nl, NFSD_A_FFV2_PROTOTYPE_NONCE, nonce, sizeof(nonce));
	nl_put_str(nl, NFSD_A_FFV2_PROTOTYPE_AUTH_DOMAIN, domain);
	nl_put_u32(nl, NFSD_A_FFV2_PROTOTYPE_CHUNK_SIZE, chunk_size);
	nl_put_u32(nl, NFSD_A_FFV2_PROTOTYPE_DATA_COUNT, data_count);
	nl_put_u32(nl, NFSD_A_FFV2_PROTOTYPE_PARITY_COUNT, 0);
	nl_put(nl, NFSD_A_FFV2_PROTOTYPE_STORE_UUID, store_uuid,
	       sizeof(store_uuid));
	nl_put(nl, NFSD_A_FFV2_PROTOTYPE_BINDING_TOKEN, binding_token,
	       sizeof(binding_token));
	nl_put_u32(nl, NFSD_A_FFV2_PROTOTYPE_WRITER_ID, writer_id);
	nl_put_u64(nl, NFSD_A_FFV2_PROTOTYPE_PNFS_CLIENTID, pnfs_clientid);
	{
		struct nlattr *objects, *object;

		objects = nl_nest_start(nl, NFSD_A_FFV2_PROTOTYPE_OBJECTS);
		object = nl_nest_start(nl, 0);
		nl_put(nl, NFSD_A_FFV2_PROTOTYPE_OBJECT_ORDINARY_HANDLE,
		       handle, (uint16_t)handle_len);
		nl_put(nl, NFSD_A_FFV2_PROTOTYPE_OBJECT_PERSISTED_HANDLE,
		       persisted_handle, sizeof(persisted_handle));
		nl_nest_end(nl, object);
		nl_nest_end(nl, objects);
	}
	len = nl_talk(nl, reply, sizeof(reply));

	nla = nl_find(reply, len, NFSD_A_FFV2_PROTOTYPE_SOURCE_UUID);
	if (!nla)
		die("registration returned no source uuid");
	value = nl_data(nla, &attrlen);
	if (attrlen != sizeof(uuid))
		die("source uuid is %zu bytes", attrlen);
	memcpy(uuid, value, sizeof(uuid));
	uuid_len = attrlen;
	print_hex("PROTO-SOURCE-UUID", uuid, uuid_len);

	nla = nl_find(reply, len, NFSD_A_FFV2_PROTOTYPE_SERVICE_UUID);
	if (nla) {
		value = nl_data(nla, &attrlen);
		print_hex("PROTO-SERVICE-UUID", value, attrlen);
	}
	nla = nl_find(reply, len, NFSD_A_FFV2_PROTOTYPE_REPLAY_UUID);
	if (nla) {
		value = nl_data(nla, &attrlen);
		print_hex("PROTO-REPLAY-UUID", value, attrlen);
	}
	nla = nl_find(reply, len, NFSD_A_FFV2_PROTOTYPE_GENERATION);
	if (!nla)
		die("registration returned no generation");
	value = nl_data(nla, &attrlen);
	if (attrlen != sizeof(generation))
		die("generation is %zu bytes", attrlen);
	memcpy(&generation, value, sizeof(generation));
	printf("PROTO-GENERATION=%llu\n", (unsigned long long)generation);

	nla = nl_find(reply, len, NFSD_A_FFV2_PROTOTYPE_OBJECTS);
	if (!nla)
		die("registration returned no object array");
	value = nl_data(nla, &attrlen);
	nla = nl_find(value, attrlen, 0);
	if (!nla)
		die("registration returned no object zero");
	object_data = nl_data(nla, &object_len);
	nla = nl_find(object_data, object_len,
		      NFSD_A_FFV2_PROTOTYPE_OBJECT_STATEID);
	if (!nla)
		die("registration returned no stateid");
	value = nl_data(nla, &attrlen);
	if (attrlen != sizeof(wire))
		die("stateid is %zu bytes", attrlen);
	print_hex("PROTO-STATEID-RAW", value, attrlen);
	memcpy(&seqid, value, sizeof(seqid));
	seqid = htonl(seqid);
	memcpy(wire, &seqid, sizeof(seqid));
	memcpy(wire + sizeof(seqid), (const uint8_t *)value + sizeof(seqid),
	       sizeof(wire) - sizeof(seqid));
	print_hex("PROTO-STATEID", wire, sizeof(wire));

	nla = nl_find(object_data, object_len,
		      NFSD_A_FFV2_PROTOTYPE_OBJECT_MAPPED_HANDLE);
	if (!nla)
		die("registration returned no mapped handle");
	value = nl_data(nla, &attrlen);
	/*
	 * A filehandle of no bytes is not one a client can present, and
	 * publishing it would hand the harness something it would have to
	 * index into.  Refuse it here rather than downstream.
	 */
	if (!attrlen || attrlen > sizeof(mapped))
		die("mapped handle is %zu bytes", attrlen);
	memcpy(mapped, value, attrlen);
	mapped_len = attrlen;
	print_hex("PROTO-MAPPED-HANDLE", mapped, mapped_len);

	if (bundle_path) {
		char staged[512];
		int fd;

		/*
		 * Written beside the bundle and renamed onto it, so a reader
		 * sees either the previous registration or this complete one
		 * and never a half-written file.  The staging name is unique,
		 * so two writers cannot stage over each other, and the run
		 * token is what tells a reader which registration it has.
		 */
		if ((size_t)snprintf(staged, sizeof(staged), "%s.XXXXXX",
				     bundle_path) >= sizeof(staged))
			die("bundle path is too long");
		fd = mkstemp(staged);
		if (fd < 0)
			die("cannot stage %s: %s", staged, strerror(errno));
		bundle = fdopen(fd, "w");
		if (!bundle) {
			close(fd);
			unlink(staged);
			die("cannot write %s: %s", staged, strerror(errno));
		}
		fprintf(bundle, "RUN=%s\n", run ? run : "");
		bundle_hex(bundle, "MAPPED_HANDLE", mapped, mapped_len);
		bundle_hex(bundle, "STATEID", wire, sizeof(wire));
		bundle_hex(bundle, "SOURCE_UUID", uuid, uuid_len);
		fprintf(bundle, "GENERATION=%llu\n",
			(unsigned long long)generation);
		fprintf(bundle, "CHUNK_SIZE=%u\n", chunk_size);
		if (fflush(bundle) || fsync(fileno(bundle))) {
			unlink(staged);
			die("cannot flush %s: %s", staged, strerror(errno));
		}
		if (fchmod(fileno(bundle), 0644)) {
			unlink(staged);
			die("cannot set the mode of %s: %s", staged,
			    strerror(errno));
		}
		if (fclose(bundle)) {
			unlink(staged);
			die("cannot complete %s: %s", staged, strerror(errno));
		}
		if (rename(staged, bundle_path)) {
			unlink(staged);
			die("cannot publish %s: %s", bundle_path,
			    strerror(errno));
		}
		printf("PROTO-BUNDLE=%s\n", bundle_path);
	}
	printf("PROTO-REGISTER=ok\n");
}

static void cmd_unregister(struct ffv2_nl *nl, const char *uuid_hex,
			   uint64_t generation)
{
	uint8_t reply[NLMSG_BUF_SIZE];
	uint8_t uuid[16];
	size_t uuid_len;

	uuid_len = parse_hex(uuid_hex, uuid, sizeof(uuid));
	if (uuid_len != sizeof(uuid))
		die("source uuid must be 16 bytes");
	nl_start(nl, nl->family, NFSD_CMD_FFV2_PROTOTYPE_UNREGISTER);
	nl_put(nl, NFSD_A_FFV2_PROTOTYPE_SOURCE_UUID, uuid, sizeof(uuid));
	nl_put(nl, NFSD_A_FFV2_PROTOTYPE_GENERATION, &generation,
	       sizeof(generation));
	nl_talk(nl, reply, sizeof(reply));
	printf("PROTO-UNREGISTER=ok\n");
}

static void usage(void)
{
	fprintf(stderr,
		"usage: ffv2-proto-ctl enable\n"
		"       ffv2-proto-ctl register <auth-domain> <handle-hex> <chunk-size> <data-count> <store-uuid-hex> <binding-token-hex> <persisted-handle-hex> <writer-id> <pnfs-clientid> [bundle-path [run-token]]\n"
		"       ffv2-proto-ctl unregister <source-uuid-hex> <generation>\n"
		"       ffv2-proto-ctl disable\n");
	exit(2);
}

int main(int argc, char **argv)
{
	struct ffv2_nl nl = {};

	if (argc < 2)
		usage();
	nl_open(&nl);

	if (!strcmp(argv[1], "enable") && argc == 2)
		cmd_enable(&nl);
	else if (!strcmp(argv[1], "register") && argc >= 11 && argc <= 13)
		cmd_register(&nl, argv[2], argv[3],
			     (uint32_t)strtoul(argv[4], NULL, 0),
			     (uint32_t)strtoul(argv[5], NULL, 0),
			     argv[6], argv[7], argv[8],
			     (uint32_t)strtoul(argv[9], NULL, 0),
			     strtoull(argv[10], NULL, 0),
			     argc >= 12 ? argv[11] : NULL,
			     argc == 13 ? argv[12] : NULL);
	else if (!strcmp(argv[1], "unregister") && argc == 4)
		cmd_unregister(&nl, argv[2], strtoull(argv[3], NULL, 0));
	else if (!strcmp(argv[1], "disable") && argc == 2)
		cmd_disable(&nl);
	else
		usage();

	close(nl.fd);
	return 0;
}
