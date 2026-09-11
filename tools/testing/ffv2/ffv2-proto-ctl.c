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

static size_t parse_hex(const char *text, uint8_t *out, size_t max)
{
	size_t len = strlen(text);
	size_t i;

	if (len % 2 || len / 2 > max)
		die("bad hex string of %zu characters", len);
	for (i = 0; i < len / 2; i++) {
		unsigned int byte;

		if (sscanf(text + 2 * i, "%2x", &byte) != 1)
			die("bad hex string");
		out[i] = (uint8_t)byte;
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

static void nl_put_str(struct ffv2_nl *nl, uint16_t type, const char *value)
{
	nl_put(nl, type, value, (uint16_t)(strlen(value) + 1));
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
	nl->family = *(const uint16_t *)nl_data(nla, &attrlen);
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
static void cmd_register(struct ffv2_nl *nl, const char *domain,
			 const char *handle_hex, uint32_t chunk_size,
			 uint32_t data_count)
{
	uint8_t reply[NLMSG_BUF_SIZE];
	uint8_t handle[128];
	uint8_t nonce[32];
	const struct nlattr *nla;
	size_t handle_len, len, attrlen;
	const void *value;

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
	nl_start(nl, nl->family, NFSD_CMD_FFV2_PROTOTYPE_REGISTER);
	nl_put(nl, NFSD_A_FFV2_PROTOTYPE_NONCE, nonce, sizeof(nonce));
	nl_put_str(nl, NFSD_A_FFV2_PROTOTYPE_AUTH_DOMAIN, domain);
	nl_put(nl, NFSD_A_FFV2_PROTOTYPE_HANDLE, handle,
	       (uint16_t)handle_len);
	nl_put_u32(nl, NFSD_A_FFV2_PROTOTYPE_CHUNK_SIZE, chunk_size);
	nl_put_u32(nl, NFSD_A_FFV2_PROTOTYPE_DATA_COUNT, data_count);
	nl_put_u32(nl, NFSD_A_FFV2_PROTOTYPE_PARITY_COUNT, 0);
	len = nl_talk(nl, reply, sizeof(reply));

	nla = nl_find(reply, len, NFSD_A_FFV2_PROTOTYPE_SOURCE_UUID);
	if (!nla)
		die("registration returned no source uuid");
	value = nl_data(nla, &attrlen);
	print_hex("PROTO-SOURCE-UUID", value, attrlen);

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
	printf("PROTO-GENERATION=%llu\n",
	       (unsigned long long)*(const uint64_t *)value);

	nla = nl_find(reply, len, NFSD_A_FFV2_PROTOTYPE_STATEID);
	if (!nla)
		die("registration returned no stateid");
	value = nl_data(nla, &attrlen);
	print_hex("PROTO-STATEID", value, attrlen);
	/*
	 * The attribute carries the server's own stateid, whose sequence id
	 * is a host-order word; stateid4 on the wire is XDR.  Both forms are
	 * printed because only one of them is what a client must present,
	 * and the difference is invisible in hex.
	 */
	if (attrlen == 16) {
		uint8_t wire[16];
		uint32_t seqid;

		memcpy(&seqid, value, sizeof(seqid));
		seqid = htonl(seqid);
		memcpy(wire, &seqid, sizeof(seqid));
		memcpy(wire + sizeof(seqid), (const uint8_t *)value + 4, 12);
		print_hex("PROTO-STATEID-WIRE", wire, sizeof(wire));
	}

	nla = nl_find(reply, len, NFSD_A_FFV2_PROTOTYPE_MAPPED_HANDLE);
	if (!nla)
		die("registration returned no mapped handle");
	value = nl_data(nla, &attrlen);
	print_hex("PROTO-MAPPED-HANDLE", value, attrlen);
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
		"       ffv2-proto-ctl register <auth-domain> <handle-hex> <chunk-size> <data-count>\n"
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
	else if (!strcmp(argv[1], "register") && argc == 6)
		cmd_register(&nl, argv[2], argv[3],
			     (uint32_t)strtoul(argv[4], NULL, 0),
			     (uint32_t)strtoul(argv[5], NULL, 0));
	else if (!strcmp(argv[1], "unregister") && argc == 4)
		cmd_unregister(&nl, argv[2], strtoull(argv[3], NULL, 0));
	else if (!strcmp(argv[1], "disable") && argc == 2)
		cmd_disable(&nl);
	else
		usage();

	close(nl.fd);
	return 0;
}
