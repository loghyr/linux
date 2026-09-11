// SPDX-License-Identifier: GPL-2.0-only
/*
 * A disposable NFSv4.2 client that issues the Flex Files v2 read
 * operations over a real NFS connection.
 *
 * The ordinary Linux client cannot ask for CHUNK_HEADER_READ or
 * CHUNK_READ, so nothing else can show that a registered object is
 * readable on the wire.  This program speaks the canonical XDR of those
 * operations and nothing else: it builds NFSv4.2 COMPOUNDs over TCP with
 * AUTH_SYS, prints every request and reply verbatim, and decodes the two
 * read replies field by field so a reply can be checked rather than
 * assumed.
 *
 * It is a demonstrator harness, not a client implementation.  It keeps no
 * state across runs, recovers from nothing, and must never be presented as
 * interoperability evidence for a real Flex Files v2 client.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define NFS_PROGRAM		100003
#define NFS_V4			4
#define NFSPROC4_COMPOUND	1

#define OP_GETFH		10
#define OP_LOOKUP		15
#define OP_PUTFH		22
#define OP_PUTROOTFH		24
#define OP_READ			25
#define OP_EXCHANGE_ID		42
#define OP_CREATE_SESSION	43
#define OP_DESTROY_SESSION	44
#define OP_SEQUENCE		53
#define OP_DESTROY_CLIENTID	57
#define OP_CHUNK_COMMIT		78
#define OP_CHUNK_HEADER_READ	81
#define OP_CHUNK_READ		83

#define NFS4_FHSIZE		128
#define NFS4_STATEID_SIZE	16
#define NFS4_SESSIONID_SIZE	16
#define NFS4_VERIFIER_SIZE	8

#define XDR_UNIT		4
#define MAX_MSG			(1024 * 1024)

/* An encoded message under construction. */
struct xbuf {
	uint8_t	*b;
	size_t	len;
	size_t	cap;
};

/* A received message being decoded. */
struct xcur {
	const uint8_t	*b;
	size_t		len;
	size_t		off;
	bool		bad;
};

struct nfs4_client {
	int		fd;
	uint32_t	xid;
	uint64_t	clientid;
	uint32_t	seq_seqid;
	uint8_t		sessionid[NFS4_SESSIONID_SIZE];
	uint8_t		fh[NFS4_FHSIZE];
	size_t		fh_len;
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

static void hexdump(const char *name, const void *data, size_t len)
{
	const uint8_t *p = data;
	size_t i;

	printf("%s len=%zu\n", name, len);
	for (i = 0; i < len; i++) {
		if (i % 32 == 0)
			printf("%s %04zx:", name, i);
		printf(" %02x", p[i]);
		if (i % 32 == 31 || i + 1 == len)
			printf("\n");
	}
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

/* The zlib CRC32 a chunk checksum carries, computed without zlib. */
static uint32_t crc32_zlib(const uint8_t *data, size_t len)
{
	uint32_t crc = ~0U;
	size_t i;
	int bit;

	for (i = 0; i < len; i++) {
		crc ^= data[i];
		for (bit = 0; bit < 8; bit++)
			crc = (crc >> 1) ^ (0xedb88320U & (~(crc & 1) + 1));
	}
	return ~crc;
}

static void xput(struct xbuf *x, const void *data, size_t len)
{
	if (x->len + len > x->cap)
		die("encode buffer overflow");
	memcpy(x->b + x->len, data, len);
	x->len += len;
}

static void xu32(struct xbuf *x, uint32_t value)
{
	uint32_t be = htonl(value);

	xput(x, &be, sizeof(be));
}

static void xu64(struct xbuf *x, uint64_t value)
{
	xu32(x, (uint32_t)(value >> 32));
	xu32(x, (uint32_t)value);
}

static void xopaque(struct xbuf *x, const void *data, size_t len)
{
	static const uint8_t pad[XDR_UNIT] = {};

	xu32(x, (uint32_t)len);
	xput(x, data, len);
	if (len % XDR_UNIT)
		xput(x, pad, XDR_UNIT - (len % XDR_UNIT));
}

static uint32_t gu32(struct xcur *c)
{
	uint32_t be;

	if (c->bad || c->off + XDR_UNIT > c->len) {
		c->bad = true;
		return 0;
	}
	memcpy(&be, c->b + c->off, sizeof(be));
	c->off += XDR_UNIT;
	return ntohl(be);
}

static uint64_t gu64(struct xcur *c)
{
	uint64_t hi = gu32(c);

	return (hi << 32) | gu32(c);
}

static const uint8_t *gbytes(struct xcur *c, size_t len)
{
	size_t aligned = (len + XDR_UNIT - 1) & ~((size_t)XDR_UNIT - 1);
	const uint8_t *p;

	if (c->bad || c->off + aligned > c->len) {
		c->bad = true;
		return NULL;
	}
	p = c->b + c->off;
	c->off += aligned;
	return p;
}

static const uint8_t *gopaque(struct xcur *c, size_t *len)
{
	*len = gu32(c);
	return gbytes(c, *len);
}

/*
 * One RPC call: record marking, the AUTH_SYS credential this demonstrator
 * presents, and the COMPOUND header.  Minor version 2 is not a choice --
 * the Flex Files v2 operation numbers are only in range there.
 */
static void rpc_start(struct xbuf *x, struct nfs4_client *c, uint32_t nops)
{
	static const char machine[] = "ffv2-live-probe";

	x->len = 0;
	xu32(x, 0);			/* record mark, filled in on send */
	xu32(x, ++c->xid);
	xu32(x, 0);			/* CALL */
	xu32(x, 2);			/* RPC version */
	xu32(x, NFS_PROGRAM);
	xu32(x, NFS_V4);
	xu32(x, NFSPROC4_COMPOUND);
	xu32(x, 1);			/* AUTH_SYS */
	xu32(x, 5 * XDR_UNIT + ((sizeof(machine) - 1 + 3) & ~3U));
	xu32(x, 0);			/* stamp */
	xopaque(x, machine, sizeof(machine) - 1);
	xu32(x, 0);			/* uid */
	xu32(x, 0);			/* gid */
	xu32(x, 0);			/* no auxiliary gids */
	xu32(x, 0);			/* AUTH_NONE verifier */
	xu32(x, 0);
	xu32(x, 0);			/* zero-length tag */
	xu32(x, 2);			/* minor version */
	xu32(x, nops);
}

static void rpc_send(struct nfs4_client *c, struct xbuf *x, const char *label)
{
	uint32_t mark = htonl(0x80000000U | (uint32_t)(x->len - XDR_UNIT));
	size_t sent = 0;

	memcpy(x->b, &mark, sizeof(mark));
	hexdump(label, x->b + XDR_UNIT, x->len - XDR_UNIT);
	while (sent < x->len) {
		ssize_t got = send(c->fd, x->b + sent, x->len - sent, 0);

		if (got <= 0)
			die("send: %s", strerror(errno));
		sent += (size_t)got;
	}
}

static void rpc_read(struct nfs4_client *c, void *data, size_t len)
{
	size_t got = 0;

	while (got < len) {
		ssize_t n = recv(c->fd, (uint8_t *)data + got, len - got, 0);

		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			die("no reply within the receive timeout");
		if (n <= 0)
			die("recv: %s", n ? strerror(errno) : "server closed");
		got += (size_t)n;
	}
}

static size_t rpc_recv(struct nfs4_client *c, uint8_t *reply, size_t cap,
		       const char *label)
{
	size_t len = 0;
	bool last = false;

	while (!last) {
		uint32_t mark;

		rpc_read(c, &mark, sizeof(mark));
		mark = ntohl(mark);
		last = mark & 0x80000000U;
		mark &= 0x7fffffffU;
		if (len + mark > cap)
			die("reply larger than %zu bytes", cap);
		rpc_read(c, reply + len, mark);
		len += mark;
	}
	hexdump(label, reply, len);
	return len;
}

/*
 * Strip the RPC reply header and the COMPOUND header, leaving the cursor
 * on the first operation result.  Anything other than a wholly accepted
 * reply is fatal: this program tests the server's operations, so a broken
 * transport is a broken test rather than a result.
 */
static uint32_t rpc_reply_open(struct xcur *c, uint32_t *nres)
{
	size_t len;
	uint32_t status;

	gu32(c);				/* xid */
	if (gu32(c) != 1)
		die("not an RPC reply");
	if (gu32(c) != 0)
		die("RPC message denied");
	gu32(c);				/* verifier flavor */
	gopaque(c, &len);			/* verifier body */
	if (gu32(c) != 0)
		die("RPC call not accepted");
	status = gu32(c);
	gopaque(c, &len);			/* tag */
	*nres = gu32(c);
	if (c->bad)
		die("truncated RPC reply");
	return status;
}

/* Consume one operation result header, checking the operation it names. */
static uint32_t op_result(struct xcur *c, uint32_t expect)
{
	uint32_t opnum = gu32(c);

	if (opnum != expect)
		die("reply names operation %u, expected %u", opnum, expect);
	return gu32(c);
}

static void put_sequence(struct xbuf *x, struct nfs4_client *c)
{
	xu32(x, OP_SEQUENCE);
	xput(x, c->sessionid, sizeof(c->sessionid));
	xu32(x, ++c->seq_seqid);
	xu32(x, 0);			/* slot */
	xu32(x, 0);			/* highest slot */
	xu32(x, 0);			/* do not cache this */
}

/* Consume a SEQUENCE result and report its status. */
static uint32_t get_sequence(struct xcur *c)
{
	uint32_t status = op_result(c, OP_SEQUENCE);

	if (status)
		return status;
	gbytes(c, NFS4_SESSIONID_SIZE);
	gu32(c);			/* sequence id */
	gu32(c);			/* slot */
	gu32(c);			/* highest slot */
	gu32(c);			/* target highest slot */
	gu32(c);			/* status flags */
	return status;
}

static void put_putfh(struct xbuf *x, const uint8_t *fh, size_t fh_len)
{
	xu32(x, OP_PUTFH);
	xopaque(x, fh, fh_len);
}

static void exchange_id(struct nfs4_client *c, uint8_t *buf, size_t cap)
{
	char owner[64];
	struct xbuf x = { .b = buf, .cap = cap };
	uint8_t reply[MAX_MSG];
	struct xcur cur = { .b = reply };
	uint32_t nres, status;
	uint8_t verifier[NFS4_VERIFIER_SIZE];
	size_t len;

	snprintf(owner, sizeof(owner), "ffv2-live-probe-%u", (unsigned int)getpid());
	memset(verifier, 0, sizeof(verifier));
	memcpy(verifier, &c->xid, sizeof(c->xid));

	rpc_start(&x, c, 1);
	xu32(&x, OP_EXCHANGE_ID);
	xput(&x, verifier, sizeof(verifier));
	xopaque(&x, owner, strlen(owner));
	xu32(&x, 0);			/* eia_flags */
	xu32(&x, 0);			/* SP4_NONE */
	xu32(&x, 0);			/* no implementation id */
	rpc_send(c, &x, "REQ-EXCHANGE-ID");

	cur.len = rpc_recv(c, reply, sizeof(reply), "REP-EXCHANGE-ID");
	rpc_reply_open(&cur, &nres);
	status = op_result(&cur, OP_EXCHANGE_ID);
	if (status)
		die("EXCHANGE_ID failed with NFS4ERR %u", status);
	c->clientid = gu64(&cur);
	gu32(&cur);			/* eir_sequenceid */
	gu32(&cur);			/* eir_flags */
	gu32(&cur);			/* spr_how */
	gu64(&cur);			/* so_minor_id */
	gopaque(&cur, &len);		/* so_major_id */
	gopaque(&cur, &len);		/* eir_server_scope */
	if (cur.bad)
		die("truncated EXCHANGE_ID reply");
	printf("PROBE-CLIENTID=%llu\n", (unsigned long long)c->clientid);
}

static void put_channel_attrs(struct xbuf *x)
{
	xu32(x, 0);			/* ca_headerpadsize */
	xu32(x, 65536);			/* ca_maxrequestsize */
	xu32(x, 65536);			/* ca_maxresponsesize */
	xu32(x, 16384);			/* ca_maxresponsesize_cached */
	xu32(x, 8);			/* ca_maxoperations */
	xu32(x, 2);			/* ca_maxrequests */
	xu32(x, 0);			/* no RDMA IRD */
}

static void create_session(struct nfs4_client *c, uint8_t *buf, size_t cap)
{
	static const char machine[] = "ffv2-live-probe";
	struct xbuf x = { .b = buf, .cap = cap };
	uint8_t reply[MAX_MSG];
	struct xcur cur = { .b = reply };
	uint32_t nres, status;
	const uint8_t *id;

	rpc_start(&x, c, 1);
	xu32(&x, OP_CREATE_SESSION);
	xu64(&x, c->clientid);
	xu32(&x, 1);			/* csa_sequence, from EXCHANGE_ID */
	xu32(&x, 0);			/* csa_flags: no persistence */
	put_channel_attrs(&x);		/* fore channel */
	put_channel_attrs(&x);		/* back channel */
	xu32(&x, 0x40000000);		/* csa_cb_program */
	xu32(&x, 1);			/* one security parameter */
	xu32(&x, 1);			/* AUTH_SYS */
	xu32(&x, 0);			/* stamp */
	xopaque(&x, machine, sizeof(machine) - 1);
	xu32(&x, 0);			/* uid */
	xu32(&x, 0);			/* gid */
	xu32(&x, 0);			/* no auxiliary gids */
	rpc_send(c, &x, "REQ-CREATE-SESSION");

	cur.len = rpc_recv(c, reply, sizeof(reply), "REP-CREATE-SESSION");
	rpc_reply_open(&cur, &nres);
	status = op_result(&cur, OP_CREATE_SESSION);
	if (status)
		die("CREATE_SESSION failed with NFS4ERR %u", status);
	id = gbytes(&cur, NFS4_SESSIONID_SIZE);
	if (!id)
		die("truncated CREATE_SESSION reply");
	memcpy(c->sessionid, id, NFS4_SESSIONID_SIZE);
	/*
	 * csr_sequence answers the CREATE_SESSION, not the session's slots:
	 * slot 0 starts its own numbering at one, so the first SEQUENCE must
	 * ask for one rather than for the next create-session id.
	 */
	gu32(&cur);
	c->seq_seqid = 0;
	print_hex("PROBE-SESSIONID", c->sessionid, NFS4_SESSIONID_SIZE);
}

static void destroy_session(struct nfs4_client *c, uint8_t *buf, size_t cap)
{
	struct xbuf x = { .b = buf, .cap = cap };
	uint8_t reply[MAX_MSG];
	struct xcur cur = { .b = reply };
	uint32_t nres;

	rpc_start(&x, c, 1);
	xu32(&x, OP_DESTROY_SESSION);
	xput(&x, c->sessionid, sizeof(c->sessionid));
	rpc_send(c, &x, "REQ-DESTROY-SESSION");
	cur.len = rpc_recv(c, reply, sizeof(reply), "REP-DESTROY-SESSION");
	rpc_reply_open(&cur, &nres);
	printf("PROBE-DESTROY-SESSION=%u\n", op_result(&cur, OP_DESTROY_SESSION));

	x.len = 0;
	rpc_start(&x, c, 1);
	xu32(&x, OP_DESTROY_CLIENTID);
	xu64(&x, c->clientid);
	rpc_send(c, &x, "REQ-DESTROY-CLIENTID");
	cur.b = reply;
	cur.off = 0;
	cur.bad = false;
	cur.len = rpc_recv(c, reply, sizeof(reply), "REP-DESTROY-CLIENTID");
	rpc_reply_open(&cur, &nres);
	printf("PROBE-DESTROY-CLIENTID=%u\n",
	       op_result(&cur, OP_DESTROY_CLIENTID));
}

/*
 * Resolve one name under the export root and read it through the ordinary
 * NFS path, so the same file is known to be reachable both ways.  The
 * filehandle GETFH returns is the one a prototype registration maps.
 */
static void lookup_ordinary(struct nfs4_client *c, const char *path,
			    uint8_t *buf, size_t cap)
{
	static const uint8_t anonymous[NFS4_STATEID_SIZE] = {};
	struct xbuf x = { .b = buf, .cap = cap };
	uint8_t reply[MAX_MSG];
	struct xcur cur = { .b = reply };
	char components[256];
	char *name, *next;
	uint32_t nres, status, lookups = 0;
	const uint8_t *data;
	size_t len;

	/*
	 * The export may sit below the NFSv4 pseudo-root, so the path is
	 * walked one component at a time from the root the server offers
	 * rather than assumed to be one name.
	 */
	snprintf(components, sizeof(components), "%s", path);
	for (name = components; *name; name++)
		if (*name == '/' && name != components && name[1])
			lookups++;
	lookups += components[0] ? 1 : 0;
	if (components[0] == '/')
		lookups--;

	rpc_start(&x, c, 4 + lookups);
	put_sequence(&x, c);
	xu32(&x, OP_PUTROOTFH);
	for (name = components; name && *name; name = next) {
		next = strchr(name, '/');
		if (next)
			*next++ = '\0';
		if (!*name)
			continue;
		xu32(&x, OP_LOOKUP);
		xopaque(&x, name, strlen(name));
	}
	xu32(&x, OP_GETFH);
	xu32(&x, OP_READ);
	xput(&x, anonymous, sizeof(anonymous));
	xu64(&x, 0);
	xu32(&x, 4096);
	rpc_send(c, &x, "REQ-ORDINARY-LOOKUP");

	cur.len = rpc_recv(c, reply, sizeof(reply), "REP-ORDINARY-LOOKUP");
	rpc_reply_open(&cur, &nres);
	status = get_sequence(&cur);
	if (status)
		die("SEQUENCE failed with NFS4ERR %u", status);
	status = op_result(&cur, OP_PUTROOTFH);
	if (status)
		die("PUTROOTFH failed with NFS4ERR %u", status);
	while (lookups--) {
		status = op_result(&cur, OP_LOOKUP);
		if (status)
			die("LOOKUP in %s failed with NFS4ERR %u", path,
			    status);
	}
	status = op_result(&cur, OP_GETFH);
	if (status)
		die("GETFH failed with NFS4ERR %u", status);
	data = gopaque(&cur, &len);
	if (!data || len > NFS4_FHSIZE)
		die("GETFH returned %zu bytes", len);
	memcpy(c->fh, data, len);
	c->fh_len = len;
	print_hex("PROBE-ORDINARY-FH", c->fh, c->fh_len);

	status = op_result(&cur, OP_READ);
	printf("PROBE-ORDINARY-READ-STATUS=%u\n", status);
	if (!status) {
		printf("PROBE-ORDINARY-READ-EOF=%u\n", gu32(&cur));
		data = gopaque(&cur, &len);
		printf("PROBE-ORDINARY-READ-LEN=%zu\n", len);
		if (data)
			hexdump("PROBE-ORDINARY-READ-DATA", data,
				len < 64 ? len : 64);
	}
	if (cur.bad)
		die("truncated ordinary lookup reply");
}

/* stateid4: a sequence id and the twelve opaque bytes that follow it. */
static void put_stateid(struct xbuf *x, const uint8_t *stateid)
{
	xput(x, stateid, NFS4_STATEID_SIZE);
}

static void put_chunk_args(struct xbuf *x, uint32_t opnum,
			   const uint8_t *stateid, uint64_t offset,
			   uint32_t count)
{
	xu32(x, opnum);
	put_stateid(x, stateid);
	xu64(x, offset);
	xu32(x, count);
}

/* chunk_owner4 */
static void get_owner(struct xcur *c, const char *label, unsigned int i)
{
	uint64_t cohort = gu64(c);
	uint32_t client = gu32(c);
	uint32_t id = gu32(c);

	printf("%s[%u]=cohort:%llu client:%u id:%u\n", label, i,
	       (unsigned long long)cohort, client, id);
}

/* chunk_guard4 */
static void get_guard(struct xcur *c, const char *label, unsigned int i)
{
	uint32_t gen = gu32(c);
	uint32_t client = gu32(c);

	printf("%s[%u]=generation:%u client:%u\n", label, i, gen, client);
}

/*
 * CHUNK_HEADER_READ4resok: five arrays that are co-indexed by contract.
 * Their lengths are printed separately precisely so a reply that disagreed
 * with itself would be visible rather than averaged away.
 */
static void decode_header_read(struct xcur *c)
{
	uint32_t counts[5];
	unsigned int i;

	printf("HDR-EOF=%u\n", gu32(c));

	counts[0] = gu32(c);
	printf("HDR-STATUS-COUNT=%u\n", counts[0]);
	for (i = 0; i < counts[0] && !c->bad; i++)
		printf("HDR-STATUS[%u]=%u\n", i, gu32(c));

	counts[1] = gu32(c);
	printf("HDR-LOCKED-COUNT=%u\n", counts[1]);
	for (i = 0; i < counts[1] && !c->bad; i++)
		printf("HDR-LOCKED[%u]=%u\n", i, gu32(c));

	counts[2] = gu32(c);
	printf("HDR-OWNER-COUNT=%u\n", counts[2]);
	for (i = 0; i < counts[2] && !c->bad; i++)
		get_owner(c, "HDR-OWNER", i);

	counts[3] = gu32(c);
	printf("HDR-GUARD-COUNT=%u\n", counts[3]);
	for (i = 0; i < counts[3] && !c->bad; i++)
		get_guard(c, "HDR-GUARD", i);

	counts[4] = gu32(c);
	printf("HDR-PREDECESSOR-COUNT=%u\n", counts[4]);
	for (i = 0; i < counts[4] && !c->bad; i++) {
		uint32_t disposition = gu32(c);

		printf("HDR-PREDECESSOR[%u]=%u\n", i, disposition);
		if (disposition != 0)
			get_owner(c, "HDR-PREDECESSOR-OWNER", i);
	}
	if (c->bad)
		die("truncated CHUNK_HEADER_READ reply");
	for (i = 1; i < 5; i++)
		if (counts[i] != counts[0])
			die("co-indexed array %u has length %u, not %u", i,
			    counts[i], counts[0]);
	printf("HDR-ARRAYS-COINDEXED=ok\n");
}

/*
 * CHUNK_READ4resok.  The payload's checksum is recomputed here rather than
 * trusted: a reply that named a length and carried different bytes would
 * otherwise pass unnoticed.
 */
static void decode_chunk_read(struct xcur *c, const uint8_t *expect,
			      size_t expect_len)
{
	uint32_t chunks;
	unsigned int i;

	printf("READ-EOF=%u\n", gu32(c));
	chunks = gu32(c);
	printf("READ-CHUNK-COUNT=%u\n", chunks);
	for (i = 0; i < chunks && !c->bad; i++) {
		const uint8_t *checksum, *payload;
		size_t checksum_len, payload_len;
		uint32_t algorithm, effective;

		algorithm = gu32(c);
		checksum = gopaque(c, &checksum_len);
		printf("READ-CHECKSUM-ALGORITHM[%u]=%u\n", i, algorithm);
		if (checksum)
			print_hex("READ-CHECKSUM", checksum, checksum_len);
		effective = gu32(c);
		printf("READ-EFFECTIVE-LEN[%u]=%u\n", i, effective);
		get_owner(c, "READ-OWNER", i);
		get_guard(c, "READ-GUARD", i);
		printf("READ-PAYLOAD-ID[%u]=%u\n", i, gu32(c));
		printf("READ-LOCKED[%u]=%u\n", i, gu32(c));
		printf("READ-STATUS[%u]=%u\n", i, gu32(c));
		payload = gopaque(c, &payload_len);
		printf("READ-PAYLOAD-LEN[%u]=%zu\n", i, payload_len);
		if (c->bad || !payload)
			break;
		hexdump("READ-PAYLOAD", payload,
			payload_len < 64 ? payload_len : 64);
		if (payload_len != effective)
			die("payload of %zu bytes under a length of %u",
			    payload_len, effective);
		if (checksum_len == sizeof(uint32_t)) {
			uint32_t claimed, computed;

			memcpy(&claimed, checksum, sizeof(claimed));
			claimed = ntohl(claimed);
			computed = crc32_zlib(payload, payload_len);
			printf("READ-CRC32-CLAIMED[%u]=%08x\n", i, claimed);
			printf("READ-CRC32-COMPUTED[%u]=%08x\n", i, computed);
			printf("READ-CRC32-MATCH[%u]=%s\n", i,
			       claimed == computed ? "yes" : "NO");
		}
		if (expect && i == 0) {
			size_t compare = payload_len < expect_len ?
					 payload_len : expect_len;

			printf("READ-CONTENT-MATCH=%s\n",
			       compare && !memcmp(payload, expect, compare) ?
			       "yes" : "NO");
		}
	}
	if (c->bad)
		die("truncated CHUNK_READ reply");
}

/*
 * One FFv2 read against one filehandle.  Every case in the matrix is this
 * shape, so the failures and the successes are produced by the same code
 * path and differ only in what they are given.
 */
static uint32_t chunk_case(struct nfs4_client *c, const char *label,
			   uint32_t opnum, const uint8_t *fh, size_t fh_len,
			   const uint8_t *stateid, uint64_t offset,
			   uint32_t count, const uint8_t *expect,
			   size_t expect_len, uint8_t *buf, size_t cap)
{
	struct xbuf x = { .b = buf, .cap = cap };
	uint8_t reply[MAX_MSG];
	struct xcur cur = { .b = reply };
	char name[64];
	uint32_t nres, status;

	rpc_start(&x, c, 3);
	put_sequence(&x, c);
	put_putfh(&x, fh, fh_len);
	put_chunk_args(&x, opnum, stateid, offset, count);
	if (opnum == OP_CHUNK_COMMIT)
		xu32(&x, 0);		/* an empty owner array */
	snprintf(name, sizeof(name), "REQ-%s", label);
	rpc_send(c, &x, name);

	snprintf(name, sizeof(name), "REP-%s", label);
	cur.len = rpc_recv(c, reply, sizeof(reply), name);
	rpc_reply_open(&cur, &nres);
	status = get_sequence(&cur);
	if (status) {
		printf("%s-SEQUENCE-STATUS=%u\n", label, status);
		return status;
	}
	status = op_result(&cur, OP_PUTFH);
	printf("%s-PUTFH-STATUS=%u\n", label, status);
	if (status)
		return status;
	status = op_result(&cur, opnum);
	printf("%s-STATUS=%u\n", label, status);
	if (status)
		return status;
	if (opnum == OP_CHUNK_HEADER_READ)
		decode_header_read(&cur);
	else if (opnum == OP_CHUNK_READ)
		decode_chunk_read(&cur, expect, expect_len);
	return status;
}

/* Hand one value to the other side of the harness. */
static void publish(const char *dir, const char *name, const char *value)
{
	char path[512];
	FILE *f;

	if (!dir)
		return;
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	f = fopen(path, "w");
	if (!f)
		die("cannot write %s: %s", path, strerror(errno));
	fprintf(f, "%s\n", value);
	fclose(f);
}

/* Wait for the other side to publish one, or give up and say so. */
static bool await(const char *dir, const char *name, unsigned int seconds)
{
	char path[512];
	unsigned int waited;
	struct stat st;

	if (!dir)
		return false;
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	for (waited = 0; waited < seconds; waited++) {
		if (!stat(path, &st))
			return true;
		sleep(1);
	}
	return false;
}

/*
 * Read one "KEY=value" line out of the registration the gate published.
 * Absent keys are an error at the call site, not here: a missing mapped
 * handle and a missing stateid are different failures.
 */
static bool registration_value(const char *dir, const char *key, char *out,
			       size_t out_size)
{
	char line[1024];
	char path[512];
	bool found = false;
	FILE *f;

	snprintf(path, sizeof(path), "%s/registration.txt", dir);
	f = fopen(path, "r");
	if (!f)
		die("cannot read %s: %s", path, strerror(errno));
	while (fgets(line, sizeof(line), f)) {
		size_t len = strlen(key);

		if (strncmp(line, key, len) || line[len] != '=')
			continue;
		snprintf(out, out_size, "%s", line + len + 1);
		out[strcspn(out, "\r\n")] = '\0';
		found = true;
		break;
	}
	fclose(f);
	return found;
}

static size_t read_expect(const char *path, uint8_t *out, size_t max)
{
	size_t len;
	FILE *f;

	if (!path)
		return 0;
	f = fopen(path, "r");
	if (!f)
		return 0;
	len = fread(out, 1, max, f);
	fclose(f);
	return len;
}

static void connect_server(struct nfs4_client *c, const char *server,
			   uint16_t port)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
	};
	uint16_t local;
	int one = 1;

	if (inet_pton(AF_INET, server, &addr.sin_addr) != 1)
		die("bad server address %s", server);
	c->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (c->fd < 0)
		die("socket: %s", strerror(errno));
	/*
	 * An ordinary export is "secure": it answers only a reserved source
	 * port.  Binding one keeps the export ordinary rather than relaxing
	 * it for the demonstrator.
	 */
	for (local = 1023; local > 512; local--) {
		struct sockaddr_in mine = {
			.sin_family = AF_INET,
			.sin_port = htons(local),
		};

		if (!bind(c->fd, (struct sockaddr *)&mine, sizeof(mine)))
			break;
	}
	if (local == 512)
		die("no reserved source port available");
	printf("PROBE-SOURCE-PORT=%u\n", local);
	if (connect(c->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		die("connect to %s:%u: %s", server, port, strerror(errno));
	setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	/*
	 * A server that never answers must not hang the harness: a bounded
	 * receive turns a silent drop into a reported one.
	 */
	{
		struct timeval tv = { .tv_sec = 60 };

		setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}
	printf("PROBE-CONNECTED=%s:%u\n", server, port);
}

static void usage(void)
{
	fprintf(stderr,
		"usage: ffv2-live-probe --server <addr> --file <path>\n"
		"                       [--port <port>] [--xchg <dir>]\n"
		"                       [--expect <file>] [--wait <seconds>]\n");
	exit(2);
}

int main(int argc, char **argv)
{
	static uint8_t request[MAX_MSG];
	struct nfs4_client c = {};
	const char *server = NULL, *file = NULL, *xchg = NULL, *expect = NULL;
	unsigned int wait_seconds = 300;
	uint8_t zero_stateid[NFS4_STATEID_SIZE] = {};
	uint8_t wrong_stateid[NFS4_STATEID_SIZE];
	uint8_t stateid[NFS4_STATEID_SIZE];
	uint8_t mapped[NFS4_FHSIZE], wrong_fh[NFS4_FHSIZE];
	uint8_t content[65536];
	size_t mapped_len, content_len;
	char value[1024];
	uint16_t port = 2049;
	int i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--server") && i + 1 < argc)
			server = argv[++i];
		else if (!strcmp(argv[i], "--file") && i + 1 < argc)
			file = argv[++i];
		else if (!strcmp(argv[i], "--port") && i + 1 < argc)
			port = (uint16_t)strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--xchg") && i + 1 < argc)
			xchg = argv[++i];
		else if (!strcmp(argv[i], "--expect") && i + 1 < argc)
			expect = argv[++i];
		else if (!strcmp(argv[i], "--wait") && i + 1 < argc)
			wait_seconds = (unsigned int)strtoul(argv[++i], NULL, 0);
		else
			usage();
	}
	if (!server || !file)
		usage();
	setvbuf(stdout, NULL, _IOLBF, 0);
	content_len = read_expect(expect, content, sizeof(content));

	connect_server(&c, server, port);
	exchange_id(&c, request, sizeof(request));
	create_session(&c, request, sizeof(request));
	lookup_ordinary(&c, file, request, sizeof(request));

	/*
	 * Case 3 runs before any registration exists as well as after it:
	 * an ordinary filehandle must never reach the provider, and the
	 * clearest way to show that is to ask it to.
	 */
	chunk_case(&c, "CASE3-ORDINARY-BEFORE", OP_CHUNK_HEADER_READ, c.fh,
		   c.fh_len, zero_stateid, 0, 1, NULL, 0, request,
		   sizeof(request));

	if (xchg) {
		char hex[2 * NFS4_FHSIZE + 1];
		size_t n;

		for (n = 0; n < c.fh_len; n++)
			snprintf(hex + 2 * n, 3, "%02x", c.fh[n]);
		publish(xchg, "ordinary-fh.hex", hex);
		printf("PROBE-PUBLISHED-FH=%s\n", hex);
	}

	if (!xchg || !await(xchg, "registration.txt", wait_seconds)) {
		printf("PROBE-REGISTRATION=absent\n");
		destroy_session(&c, request, sizeof(request));
		close(c.fd);
		return 1;
	}
	if (!registration_value(xchg, "MAPPED_HANDLE", value, sizeof(value)))
		die("registration published no mapped handle");
	mapped_len = parse_hex(value, mapped, sizeof(mapped));
	if (!registration_value(xchg, "STATEID", value, sizeof(value)))
		die("registration published no stateid");
	if (parse_hex(value, stateid, sizeof(stateid)) != sizeof(stateid))
		die("stateid must be 16 bytes");
	print_hex("PROBE-MAPPED-HANDLE", mapped, mapped_len);
	print_hex("PROBE-STATEID", stateid, sizeof(stateid));

	chunk_case(&c, "CASE1-HEADER-READ", OP_CHUNK_HEADER_READ, mapped,
		   mapped_len, stateid, 0, 1, NULL, 0, request,
		   sizeof(request));
	chunk_case(&c, "CASE2-CHUNK-READ", OP_CHUNK_READ, mapped, mapped_len,
		   stateid, 0, 1, content_len ? content : NULL, content_len,
		   request, sizeof(request));
	chunk_case(&c, "CASE3-ORDINARY-AFTER", OP_CHUNK_READ, c.fh, c.fh_len,
		   stateid, 0, 1, NULL, 0, request, sizeof(request));
	chunk_case(&c, "CASE4-EXCLUDED-COMMIT", OP_CHUNK_COMMIT, mapped,
		   mapped_len, stateid, 0, 1, NULL, 0, request,
		   sizeof(request));

	memcpy(wrong_stateid, stateid, sizeof(wrong_stateid));
	wrong_stateid[NFS4_STATEID_SIZE - 1] ^= 0xff;
	chunk_case(&c, "CASE5-WRONG-STATEID", OP_CHUNK_READ, mapped,
		   mapped_len, wrong_stateid, 0, 1, NULL, 0, request,
		   sizeof(request));

	memcpy(wrong_fh, mapped, mapped_len);
	wrong_fh[mapped_len - 1] ^= 0xff;
	chunk_case(&c, "CASE5-WRONG-HANDLE", OP_CHUNK_READ, wrong_fh,
		   mapped_len, stateid, 0, 1, NULL, 0, request,
		   sizeof(request));

	publish(xchg, "client-cases-done", "done");
	if (await(xchg, "server-retired", wait_seconds)) {
		chunk_case(&c, "CASE6-AFTER-RETIREMENT", OP_CHUNK_READ, mapped,
			   mapped_len, stateid, 0, 1, NULL, 0, request,
			   sizeof(request));
	} else {
		printf("CASE6-AFTER-RETIREMENT=unavailable\n");
	}

	destroy_session(&c, request, sizeof(request));
	close(c.fd);
	printf("PROBE-DONE\n");
	return 0;
}
