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

#define ARRAY_SIZE(a)		(sizeof(a) / sizeof((a)[0]))

#define XDR_UNIT		4
#define MAX_MSG			(1024 * 1024)

/*
 * checksum_algorithm4.  Only CRC32 is wired, and it is always four bytes;
 * a reply naming anything else is a reply this harness must refuse rather
 * than describe.
 */
#define FFV2_CHECKSUM_ALG_CRC32	1
#define FFV2_CHECKSUM_CRC32_LEN	4

/*
 * Which operation a case is entitled to end at.  A refusal the FFv2
 * dispatch produces and a refusal PUTFH produces can carry the same
 * number, and a case that accepted either would prove neither: an
 * NFS4ERR_STALE from PUTFH says the handle did not resolve, not that the
 * gate refused the operation.
 */
enum terminal_op {
	TERM_FFV2,	/* SEQUENCE and PUTFH succeed; the FFv2 op decides */
	TERM_PUTFH,	/* PUTFH itself refuses, and the FFv2 op never runs */
};

/* The statuses this matrix requires, named where they are asserted. */
#define NFS4_OK			0
#define NFS4ERR_STALE		70
#define NFS4ERR_NOTSUPP		10004
#define NFS4ERR_BAD_STATEID	10025
#define NFS4ERR_SEQ_MISORDERED	10063

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

/*
 * What a payload is required to be.  The object's bytes come from the file
 * the harness exported; the chunk the server may return is the slice of
 * them the registration's chunk size names, so the comparison is exact in
 * length as well as content.
 */
struct probe_expect {
	const uint8_t	*data;
	size_t		len;
	uint32_t	chunk_size;
	bool		requested;
};

static struct probe_expect probe_expect;

struct nfs4_client {
	int		fd;
	uint32_t	xid;
	uint64_t	clientid;
	uint32_t	seq_seqid;
	uint8_t		sessionid[NFS4_SESSIONID_SIZE];
	uint8_t		fh[NFS4_FHSIZE];
	size_t		fh_len;
};

/*
 * A case that decoded cleanly can still be wrong.  Integrity failures are
 * recorded rather than printed, so the matrix finishes and the process
 * still exits non-zero: a mismatch that only appeared in the output would
 * be evidence of nothing.
 */
static unsigned int probe_failures;

static void fail(const char *fmt, ...)
{
	va_list ap;

	probe_failures++;
	printf("PROBE-FAIL: ");
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
}

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
	size_t remaining, aligned;
	const uint8_t *p;

	if (c->bad)
		return NULL;
	/*
	 * Bounded against what is left before the length is rounded up, so
	 * the rounding cannot overflow a length that came off the wire.
	 */
	remaining = c->len - c->off;
	if (len > remaining) {
		c->bad = true;
		return NULL;
	}
	aligned = (len + XDR_UNIT - 1) & ~((size_t)XDR_UNIT - 1);
	if (aligned > remaining) {
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

/*
 * The checks every reply owes, whatever it carried: nothing truncated, the
 * results it announced are the results it produced, the compound status is
 * the status of the last of them, and nothing follows the last result.
 */
static void reply_complete(struct xcur *c, const char *label, uint32_t nres,
			   uint32_t results, uint32_t compound, uint32_t status)
{
	if (c->bad)
		fail("%s reply is truncated", label);
	if (nres != results)
		fail("%s announced %u results and carried %u", label, nres,
		     results);
	if (compound != status)
		fail("%s compound status %u disagrees with its last operation's %u",
		     label, compound, status);
	if (!c->bad && c->off != c->len)
		fail("%s reply carries %zu bytes after its last result", label,
		     c->len - c->off);
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
	uint32_t compound, nres, status;
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
	compound = rpc_reply_open(&cur, &nres);
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
	if (gu32(&cur)) {		/* eir_server_impl_id<> */
		gopaque(&cur, &len);	/* nii_domain */
		gopaque(&cur, &len);	/* nii_name */
		gu64(&cur);		/* nii_date.seconds */
		gu32(&cur);		/* nii_date.nseconds */
	}
	if (cur.bad)
		die("truncated EXCHANGE_ID reply");
	reply_complete(&cur, "EXCHANGE-ID", nres, 1, compound, status);
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

/* The seven channel attributes a CREATE_SESSION reply echoes back. */
static void get_channel_attrs(struct xcur *c)
{
	uint32_t rdma;

	gu32(c);			/* ca_headerpadsize */
	gu32(c);			/* ca_maxrequestsize */
	gu32(c);			/* ca_maxresponsesize */
	gu32(c);			/* ca_maxresponsesize_cached */
	gu32(c);			/* ca_maxoperations */
	gu32(c);			/* ca_maxrequests */
	for (rdma = gu32(c); rdma && !c->bad; rdma--)
		gu32(c);		/* ca_rdma_ird<> */
}

static void create_session(struct nfs4_client *c, uint8_t *buf, size_t cap)
{
	static const char machine[] = "ffv2-live-probe";
	struct xbuf x = { .b = buf, .cap = cap };
	uint8_t reply[MAX_MSG];
	struct xcur cur = { .b = reply };
	uint32_t compound, nres, status;
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
	compound = rpc_reply_open(&cur, &nres);
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
	gu32(&cur);			/* csr_flags */
	get_channel_attrs(&cur);	/* fore channel */
	get_channel_attrs(&cur);	/* back channel */
	if (cur.bad)
		die("truncated CREATE_SESSION reply");
	reply_complete(&cur, "CREATE-SESSION", nres, 1, compound, status);
	print_hex("PROBE-SESSIONID", c->sessionid, NFS4_SESSIONID_SIZE);
}

static void destroy_session(struct nfs4_client *c, uint8_t *buf, size_t cap)
{
	struct xbuf x = { .b = buf, .cap = cap };
	uint8_t reply[MAX_MSG];
	struct xcur cur = { .b = reply };
	uint32_t compound, nres, status;

	rpc_start(&x, c, 1);
	xu32(&x, OP_DESTROY_SESSION);
	xput(&x, c->sessionid, sizeof(c->sessionid));
	rpc_send(c, &x, "REQ-DESTROY-SESSION");
	cur.len = rpc_recv(c, reply, sizeof(reply), "REP-DESTROY-SESSION");
	compound = rpc_reply_open(&cur, &nres);
	status = op_result(&cur, OP_DESTROY_SESSION);
	printf("PROBE-DESTROY-SESSION=%u\n", status);
	reply_complete(&cur, "DESTROY-SESSION", nres, 1, compound, status);
	if (status)
		fail("DESTROY_SESSION returned NFS4ERR %u", status);

	x.len = 0;
	rpc_start(&x, c, 1);
	xu32(&x, OP_DESTROY_CLIENTID);
	xu64(&x, c->clientid);
	rpc_send(c, &x, "REQ-DESTROY-CLIENTID");
	cur.b = reply;
	cur.off = 0;
	cur.bad = false;
	cur.len = rpc_recv(c, reply, sizeof(reply), "REP-DESTROY-CLIENTID");
	compound = rpc_reply_open(&cur, &nres);
	status = op_result(&cur, OP_DESTROY_CLIENTID);
	printf("PROBE-DESTROY-CLIENTID=%u\n", status);
	reply_complete(&cur, "DESTROY-CLIENTID", nres, 1, compound, status);
	if (status)
		fail("DESTROY_CLIENTID returned NFS4ERR %u", status);
}

/*
 * Resolve one name under the export root and read it through the ordinary
 * NFS path, so the same file is known to be reachable both ways.  The
 * filehandle GETFH returns is the one a prototype registration maps.
 */
/*
 * Count the components a path names.  A leading slash is accepted and
 * ignored: the path is always relative to the root the server offers, and
 * "/export/data/x" and "export/data/x" name the same walk.  Empty
 * components are not counted, because none is emitted for them.
 */
static uint32_t count_components(const char *path)
{
	uint32_t components = 0;
	const char *p = path;

	while (*p) {
		while (*p == '/')
			p++;
		if (!*p)
			break;
		components++;
		while (*p && *p != '/')
			p++;
	}
	return components;
}

static void lookup_ordinary(struct nfs4_client *c, const char *path,
			    uint8_t *buf, size_t cap)
{
	static const uint8_t anonymous[NFS4_STATEID_SIZE] = {};
	struct xbuf x = { .b = buf, .cap = cap };
	uint8_t reply[MAX_MSG];
	struct xcur cur = { .b = reply };
	char components[256];
	char *name, *next;
	uint32_t compound, nres, status, results = 0;
	uint32_t lookups = count_components(path);
	uint32_t emitted = 0;
	const uint8_t *data;
	size_t len;

	/*
	 * The export may sit below the NFSv4 pseudo-root, so the path is
	 * walked one component at a time from the root the server offers
	 * rather than assumed to be one name.
	 */
	if (!lookups)
		die("--file names no component");
	snprintf(components, sizeof(components), "%s", path);

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
		emitted++;
	}
	if (emitted != lookups)
		die("emitted %u lookups for a path counted as %u", emitted,
		    lookups);
	xu32(&x, OP_GETFH);
	xu32(&x, OP_READ);
	xput(&x, anonymous, sizeof(anonymous));
	xu64(&x, 0);
	xu32(&x, 4096);
	rpc_send(c, &x, "REQ-ORDINARY-LOOKUP");

	cur.len = rpc_recv(c, reply, sizeof(reply), "REP-ORDINARY-LOOKUP");
	compound = rpc_reply_open(&cur, &nres);
	status = get_sequence(&cur);
	results++;
	if (status)
		die("SEQUENCE failed with NFS4ERR %u", status);
	status = op_result(&cur, OP_PUTROOTFH);
	results++;
	if (status)
		die("PUTROOTFH failed with NFS4ERR %u", status);
	while (lookups--) {
		status = op_result(&cur, OP_LOOKUP);
		results++;
		if (status)
			die("LOOKUP in %s failed with NFS4ERR %u", path,
			    status);
	}
	status = op_result(&cur, OP_GETFH);
	results++;
	if (status)
		die("GETFH failed with NFS4ERR %u", status);
	data = gopaque(&cur, &len);
	if (!data || len > NFS4_FHSIZE)
		die("GETFH returned %zu bytes", len);
	memcpy(c->fh, data, len);
	c->fh_len = len;
	print_hex("PROBE-ORDINARY-FH", c->fh, c->fh_len);

	status = op_result(&cur, OP_READ);
	results++;
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
	reply_complete(&cur, "ORDINARY-LOOKUP", nres, results, compound,
		       status);
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
static void decode_header_read(struct xcur *c, uint32_t count)
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
	if (c->bad) {
		fail("truncated CHUNK_HEADER_READ reply");
		return;
	}
	for (i = 1; i < 5; i++)
		if (counts[i] != counts[0]) {
			fail("co-indexed array %u has length %u, not %u", i,
			     counts[i], counts[0]);
			return;
		}
	printf("HDR-ARRAYS-COINDEXED=ok\n");
	/*
	 * Co-indexed arrays of the wrong length are co-indexed and useless.
	 * A successful header read must describe the chunks that were asked
	 * for; none, or more than were asked for, is not that.  Checked
	 * after every announced element has been decoded, so the
	 * trailing-byte rule still means what it says.
	 */
	if (counts[0] != count)
		fail("header read described %u chunks for a request of %u",
		     counts[0], count);
}

/*
 * The bytes chunk @index of the object must carry.  A chunk is named by its
 * index, not by a byte offset, so the bytes it covers are the chunk-sized
 * slice at index * chunk_size; only the object's last chunk is shorter.
 * The multiplication is checked, because the index comes off the wire.
 */
static size_t expected_chunk(uint64_t index, const uint8_t **bytes)
{
	uint64_t byte_off;
	size_t remaining;

	*bytes = NULL;
	if (!probe_expect.requested || !probe_expect.chunk_size)
		return 0;
	if (index > UINT64_MAX / probe_expect.chunk_size)
		return 0;
	byte_off = index * probe_expect.chunk_size;
	if (byte_off >= probe_expect.len)
		return 0;
	remaining = probe_expect.len - (size_t)byte_off;
	*bytes = probe_expect.data + byte_off;
	return remaining < probe_expect.chunk_size ? remaining :
						     probe_expect.chunk_size;
}

/*
 * CHUNK_READ4resok.  Every field a reply could get wrong is checked rather
 * than printed: the algorithm, the checksum width, the checksum itself
 * recomputed from the received bytes, the payload length against the length
 * the entry declared, and the payload against the object it claims to be a
 * chunk of.  A case that fails any of these is a failed case.
 */
static void decode_chunk_read(struct xcur *c, uint64_t offset, uint32_t count)
{
	uint32_t chunks;
	unsigned int i;

	printf("READ-EOF=%u\n", gu32(c));
	chunks = gu32(c);
	printf("READ-CHUNK-COUNT=%u\n", chunks);
	/*
	 * A successful read of a live object carries chunks.  A reply with
	 * none would be an end-of-object result, which this matrix does not
	 * ask for and which would need a case of its own to be evidence of
	 * anything.
	 */
	if (!chunks) {
		fail("successful read returned no chunk");
		return;
	}

	for (i = 0; i < chunks && !c->bad; i++) {
		const uint8_t *checksum, *payload, *want;
		size_t checksum_len, payload_len, want_len;
		uint32_t algorithm, effective, claimed, computed;

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
		if (c->bad || !payload) {
			fail("truncated CHUNK_READ reply");
			return;
		}
		hexdump("READ-PAYLOAD", payload,
			payload_len < 64 ? payload_len : 64);

		if (algorithm != FFV2_CHECKSUM_ALG_CRC32) {
			fail("chunk %u names checksum algorithm %u, not CRC32",
			     i, algorithm);
			continue;
		}
		if (checksum_len != FFV2_CHECKSUM_CRC32_LEN) {
			fail("chunk %u carries a %zu-byte CRC32", i,
			     checksum_len);
			continue;
		}
		if (payload_len != effective) {
			fail("chunk %u carries %zu bytes under a length of %u",
			     i, payload_len, effective);
			continue;
		}
		memcpy(&claimed, checksum, sizeof(claimed));
		claimed = ntohl(claimed);
		computed = crc32_zlib(payload, payload_len);
		printf("READ-CRC32-CLAIMED[%u]=%08x\n", i, claimed);
		printf("READ-CRC32-COMPUTED[%u]=%08x\n", i, computed);
		if (claimed != computed) {
			fail("chunk %u claims CRC32 %08x, its bytes give %08x",
			     i, claimed, computed);
			continue;
		}
		printf("READ-CRC32-MATCH[%u]=yes\n", i);

		if (!probe_expect.requested)
			continue;
		/*
		 * The index of this element is the requested index plus its
		 * position, and that addition is checked before it is made:
		 * a sum that wrapped would name a low index and could be
		 * compared successfully against a chunk the reply is not
		 * carrying.  expected_chunk() checks the index it is given,
		 * which is too late to catch a wrap that has happened.
		 */
		if ((uint64_t)i > UINT64_MAX - offset) {
			fail("chunk %u is at index %llu + %u, past the end of the index space",
			     i, (unsigned long long)offset, i);
			continue;
		}
		want_len = expected_chunk(offset + i, &want);
		if (payload_len != want_len) {
			fail("chunk %u carries %zu bytes, not the %zu the object holds",
			     i, payload_len, want_len);
			continue;
		}
		if (!want || memcmp(payload, want, want_len)) {
			fail("chunk %u carries bytes the object does not hold at index %llu",
			     i, (unsigned long long)(offset + i));
			continue;
		}
		printf("READ-CONTENT-MATCH[%u]=yes\n", i);
	}
	if (c->bad) {
		fail("truncated CHUNK_READ reply");
		return;
	}
	/*
	 * Judged after the whole reply has been decoded, so that a reply
	 * with the wrong number of chunks is still consumed and the
	 * trailing-byte rule keeps meaning what it says.  Every chunk the
	 * reply carried was compared above; a reply carrying fewer than were
	 * asked for leaves part of the request unevidenced, and one carrying
	 * more was never asked for at all.
	 */
	if (chunks != count)
		fail("read returned %u chunks for a request of %u", chunks,
		     count);
}

/*
 * One FFv2 read against one filehandle.  Every case in the matrix is this
 * shape, so the failures and the successes are produced by the same code
 * path and differ only in what they are given.
 *
 * A case is complete only when the compound status agrees with its last
 * operation, the reply carries exactly the results it announced, and the
 * cursor has consumed the whole record.
 */
static void chunk_case(struct nfs4_client *c, const char *label,
		       uint32_t opnum, const uint8_t *fh, size_t fh_len,
		       const uint8_t *stateid, uint64_t offset,
		       uint32_t count, enum terminal_op terminal, uint32_t want,
		       uint8_t *buf, size_t cap)
{
	struct xbuf x = { .b = buf, .cap = cap };
	uint8_t reply[MAX_MSG];
	struct xcur cur = { .b = reply };
	uint32_t compound, nres, status, results = 0;
	bool misterminated = false;
	char name[64];

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
	compound = rpc_reply_open(&cur, &nres);
	printf("%s-COMPOUND-STATUS=%u\n", label, compound);

	status = get_sequence(&cur);
	results++;
	if (status) {
		/*
		 * The session failed the request, so no case's subject ever
		 * ran.  A SEQUENCE error that happens to carry the number the
		 * case expected is still not the refusal the case is about.
		 */
		printf("%s-SEQUENCE-STATUS=%u\n", label, status);
		fail("%s stopped at SEQUENCE with NFS4ERR %u; nothing it names ran",
		     label, status);
		misterminated = true;
		goto out;
	}
	status = op_result(&cur, OP_PUTFH);
	results++;
	printf("%s-PUTFH-STATUS=%u\n", label, status);
	if (status) {
		/*
		 * The case stopped here.  That is the whole case when PUTFH
		 * is the operation under test, and a failed case otherwise:
		 * an FFv2 refusal that never reached the FFv2 operation is
		 * not an FFv2 refusal.
		 */
		if (terminal != TERM_PUTFH)
			fail("%s stopped at PUTFH with NFS4ERR %u; the %s it names never ran",
			     label, status, opnum == OP_CHUNK_READ ?
			     "CHUNK_READ" : "operation");
		goto out;
	}
	if (terminal == TERM_PUTFH) {
		/*
		 * The handle resolved where the case required it to be
		 * refused.  Reported once, and the rest of the reply is still
		 * decoded, because a check that stops reading turns one
		 * defect into a report of three.
		 */
		fail("%s expected PUTFH to refuse the handle and it resolved",
		     label);
		misterminated = true;
	}
	status = op_result(&cur, opnum);
	results++;
	printf("%s-STATUS=%u\n", label, status);
	if (status)
		goto out;
	if (opnum == OP_CHUNK_HEADER_READ)
		decode_header_read(&cur, count);
	else if (opnum == OP_CHUNK_READ)
		decode_chunk_read(&cur, offset, count);
out:
	/*
	 * A compound that stopped early announces only the results it
	 * produced, and its status is that of the operation that stopped it.
	 */
	reply_complete(&cur, label, nres, results, compound, status);
	/*
	 * A case ends at the operation it names, and carries the results
	 * that reaching it requires: three for one the FFv2 operation
	 * decides, two for one PUTFH refuses.
	 */
	if (!misterminated) {
		uint32_t expected = terminal == TERM_PUTFH ? 2 : 3;

		if (results != expected)
			fail("%s carried %u results, expected %u for a case ending at %s",
			     label, results, expected,
			     terminal == TERM_PUTFH ? "PUTFH" :
						      "its FFv2 operation");
	}
	/*
	 * The status the case exists to produce.  A refusal that stopped
	 * refusing, or a read that stopped succeeding, is a failed case even
	 * when the reply is well formed.
	 */
	if (!misterminated && status != want)
		fail("%s ended with NFS4ERR %u, expected %u", label, status,
		     want);
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

/*
 * The registration, read once.  Opening the file per key would let a
 * registration replaced between two opens hand back one run's token with
 * another run's handle and stateid, which is the race the token exists to
 * rule out.  Everything the probe consumes therefore comes from one
 * snapshot of one complete file.
 */
struct bundle {
	char	text[4096];
	size_t	len;
};

static bool bundle_read(const char *dir, struct bundle *b)
{
	char path[512];
	FILE *f;

	snprintf(path, sizeof(path), "%s/registration.txt", dir);
	f = fopen(path, "r");
	if (!f)
		return false;
	b->len = fread(b->text, 1, sizeof(b->text) - 1, f);
	if (ferror(f) || !feof(f)) {
		fclose(f);
		return false;
	}
	fclose(f);
	b->text[b->len] = '\0';
	return b->len != 0;
}

/*
 * The keys a bundle may carry.  An unknown key is a bundle this probe does
 * not understand, and a repeated one is a bundle that says two things; both
 * are refused rather than resolved by taking the first.
 */
static const char * const bundle_keys[] = {
	"RUN", "MAPPED_HANDLE", "STATEID", "SOURCE_UUID", "GENERATION",
	"CHUNK_SIZE",
};

/*
 * Which key a line names, or -1 for none of them.  The length is compared
 * before the bytes, so a key longer than any this client knows is refused
 * by its length and nothing is read past the end of a literal to find that
 * out.
 */
static int bundle_key_index(const char *key, size_t len)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(bundle_keys); i++)
		if (strlen(bundle_keys[i]) == len &&
		    !memcmp(key, bundle_keys[i], len))
			return (int)i;
	return -1;
}

/*
 * Check the snapshot before anything reads a value out of it.
 *
 * The grammar is the one the control tool writes and nothing wider: a
 * whole number of "KNOWN_KEY=value\n" records, each key known, each key
 * once, each value non-empty, and every key this client knows present.
 * The writer emits all of them and renames the file into place afterwards,
 * so a snapshot missing a record or a final newline is a snapshot that was
 * not written by a registration that finished, and is refused rather than
 * read.  No key is conditional; a field that ever becomes optional has to
 * say so here.
 */
static bool bundle_well_formed(const struct bundle *b, const char **why)
{
	unsigned int seen[ARRAY_SIZE(bundle_keys)] = {};
	const char *p = b->text;
	size_t i;

	while (*p) {
		const char *eol = strchr(p, '\n');
		const char *eq;
		size_t line, klen;
		int key;

		if (!eol) {
			*why = "the bundle's last line is not terminated";
			return false;
		}
		line = (size_t)(eol - p);
		if (!line) {
			*why = "a bundle line is empty";
			return false;
		}
		eq = memchr(p, '=', line);
		if (!eq) {
			*why = "a bundle line has no value";
			return false;
		}
		klen = (size_t)(eq - p);
		if (!klen || (size_t)(eol - eq) < 2) {
			*why = "a bundle line has an empty key or value";
			return false;
		}
		key = bundle_key_index(p, klen);
		if (key < 0) {
			*why = "the bundle carries a key this client does not know";
			return false;
		}
		if (seen[key]++) {
			*why = "the bundle carries a key twice";
			return false;
		}
		p = eol + 1;
	}
	for (i = 0; i < ARRAY_SIZE(bundle_keys); i++)
		if (!seen[i]) {
			*why = "the bundle is missing a key this client requires";
			return false;
		}
	return true;
}

/*
 * One "KEY=value" line out of the snapshot.  Terminated records only, for
 * the same reason the grammar above requires them: this also runs before
 * the grammar has been checked, when a directory is being watched for this
 * run's registration to appear in it.
 */
static bool bundle_value(const struct bundle *b, const char *key, char *out,
			 size_t out_size)
{
	const char *p = b->text;
	size_t klen = strlen(key);

	while (*p) {
		const char *eol = strchr(p, '\n');
		size_t line;

		if (!eol)
			break;
		line = (size_t)(eol - p);
		if (line > klen && !strncmp(p, key, klen) && p[klen] == '=') {
			size_t vlen = line - klen - 1;

			if (vlen >= out_size)
				return false;
			memcpy(out, p + klen + 1, vlen);
			out[vlen] = '\0';
			out[strcspn(out, "\r")] = '\0';
			return true;
		}
		p = eol + 1;
	}
	return false;
}

static bool bundle_is_mine(const struct bundle *b, const char *run)
{
	char value[256];

	return bundle_value(b, "RUN", value, sizeof(value)) &&
	       !strcmp(value, run);
}

/* Wait for this run's registration to appear, or give up and say so. */
static bool await_registration(const char *dir, const char *run,
			       struct bundle *b, unsigned int seconds)
{
	unsigned int waited;

	for (waited = 0; waited < seconds; waited++) {
		if (bundle_read(dir, b) && bundle_is_mine(b, run))
			return true;
		sleep(1);
	}
	return false;
}

/*
 * Wait for a marker this run wrote.  The marker carries the run token for
 * the same reason the bundle does: a marker left by an earlier run in a
 * reused directory would otherwise say that this run's server retired
 * something.
 */
static bool await_marker(const char *dir, const char *name, const char *run,
			 unsigned int seconds)
{
	char line[256];
	char path[512];
	unsigned int waited;

	if (!dir)
		return false;
	snprintf(path, sizeof(path), "%s/%s", dir, name);
	for (waited = 0; waited < seconds; waited++) {
		FILE *f = fopen(path, "r");

		if (f) {
			bool mine = fgets(line, sizeof(line), f);

			fclose(f);
			if (mine) {
				line[strcspn(line, "\r\n")] = '\0';
				if (!strcmp(line, run))
					return true;
			}
		}
		sleep(1);
	}
	return false;
}

static size_t read_expect(const char *path, uint8_t *out, size_t max)
{
	size_t len;
	FILE *f;

	f = fopen(path, "r");
	if (!f)
		die("cannot read expected content %s: %s", path,
		    strerror(errno));
	len = fread(out, 1, max, f);
	if (ferror(f))
		die("error reading expected content %s", path);
	if (!feof(f) && len == max)
		die("expected content %s is larger than %zu bytes", path, max);
	fclose(f);
	if (!len)
		die("expected content %s is empty", path);
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
		"                       [--expect <file>] [--wait <seconds>]\n"
		"                       [--read-count <chunks>]\n"
		"                       [--read-index <index>] [--interleave]\n"
		"                       [--no-retirement] [--mutate-ordinary]\n"
		"                       [--mutate-sequence]\n");
	exit(2);
}

int main(int argc, char **argv)
{
	static uint8_t request[MAX_MSG];
	static struct bundle bundle;
	struct nfs4_client c = {};
	const char *why = NULL;
	const char *server = NULL, *file = NULL, *xchg = NULL, *expect = NULL;
	unsigned int wait_seconds = 300;
	uint8_t zero_stateid[NFS4_STATEID_SIZE] = {};
	uint8_t wrong_stateid[NFS4_STATEID_SIZE];
	uint8_t stateid[NFS4_STATEID_SIZE];
	uint8_t mapped[NFS4_FHSIZE], wrong_fh[NFS4_FHSIZE];
	static uint8_t content[1024 * 1024];
	size_t mapped_len;
	char value[1024];
	char run[64];
	bool interleave = false, retirement = true, mutate_ordinary = false;
	bool mutate_sequence = false;
	uint32_t read_count = 1;
	uint64_t read_index = 0;
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
		else if (!strcmp(argv[i], "--read-count") && i + 1 < argc)
			read_count = (uint32_t)strtoul(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--read-index") && i + 1 < argc)
			read_index = (uint64_t)strtoull(argv[++i], NULL, 0);
		else if (!strcmp(argv[i], "--interleave"))
			interleave = true;
		else if (!strcmp(argv[i], "--no-retirement"))
			retirement = false;
		else if (!strcmp(argv[i], "--mutate-ordinary"))
			mutate_ordinary = true;
		else if (!strcmp(argv[i], "--mutate-sequence"))
			mutate_sequence = true;
		else
			usage();
	}
	if (!server || !file || !read_count)
		usage();
	setvbuf(stdout, NULL, _IOLBF, 0);
	snprintf(run, sizeof(run), "%u-%llu", (unsigned int)getpid(),
		 (unsigned long long)time(NULL));
	if (expect) {
		probe_expect.data = content;
		probe_expect.len = read_expect(expect, content,
					       sizeof(content));
		probe_expect.requested = true;
		printf("PROBE-EXPECT-LEN=%zu\n", probe_expect.len);
	} else {
		printf("PROBE-EXPECT=not-requested\n");
	}
	printf("PROBE-READ-INDEX=%llu\n", (unsigned long long)read_index);

	connect_server(&c, server, port);
	exchange_id(&c, request, sizeof(request));
	create_session(&c, request, sizeof(request));
	lookup_ordinary(&c, file, request, sizeof(request));

	if (xchg) {
		char handoff[2 * NFS4_FHSIZE + sizeof(run) + 16];
		char hex[2 * NFS4_FHSIZE + 1];
		size_t n;

		for (n = 0; n < c.fh_len; n++)
			snprintf(hex + 2 * n, 3, "%02x", c.fh[n]);
		snprintf(handoff, sizeof(handoff), "RUN=%s\nFH=%s", run, hex);
		publish(xchg, "ordinary-fh.hex", handoff);
		printf("PROBE-PUBLISHED-FH=%s\n", hex);
		printf("PROBE-RUN=%s\n", run);
	}

	/*
	 * A control run mutates the ordinary handle so that PUTFH refuses it
	 * with the same status the FFv2 operation would have produced.  The
	 * case must fail then, because a refusal that never reached the FFv2
	 * operation is not the refusal the case is about.
	 */
	if (mutate_ordinary && c.fh_len) {
		c.fh[c.fh_len - 1] ^= 0xff;
		printf("PROBE-ORDINARY-MUTATED=yes\n");
	}
	/*
	 * Case 3 runs before any registration exists as well as after it:
	 * an ordinary filehandle must never reach the provider, and the
	 * clearest way to show that is to ask it to.
	 *
	 * A control run skips the slot's sequence id so the session refuses
	 * the request, and asks this case to expect that refusal's number.
	 * The case must still fail: an error from SEQUENCE means nothing the
	 * case names ever ran, whatever number it carries.
	 */
	if (mutate_sequence) {
		c.seq_seqid += 7;
		printf("PROBE-SEQUENCE-MUTATED=yes\n");
		chunk_case(&c, "CASE3-ORDINARY-BEFORE", OP_CHUNK_HEADER_READ,
			   c.fh, c.fh_len, zero_stateid, 0, 1, TERM_FFV2,
			   NFS4ERR_SEQ_MISORDERED, request, sizeof(request));
		printf("PROBE-FAILURES=%u\n", probe_failures);
		printf("PROBE-DONE\n");
		return probe_failures ? 1 : 0;
	}
	chunk_case(&c, "CASE3-ORDINARY-BEFORE", OP_CHUNK_HEADER_READ, c.fh,
		   c.fh_len, zero_stateid, 0, 1, TERM_FFV2, NFS4ERR_STALE,
		   request, sizeof(request));

	if (!xchg || !await_registration(xchg, run, &bundle, wait_seconds)) {
		printf("PROBE-REGISTRATION=absent\n");
		destroy_session(&c, request, sizeof(request));
		close(c.fd);
		printf("PROBE-FAILURES=%u\n", probe_failures + 1);
		return 1;
	}
	if (!bundle_well_formed(&bundle, &why))
		die("registration is malformed: %s", why);
	if (!bundle_value(&bundle, "MAPPED_HANDLE", value, sizeof(value)))
		die("registration published no mapped handle");
	mapped_len = parse_hex(value, mapped, sizeof(mapped));
	/*
	 * A filehandle is at least one byte and at most NFS4_FHSIZE.  This
	 * is checked before the handle is copied or indexed, because the
	 * mutation the wrong-handle case makes would otherwise index behind
	 * an empty one.
	 */
	if (!mapped_len || mapped_len > NFS4_FHSIZE)
		die("registration published a %zu-byte mapped handle",
		    mapped_len);
	/*
	 * The bundle must belong to this run.  A directory that still holds
	 * an earlier run's registration would otherwise answer immediately
	 * with a stateid and a handle that name nothing this client asked
	 * for.
	 */
	if (!bundle_value(&bundle, "RUN", value, sizeof(value)))
		die("registration published no run token");
	if (strcmp(value, run))
		die("registration belongs to run %s, not %s", value, run);
	if (!bundle_value(&bundle, "STATEID", value, sizeof(value)))
		die("registration published no stateid");
	if (parse_hex(value, stateid, sizeof(stateid)) != sizeof(stateid))
		die("stateid must be 16 bytes");
	/*
	 * A chunk is the slice of the object the registration's chunk size
	 * names, so the payload comparison cannot be made without it.
	 */
	if (probe_expect.requested) {
		if (!bundle_value(&bundle, "CHUNK_SIZE", value,
				  sizeof(value)))
			die("registration published no chunk size");
		probe_expect.chunk_size = (uint32_t)strtoul(value, NULL, 0);
		if (!probe_expect.chunk_size)
			die("registration published a zero chunk size");
		printf("PROBE-CHUNK-SIZE=%u\n", probe_expect.chunk_size);
	}
	print_hex("PROBE-MAPPED-HANDLE", mapped, mapped_len);
	print_hex("PROBE-STATEID", stateid, sizeof(stateid));

	/*
	 * The index is a knob for the same reason the count is: a control
	 * run asks for a chunk index the object cannot have, and a reply
	 * that satisfied such a request would be a reply this client must
	 * refuse rather than compare.  The matrix leaves it at zero.
	 */
	chunk_case(&c, "CASE1-HEADER-READ", OP_CHUNK_HEADER_READ, mapped,
		   mapped_len, stateid, read_index, read_count, TERM_FFV2,
		   NFS4_OK, request, sizeof(request));
	/*
	 * The interleaving harness retires the registration while that read
	 * is held inside the server, so every later case would meet a
	 * retired mapping.  Those cases belong to the matrix run, not to
	 * this one, and asking for them here would be asking the server for
	 * a refusal and calling it a matrix.
	 */
	if (interleave)
		goto retired;
	/*
	 * The contract asks for one chunk.  The count is a knob so that a
	 * control run can ask for more than the object holds and see the
	 * "every requested chunk was compared" rule refuse the reply.
	 */
	chunk_case(&c, "CASE2-CHUNK-READ", OP_CHUNK_READ, mapped, mapped_len,
		   stateid, read_index, read_count, TERM_FFV2, NFS4_OK,
		   request, sizeof(request));
	chunk_case(&c, "CASE3-ORDINARY-AFTER-PUTFH", OP_CHUNK_READ, c.fh,
		   c.fh_len, stateid, 0, 1, TERM_PUTFH, NFS4ERR_STALE,
		   request, sizeof(request));
	chunk_case(&c, "CASE4-EXCLUDED-COMMIT", OP_CHUNK_COMMIT, mapped,
		   mapped_len, stateid, 0, 1, TERM_FFV2, NFS4ERR_NOTSUPP,
		   request, sizeof(request));

	memcpy(wrong_stateid, stateid, sizeof(wrong_stateid));
	wrong_stateid[NFS4_STATEID_SIZE - 1] ^= 0xff;
	chunk_case(&c, "CASE5-WRONG-STATEID", OP_CHUNK_READ, mapped,
		   mapped_len, wrong_stateid, 0, 1, TERM_FFV2,
		   NFS4ERR_BAD_STATEID, request, sizeof(request));

	memcpy(wrong_fh, mapped, mapped_len);
	wrong_fh[mapped_len - 1] ^= 0xff;
	chunk_case(&c, "CASE5-WRONG-HANDLE-PUTFH", OP_CHUNK_READ, wrong_fh,
		   mapped_len, stateid, 0, 1, TERM_PUTFH, NFS4ERR_STALE,
		   request, sizeof(request));

retired:
	publish(xchg, "client-cases-done", run);
	if (await_marker(xchg, "server-retired", run, wait_seconds)) {
		chunk_case(&c, "CASE6-AFTER-RETIREMENT-PUTFH", OP_CHUNK_READ, mapped,
			   mapped_len, stateid, 0, 1, TERM_PUTFH,
			   NFS4ERR_STALE, request, sizeof(request));
	} else if (retirement) {
		/*
		 * The run said retirement would happen, so its absence is a
		 * missing case rather than an absent one: the reads are only
		 * half the claim if nothing is ever taken away again.
		 */
		fail("no retirement marker for this run arrived");
	} else {
		printf("CASE6-AFTER-RETIREMENT=not-requested\n");
	}

	destroy_session(&c, request, sizeof(request));
	close(c.fd);
	printf("PROBE-FAILURES=%u\n", probe_failures);
	printf("PROBE-DONE\n");
	return probe_failures ? 1 : 0;
}
