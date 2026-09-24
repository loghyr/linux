// SPDX-License-Identifier: GPL-2.0-only
#include <linux/crc32.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <linux/vmalloc.h>
#include <crypto/sha2.h>

#include "ffv2.h"
#include "ffv2_store.h"

#define FFV2_SUPER_MAGIC	0x44325342
#define FFV2_WAL_MAGIC		0x4432574c
#define FFV2_PAYLOAD_MAGIC	0x44325059

static const char ffv2_super_domain[] = "FFV2-D2-SB-v1";
static const char ffv2_wal_domain[] = "FFV2-D2-WAL-v1";
static const char ffv2_payload_domain[] = "FFV2-D2-PAY-v1";
static const char ffv2_token_domain[] = "FFV2-D2-TOKEN-v1";

struct ffv2_cursor {
	u8 *data;
	size_t capacity;
	size_t offset;
	bool failed;
};

static void ffv2_put_bytes(struct ffv2_cursor *cursor, const void *value,
			   size_t len)
{
	if (cursor->failed || len > cursor->capacity - cursor->offset) {
		cursor->failed = true;
		return;
	}
	memcpy(cursor->data + cursor->offset, value, len);
	cursor->offset += len;
}

static void ffv2_put_u8(struct ffv2_cursor *cursor, u8 value)
{
	ffv2_put_bytes(cursor, &value, sizeof(value));
}

static void ffv2_put_u16(struct ffv2_cursor *cursor, u16 value)
{
	__be16 encoded = cpu_to_be16(value);

	ffv2_put_bytes(cursor, &encoded, sizeof(encoded));
}

static void ffv2_put_u32(struct ffv2_cursor *cursor, u32 value)
{
	__be32 encoded = cpu_to_be32(value);

	ffv2_put_bytes(cursor, &encoded, sizeof(encoded));
}

static void ffv2_put_u64(struct ffv2_cursor *cursor, u64 value)
{
	__be64 encoded = cpu_to_be64(value);

	ffv2_put_bytes(cursor, &encoded, sizeof(encoded));
}

static void ffv2_get_bytes(struct ffv2_cursor *cursor, void *value, size_t len)
{
	if (cursor->failed || len > cursor->capacity - cursor->offset) {
		cursor->failed = true;
		return;
	}
	memcpy(value, cursor->data + cursor->offset, len);
	cursor->offset += len;
}

static u8 ffv2_get_u8(struct ffv2_cursor *cursor)
{
	u8 value = 0;

	ffv2_get_bytes(cursor, &value, sizeof(value));
	return value;
}

static u16 ffv2_get_u16(struct ffv2_cursor *cursor)
{
	__be16 encoded = 0;

	ffv2_get_bytes(cursor, &encoded, sizeof(encoded));
	return be16_to_cpu(encoded);
}

static u32 ffv2_get_u32(struct ffv2_cursor *cursor)
{
	__be32 encoded = 0;

	ffv2_get_bytes(cursor, &encoded, sizeof(encoded));
	return be32_to_cpu(encoded);
}

static u64 ffv2_get_u64(struct ffv2_cursor *cursor)
{
	__be64 encoded = 0;

	ffv2_get_bytes(cursor, &encoded, sizeof(encoded));
	return be64_to_cpu(encoded);
}

static bool ffv2_all_zero(const u8 *data, size_t len)
{
	while (len--)
		if (*data++)
			return false;
	return true;
}

static bool ffv2_uuid_matches(const u8 *value, const u8 *expected)
{
	return !expected || !memcmp(value, expected, NFSD_FFV2_STORE_UUID_SIZE);
}

static u32 ffv2_crc(const char *domain, const u8 *data, size_t len)
{
	u32 crc = crc32c(~0, domain, strlen(domain));

	return ~crc32c(crc, data, len);
}

static void ffv2_put_common(struct ffv2_cursor *cursor, u32 magic, u16 type,
			    u32 header_size, u32 total_size,
			    const u8 store_uuid[NFSD_FFV2_STORE_UUID_SIZE])
{
	ffv2_put_u32(cursor, magic);
	ffv2_put_u16(cursor, NFSD_FFV2_FORMAT_VERSION);
	ffv2_put_u16(cursor, type);
	ffv2_put_u32(cursor, header_size);
	ffv2_put_u32(cursor, total_size);
	ffv2_put_u32(cursor, ~total_size);
	ffv2_put_bytes(cursor, store_uuid, NFSD_FFV2_STORE_UUID_SIZE);
}

static int ffv2_get_common(struct ffv2_cursor *cursor, u32 magic, u16 type,
			   u32 header_size, u32 total_size,
			   const u8 *expected_store, u8 *store_uuid)
{
	u32 got_magic = ffv2_get_u32(cursor);
	u16 version = ffv2_get_u16(cursor);
	u16 got_type = ffv2_get_u16(cursor);
	u32 got_header = ffv2_get_u32(cursor);
	u32 got_total = ffv2_get_u32(cursor);
	u32 complement = ffv2_get_u32(cursor);

	ffv2_get_bytes(cursor, store_uuid, NFSD_FFV2_STORE_UUID_SIZE);
	if (cursor->failed || got_magic != magic ||
	    version != NFSD_FFV2_FORMAT_VERSION || got_type != type ||
	    got_header != header_size || got_total != total_size ||
	    (got_total ^ complement) != U32_MAX ||
	    !ffv2_uuid_matches(store_uuid, expected_store))
		return -EBADMSG;
	return 0;
}

static void ffv2_put_crc(struct ffv2_cursor *cursor, const char *domain,
			 const u8 *data, size_t covered)
{
	ffv2_put_u32(cursor, ffv2_crc(domain, data, covered));
}

static bool ffv2_crc_valid(const char *domain, const u8 *data, size_t total)
{
	return total >= sizeof(__be32) &&
	       get_unaligned_be32(data + total - sizeof(__be32)) ==
		       ffv2_crc(domain, data, total - sizeof(__be32));
}

int nfsd_ffv2_super_encode(const struct nfsd_ffv2_super_record *record,
			   u8 out[NFSD_FFV2_SUPER_SLOT_SIZE])
{
	struct ffv2_cursor cursor = {
		.data = out,
		.capacity = NFSD_FFV2_SUPER_RECORD_SIZE,
	};

	if (!record || !out ||
	    record->root_handle_len > NFSD_FFV2_STORE_HANDLE_SIZE ||
	    record->state < NFSD_FFV2_SUPER_CLEAN ||
	    record->state > NFSD_FFV2_SUPER_RETIRED ||
	    record->format_floor > NFSD_FFV2_FORMAT_VERSION)
		return -EINVAL;
	memset(out, 0, NFSD_FFV2_SUPER_SLOT_SIZE);
	ffv2_put_common(&cursor, FFV2_SUPER_MAGIC, NFSD_FFV2_SUPER_SLOT,
			NFSD_FFV2_PROLOGUE_SIZE, NFSD_FFV2_SUPER_RECORD_SIZE,
			record->store_uuid);
	ffv2_put_u64(&cursor, record->generation);
	ffv2_put_bytes(&cursor, record->fs_uuid, sizeof(record->fs_uuid));
	ffv2_put_u64(&cursor, record->fs_dev_hint);
	ffv2_put_u16(&cursor, record->root_handle_type);
	ffv2_put_u16(&cursor, record->root_handle_len);
	ffv2_put_bytes(&cursor, record->root_handle, sizeof(record->root_handle));
	ffv2_put_bytes(&cursor, record->export_uuid, sizeof(record->export_uuid));
	ffv2_put_u64(&cursor, record->ds_incarnation);
	ffv2_put_u64(&cursor, record->verifier_epoch);
	ffv2_put_bytes(&cursor, record->write_verifier,
		       sizeof(record->write_verifier));
	ffv2_put_bytes(&cursor, record->wal_uuid, sizeof(record->wal_uuid));
	ffv2_put_bytes(&cursor, record->payload_uuid,
		       sizeof(record->payload_uuid));
	ffv2_put_bytes(&cursor, record->binding_token_digest,
		       sizeof(record->binding_token_digest));
	ffv2_put_u64(&cursor, record->wal_durable_lsn);
	ffv2_put_u64(&cursor, record->wal_durable_bytes);
	ffv2_put_u64(&cursor, record->payload_durable_bytes);
	ffv2_put_u64(&cursor, record->capacity_wal_bytes);
	ffv2_put_u64(&cursor, record->capacity_payload_bytes);
	ffv2_put_u32(&cursor, record->state);
	ffv2_put_u32(&cursor, record->format_floor);
	ffv2_put_u32(&cursor, 0);
	if (cursor.failed || cursor.offset != NFSD_FFV2_SUPER_RECORD_SIZE - 4)
		return -EOVERFLOW;
	ffv2_put_crc(&cursor, ffv2_super_domain, out, cursor.offset);
	return cursor.failed ? -EOVERFLOW : 0;
}

int nfsd_ffv2_super_decode(const u8 in[NFSD_FFV2_SUPER_SLOT_SIZE],
			   const u8 *expected_store,
			   struct nfsd_ffv2_super_record *record)
{
	struct ffv2_cursor cursor = {
		.data = (u8 *)in,
		.capacity = NFSD_FFV2_SUPER_RECORD_SIZE - 4,
	};
	u32 reserved;
	int error;

	if (!in || !record ||
	    !ffv2_crc_valid(ffv2_super_domain, in,
			    NFSD_FFV2_SUPER_RECORD_SIZE) ||
	    !ffv2_all_zero(in + NFSD_FFV2_SUPER_RECORD_SIZE,
			   NFSD_FFV2_SUPER_SLOT_SIZE -
				   NFSD_FFV2_SUPER_RECORD_SIZE))
		return -EBADMSG;
	memset(record, 0, sizeof(*record));
	error = ffv2_get_common(&cursor, FFV2_SUPER_MAGIC,
				NFSD_FFV2_SUPER_SLOT, NFSD_FFV2_PROLOGUE_SIZE,
				NFSD_FFV2_SUPER_RECORD_SIZE, expected_store,
				record->store_uuid);
	if (error)
		return error;
	record->generation = ffv2_get_u64(&cursor);
	ffv2_get_bytes(&cursor, record->fs_uuid, sizeof(record->fs_uuid));
	record->fs_dev_hint = ffv2_get_u64(&cursor);
	record->root_handle_type = ffv2_get_u16(&cursor);
	record->root_handle_len = ffv2_get_u16(&cursor);
	ffv2_get_bytes(&cursor, record->root_handle, sizeof(record->root_handle));
	ffv2_get_bytes(&cursor, record->export_uuid, sizeof(record->export_uuid));
	record->ds_incarnation = ffv2_get_u64(&cursor);
	record->verifier_epoch = ffv2_get_u64(&cursor);
	ffv2_get_bytes(&cursor, record->write_verifier,
		       sizeof(record->write_verifier));
	ffv2_get_bytes(&cursor, record->wal_uuid, sizeof(record->wal_uuid));
	ffv2_get_bytes(&cursor, record->payload_uuid,
		       sizeof(record->payload_uuid));
	ffv2_get_bytes(&cursor, record->binding_token_digest,
		       sizeof(record->binding_token_digest));
	record->wal_durable_lsn = ffv2_get_u64(&cursor);
	record->wal_durable_bytes = ffv2_get_u64(&cursor);
	record->payload_durable_bytes = ffv2_get_u64(&cursor);
	record->capacity_wal_bytes = ffv2_get_u64(&cursor);
	record->capacity_payload_bytes = ffv2_get_u64(&cursor);
	record->state = ffv2_get_u32(&cursor);
	record->format_floor = ffv2_get_u32(&cursor);
	reserved = ffv2_get_u32(&cursor);
	if (cursor.failed || cursor.offset != cursor.capacity || reserved ||
	    !record->generation ||
	    record->root_handle_len > NFSD_FFV2_STORE_HANDLE_SIZE ||
	    !ffv2_all_zero(record->root_handle + record->root_handle_len,
			   NFSD_FFV2_STORE_HANDLE_SIZE -
				   record->root_handle_len) ||
	    record->state < NFSD_FFV2_SUPER_CLEAN ||
	    record->state > NFSD_FFV2_SUPER_RETIRED ||
	    record->format_floor != NFSD_FFV2_FORMAT_VERSION ||
	    record->ds_incarnation > NFSD_FFV2_MAX_INCARNATION ||
	    record->wal_durable_bytes > record->capacity_wal_bytes ||
	    record->payload_durable_bytes > record->capacity_payload_bytes ||
	    record->capacity_wal_bytes < NFSD_FFV2_MIN_WAL_SIZE ||
	    record->capacity_payload_bytes < 2 * NFSD_FFV2_PAYLOAD_ALIGN ||
	    !IS_ALIGNED(record->capacity_payload_bytes,
			NFSD_FFV2_PAYLOAD_ALIGN))
		return -EBADMSG;
	return 0;
}

static void ffv2_put_wal_header(struct ffv2_cursor *cursor,
				const struct nfsd_ffv2_wal_header *header,
				u32 total_size)
{
	ffv2_put_common(cursor, FFV2_WAL_MAGIC, header->family,
			NFSD_FFV2_WAL_HEADER_SIZE, total_size,
			header->store_uuid);
	ffv2_put_bytes(cursor, header->wal_uuid, sizeof(header->wal_uuid));
	ffv2_put_u64(cursor, header->lsn);
	ffv2_put_u64(cursor, header->ds_incarnation);
	ffv2_put_u32(cursor, 0);
}

static int ffv2_get_wal_header(struct ffv2_cursor *cursor, size_t len,
			       const u8 *expected_store,
			       const u8 *expected_wal,
			       struct nfsd_ffv2_wal_header *header)
{
	u32 magic = ffv2_get_u32(cursor);
	u16 version = ffv2_get_u16(cursor);
	u16 family = ffv2_get_u16(cursor);
	u32 header_size = ffv2_get_u32(cursor);
	u32 total_size = ffv2_get_u32(cursor);
	u32 complement = ffv2_get_u32(cursor);
	u32 reserved;

	ffv2_get_bytes(cursor, header->store_uuid, sizeof(header->store_uuid));
	ffv2_get_bytes(cursor, header->wal_uuid, sizeof(header->wal_uuid));
	header->lsn = ffv2_get_u64(cursor);
	header->ds_incarnation = ffv2_get_u64(cursor);
	reserved = ffv2_get_u32(cursor);
	if (cursor->failed || magic != FFV2_WAL_MAGIC ||
	    version != NFSD_FFV2_FORMAT_VERSION || family < 1 || family > 4 ||
	    header_size != NFSD_FFV2_WAL_HEADER_SIZE ||
	    total_size < NFSD_FFV2_WAL_HEADER_SIZE + 4 ||
	    total_size > NFSD_FFV2_MAX_WAL_RECORD_SIZE || total_size > len ||
	    (total_size ^ complement) != U32_MAX || reserved ||
	    !ffv2_uuid_matches(header->store_uuid, expected_store) ||
	    !ffv2_uuid_matches(header->wal_uuid, expected_wal) || !header->lsn ||
	    !header->ds_incarnation ||
	    header->ds_incarnation > NFSD_FFV2_MAX_INCARNATION)
		return -EBADMSG;
	header->family = family;
	header->total_bytes = total_size;
	return 0;
}

static bool
ffv2_recovery_decision_valid(const struct nfsd_ffv2_start_record *record)
{
	u32 decision = record->recovery_decision;
	u32 scan = decision & (NFSD_FFV2_RECOVERY_CLEAN_SCAN |
			       NFSD_FFV2_RECOVERY_TRUNCATED_TAIL |
			       NFSD_FFV2_RECOVERY_DISCARDED_UNSTABLE);
	u32 known = NFSD_FFV2_RECOVERY_FIRST_PROVISION |
		    NFSD_FFV2_RECOVERY_CLEAN_SCAN |
		    NFSD_FFV2_RECOVERY_TRUNCATED_TAIL |
		    NFSD_FFV2_RECOVERY_DISCARDED_UNSTABLE |
		    NFSD_FFV2_RECOVERY_ADMIN_CLEARED_FENCE |
		    NFSD_FFV2_RECOVERY_TRUNCATED_NONZERO_TAIL;

	if (decision & ~known)
		return false;
	if (decision & NFSD_FFV2_RECOVERY_FIRST_PROVISION)
		return decision == NFSD_FFV2_RECOVERY_FIRST_PROVISION &&
		       !record->prev_incarnation && !record->last_valid_lsn_before &&
		       !record->truncated_bytes;
	if (!scan ||
	    ((decision & NFSD_FFV2_RECOVERY_CLEAN_SCAN) &&
	     (decision & (NFSD_FFV2_RECOVERY_TRUNCATED_TAIL |
			  NFSD_FFV2_RECOVERY_DISCARDED_UNSTABLE))))
		return false;
	if ((decision & NFSD_FFV2_RECOVERY_TRUNCATED_NONZERO_TAIL) &&
	    !(decision & NFSD_FFV2_RECOVERY_TRUNCATED_TAIL))
		return false;
	if (!!record->truncated_bytes !=
	    !!(decision & NFSD_FFV2_RECOVERY_TRUNCATED_TAIL))
		return false;
	return record->verifier_changed ==
	       !!(decision & (NFSD_FFV2_RECOVERY_DISCARDED_UNSTABLE |
			      NFSD_FFV2_RECOVERY_TRUNCATED_NONZERO_TAIL));
}

int nfsd_ffv2_start_encode(const struct nfsd_ffv2_wal_header *header,
			   const struct nfsd_ffv2_start_record *record,
			   u8 out[NFSD_FFV2_START_RECORD_SIZE])
{
	struct ffv2_cursor cursor = {
		.data = out,
		.capacity = NFSD_FFV2_START_RECORD_SIZE,
	};

	if (!header || !record || !out ||
	    header->family != NFSD_FFV2_WAL_START || !header->lsn ||
	    header->ds_incarnation != record->ds_incarnation ||
	    !ffv2_recovery_decision_valid(record))
		return -EINVAL;
	ffv2_put_wal_header(&cursor, header, NFSD_FFV2_START_RECORD_SIZE);
	ffv2_put_u32(&cursor, NFSD_FFV2_FORMAT_VERSION);
	ffv2_put_u64(&cursor, record->ds_incarnation);
	ffv2_put_u64(&cursor, record->prev_incarnation);
	ffv2_put_u64(&cursor, record->verifier_epoch);
	ffv2_put_u8(&cursor, record->verifier_changed);
	ffv2_put_u32(&cursor, record->recovery_decision);
	ffv2_put_u64(&cursor, record->truncated_bytes);
	ffv2_put_u64(&cursor, record->last_valid_lsn_before);
	ffv2_put_u64(&cursor, record->wal_append_cursor);
	ffv2_put_u64(&cursor, record->payload_append_cursor);
	ffv2_put_u64(&cursor, record->capacity_wal_bytes);
	ffv2_put_u64(&cursor, record->capacity_payload_bytes);
	ffv2_put_bytes(&cursor, record->export_uuid, sizeof(record->export_uuid));
	ffv2_put_u64(&cursor, record->live_txn_wal_reserved);
	ffv2_put_u64(&cursor, record->live_txn_payload_outstanding);
	ffv2_put_u64(&cursor, record->live_txn_payload_staged);
	if (cursor.failed || cursor.offset != NFSD_FFV2_START_RECORD_SIZE - 4)
		return -EOVERFLOW;
	ffv2_put_crc(&cursor, ffv2_wal_domain, out, cursor.offset);
	return cursor.failed ? -EOVERFLOW : 0;
}

int nfsd_ffv2_start_decode(const u8 *in, size_t len,
			   const u8 *expected_store, const u8 *expected_wal,
			   struct nfsd_ffv2_wal_header *header,
			   struct nfsd_ffv2_start_record *record)
{
	struct ffv2_cursor cursor = {
		.data = (u8 *)in,
		.capacity = len,
	};
	u32 format;
	int error;

	if (!in || !header || !record || len < NFSD_FFV2_START_RECORD_SIZE)
		return -EINVAL;
	memset(header, 0, sizeof(*header));
	memset(record, 0, sizeof(*record));
	error = ffv2_get_wal_header(&cursor, len, expected_store, expected_wal,
				    header);
	if (error || header->family != NFSD_FFV2_WAL_START ||
	    header->total_bytes != NFSD_FFV2_START_RECORD_SIZE ||
	    !ffv2_crc_valid(ffv2_wal_domain, in, header->total_bytes))
		return -EBADMSG;
	format = ffv2_get_u32(&cursor);
	record->ds_incarnation = ffv2_get_u64(&cursor);
	record->prev_incarnation = ffv2_get_u64(&cursor);
	record->verifier_epoch = ffv2_get_u64(&cursor);
	{
		u8 verifier_changed = ffv2_get_u8(&cursor);

		if (verifier_changed > 1)
			return -EBADMSG;
		record->verifier_changed = verifier_changed;
	}
	record->recovery_decision = ffv2_get_u32(&cursor);
	record->truncated_bytes = ffv2_get_u64(&cursor);
	record->last_valid_lsn_before = ffv2_get_u64(&cursor);
	record->wal_append_cursor = ffv2_get_u64(&cursor);
	record->payload_append_cursor = ffv2_get_u64(&cursor);
	record->capacity_wal_bytes = ffv2_get_u64(&cursor);
	record->capacity_payload_bytes = ffv2_get_u64(&cursor);
	ffv2_get_bytes(&cursor, record->export_uuid, sizeof(record->export_uuid));
	record->live_txn_wal_reserved = ffv2_get_u64(&cursor);
	record->live_txn_payload_outstanding = ffv2_get_u64(&cursor);
	record->live_txn_payload_staged = ffv2_get_u64(&cursor);
	if (cursor.failed || cursor.offset != NFSD_FFV2_START_RECORD_SIZE - 4 ||
	    format != NFSD_FFV2_FORMAT_VERSION ||
	    record->ds_incarnation != header->ds_incarnation ||
	    !ffv2_recovery_decision_valid(record))
		return -EBADMSG;
	return 0;
}

static void ffv2_file_key(const u8 *handle, u32 len, u8 out[32])
{
	u8 input[sizeof("FFV2-D2-FILEKEY-v1") - 1 + sizeof(__be32) +
		 NFSD_FFV2_STORE_HANDLE_SIZE];
	__be32 encoded = cpu_to_be32(len);
	size_t domain_len = sizeof("FFV2-D2-FILEKEY-v1") - 1;

	memcpy(input, "FFV2-D2-FILEKEY-v1", domain_len);
	memcpy(input + domain_len, &encoded, sizeof(encoded));
	memcpy(input + domain_len + sizeof(encoded), handle, len);
	sha256(input, domain_len + sizeof(encoded) + len, out);
}

static bool ffv2_store_key_valid(const u8 operation_key[32],
				 const u8 session[16], u32 slot, u32 sequence,
				 u32 ordinal, const u8 request_digest[32],
				 u64 incarnation)
{
	u8 expected[32] = {};

	if (!ffv2_all_zero(session, 16) || slot || ordinal ||
	    !ffv2_all_zero(request_digest, 32) || !sequence)
		return false;
	put_unaligned_be64(incarnation, expected);
	put_unaligned_be32(sequence, expected + 12);
	return !memcmp(operation_key, expected, sizeof(expected));
}

static bool ffv2_operation_key_valid(const u8 operation_key[32],
				     const u8 session[16], u32 slot,
				     u32 sequence, u32 ordinal)
{
	u8 input[sizeof("FFV2-D2-OPKEY-v1") - 1 + 28];
	u8 expected[SHA256_DIGEST_SIZE];
	u8 *at = input;

	if (ffv2_all_zero(session, 16))
		return false;
	memcpy(at, "FFV2-D2-OPKEY-v1", sizeof("FFV2-D2-OPKEY-v1") - 1);
	at += sizeof("FFV2-D2-OPKEY-v1") - 1;
	memcpy(at, session, 16);
	at += 16;
	put_unaligned_be32(slot, at);
	put_unaligned_be32(sequence, at + 4);
	put_unaligned_be32(ordinal, at + 8);
	sha256(input, sizeof(input), expected);
	return !memcmp(operation_key, expected, sizeof(expected));
}

int nfsd_ffv2_control_decode(const u8 *in, size_t len,
			     const u8 *expected_store, const u8 *expected_wal,
			     struct nfsd_ffv2_wal_header *header,
			     struct nfsd_ffv2_control_record *record)
{
	struct ffv2_cursor cursor = { .data = (u8 *)in, .capacity = len };
	u8 operation_key[32], request_digest[32];
	u32 slot, sequence, ordinal;
	int error;

	if (!in || !header || !record ||
	    len < NFSD_FFV2_WAL_HEADER_SIZE + NFSD_FFV2_CONTROL_PREFIX_SIZE + 4)
		return -EINVAL;
	memset(header, 0, sizeof(*header));
	memset(record, 0, sizeof(*record));
	error = ffv2_get_wal_header(&cursor, len, expected_store, expected_wal,
				    header);
	if (error || header->family != NFSD_FFV2_WAL_CONTROL ||
	    header->total_bytes != len ||
	    !ffv2_crc_valid(ffv2_wal_domain, in, len))
		return -EBADMSG;
	record->subtype = ffv2_get_u32(&cursor);
	record->transition = ffv2_get_u32(&cursor);
	record->status = ffv2_get_u32(&cursor);
	ffv2_get_bytes(&cursor, operation_key, sizeof(operation_key));
	ffv2_get_bytes(&cursor, request_digest, sizeof(request_digest));
	ffv2_get_bytes(&cursor, record->session, sizeof(record->session));
	slot = ffv2_get_u32(&cursor);
	sequence = ffv2_get_u32(&cursor);
	ordinal = ffv2_get_u32(&cursor);
	ffv2_get_bytes(&cursor, record->admission_issuer,
		       sizeof(record->admission_issuer));
	record->admission_authority_epoch = ffv2_get_u64(&cursor);
	record->admission_client_id = ffv2_get_u64(&cursor);
	record->body_len = len - NFSD_FFV2_WAL_HEADER_SIZE -
			   NFSD_FFV2_CONTROL_PREFIX_SIZE - 4;
	record->body = in + cursor.offset;
	if (cursor.failed || cursor.offset != NFSD_FFV2_WAL_HEADER_SIZE +
					  NFSD_FFV2_CONTROL_PREFIX_SIZE ||
	    !ffv2_operation_key_valid(operation_key, record->session, slot,
				      sequence, ordinal) ||
	    record->transition != NFSD_FFV2_COMMITTED || record->status != 1)
		return -EBADMSG;
	return 0;
}

int nfsd_ffv2_file_register_decode(const u8 *in, size_t len,
				   const u8 *expected_store,
				   const u8 *expected_wal,
				   struct nfsd_ffv2_wal_header *header,
				   struct nfsd_ffv2_file_register_record *record)
{
	struct ffv2_cursor cursor = { .data = (u8 *)in, .capacity = len };
	u8 operation_key[32], request_digest[32], session[16], computed[32];
	u8 admission_issuer[16];
	u64 admission_epoch, admission_client;
	u32 subtype, slot, sequence, ordinal;
	int error;

	if (!in || !header || !record ||
	    len < NFSD_FFV2_FILE_REGISTER_RECORD_SIZE)
		return -EINVAL;
	memset(header, 0, sizeof(*header));
	memset(record, 0, sizeof(*record));
	error = ffv2_get_wal_header(&cursor, len, expected_store, expected_wal,
				    header);
	if (error || header->family != NFSD_FFV2_WAL_CONTROL ||
	    header->total_bytes != NFSD_FFV2_FILE_REGISTER_RECORD_SIZE ||
	    !ffv2_crc_valid(ffv2_wal_domain, in, header->total_bytes))
		return -EBADMSG;
	subtype = ffv2_get_u32(&cursor);
	record->transition = ffv2_get_u32(&cursor);
	record->status = ffv2_get_u32(&cursor);
	ffv2_get_bytes(&cursor, operation_key, sizeof(operation_key));
	ffv2_get_bytes(&cursor, request_digest, sizeof(request_digest));
	ffv2_get_bytes(&cursor, session, sizeof(session));
	slot = ffv2_get_u32(&cursor);
	sequence = ffv2_get_u32(&cursor);
	ordinal = ffv2_get_u32(&cursor);
	ffv2_get_bytes(&cursor, admission_issuer, sizeof(admission_issuer));
	admission_epoch = ffv2_get_u64(&cursor);
	admission_client = ffv2_get_u64(&cursor);
	ffv2_get_bytes(&cursor, record->file_key, sizeof(record->file_key));
	record->handle_type = ffv2_get_u16(&cursor);
	record->handle_len = ffv2_get_u16(&cursor);
	ffv2_get_bytes(&cursor, record->handle, sizeof(record->handle));
	record->chunk_bytes = ffv2_get_u32(&cursor);
	record->max_chunks = ffv2_get_u64(&cursor);
	record->logical_eof = ffv2_get_u64(&cursor);
	if (cursor.failed ||
	    cursor.offset != NFSD_FFV2_FILE_REGISTER_RECORD_SIZE - 4 ||
	    subtype != NFSD_FFV2_FILE_REGISTER ||
	    record->transition != NFSD_FFV2_COMMITTED || record->status != 1 ||
	    !ffv2_store_key_valid(operation_key, session, slot, sequence,
				  ordinal, request_digest,
				  header->ds_incarnation) ||
	    !ffv2_all_zero(admission_issuer, sizeof(admission_issuer)) ||
	    admission_epoch || admission_client || record->handle_type ||
	    record->handle_len != 32 ||
	    !ffv2_all_zero(record->handle + record->handle_len,
			   sizeof(record->handle) - record->handle_len) ||
	    record->chunk_bytes < 4096 || record->chunk_bytes > 1024 * 1024 ||
	    !IS_ALIGNED(record->chunk_bytes, 4096) || !record->max_chunks ||
	    record->max_chunks > U64_MAX / record->chunk_bytes ||
	    record->logical_eof)
		return -EBADMSG;
	ffv2_file_key(record->handle, record->handle_len, computed);
	return memcmp(computed, record->file_key, sizeof(computed)) ?
		       -EBADMSG : 0;
}

static bool ffv2_entry_pair_valid(u32 transition, u32 status)
{
	if (transition == NFSD_FFV2_PREPARED ||
	    transition == NFSD_FFV2_FINALIZED ||
	    transition == NFSD_FFV2_COMMITTED ||
	    transition == NFSD_FFV2_ROLLED_BACK)
		return status == 1;
	if (transition == NFSD_FFV2_ABORTED)
		return status == 3 || status == 4 || status == 5 || status == 7 ||
		       status == 8 || status == 9;
	return transition == NFSD_FFV2_REFUSED &&
	       (status == 2 || status == 3 || status == 4 || status == 5 ||
		status == 6 || status == 7 || status == 8 || status == 9);
}

int nfsd_ffv2_entry_decode(const u8 *in, size_t len,
			   const u8 *expected_store, const u8 *expected_wal,
			   struct nfsd_ffv2_wal_header *header,
			   struct nfsd_ffv2_entry_record *record)
{
	struct ffv2_cursor cursor = { .data = (u8 *)in, .capacity = len };
	u8 operation_key[32], request_digest[32], session[16];
	u8 predecessor_present, postcond_present, result_activated;
	u8 result_guard_never_written;
	u32 slot, sequence, ordinal;
	int error;

	if (!in || !header || !record || len < NFSD_FFV2_ENTRY_RECORD_SIZE)
		return -EINVAL;
	memset(header, 0, sizeof(*header));
	memset(record, 0, sizeof(*record));
	error = ffv2_get_wal_header(&cursor, len, expected_store, expected_wal,
				    header);
	if (error || header->family != NFSD_FFV2_WAL_ENTRY ||
	    header->total_bytes != NFSD_FFV2_ENTRY_RECORD_SIZE ||
	    !ffv2_crc_valid(ffv2_wal_domain, in, header->total_bytes))
		return -EBADMSG;
	record->transition = ffv2_get_u32(&cursor);
	record->status = ffv2_get_u32(&cursor);
	record->disposition = ffv2_get_u32(&cursor);
	record->stability = ffv2_get_u32(&cursor);
	record->batch_ordinal = ffv2_get_u32(&cursor);
	record->batch_count = ffv2_get_u32(&cursor);
	ffv2_get_bytes(&cursor, record->file_key, sizeof(record->file_key));
	record->chunk_index = ffv2_get_u64(&cursor);
	record->txn_id = ffv2_get_u64(&cursor);
	ffv2_get_bytes(&cursor, session, sizeof(session));
	slot = ffv2_get_u32(&cursor);
	sequence = ffv2_get_u32(&cursor);
	ordinal = ffv2_get_u32(&cursor);
	ffv2_get_bytes(&cursor, operation_key, sizeof(operation_key));
	ffv2_get_bytes(&cursor, request_digest, sizeof(request_digest));
	ffv2_get_bytes(&cursor, record->admission.session, 16);
	ffv2_get_bytes(&cursor, record->admission.principal, 16);
	ffv2_get_bytes(&cursor, record->admission.issuer, 16);
	record->admission.authority_epoch = ffv2_get_u64(&cursor);
	record->admission.fence_sequence = ffv2_get_u64(&cursor);
	record->admission.lease_epoch = ffv2_get_u64(&cursor);
	record->admission.client_id = ffv2_get_u64(&cursor);
	record->admission.stateid_seqid = ffv2_get_u32(&cursor);
	ffv2_get_bytes(&cursor, record->admission.stateid_other, 12);
	record->admission.writer = ffv2_get_u32(&cursor);
	record->admission.rights = ffv2_get_u32(&cursor);
	record->owner_cohort = ffv2_get_u64(&cursor);
	record->owner_client_id = ffv2_get_u32(&cursor);
	record->owner_co_id = ffv2_get_u32(&cursor);
	record->generation = ffv2_get_u32(&cursor);
	predecessor_present = ffv2_get_u8(&cursor);
	record->predecessor_object_id = ffv2_get_u64(&cursor);
	record->predecessor_generation = ffv2_get_u32(&cursor);
	postcond_present = ffv2_get_u8(&cursor);
	record->postcond_id = ffv2_get_u64(&cursor);
	record->payload_object_id = ffv2_get_u64(&cursor);
	record->payload_object_offset = ffv2_get_u64(&cursor);
	record->payload_content_len = ffv2_get_u32(&cursor);
	record->extent_kind = ffv2_get_u32(&cursor);
	record->extent_high_water = ffv2_get_u64(&cursor);
	record->extent_highest_index = ffv2_get_u64(&cursor);
	record->index_generation = ffv2_get_u64(&cursor);
	ffv2_get_bytes(&cursor, record->result_verifier,
		       sizeof(record->result_verifier));
	result_activated = ffv2_get_u8(&cursor);
	record->result_visible_object_id = ffv2_get_u64(&cursor);
	record->result_effective_len = ffv2_get_u32(&cursor);
	record->result_checksum_algorithm = ffv2_get_u32(&cursor);
	record->result_checksum_len = ffv2_get_u32(&cursor);
	ffv2_get_bytes(&cursor, record->result_checksum,
		       sizeof(record->result_checksum));
	result_guard_never_written = ffv2_get_u8(&cursor);
	record->result_guard_generation = ffv2_get_u32(&cursor);
	record->result_guard_writer = ffv2_get_u32(&cursor);
	if (cursor.failed || cursor.offset != NFSD_FFV2_ENTRY_RECORD_SIZE - 4 ||
	    !ffv2_operation_key_valid(operation_key, session, slot, sequence,
				      ordinal) ||
	    record->batch_count < 1 || record->batch_count > 16 ||
	    record->batch_ordinal >= record->batch_count ||
	    !ffv2_entry_pair_valid(record->transition, record->status) ||
	    record->status > 12 || record->disposition != 1 ||
	    record->stability < 1 || record->stability > 3 ||
	    record->extent_kind < 1 || record->extent_kind > 3 ||
	    predecessor_present > 1 || postcond_present > 1 ||
	    result_activated > 1 || result_guard_never_written > 1 ||
	    (!predecessor_present &&
	     (record->predecessor_object_id || record->predecessor_generation)) ||
	    (!postcond_present && record->postcond_id) ||
	    record->result_checksum_len > sizeof(record->result_checksum) ||
	    !ffv2_all_zero(record->result_checksum +
				     record->result_checksum_len,
			   sizeof(record->result_checksum) -
				     record->result_checksum_len) ||
	    (!record->payload_object_id && record->payload_object_offset) ||
	    (record->payload_object_id &&
	     (!(record->payload_object_id >> 40) ||
	      (record->payload_object_id >> 40) > header->ds_incarnation ||
	      record->payload_object_offset < NFSD_FFV2_PAYLOAD_ALIGN ||
	      !IS_ALIGNED(record->payload_object_offset,
			  NFSD_FFV2_PAYLOAD_ALIGN))))
		return -EBADMSG;
	record->predecessor_present = predecessor_present;
	record->postcond_present = postcond_present;
	record->result_activated = result_activated;
	record->result_guard_never_written = result_guard_never_written;
	return 0;
}

int
nfsd_ffv2_payload_header_encode(const struct nfsd_ffv2_payload_header *header,
				u8 out[NFSD_FFV2_PAYLOAD_ALIGN])
{
	struct ffv2_cursor cursor = {
		.data = out,
		.capacity = NFSD_FFV2_PAYLOAD_HEADER_SIZE + 4,
	};

	if (!header || !out)
		return -EINVAL;
	memset(out, 0, NFSD_FFV2_PAYLOAD_ALIGN);
	ffv2_put_common(&cursor, FFV2_PAYLOAD_MAGIC,
			NFSD_FFV2_PAYLOAD_FILE_HEADER,
			NFSD_FFV2_PAYLOAD_HEADER_SIZE,
			NFSD_FFV2_PAYLOAD_HEADER_SIZE + 4, header->store_uuid);
	ffv2_put_bytes(&cursor, header->payload_uuid,
		       sizeof(header->payload_uuid));
	ffv2_put_bytes(&cursor, header->wal_uuid, sizeof(header->wal_uuid));
	ffv2_put_u64(&cursor, NFSD_FFV2_PAYLOAD_ALIGN);
	ffv2_put_u32(&cursor, 0);
	if (cursor.failed || cursor.offset != NFSD_FFV2_PAYLOAD_HEADER_SIZE)
		return -EOVERFLOW;
	ffv2_put_crc(&cursor, ffv2_payload_domain, out, cursor.offset);
	return cursor.failed ? -EOVERFLOW : 0;
}

int
nfsd_ffv2_payload_header_decode(const u8 in[NFSD_FFV2_PAYLOAD_ALIGN],
				const u8 *expected_store,
				struct nfsd_ffv2_payload_header *header)
{
	struct ffv2_cursor cursor = {
		.data = (u8 *)in,
		.capacity = NFSD_FFV2_PAYLOAD_HEADER_SIZE,
	};
	u64 object_size;
	u32 reserved;
	int error;

	if (!in || !header ||
	    !ffv2_crc_valid(ffv2_payload_domain, in,
			    NFSD_FFV2_PAYLOAD_HEADER_SIZE + 4) ||
	    !ffv2_all_zero(in + NFSD_FFV2_PAYLOAD_HEADER_SIZE + 4,
			   NFSD_FFV2_PAYLOAD_ALIGN -
				   NFSD_FFV2_PAYLOAD_HEADER_SIZE - 4))
		return -EBADMSG;
	memset(header, 0, sizeof(*header));
	error = ffv2_get_common(&cursor, FFV2_PAYLOAD_MAGIC,
				NFSD_FFV2_PAYLOAD_FILE_HEADER,
				NFSD_FFV2_PAYLOAD_HEADER_SIZE,
				NFSD_FFV2_PAYLOAD_HEADER_SIZE + 4,
				expected_store, header->store_uuid);
	if (error)
		return error;
	ffv2_get_bytes(&cursor, header->payload_uuid,
		       sizeof(header->payload_uuid));
	ffv2_get_bytes(&cursor, header->wal_uuid, sizeof(header->wal_uuid));
	object_size = ffv2_get_u64(&cursor);
	reserved = ffv2_get_u32(&cursor);
	if (cursor.failed || cursor.offset != cursor.capacity ||
	    object_size != NFSD_FFV2_PAYLOAD_ALIGN || reserved)
		return -EBADMSG;
	return 0;
}

size_t nfsd_ffv2_payload_record_size(u32 content_len)
{
	size_t total;

	if (check_add_overflow((size_t)NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE,
			       (size_t)content_len, &total) ||
	    check_add_overflow(total, sizeof(__be32), &total))
		return 0;
	return ALIGN(total, NFSD_FFV2_PAYLOAD_ALIGN);
}

static bool
ffv2_payload_checksum_valid(const struct nfsd_ffv2_payload_record *record)
{
	u8 computed[NFSD_FFV2_STORE_CHECKSUM_SIZE] = {};
	u32 expected_len;
	u64 a = 0, b = 0, c = 0, d = 0;
	u32 i;

	switch (record->checksum_algorithm) {
	case 0:
		expected_len = 0;
		break;
	case 1:
		expected_len = sizeof(__be32);
		put_unaligned_be32(~crc32_le(~0, record->content,
					     record->content_len),
			     computed);
		break;
	case 2:
		expected_len = sizeof(__be32);
		put_unaligned_be32(~crc32c(~0, record->content,
					   record->content_len),
			     computed);
		break;
	case 3:
		if (!IS_ALIGNED(record->content_len, sizeof(u32)))
			return false;
		expected_len = 4 * sizeof(__be64);
		for (i = 0; i < record->content_len; i += sizeof(u32)) {
			a += get_unaligned_le32(record->content + i);
			b += a;
			c += b;
			d += c;
		}
		put_unaligned_be64(a, computed);
		put_unaligned_be64(b, computed + 8);
		put_unaligned_be64(c, computed + 16);
		put_unaligned_be64(d, computed + 24);
		break;
	case 4:
		expected_len = SHA256_DIGEST_SIZE;
		sha256(record->content, record->content_len, computed);
		break;
	default:
		return false;
	}
	return record->checksum_len == expected_len &&
	       !memcmp(record->checksum, computed, sizeof(computed));
}

int nfsd_ffv2_payload_encode(const struct nfsd_ffv2_payload_record *record,
			     u8 *out, size_t capacity, size_t *written)
{
	struct ffv2_cursor cursor;
	size_t object_size, total;

	if (!record || !out || !written ||
	    record->checksum_len > NFSD_FFV2_STORE_CHECKSUM_SIZE ||
	    (record->content_len && !record->content) ||
	    !ffv2_all_zero(record->checksum + record->checksum_len,
			   NFSD_FFV2_STORE_CHECKSUM_SIZE - record->checksum_len) ||
	    !ffv2_payload_checksum_valid(record))
		return -EINVAL;
	object_size = nfsd_ffv2_payload_record_size(record->content_len);
	total = NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE + record->content_len + 4;
	if (!object_size || object_size > capacity || object_size > U32_MAX ||
	    (record->object_bytes && record->object_bytes != object_size))
		return -EFBIG;
	memset(out, 0, object_size);
	cursor = (struct ffv2_cursor){ .data = out, .capacity = total };
	ffv2_put_common(&cursor, FFV2_PAYLOAD_MAGIC, NFSD_FFV2_PAYLOAD_DATA,
			NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE, total,
			record->store_uuid);
	ffv2_put_u64(&cursor, record->object_id);
	ffv2_put_u32(&cursor, ~crc32c(~0, record->content, record->content_len));
	ffv2_put_u32(&cursor, record->checksum_algorithm);
	ffv2_put_u32(&cursor, record->checksum_len);
	ffv2_put_bytes(&cursor, record->checksum, sizeof(record->checksum));
	ffv2_put_u32(&cursor, record->content_len);
	ffv2_put_u64(&cursor, object_size);
	ffv2_put_u32(&cursor, 0);
	if (cursor.failed || cursor.offset != NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE)
		return -EOVERFLOW;
	ffv2_put_bytes(&cursor, record->content, record->content_len);
	ffv2_put_crc(&cursor, ffv2_payload_domain, out,
		     NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE);
	if (cursor.failed || cursor.offset != total)
		return -EOVERFLOW;
	*written = object_size;
	return 0;
}

int nfsd_ffv2_payload_decode(const u8 *in, size_t len,
			     const u8 *expected_store,
			     struct nfsd_ffv2_payload_record *record,
			     bool *content_valid)
{
	struct ffv2_cursor cursor;
	u32 total, reserved, stored_crc;
	u64 object_size;
	int error;

	if (!in || !record || !content_valid ||
	    len < NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE + 4)
		return -EINVAL;
	*content_valid = false;
	total = get_unaligned_be32(in + 12);
	if (total < NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE + 4 || total > len)
		return -EBADMSG;
	memset(record, 0, sizeof(*record));
	cursor = (struct ffv2_cursor){
		.data = (u8 *)in,
		.capacity = NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE,
	};
	error = ffv2_get_common(&cursor, FFV2_PAYLOAD_MAGIC,
				NFSD_FFV2_PAYLOAD_DATA,
				NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE, total,
				expected_store, record->store_uuid);
	if (error)
		return error;
	record->object_id = ffv2_get_u64(&cursor);
	stored_crc = ffv2_get_u32(&cursor);
	record->checksum_algorithm = ffv2_get_u32(&cursor);
	record->checksum_len = ffv2_get_u32(&cursor);
	ffv2_get_bytes(&cursor, record->checksum, sizeof(record->checksum));
	record->content_len = ffv2_get_u32(&cursor);
	object_size = ffv2_get_u64(&cursor);
	reserved = ffv2_get_u32(&cursor);
	if (cursor.failed || cursor.offset != cursor.capacity ||
	    record->checksum_len > NFSD_FFV2_STORE_CHECKSUM_SIZE ||
	    !ffv2_all_zero(record->checksum + record->checksum_len,
			   NFSD_FFV2_STORE_CHECKSUM_SIZE - record->checksum_len) ||
	    total != NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE + record->content_len + 4 ||
	    object_size != nfsd_ffv2_payload_record_size(record->content_len) ||
	    object_size > len || reserved ||
	    get_unaligned_be32(in + total - 4) !=
		    ffv2_crc(ffv2_payload_domain, in,
			     NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE) ||
	    !ffv2_all_zero(in + total, object_size - total))
		return -EBADMSG;
	record->content = in + NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE;
	record->content_crc32c = stored_crc;
	record->object_bytes = object_size;
	*content_valid = stored_crc ==
			 ~crc32c(~0, record->content, record->content_len) &&
			 ffv2_payload_checksum_valid(record);
	return 0;
}

struct nfsd_ffv2_store {
	struct nfsd_ffv2_reservation *reservation;
	struct file *super_file;
	struct file *wal_file;
	struct file *payload_file;
	struct nfsd_ffv2_super_record super;
	/* Serializes checkpoints and their in-memory selected slot. */
	struct mutex lock;
	unsigned int newest_slot;
	u64 wal_cursor;
	u64 payload_cursor;
	u64 wal_payload_cursor;
	u64 next_lsn;
	struct list_head registrations;
	struct list_head transactions;
	struct list_head admissions;
	u32 registration_count;
	u32 transaction_count;
	u32 admission_count;
	bool failed;
#ifdef CONFIG_NFSD_FFV2_LIVE_TEST
	bool fail_next_io;
#endif
};

struct ffv2_registration {
	struct list_head node;
	u8 file_key[32];
	u8 handle[32];
	u32 chunk_bytes;
	u64 max_chunks;
};

struct ffv2_admission {
	struct list_head node;
	u64 id;
	u64 incarnation;
	struct nfsd_ffv2_admission_record authority;
	u8 file_key[32];
	bool authority_seen;
	bool object_known;
};

struct ffv2_transaction {
	struct list_head node;
	u8 file_key[32];
	u64 chunk_index;
	u64 txn_id;
	u64 payload_bytes;
	u64 incarnation;
	u64 admission_id;
	u32 phase;
};

struct ffv2_scan_result {
	u64 valid_bytes;
	u64 truncated_bytes;
	u64 last_lsn;
	u64 incarnation;
	u64 payload_cursor;
	u64 live_wal_reserved;
	u64 live_payload_staged;
	bool nonzero_tail;
};

static void ffv2_store_replay_free(struct nfsd_ffv2_store *store)
{
	struct ffv2_registration *registration, *next_registration;
	struct ffv2_transaction *transaction, *next_transaction;
	struct ffv2_admission *admission, *next_admission;

	list_for_each_entry_safe(registration, next_registration,
				 &store->registrations, node) {
		list_del(&registration->node);
		kfree(registration);
	}
	list_for_each_entry_safe(transaction, next_transaction,
				 &store->transactions, node) {
		list_del(&transaction->node);
		kfree(transaction);
	}
	list_for_each_entry_safe(admission, next_admission,
				 &store->admissions, node) {
		list_del(&admission->node);
		kfree(admission);
	}
}

static void ffv2_token_digest(const u8 token[32], u8 digest[32])
{
	u8 input[sizeof(ffv2_token_domain) - 1 + sizeof(__be32) + 32];
	__be32 len = cpu_to_be32(32);

	memcpy(input, ffv2_token_domain, sizeof(ffv2_token_domain) - 1);
	memcpy(input + sizeof(ffv2_token_domain) - 1, &len, sizeof(len));
	memcpy(input + sizeof(ffv2_token_domain) - 1 + sizeof(len), token, 32);
	sha256(input, sizeof(input), digest);
}

static struct file *ffv2_store_open_file(const struct path *root,
					 const char *name)
{
	struct file *file;
	struct dentry *dentry;
	struct path path;
	struct qstr q = QSTR_LEN(name, strlen(name));

	/* Resolve one fixed direct child and reject special files before open. */
	inode_lock(d_inode(root->dentry));
	dentry = lookup_one(mnt_idmap(root->mnt), &q, root->dentry);
	if (IS_ERR(dentry)) {
		inode_unlock(d_inode(root->dentry));
		return ERR_CAST(dentry);
	}
	if (!d_is_reg(dentry) || !d_inode(dentry)->i_nlink ||
	    dentry->d_parent != root->dentry) {
		dput(dentry);
		inode_unlock(d_inode(root->dentry));
		return ERR_PTR(-EINVAL);
	}
	path.mnt = mntget(root->mnt);
	path.dentry = dentry;
	inode_unlock(d_inode(root->dentry));
	file = dentry_open(&path, O_RDWR | O_LARGEFILE | O_NOFOLLOW,
			   current_cred());
	if (IS_ERR(file))
		return file;
	if (file_inode(file)->i_sb != root->mnt->mnt_sb) {
		fput(file);
		return ERR_PTR(-EXDEV);
	}
	return file;
}

static int ffv2_store_read_all(struct file *file, void *data, size_t len,
			       loff_t offset)
{
	u8 *cursor = data;
	ssize_t done;

	while (len) {
		done = kernel_read(file, cursor, len, &offset);
		if (done < 0)
			return done;
		if (!done)
			return -EIO;
		cursor += done;
		len -= done;
	}
	return 0;
}

static int ffv2_store_write_all(struct file *file, const void *data, size_t len,
				loff_t offset)
{
	const u8 *cursor = data;
	ssize_t done;

	while (len) {
		done = kernel_write(file, cursor, len, &offset);
		if (done < 0)
			return done;
		if (!done)
			return -EIO;
		cursor += done;
		len -= done;
	}
	return 0;
}

static int ffv2_store_zero_range(struct file *file, loff_t offset, u64 len,
				 bool *all_zero)
{
	u8 buffer[512];

	*all_zero = true;
	while (len) {
		size_t count = min_t(u64, len, sizeof(buffer));
		int error = ffv2_store_read_all(file, buffer, count, offset);

		if (error)
			return error;
		if (!ffv2_all_zero(buffer, count)) {
			*all_zero = false;
			return 0;
		}
		offset += count;
		len -= count;
	}
	return 0;
}

static int ffv2_store_read_super(struct nfsd_ffv2_store *store,
				 const u8 expected_store[16])
{
	struct nfsd_ffv2_super_record slots[2];
	bool valid[2] = {};
	u8 *bytes;
	unsigned int i, selected;
	int error;

	bytes = kmalloc(NFSD_FFV2_SUPER_SLOT_SIZE, GFP_KERNEL);
	if (!bytes)
		return -ENOMEM;
	for (i = 0; i < ARRAY_SIZE(slots); i++) {
		error = ffv2_store_read_all(store->super_file, bytes,
					    NFSD_FFV2_SUPER_SLOT_SIZE,
					    i * NFSD_FFV2_SUPER_SLOT_SIZE);
		if (!error)
			valid[i] = !nfsd_ffv2_super_decode(bytes, expected_store,
							    &slots[i]);
	}
	kfree(bytes);
	if (!valid[0] && !valid[1])
		return -EBADMSG;
	if (valid[0] && valid[1] && slots[0].generation == slots[1].generation)
		return -EBADMSG;
	selected = !valid[0] ||
		   (valid[1] && slots[1].generation > slots[0].generation);
	store->super = slots[selected];
	store->newest_slot = selected;
	if (store->super.state == NFSD_FFV2_SUPER_FENCED ||
	    store->super.state == NFSD_FFV2_SUPER_RETIRED)
		return -ESHUTDOWN;
	if (!store->super.ds_incarnation &&
	    store->super.state == NFSD_FFV2_SUPER_NEEDS_RECOVERY)
		return -EBADMSG;
	return 0;
}

static int ffv2_store_validate_files(struct nfsd_ffv2_store *store,
				     const struct path *root,
				     const u8 expected_export[16],
				     const u8 binding_token[32])
{
	struct nfsd_ffv2_payload_header payload_header;
	struct nfsd_ffv2_payload_header *header = &payload_header;
	const u8 *store_uuid = store->super.store_uuid;
	u8 digest[32];
	u8 *payload_bytes;
	loff_t payload_size;
	loff_t wal_size;
	int error;

	wal_size = i_size_read(file_inode(store->wal_file));
	payload_size = i_size_read(file_inode(store->payload_file));
	if (i_size_read(file_inode(store->super_file)) !=
					       NFSD_FFV2_SUPER_FILE_SIZE ||
	    wal_size <= 0 || wal_size > store->super.capacity_wal_bytes ||
	    payload_size < NFSD_FFV2_PAYLOAD_ALIGN ||
	    payload_size > store->super.capacity_payload_bytes ||
	    store->super.wal_durable_bytes > wal_size ||
	    store->super.payload_durable_bytes > payload_size ||
	    memcmp(root->mnt->mnt_sb->s_uuid.b, store->super.fs_uuid,
		   sizeof(store->super.fs_uuid)) || store->super.root_handle_type ||
	    store->super.root_handle_len ||
	    memcmp(store->super.export_uuid, expected_export, 16))
		return -EBADMSG;
	ffv2_token_digest(binding_token, digest);
	if (memcmp(store->super.binding_token_digest, digest, sizeof(digest)))
		return -EKEYREJECTED;

	payload_bytes = kmalloc(NFSD_FFV2_PAYLOAD_ALIGN, GFP_KERNEL);
	if (!payload_bytes) {
		error = -ENOMEM;
		goto out;
	}
	error = ffv2_store_read_all(store->payload_file, payload_bytes,
				    NFSD_FFV2_PAYLOAD_ALIGN, 0);
	if (error)
		goto out;
	error = nfsd_ffv2_payload_header_decode(payload_bytes, store_uuid, header);
	if (error || memcmp(payload_header.payload_uuid,
			    store->super.payload_uuid, 16) ||
	    memcmp(payload_header.wal_uuid, store->super.wal_uuid, 16)) {
		error = -EBADMSG;
		goto out;
	}
out:
	kfree(payload_bytes);
	return error;
}

static bool ffv2_wal_prologue_valid(const u8 *bytes,
				    const struct nfsd_ffv2_store *store,
				    u32 *total)
{
	*total = get_unaligned_be32(bytes + 12);
	return get_unaligned_be32(bytes) == FFV2_WAL_MAGIC &&
	       get_unaligned_be16(bytes + 4) == NFSD_FFV2_FORMAT_VERSION &&
	       get_unaligned_be32(bytes + 8) == NFSD_FFV2_WAL_HEADER_SIZE &&
	       (*total ^ get_unaligned_be32(bytes + 16)) == U32_MAX &&
	       *total >= NFSD_FFV2_WAL_HEADER_SIZE + 4 &&
	       *total <= NFSD_FFV2_MAX_DAMAGED_TAIL_SIZE &&
	       !memcmp(bytes + 20, store->super.store_uuid, 16) &&
	       !memcmp(bytes + 36, store->super.wal_uuid, 16);
}

static int
ffv2_replay_file_register(struct nfsd_ffv2_store *store,
			  const struct nfsd_ffv2_file_register_record *record)
{
	struct ffv2_registration *registration;

	if (store->registration_count == NFSD_FFV2_MAX_OBJECTS)
		return -EBADMSG;
	list_for_each_entry(registration, &store->registrations, node)
		if (!memcmp(registration->file_key, record->file_key, 32) ||
		    !memcmp(registration->handle, record->handle, 32))
			return -EBADMSG;
	registration = kmalloc_obj(*registration, GFP_KERNEL);
	if (!registration)
		return -ENOMEM;
	memcpy(registration->file_key, record->file_key, 32);
	memcpy(registration->handle, record->handle, 32);
	registration->chunk_bytes = record->chunk_bytes;
	registration->max_chunks = record->max_chunks;
	list_add_tail(&registration->node, &store->registrations);
	store->registration_count++;
	return 0;
}

static struct ffv2_registration *
ffv2_replay_file(struct nfsd_ffv2_store *store, const u8 file_key[32])
{
	struct ffv2_registration *registration;

	list_for_each_entry(registration, &store->registrations, node)
		if (!memcmp(registration->file_key, file_key, 32))
			return registration;
	return NULL;
}

static struct ffv2_admission *
ffv2_replay_admission_find(struct nfsd_ffv2_store *store, u64 id)
{
	struct ffv2_admission *admission;

	list_for_each_entry(admission, &store->admissions, node)
		if (admission->id == id)
			return admission;
	return NULL;
}

static bool ffv2_stateid_valid(u64 id, u32 seqid, const u8 other[12])
{
	u8 expected[12] = { 'T', 'A', 'T', 'E' };

	put_unaligned_be64(id, expected + 4);
	return seqid == 0x44324253 && !memcmp(other, expected, 12);
}

static int ffv2_replay_trust(struct nfsd_ffv2_store *store,
			     const struct nfsd_ffv2_wal_header *header,
			     const struct nfsd_ffv2_control_record *record)
{
	struct ffv2_cursor cursor = {
		.data = (u8 *)record->body,
		.capacity = record->body_len,
	};
	struct nfsd_ffv2_admission_record authority = {};
	struct ffv2_admission *actor, *admission;
	u64 beneficiary;
	u32 iomode;

	if (!record->admission_client_id || record->body_len != 84 ||
	    store->admission_count == NFSD_FFV2_MAX_ADMISSIONS)
		return -EBADMSG;
	authority.stateid_seqid = ffv2_get_u32(&cursor);
	ffv2_get_bytes(&cursor, authority.stateid_other, 12);
	authority.lease_epoch = ffv2_get_u64(&cursor);
	authority.fence_sequence = ffv2_get_u64(&cursor);
	iomode = ffv2_get_u32(&cursor);
	ffv2_get_bytes(&cursor, authority.session, 16);
	beneficiary = ffv2_get_u64(&cursor);
	ffv2_get_bytes(&cursor, authority.principal, 16);
	authority.writer = ffv2_get_u32(&cursor);
	authority.rights = ffv2_get_u32(&cursor);
	memcpy(authority.issuer, record->admission_issuer, 16);
	authority.authority_epoch = record->admission_authority_epoch;
	authority.client_id = beneficiary;
	if (cursor.failed || cursor.offset != cursor.capacity || !beneficiary ||
	    !ffv2_stateid_valid(beneficiary, authority.stateid_seqid,
				 authority.stateid_other) ||
	    iomode != (authority.rights & (NFSD_FFV2_RIGHT_READ |
					    NFSD_FFV2_RIGHT_WRITE)) ||
	    ffv2_replay_admission_find(store, beneficiary))
		return -EBADMSG;
	actor = ffv2_replay_admission_find(store,
					   record->admission_client_id);
	if (record->admission_client_id != beneficiary &&
	    (!actor || !actor->authority_seen ||
	     !(actor->authority.rights & NFSD_FFV2_RIGHT_CONTROL) ||
	     memcmp(actor->authority.issuer, authority.issuer, 16) ||
	     actor->authority.authority_epoch != authority.authority_epoch))
		return -EBADMSG;
	admission = kzalloc_obj(*admission, GFP_KERNEL);
	if (!admission)
		return -ENOMEM;
	admission->id = beneficiary;
	admission->incarnation = header->ds_incarnation;
	admission->authority = authority;
	list_add_tail(&admission->node, &store->admissions);
	store->admission_count++;
	return 0;
}

static int ffv2_replay_authority(struct nfsd_ffv2_store *store,
				 const struct nfsd_ffv2_control_record *record)
{
	struct ffv2_cursor cursor = {
		.data = (u8 *)record->body,
		.capacity = record->body_len,
	};
	struct ffv2_admission *actor;
	struct ffv2_admission *beneficiaries[NFSD_FFV2_MAX_AUTHORITY_STATEIDS];
	u8 issuer[16], stateid[16], previous[16] = {};
	u64 epoch;
	u32 count, i;

	actor = ffv2_replay_admission_find(store,
					   record->admission_client_id);
	ffv2_get_bytes(&cursor, issuer, sizeof(issuer));
	epoch = ffv2_get_u64(&cursor);
	count = ffv2_get_u32(&cursor);
	if (cursor.failed || !actor || count > ARRAY_SIZE(beneficiaries) ||
	    record->body_len != 28 + count * 16 ||
	    memcmp(issuer, record->admission_issuer, 16) ||
	    memcmp(issuer, actor->authority.issuer, 16) ||
	    record->admission_authority_epoch !=
					actor->authority.authority_epoch)
		return -EBADMSG;
	for (i = 0; i < count; i++) {
		u32 seqid = ffv2_get_u32(&cursor);
		u64 id;

		put_unaligned_be32(seqid, stateid);
		ffv2_get_bytes(&cursor, stateid + 4, 12);
		if ((i && memcmp(previous, stateid, sizeof(stateid)) >= 0) ||
		    seqid != 0x44324253 || memcmp(stateid + 4, "TATE", 4))
			return -EBADMSG;
		id = get_unaligned_be64(stateid + 8);
		beneficiaries[i] = ffv2_replay_admission_find(store, id);
		if (!beneficiaries[i] || beneficiaries[i]->authority_seen)
			return -EBADMSG;
		memcpy(previous, stateid, sizeof(previous));
	}
	if (cursor.failed || cursor.offset != cursor.capacity)
		return -EBADMSG;
	if (!actor->authority_seen ||
	    !(actor->authority.rights & NFSD_FFV2_RIGHT_CONTROL)) {
		bool self = false;

		for (i = 0; i < count; i++)
			self |= beneficiaries[i] == actor;
		if (!self)
			return -EBADMSG;
	}
	for (i = 0; i < count; i++) {
		beneficiaries[i]->authority_seen = true;
		memcpy(beneficiaries[i]->authority.issuer, issuer, 16);
		beneficiaries[i]->authority.authority_epoch = epoch;
	}
	return 0;
}

static struct ffv2_transaction *
ffv2_replay_transaction(struct nfsd_ffv2_store *store, u64 txn_id)
{
	struct ffv2_transaction *transaction;

	list_for_each_entry(transaction, &store->transactions, node)
		if (transaction->txn_id == txn_id)
			return transaction;
	return NULL;
}

static int ffv2_replay_payload(struct nfsd_ffv2_store *store,
			       const struct nfsd_ffv2_entry_record *entry,
			       u64 *object_end)
{
	struct nfsd_ffv2_payload_record payload;
	u64 extent;
	u8 *bytes;
	bool content_valid;
	int error;

	*object_end = 0;
	if (!entry->payload_object_id)
		return entry->payload_content_len ? -EBADMSG : 0;
	extent = nfsd_ffv2_payload_record_size(entry->payload_content_len);
	if (!extent || entry->payload_object_offset >
					store->super.capacity_payload_bytes ||
	    extent > store->super.capacity_payload_bytes -
					entry->payload_object_offset ||
	    entry->payload_object_offset + extent >
				i_size_read(file_inode(store->payload_file)))
		return -EBADMSG;
	bytes = kvmalloc(extent, GFP_KERNEL);
	if (!bytes)
		return -ENOMEM;
	error = ffv2_store_read_all(store->payload_file, bytes, extent,
				    entry->payload_object_offset);
	if (!error)
		error = nfsd_ffv2_payload_decode(bytes, extent,
						 store->super.store_uuid, &payload,
						 &content_valid);
	if (!error && (payload.object_id != entry->payload_object_id ||
		       payload.content_len != entry->payload_content_len))
		error = -EBADMSG;
	kvfree(bytes);
	if (error)
		return error;
	*object_end = entry->payload_object_offset + extent;
	return 0;
}

bool nfsd_ffv2_payload_geometry_valid(u64 chunk_index, u32 content_len,
				      u32 chunk_bytes, u64 max_chunks)
{
	return chunk_index < 64 && chunk_index < max_chunks && content_len &&
	       content_len <= chunk_bytes;
}

static int ffv2_replay_entry(struct nfsd_ffv2_store *store,
			     const struct nfsd_ffv2_wal_header *header,
			     const struct nfsd_ffv2_entry_record *entry,
			     struct ffv2_scan_result *scan,
			     u64 *highest_payload_id)
{
	struct ffv2_transaction *transaction;
	struct ffv2_registration *registration;
	struct ffv2_admission *admission;
	u64 object_end;
	int error;

	registration = ffv2_replay_file(store, entry->file_key);
	if (!registration)
		return -EBADMSG;
	admission = ffv2_replay_admission_find(store,
					       entry->admission.client_id);
	if (entry->transition == NFSD_FFV2_REFUSED ||
	    entry->transition == NFSD_FFV2_ABORTED) {
		if (entry->admission.client_id &&
		    (!admission || !admission->authority_seen ||
		     memcmp(&admission->authority, &entry->admission,
			    sizeof(entry->admission))))
			return -EBADMSG;
	} else if (!admission || !admission->authority_seen ||
		   admission->incarnation != header->ds_incarnation ||
		   memcmp(&admission->authority, &entry->admission,
			  sizeof(entry->admission)) ||
		   (entry->payload_object_id &&
		    !(admission->authority.rights & NFSD_FFV2_RIGHT_WRITE)) ||
		   (admission->object_known &&
		    memcmp(admission->file_key, entry->file_key, 32))) {
		return -EBADMSG;
	} else if (!admission->object_known) {
		memcpy(admission->file_key, entry->file_key, 32);
		admission->object_known = true;
	}
	if (entry->payload_object_id &&
	    !nfsd_ffv2_payload_geometry_valid(entry->chunk_index,
					      entry->payload_content_len,
					      registration->chunk_bytes,
					      registration->max_chunks))
		return -EBADMSG;
	error = ffv2_replay_payload(store, entry, &object_end);
	if (error)
		return error;
	if (entry->payload_object_id) {
		if (entry->status != 1 || !entry->txn_id ||
		    store->transaction_count == NFSD_FFV2_MAX_TRANSACTIONS ||
		    entry->payload_object_id <= *highest_payload_id ||
		    ffv2_replay_transaction(store, entry->txn_id) ||
		    (entry->transition != NFSD_FFV2_PREPARED &&
		     entry->transition != NFSD_FFV2_FINALIZED &&
		     entry->transition != NFSD_FFV2_COMMITTED))
			return -EBADMSG;
		transaction = kzalloc_obj(*transaction, GFP_KERNEL);
		if (!transaction)
			return -ENOMEM;
		memcpy(transaction->file_key, entry->file_key, 32);
		transaction->chunk_index = entry->chunk_index;
		transaction->txn_id = entry->txn_id;
		transaction->payload_bytes = object_end -
					     entry->payload_object_offset;
		transaction->incarnation = header->ds_incarnation;
		transaction->admission_id = entry->admission.client_id;
		transaction->phase = entry->transition;
		list_add_tail(&transaction->node, &store->transactions);
		store->transaction_count++;
		*highest_payload_id = entry->payload_object_id;
		if (scan->payload_cursor < object_end)
			scan->payload_cursor = object_end;
		return 0;
	} else if (entry->transition == NFSD_FFV2_REFUSED ||
		   entry->transition == NFSD_FFV2_ABORTED) {
		return 0;
	}
	if (entry->transition != NFSD_FFV2_FINALIZED &&
	    entry->transition != NFSD_FFV2_COMMITTED &&
	    entry->transition != NFSD_FFV2_ROLLED_BACK)
		return -EBADMSG;
	transaction = ffv2_replay_transaction(store, entry->txn_id);
	if (!transaction ||
	    memcmp(transaction->file_key, entry->file_key, 32) ||
	    transaction->chunk_index != entry->chunk_index ||
	    transaction->incarnation != header->ds_incarnation ||
	    transaction->admission_id != entry->admission.client_id ||
	    (entry->transition == NFSD_FFV2_FINALIZED &&
	     transaction->phase != NFSD_FFV2_PREPARED) ||
	    (entry->transition == NFSD_FFV2_COMMITTED &&
	     transaction->phase != NFSD_FFV2_FINALIZED) ||
	    (entry->transition == NFSD_FFV2_ROLLED_BACK &&
	     transaction->phase != NFSD_FFV2_PREPARED &&
	     transaction->phase != NFSD_FFV2_FINALIZED))
		return -EBADMSG;
	transaction->phase = entry->transition;
	return 0;
}

static int ffv2_replay_account(struct nfsd_ffv2_store *store,
			       struct ffv2_scan_result *scan)
{
	struct ffv2_transaction *transaction;
	u64 wal = 0, staged = 0, add;

	list_for_each_entry(transaction, &store->transactions, node) {
		if (transaction->phase == NFSD_FFV2_PREPARED)
			add = 2 * NFSD_FFV2_ENTRY_RECORD_SIZE;
		else if (transaction->phase == NFSD_FFV2_FINALIZED)
			add = NFSD_FFV2_ENTRY_RECORD_SIZE;
		else
			continue;
		if (check_add_overflow(wal, add, &wal) ||
		    check_add_overflow(staged, transaction->payload_bytes, &staged))
			return -EOVERFLOW;
	}
	scan->live_wal_reserved = wal;
	scan->live_payload_staged = staged;
	return 0;
}

static int ffv2_store_decode_start(struct nfsd_ffv2_store *store,
				   const u8 *record, size_t len,
				   struct nfsd_ffv2_wal_header *header,
				   struct nfsd_ffv2_start_record *start)
{
	return nfsd_ffv2_start_decode(record, len, store->super.store_uuid,
				      store->super.wal_uuid, header, start);
}

static int
ffv2_store_decode_registration(struct nfsd_ffv2_store *store,
			       const u8 *record,
			       size_t len, struct nfsd_ffv2_wal_header *header,
			       struct nfsd_ffv2_file_register_record *registration)
{
	return nfsd_ffv2_file_register_decode(record, len,
					       store->super.store_uuid,
					       store->super.wal_uuid, header,
					       registration);
}

static int ffv2_replay_control(struct nfsd_ffv2_store *store,
			       const u8 *bytes, size_t len,
			       struct nfsd_ffv2_wal_header *header)
{
	struct nfsd_ffv2_control_record record;
	u32 subtype;
	int error;

	if (len < NFSD_FFV2_WAL_HEADER_SIZE + sizeof(__be32))
		return -EBADMSG;
	subtype = get_unaligned_be32(bytes + NFSD_FFV2_WAL_HEADER_SIZE);
	if (subtype == NFSD_FFV2_FILE_REGISTER) {
		struct nfsd_ffv2_file_register_record registration;

		error = ffv2_store_decode_registration(store, bytes, len, header,
						       &registration);
		return error ?: ffv2_replay_file_register(store, &registration);
	}
	error = nfsd_ffv2_control_decode(bytes, len, store->super.store_uuid,
					 store->super.wal_uuid, header, &record);
	if (error)
		return error;
	if (record.subtype == NFSD_FFV2_TRUST_STATEID)
		return ffv2_replay_trust(store, header, &record);
	if (record.subtype == NFSD_FFV2_AUTHORITY_ADMIT)
		return ffv2_replay_authority(store, &record);
	return -EOPNOTSUPP;
}

static int ffv2_store_decode_entry(struct nfsd_ffv2_store *store,
				   const u8 *record, size_t len,
				   struct nfsd_ffv2_wal_header *header,
				   struct nfsd_ffv2_entry_record *entry)
{
	return nfsd_ffv2_entry_decode(record, len, store->super.store_uuid,
				      store->super.wal_uuid, header, entry);
}

static int ffv2_store_scan_wal(struct nfsd_ffv2_store *store,
			       struct ffv2_scan_result *scan)
{
	loff_t size = i_size_read(file_inode(store->wal_file));
	u64 at = 0, expected_lsn = 1, incarnation = 0;
	u64 highest_payload_id = 0;
	u8 header_bytes[NFSD_FFV2_WAL_HEADER_SIZE];
	bool saw_start = false;
	int error;

	memset(scan, 0, sizeof(*scan));
	scan->payload_cursor = NFSD_FFV2_PAYLOAD_ALIGN;
	while (at < size) {
		u64 remain = size - at;
		u8 *record;
		u32 total = 0;
		bool all_zero;

		if (remain < NFSD_FFV2_WAL_HEADER_SIZE) {
			error = ffv2_store_zero_range(store->wal_file, at, remain,
						      &all_zero);
			if (error)
				return error;
			scan->nonzero_tail = !all_zero;
			break;
		}
		error = ffv2_store_read_all(store->wal_file, header_bytes,
					    sizeof(header_bytes), at);
		if (error)
			return error;
		if (!ffv2_wal_prologue_valid(header_bytes, store, &total) ||
		    total > NFSD_FFV2_MAX_WAL_RECORD_SIZE) {
			if (remain > NFSD_FFV2_MAX_DAMAGED_TAIL_SIZE)
				return -EBADMSG;
			error = ffv2_store_zero_range(store->wal_file, at, remain,
						      &all_zero);
			if (error)
				return error;
			if (all_zero)
				break;
			return -EBADMSG;
		}
		if (total > remain) {
			scan->nonzero_tail = true;
			break;
		}
		record = kmalloc(total, GFP_KERNEL);
		if (!record)
			return -ENOMEM;
		error = ffv2_store_read_all(store->wal_file, record, total, at);
		if (!error) {
			struct ffv2_cursor cursor = {
				.data = record,
				.capacity = total,
			};
			struct nfsd_ffv2_wal_header header;

			error = ffv2_get_wal_header(&cursor, total,
						    store->super.store_uuid,
						    store->super.wal_uuid,
						    &header);
			if (!error &&
			    !ffv2_crc_valid(ffv2_wal_domain, record,
					    header.total_bytes))
				error = -EBADMSG;
			if (!error &&
			    (header.lsn != expected_lsn ||
			     (!saw_start &&
			      header.family != NFSD_FFV2_WAL_START) ||
			     (saw_start && header.family != NFSD_FFV2_WAL_START &&
			      header.ds_incarnation != incarnation)))
				error = -EBADMSG;
			if (!error && header.family == NFSD_FFV2_WAL_START) {
				struct nfsd_ffv2_start_record start;

				error = ffv2_replay_account(store, scan);
				if (!error)
					error = ffv2_store_decode_start(store, record,
									total, &header, &start);
				if (!error &&
				    (start.prev_incarnation != incarnation ||
				     start.last_valid_lsn_before != expected_lsn - 1 ||
				     start.wal_append_cursor != at + total ||
				     start.payload_append_cursor != scan->payload_cursor ||
				     start.capacity_wal_bytes !=
						store->super.capacity_wal_bytes ||
				     start.capacity_payload_bytes !=
						store->super.capacity_payload_bytes ||
				     memcmp(start.export_uuid,
					    store->super.export_uuid, 16) ||
				     start.live_txn_wal_reserved !=
						scan->live_wal_reserved ||
				     start.live_txn_payload_outstanding ||
				     start.live_txn_payload_staged !=
						scan->live_payload_staged ||
				     (!saw_start &&
				      (header.lsn != 1 || header.ds_incarnation != 1 ||
				       start.verifier_epoch || start.verifier_changed ||
				       start.recovery_decision !=
					NFSD_FFV2_RECOVERY_FIRST_PROVISION)) ||
				     (saw_start && header.ds_incarnation !=
							incarnation + 1)))
					error = -EBADMSG;
				if (!error) {
					incarnation = header.ds_incarnation;
					saw_start = true;
				}
			} else if (!error &&
				   header.family == NFSD_FFV2_WAL_CONTROL) {
				error = ffv2_replay_control(store, record, total,
							    &header);
			} else if (!error &&
				   header.family == NFSD_FFV2_WAL_ENTRY) {
				struct nfsd_ffv2_entry_record entry;

				error = ffv2_store_decode_entry(store, record,
								total, &header, &entry);
				if (!error)
					error = ffv2_replay_entry(store, &header, &entry,
								  scan,
								  &highest_payload_id);
			} else if (!error) {
				/* COHORT replay is required before accepting its state. */
				error = -EOPNOTSUPP;
			}
		}
		kfree(record);
		if (error)
			return error == -ENOMEM ? error : -EBADMSG;
		at += total;
		expected_lsn++;
	}
	if (!saw_start || store->super.wal_durable_lsn > expected_lsn - 1 ||
	    store->super.wal_durable_bytes > at ||
	    store->super.payload_durable_bytes > scan->payload_cursor ||
	    store->super.ds_incarnation > incarnation)
		return -EBADMSG;
	scan->valid_bytes = at;
	scan->truncated_bytes = size - at;
	scan->last_lsn = expected_lsn - 1;
	scan->incarnation = incarnation;
	error = ffv2_replay_account(store, scan);
	if (error)
		return error;
	if (scan->truncated_bytes &&
	    (vfs_truncate(&store->wal_file->f_path, at) ||
	     vfs_fsync(store->wal_file, 0)))
		return -EIO;
	if (i_size_read(file_inode(store->payload_file)) > scan->payload_cursor &&
	    (vfs_truncate(&store->payload_file->f_path, scan->payload_cursor) ||
	     vfs_fsync(store->payload_file, 0)))
		return -EIO;
	return 0;
}

static void ffv2_store_verifier(const u8 store_uuid[16], u64 epoch, u8 out[8])
{
	u8 input[sizeof("FFV2-D2-VERIFIER-v1") - 1 + 24];
	u8 digest[SHA256_DIGEST_SIZE];
	__be64 encoded = cpu_to_be64(epoch);

	memcpy(input, "FFV2-D2-VERIFIER-v1",
	       sizeof("FFV2-D2-VERIFIER-v1") - 1);
	memcpy(input + sizeof("FFV2-D2-VERIFIER-v1") - 1, store_uuid, 16);
	memcpy(input + sizeof("FFV2-D2-VERIFIER-v1") - 1 + 16, &encoded, 8);
	sha256(input, sizeof(input), digest);
	memcpy(out, digest, 8);
}

static int ffv2_store_write_super(struct nfsd_ffv2_store *store,
				  const struct nfsd_ffv2_super_record *record)
{
	u8 *bytes;
	unsigned int slot = store->newest_slot ^ 1;
	int error;

	bytes = kmalloc(NFSD_FFV2_SUPER_SLOT_SIZE, GFP_KERNEL);
	if (!bytes)
		return -ENOMEM;
	error = nfsd_ffv2_super_encode(record, bytes);
	if (!error)
		error = ffv2_store_write_all(store->super_file, bytes,
					     NFSD_FFV2_SUPER_SLOT_SIZE,
					     slot * NFSD_FFV2_SUPER_SLOT_SIZE);
	if (!error)
		error = vfs_fsync(store->super_file, 0);
	kfree(bytes);
	if (error) {
		store->failed = true;
		return error;
	}
	store->super = *record;
	store->newest_slot = slot;
	return 0;
}

bool nfsd_ffv2_restart_fits(u64 valid_bytes, u64 live_wal_reserved,
			    u64 capacity_wal_bytes, u64 *append_cursor)
{
	u64 required;

	return !check_add_overflow((u64)NFSD_FFV2_START_RECORD_SIZE,
				   live_wal_reserved, &required) &&
	       !check_add_overflow(valid_bytes,
				   (u64)NFSD_FFV2_START_RECORD_SIZE,
				   append_cursor) &&
	       valid_bytes <= capacity_wal_bytes &&
	       required <= capacity_wal_bytes - valid_bytes;
}

static int ffv2_store_start(struct nfsd_ffv2_store *store,
			    const struct ffv2_scan_result *scan)
{
	struct nfsd_ffv2_wal_header header = {
		.family = NFSD_FFV2_WAL_START,
		.lsn = scan->last_lsn + 1,
		.ds_incarnation = scan->incarnation + 1,
	};
	struct nfsd_ffv2_start_record start = {
		.ds_incarnation = scan->incarnation + 1,
		.prev_incarnation = scan->incarnation,
		.recovery_decision = scan->truncated_bytes ?
			NFSD_FFV2_RECOVERY_TRUNCATED_TAIL :
			NFSD_FFV2_RECOVERY_CLEAN_SCAN,
		.truncated_bytes = scan->truncated_bytes,
		.last_valid_lsn_before = scan->last_lsn,
		.payload_append_cursor = scan->payload_cursor,
		.capacity_wal_bytes = store->super.capacity_wal_bytes,
		.capacity_payload_bytes = store->super.capacity_payload_bytes,
		.live_txn_wal_reserved = scan->live_wal_reserved,
		.live_txn_payload_staged = scan->live_payload_staged,
	};
	struct nfsd_ffv2_super_record next = store->super;
	u8 bytes[NFSD_FFV2_START_RECORD_SIZE];
	int error;

	/* RECOVERY_ADMIT charging and restart reap bytes remain unsupported. */
	if (!nfsd_ffv2_restart_fits(scan->valid_bytes,
				    scan->live_wal_reserved,
				    store->super.capacity_wal_bytes,
				    &start.wal_append_cursor) ||
	    scan->incarnation >= NFSD_FFV2_MAX_INCARNATION ||
	    store->super.generation == U64_MAX)
		return -ENOSPC;
	if (scan->nonzero_tail) {
		start.recovery_decision |=
			NFSD_FFV2_RECOVERY_TRUNCATED_NONZERO_TAIL;
		start.verifier_changed = true;
		start.verifier_epoch = start.ds_incarnation;
	} else {
		start.verifier_epoch = store->super.verifier_epoch;
	}
	memcpy(header.store_uuid, store->super.store_uuid, 16);
	memcpy(header.wal_uuid, store->super.wal_uuid, 16);
	memcpy(start.export_uuid, store->super.export_uuid, 16);
	error = nfsd_ffv2_start_encode(&header, &start, bytes);
	if (error)
		return error;
	error = vfs_fsync(store->payload_file, 0);
	if (!error)
		error = ffv2_store_write_all(store->wal_file, bytes, sizeof(bytes),
					     scan->valid_bytes);
	if (!error)
		error = vfs_fsync(store->wal_file, 0);
	if (error) {
		store->failed = true;
		return error;
	}
	store->wal_cursor = start.wal_append_cursor;
	store->payload_cursor = start.payload_append_cursor;
	store->wal_payload_cursor = start.payload_append_cursor;
	store->next_lsn = header.lsn + 1;
	next.generation++;
	next.ds_incarnation = start.ds_incarnation;
	next.verifier_epoch = start.verifier_epoch;
	if (start.verifier_changed)
		ffv2_store_verifier(next.store_uuid, next.verifier_epoch,
				    next.write_verifier);
	next.wal_durable_lsn = header.lsn;
	next.wal_durable_bytes = store->wal_cursor;
	next.payload_durable_bytes = store->payload_cursor;
	next.state = NFSD_FFV2_SUPER_CLEAN;
	return ffv2_store_write_super(store, &next);
}

int nfsd_ffv2_store_open(struct nfsd_ffv2_reservation *reservation,
			 struct nfsd_ffv2_store **result)
{
	struct nfsd_ffv2_store *store = NULL;
	struct path root;
	struct ffv2_scan_result scan;
	u8 store_uuid[16], export_uuid[16], binding_token[32];
	int error;

	if (!result)
		return -EINVAL;
	*result = NULL;
	error = nfsd_ffv2_reservation_store_root(reservation, &root, store_uuid,
						 export_uuid, binding_token);
	if (error)
		return error;
	error = nfsd_ffv2_reservation_store_begin(reservation);
	if (error)
		goto out_ref;
	if (root.mnt->mnt_sb->s_magic != XFS_SUPER_MAGIC) {
		error = -EOPNOTSUPP;
		goto out_end;
	}
	store = kzalloc(sizeof(*store), GFP_KERNEL);
	if (!store) {
		error = -ENOMEM;
		goto out_end;
	}
	store->reservation = reservation;
	mutex_init(&store->lock);
	INIT_LIST_HEAD(&store->registrations);
	INIT_LIST_HEAD(&store->transactions);
	INIT_LIST_HEAD(&store->admissions);
	store->super_file = ffv2_store_open_file(&root, "super");
	if (IS_ERR(store->super_file)) {
		error = PTR_ERR(store->super_file);
		store->super_file = NULL;
		goto out_store;
	}
	store->wal_file = ffv2_store_open_file(&root, "wal");
	if (IS_ERR(store->wal_file)) {
		error = PTR_ERR(store->wal_file);
		store->wal_file = NULL;
		goto out_store;
	}
	store->payload_file = ffv2_store_open_file(&root, "payload");
	if (IS_ERR(store->payload_file)) {
		error = PTR_ERR(store->payload_file);
		store->payload_file = NULL;
		goto out_store;
	}
	error = ffv2_store_read_super(store, store_uuid);
	if (error)
		goto out_store;
	error = ffv2_store_validate_files(store, &root, export_uuid,
					  binding_token);
	if (error)
		goto out_store;
	error = ffv2_store_scan_wal(store, &scan);
	if (error)
		goto out_store;
	error = ffv2_store_start(store, &scan);
	if (error)
		goto out_store;
	nfsd_ffv2_reservation_store_end(reservation);
	path_put(&root);
	*result = store;
	return 0;

out_store:
	nfsd_ffv2_reservation_store_end(reservation);
	nfsd_ffv2_store_close(store);
	path_put(&root);
	return error;
out_end:
	nfsd_ffv2_reservation_store_end(reservation);
out_ref:
	nfsd_ffv2_reservation_store_put(reservation);
	path_put(&root);
	return error;
}

void nfsd_ffv2_store_close(struct nfsd_ffv2_store *store)
{
	if (!store)
		return;
	if (store->payload_file)
		fput(store->payload_file);
	if (store->wal_file)
		fput(store->wal_file);
	if (store->super_file)
		fput(store->super_file);
	ffv2_store_replay_free(store);
	mutex_destroy(&store->lock);
	nfsd_ffv2_reservation_store_put(store->reservation);
	kfree(store);
}

int nfsd_ffv2_store_get_super(struct nfsd_ffv2_store *store,
			      struct nfsd_ffv2_super_record *record)
{
	int error;

	error = nfsd_ffv2_reservation_store_begin(store->reservation);
	if (error)
		return error;
	mutex_lock(&store->lock);
	*record = store->super;
	mutex_unlock(&store->lock);
	nfsd_ffv2_reservation_store_end(store->reservation);
	return 0;
}

static int ffv2_store_read_range_valid(struct file *file, size_t len,
				       loff_t offset)
{
	loff_t end;

	if (len > LLONG_MAX || offset < 0 ||
	    check_add_overflow(offset, (loff_t)len, &end) ||
	    end > i_size_read(file_inode(file)))
		return -EIO;
	return 0;
}

static int ffv2_store_write_range_valid(struct file *file, u64 capacity,
					size_t len, loff_t offset)
{
	loff_t end;

	if (i_size_read(file_inode(file)) > capacity)
		return -EBADMSG;
	if (len > LLONG_MAX || offset < 0 ||
	    check_add_overflow(offset, (loff_t)len, &end) ||
	    end > capacity)
		return -EFBIG;
	return 0;
}

int nfsd_ffv2_store_read_payload(struct nfsd_ffv2_store *store, void *data,
				 size_t len, loff_t offset)
{
	int error;

	error = nfsd_ffv2_reservation_store_begin(store->reservation);
	if (error)
		return error;
	mutex_lock(&store->lock);
	error = ffv2_store_read_range_valid(store->payload_file, len, offset);
	if (!error)
		error = ffv2_store_read_all(store->payload_file, data, len, offset);
	mutex_unlock(&store->lock);
	nfsd_ffv2_reservation_store_end(store->reservation);
	return error;
}

int nfsd_ffv2_store_append_payload(struct nfsd_ffv2_store *store,
				   const struct nfsd_ffv2_payload_record *record,
				   u64 *offset)
{
	size_t len, written;
	u8 *data;
	int error;

	if (!store || !record || !offset ||
	    memcmp(record->store_uuid, store->super.store_uuid, 16))
		return -EINVAL;
	len = nfsd_ffv2_payload_record_size(record->content_len);
	if (!len)
		return -EOVERFLOW;
	data = kvmalloc(len, GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	error = nfsd_ffv2_payload_encode(record, data, len, &written);
	if (error)
		goto out;
	if (written != len) {
		error = -EIO;
		goto out;
	}
	error = nfsd_ffv2_reservation_store_begin(store->reservation);
	if (error)
		goto out;
	mutex_lock(&store->lock);
	if (store->failed || store->payload_cursor !=
				 i_size_read(file_inode(store->payload_file))) {
		store->failed = true;
		error = -EIO;
		goto out_unlock;
	}
	error = ffv2_store_write_range_valid(store->payload_file,
					     store->super.capacity_payload_bytes,
					     len, store->payload_cursor);
	if (!error)
		error = ffv2_store_write_all(store->payload_file, data, len,
					     store->payload_cursor);
#ifdef CONFIG_NFSD_FFV2_LIVE_TEST
	if (!error && store->fail_next_io) {
		store->fail_next_io = false;
		error = -EIO;
	}
#endif
	if (!error)
		error = vfs_fsync(store->payload_file, 0);
	if (error) {
		store->failed = true;
	} else {
		*offset = store->payload_cursor;
		store->payload_cursor += len;
	}
out_unlock:
	mutex_unlock(&store->lock);
	nfsd_ffv2_reservation_store_end(store->reservation);
out:
	kvfree(data);
	return error;
}

#ifdef CONFIG_NFSD_FFV2_LIVE_TEST
void nfsd_ffv2_store_test_fail_next_io(struct nfsd_ffv2_store *store)
{
	mutex_lock(&store->lock);
	store->fail_next_io = true;
	mutex_unlock(&store->lock);
}

u64 nfsd_ffv2_store_test_payload_size(struct nfsd_ffv2_store *store)
{
	return i_size_read(file_inode(store->payload_file));
}
#endif

int nfsd_ffv2_store_read_wal(struct nfsd_ffv2_store *store, void *data,
			     size_t len, loff_t offset)
{
	int error;

	error = nfsd_ffv2_reservation_store_begin(store->reservation);
	if (error)
		return error;
	mutex_lock(&store->lock);
	error = ffv2_store_read_range_valid(store->wal_file, len, offset);
	if (!error)
		error = ffv2_store_read_all(store->wal_file, data, len, offset);
	mutex_unlock(&store->lock);
	nfsd_ffv2_reservation_store_end(store->reservation);
	return error;
}

int nfsd_ffv2_store_checkpoint(struct nfsd_ffv2_store *store,
			       const struct nfsd_ffv2_super_record *record)
{
	int error;

	if (!store || !record)
		return -EINVAL;
	error = nfsd_ffv2_reservation_store_begin(store->reservation);
	if (error)
		return error;
	mutex_lock(&store->lock);
	if (store->failed) {
		error = -EIO;
		goto out_unlock;
	}
	if (memcmp(record->store_uuid, store->super.store_uuid, 16) ||
	    memcmp(record->fs_uuid, store->super.fs_uuid, 16) ||
	    memcmp(record->export_uuid, store->super.export_uuid, 16) ||
	    memcmp(record->wal_uuid, store->super.wal_uuid, 16) ||
	    memcmp(record->payload_uuid, store->super.payload_uuid, 16) ||
	    memcmp(record->binding_token_digest,
		   store->super.binding_token_digest, 32) ||
	    record->fs_dev_hint != store->super.fs_dev_hint ||
	    record->root_handle_type != store->super.root_handle_type ||
	    record->root_handle_len != store->super.root_handle_len ||
	    memcmp(record->root_handle, store->super.root_handle,
		   sizeof(record->root_handle)) ||
	    record->ds_incarnation != store->super.ds_incarnation ||
	    record->verifier_epoch != store->super.verifier_epoch ||
	    memcmp(record->write_verifier, store->super.write_verifier, 8) ||
	    record->state != NFSD_FFV2_SUPER_CLEAN ||
	    record->format_floor != store->super.format_floor ||
	    record->generation <= store->super.generation ||
	    record->capacity_wal_bytes != store->super.capacity_wal_bytes ||
	    record->capacity_payload_bytes != store->super.capacity_payload_bytes ||
	    record->wal_durable_lsn != store->next_lsn - 1 ||
	    record->wal_durable_bytes != store->wal_cursor ||
	    record->payload_durable_bytes != store->wal_payload_cursor) {
		error = -EINVAL;
		goto out_unlock;
	}
	if (i_size_read(file_inode(store->super_file)) !=
					       NFSD_FFV2_SUPER_FILE_SIZE) {
		error = -EBADMSG;
		goto out_unlock;
	}
	error = ffv2_store_write_range_valid(store->payload_file,
					     store->super.capacity_payload_bytes,
					     0, 0);
	if (error)
		goto out_unlock;
	error = ffv2_store_write_range_valid(store->wal_file,
					     store->super.capacity_wal_bytes,
					     0, 0);
	if (error)
		goto out_unlock;
	if (record->payload_durable_bytes >
				i_size_read(file_inode(store->payload_file)) ||
	    record->wal_durable_bytes > i_size_read(file_inode(store->wal_file))) {
		error = -EINVAL;
		goto out_unlock;
	}
	error = vfs_fsync(store->payload_file, 0);
	if (error)
		goto out_failed;
	error = vfs_fsync(store->wal_file, 0);
	if (error)
		goto out_failed;
	error = ffv2_store_write_super(store, record);
	goto out_unlock;
out_failed:
	store->failed = true;
out_unlock:
	mutex_unlock(&store->lock);
	nfsd_ffv2_reservation_store_end(store->reservation);
	return error;
}
