// SPDX-License-Identifier: GPL-2.0-only
#include <linux/crc32.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/overflow.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <crypto/sha2.h>

#include "ffv2_store.h"

#define FFV2_SUPER_MAGIC	0x44325342
#define FFV2_WAL_MAGIC		0x4432574c
#define FFV2_PAYLOAD_MAGIC	0x44325059

static const char ffv2_super_domain[] = "FFV2-D2-SB-v1";
static const char ffv2_wal_domain[] = "FFV2-D2-WAL-v1";
static const char ffv2_payload_domain[] = "FFV2-D2-PAY-v1";

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
	u8 predecessor_present, postcond_present, result_activated;
	u8 result_guard_never_written;
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
	ffv2_get_bytes(&cursor, record->session, sizeof(record->session));
	record->slot = ffv2_get_u32(&cursor);
	record->sequence = ffv2_get_u32(&cursor);
	record->ordinal = ffv2_get_u32(&cursor);
	ffv2_get_bytes(&cursor, record->operation_key,
		       sizeof(record->operation_key));
	ffv2_get_bytes(&cursor, record->request_digest,
		       sizeof(record->request_digest));
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
	record->writer_payload_id = ffv2_get_u32(&cursor);
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
	    !ffv2_operation_key_valid(record->operation_key, record->session,
				      record->slot, record->sequence,
				      record->ordinal) ||
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
	    (!record->payload_object_id && record->writer_payload_id) ||
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

static bool ffv2_store_checksum_valid(u32 algorithm, const u8 *checksum,
				      u32 checksum_len, const u8 *content,
				      u32 content_len)
{
	u8 computed[NFSD_FFV2_STORE_CHECKSUM_SIZE] = {};
	u32 expected_len;
	u64 a = 0, b = 0, c = 0, d = 0;
	u32 i;

	switch (algorithm) {
	case NFSD_FFV2_STORE_CHECKSUM_NONE:
		expected_len = 0;
		break;
	case NFSD_FFV2_STORE_CHECKSUM_CRC32:
		expected_len = sizeof(__be32);
		put_unaligned_be32(~crc32_le(~0, content, content_len),
				   computed);
		break;
	case NFSD_FFV2_STORE_CHECKSUM_CRC32C:
		expected_len = sizeof(__be32);
		put_unaligned_be32(~crc32c(~0, content, content_len), computed);
		break;
	case NFSD_FFV2_STORE_CHECKSUM_FLETCHER4:
		if (!IS_ALIGNED(content_len, sizeof(u32)))
			return false;
		expected_len = 4 * sizeof(__be64);
		for (i = 0; i < content_len; i += sizeof(u32)) {
			a += get_unaligned_le32(content + i);
			b += a;
			c += b;
			d += c;
		}
		put_unaligned_be64(a, computed);
		put_unaligned_be64(b, computed + 8);
		put_unaligned_be64(c, computed + 16);
		put_unaligned_be64(d, computed + 24);
		break;
	case NFSD_FFV2_STORE_CHECKSUM_SHA256:
		expected_len = SHA256_DIGEST_SIZE;
		sha256(content, content_len, computed);
		break;
	default:
		return false;
	}
	return checksum_len == expected_len &&
	       !memcmp(checksum, computed, sizeof(computed));
}

static bool
ffv2_payload_checksum_valid(const struct nfsd_ffv2_payload_record *record)
{
	return ffv2_store_checksum_valid(record->checksum_algorithm,
					      record->checksum,
					      record->checksum_len,
					      record->content,
					      record->content_len);
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
			   NFSD_FFV2_STORE_CHECKSUM_SIZE -
				   record->checksum_len) ||
	    total != NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE + record->content_len +
			     4 ||
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
	*content_valid = stored_crc == ~crc32c(~0, record->content,
					       record->content_len) &&
			 ffv2_payload_checksum_valid(record);
	return 0;
}

bool nfsd_ffv2_payload_geometry_valid(u64 chunk_index, u32 content_len,
				      u32 chunk_bytes, u64 max_chunks)
{
	return chunk_index < 64 && chunk_index < max_chunks && content_len &&
	       content_len <= chunk_bytes;
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
