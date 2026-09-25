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

static void ffv2_operation_key(const u8 session[16], u32 slot, u32 sequence,
			       u32 ordinal, u8 operation_key[32])
{
	u8 input[sizeof("FFV2-D2-OPKEY-v1") - 1 + 28];
	u8 *at = input;

	memcpy(at, "FFV2-D2-OPKEY-v1", sizeof("FFV2-D2-OPKEY-v1") - 1);
	at += sizeof("FFV2-D2-OPKEY-v1") - 1;
	memcpy(at, session, 16);
	at += 16;
	put_unaligned_be32(slot, at);
	put_unaligned_be32(sequence, at + 4);
	put_unaligned_be32(ordinal, at + 8);
	sha256(input, sizeof(input), operation_key);
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

static int
ffv2_control_encode(const struct nfsd_ffv2_wal_header *header, u32 subtype,
		    const struct nfsd_ffv2_store_operation *operation,
		    const u8 issuer[16], u64 authority_epoch, u64 client_id,
		    const u8 *body, u32 body_len, u8 *out, size_t capacity)
{
	struct ffv2_cursor cursor = { .data = out, .capacity = capacity };
	u8 operation_key[32];
	u32 total;

	if (check_add_overflow((u32)(NFSD_FFV2_WAL_HEADER_SIZE +
				       NFSD_FFV2_CONTROL_PREFIX_SIZE + 4),
			       body_len, &total) || total != capacity)
		return -EOVERFLOW;
	ffv2_operation_key(operation->session, operation->slot,
			   operation->sequence, operation->ordinal,
			   operation_key);
	ffv2_put_wal_header(&cursor, header, total);
	ffv2_put_u32(&cursor, subtype);
	ffv2_put_u32(&cursor, NFSD_FFV2_COMMITTED);
	ffv2_put_u32(&cursor, 1);
	ffv2_put_bytes(&cursor, operation_key, sizeof(operation_key));
	ffv2_put_bytes(&cursor, operation->request_digest,
		       sizeof(operation->request_digest));
	ffv2_put_bytes(&cursor, operation->session, sizeof(operation->session));
	ffv2_put_u32(&cursor, operation->slot);
	ffv2_put_u32(&cursor, operation->sequence);
	ffv2_put_u32(&cursor, operation->ordinal);
	ffv2_put_bytes(&cursor, issuer, 16);
	ffv2_put_u64(&cursor, authority_epoch);
	ffv2_put_u64(&cursor, client_id);
	ffv2_put_bytes(&cursor, body, body_len);
	if (cursor.failed || cursor.offset != total - 4)
		return -EOVERFLOW;
	ffv2_put_crc(&cursor, ffv2_wal_domain, out, cursor.offset);
	return cursor.failed ? -EOVERFLOW : 0;
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

static int
ffv2_entry_encode(const struct nfsd_ffv2_wal_header *header,
		  const struct nfsd_ffv2_entry_record *record,
		  u8 out[NFSD_FFV2_ENTRY_RECORD_SIZE])
{
	struct ffv2_cursor cursor = {
		.data = out,
		.capacity = NFSD_FFV2_ENTRY_RECORD_SIZE,
	};

	if (!header || !record || !out ||
	    header->family != NFSD_FFV2_WAL_ENTRY || !header->lsn ||
	    !ffv2_entry_pair_valid(record->transition, record->status))
		return -EINVAL;
	ffv2_put_wal_header(&cursor, header, NFSD_FFV2_ENTRY_RECORD_SIZE);
	ffv2_put_u32(&cursor, record->transition);
	ffv2_put_u32(&cursor, record->status);
	ffv2_put_u32(&cursor, record->disposition);
	ffv2_put_u32(&cursor, record->stability);
	ffv2_put_u32(&cursor, record->batch_ordinal);
	ffv2_put_u32(&cursor, record->batch_count);
	ffv2_put_bytes(&cursor, record->file_key, sizeof(record->file_key));
	ffv2_put_u64(&cursor, record->chunk_index);
	ffv2_put_u64(&cursor, record->txn_id);
	ffv2_put_bytes(&cursor, record->session, sizeof(record->session));
	ffv2_put_u32(&cursor, record->slot);
	ffv2_put_u32(&cursor, record->sequence);
	ffv2_put_u32(&cursor, record->ordinal);
	ffv2_put_bytes(&cursor, record->operation_key,
		       sizeof(record->operation_key));
	ffv2_put_bytes(&cursor, record->request_digest,
		       sizeof(record->request_digest));
	ffv2_put_bytes(&cursor, record->admission.session,
		       sizeof(record->admission.session));
	ffv2_put_bytes(&cursor, record->admission.principal,
		       sizeof(record->admission.principal));
	ffv2_put_bytes(&cursor, record->admission.issuer,
		       sizeof(record->admission.issuer));
	ffv2_put_u64(&cursor, record->admission.authority_epoch);
	ffv2_put_u64(&cursor, record->admission.fence_sequence);
	ffv2_put_u64(&cursor, record->admission.lease_epoch);
	ffv2_put_u64(&cursor, record->admission.client_id);
	ffv2_put_u32(&cursor, record->admission.stateid_seqid);
	ffv2_put_bytes(&cursor, record->admission.stateid_other,
		       sizeof(record->admission.stateid_other));
	ffv2_put_u32(&cursor, record->admission.writer);
	ffv2_put_u32(&cursor, record->admission.rights);
	ffv2_put_u64(&cursor, record->owner_cohort);
	ffv2_put_u32(&cursor, record->owner_client_id);
	ffv2_put_u32(&cursor, record->owner_co_id);
	ffv2_put_u32(&cursor, record->generation);
	ffv2_put_u8(&cursor, record->predecessor_present);
	ffv2_put_u64(&cursor, record->predecessor_object_id);
	ffv2_put_u32(&cursor, record->predecessor_generation);
	ffv2_put_u8(&cursor, record->postcond_present);
	ffv2_put_u64(&cursor, record->postcond_id);
	ffv2_put_u64(&cursor, record->payload_object_id);
	ffv2_put_u32(&cursor, record->writer_payload_id);
	ffv2_put_u64(&cursor, record->payload_object_offset);
	ffv2_put_u32(&cursor, record->payload_content_len);
	ffv2_put_u32(&cursor, record->extent_kind);
	ffv2_put_u64(&cursor, record->extent_high_water);
	ffv2_put_u64(&cursor, record->extent_highest_index);
	ffv2_put_u64(&cursor, record->index_generation);
	ffv2_put_bytes(&cursor, record->result_verifier,
		       sizeof(record->result_verifier));
	ffv2_put_u8(&cursor, record->result_activated);
	ffv2_put_u64(&cursor, record->result_visible_object_id);
	ffv2_put_u32(&cursor, record->result_effective_len);
	ffv2_put_u32(&cursor, record->result_checksum_algorithm);
	ffv2_put_u32(&cursor, record->result_checksum_len);
	ffv2_put_bytes(&cursor, record->result_checksum,
		       sizeof(record->result_checksum));
	ffv2_put_u8(&cursor, record->result_guard_never_written);
	ffv2_put_u32(&cursor, record->result_guard_generation);
	ffv2_put_u32(&cursor, record->result_guard_writer);
	if (cursor.failed || cursor.offset != NFSD_FFV2_ENTRY_RECORD_SIZE - 4)
		return -EOVERFLOW;
	ffv2_put_crc(&cursor, ffv2_wal_domain, out, cursor.offset);
	return cursor.failed ? -EOVERFLOW : 0;
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

bool nfsd_ffv2_store_checksum_valid(u32 algorithm, const u8 *checksum,
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
	return nfsd_ffv2_store_checksum_valid(record->checksum_algorithm,
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
	u64 index_generation;
	u64 next_txn_id;
	u64 next_version_id;
	u64 next_payload_sequence;
	u64 next_admission_id;
	struct list_head registrations;
	struct list_head transactions;
	struct list_head owners;
	struct list_head admissions;
	struct list_head receipts;
	u32 registration_count;
	u32 transaction_count;
	u32 admission_count;
	bool failed;
#ifdef CONFIG_NFSD_FFV2_LIVE_TEST
	bool fail_next_io;
	bool fail_next_alloc;
#endif
};

struct ffv2_transaction;

struct ffv2_receipt {
	struct list_head node;
	struct nfsd_ffv2_entry_record entry;
};

struct ffv2_registration {
	struct list_head node;
	u8 file_key[32];
	u8 handle[32];
	u32 chunk_bytes;
	u64 max_chunks;
	struct ffv2_transaction *visible[64];
	struct ffv2_transaction *pending[64];
	u64 logical_eof;
	struct {
		u32 generation;
		u32 writer;
		bool never_written;
	} guard[64];
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
	struct list_head owner_node;
	u8 file_key[32];
	u64 chunk_index;
	u64 txn_id;
	u64 version_object_id;
	u32 version_generation;
	bool predecessor_present;
	u64 predecessor_object_id;
	u32 predecessor_generation;
	u64 payload_object_id;
	u32 writer_payload_id;
	u64 payload_object_offset;
	u32 content_len;
	u32 content_crc32c;
	u32 checksum_algorithm;
	u32 checksum_len;
	u8 checksum[NFSD_FFV2_STORE_CHECKSUM_SIZE];
	u64 owner_cohort;
	u32 owner_client_id;
	u32 owner_co_id;
	u32 guard_generation;
	u32 guard_writer;
	bool guard_never_written;
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

static int ffv2_store_append_wal_locked(struct nfsd_ffv2_store *store,
					const u8 *data, size_t len);
static int ffv2_store_wal_fits(struct nfsd_ffv2_store *store,
			       u64 append, u64 additional_reserve);

static void ffv2_store_replay_free(struct nfsd_ffv2_store *store)
{
	struct ffv2_registration *registration, *next_registration;
	struct ffv2_transaction *transaction, *next_transaction;
	struct ffv2_admission *admission, *next_admission;
	struct ffv2_receipt *receipt, *next_receipt;

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
	list_for_each_entry_safe(receipt, next_receipt, &store->receipts, node) {
		list_del(&receipt->node);
		kfree(receipt);
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
	u32 i;

	if (store->registration_count == NFSD_FFV2_MAX_OBJECTS)
		return -EBADMSG;
	list_for_each_entry(registration, &store->registrations, node)
		if (!memcmp(registration->file_key, record->file_key, 32) ||
		    !memcmp(registration->handle, record->handle, 32))
			return -EBADMSG;
	registration = kzalloc_obj(*registration, GFP_KERNEL);
	if (!registration)
		return -ENOMEM;
	memcpy(registration->file_key, record->file_key, 32);
	memcpy(registration->handle, record->handle, 32);
	registration->chunk_bytes = record->chunk_bytes;
	registration->max_chunks = record->max_chunks;
	for (i = 0; i < ARRAY_SIZE(registration->guard); i++)
		registration->guard[i].never_written = true;
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
			     const struct nfsd_ffv2_control_record *record,
			     struct ffv2_admission *new_admission)
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
	admission = new_admission;
	if (!admission) {
		admission = kzalloc_obj(*admission, GFP_KERNEL);
		if (!admission)
			return -ENOMEM;
	}
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

static struct ffv2_transaction *
ffv2_replay_owner(struct nfsd_ffv2_store *store, u64 cohort, u32 client_id,
		  u32 co_id)
{
	struct ffv2_transaction *transaction;

	list_for_each_entry(transaction, &store->owners, owner_node)
		if (transaction->owner_cohort == cohort &&
		    transaction->owner_client_id == client_id &&
		    transaction->owner_co_id == co_id)
			return transaction;
	return NULL;
}

static struct ffv2_receipt *
ffv2_replay_receipt(struct nfsd_ffv2_store *store, const u8 operation_key[32])
{
	struct ffv2_receipt *receipt;

	list_for_each_entry(receipt, &store->receipts, node)
		if (!memcmp(receipt->entry.operation_key, operation_key, 32))
			return receipt;
	return NULL;
}

static int
ffv2_replay_receipt_add(struct nfsd_ffv2_store *store,
			const struct nfsd_ffv2_entry_record *entry,
			struct ffv2_receipt *receipt)
{
	if (ffv2_replay_receipt(store, entry->operation_key))
		return -EBADMSG;
	if (!receipt) {
		receipt = kmalloc_obj(*receipt, GFP_KERNEL);
		if (!receipt)
			return -ENOMEM;
	}
	receipt->entry = *entry;
	list_add_tail(&receipt->node, &store->receipts);
	return 0;
}

static int ffv2_replay_payload(struct nfsd_ffv2_store *store,
			       const struct nfsd_ffv2_entry_record *entry,
			       u64 *object_end,
			       struct nfsd_ffv2_payload_record *result)
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
	if (!error && result) {
		*result = payload;
		result->content = NULL;
	}
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

static struct ffv2_transaction *
ffv2_replay_version(struct nfsd_ffv2_store *store, u64 version_object_id)
{
	struct ffv2_transaction *transaction;

	list_for_each_entry(transaction, &store->transactions, node)
		if (transaction->version_object_id == version_object_id)
			return transaction;
	return NULL;
}

static int ffv2_replay_extent(struct nfsd_ffv2_store *store,
			      struct ffv2_registration *registration,
			      const struct nfsd_ffv2_entry_record *entry,
			      u64 prior_eof)
{
	u64 eof = 0, end, highest = 0;
	u32 kind, i;
	bool any = false;

	for (i = 0; i < ARRAY_SIZE(registration->visible); i++) {
		struct ffv2_transaction *version = registration->visible[i];

		if (!version)
			continue;
		if (check_mul_overflow((u64)i, (u64)registration->chunk_bytes,
				       &end) ||
		    check_add_overflow(end, (u64)version->content_len, &end))
			return -EBADMSG;
		if (end > eof)
			eof = end;
		if (!any || i > highest)
			highest = i;
		any = true;
	}
	kind = eof > prior_eof ? 2 : eof < prior_eof ? 3 : 1;
	if (entry->extent_kind != kind || entry->extent_high_water != eof ||
	    entry->extent_highest_index != (any ? highest : 0) ||
	    entry->index_generation != store->index_generation)
		return -EBADMSG;
	registration->logical_eof = eof;
	return 0;
}

static int ffv2_replay_entry_identity(
	const struct ffv2_transaction *transaction,
	const struct nfsd_ffv2_entry_record *entry)
{
	if (transaction->chunk_index != entry->chunk_index ||
	    transaction->txn_id != entry->txn_id ||
	    transaction->owner_cohort != entry->owner_cohort ||
	    transaction->owner_client_id != entry->owner_client_id ||
	    transaction->owner_co_id != entry->owner_co_id ||
	    transaction->predecessor_present != entry->predecessor_present ||
	    transaction->predecessor_object_id != entry->predecessor_object_id ||
	    transaction->predecessor_generation != entry->predecessor_generation ||
	    entry->generation != transaction->guard_generation ||
	    entry->result_guard_generation != transaction->guard_generation ||
	    entry->result_guard_writer != transaction->guard_writer ||
	    entry->result_guard_never_written !=
					transaction->guard_never_written)
		return -EBADMSG;
	return 0;
}

static int ffv2_replay_publish(struct nfsd_ffv2_store *store,
			       struct ffv2_registration *registration,
			       struct ffv2_transaction *transaction)
{
	struct ffv2_transaction *predecessor = NULL;

	if (transaction->predecessor_present) {
		predecessor = ffv2_replay_version(
			store, transaction->predecessor_object_id);
		if (!predecessor ||
		    memcmp(predecessor->file_key, transaction->file_key, 32) ||
		    predecessor->chunk_index != transaction->chunk_index ||
		    predecessor->version_generation !=
					transaction->predecessor_generation)
			return -EBADMSG;
	}
	if (registration->visible[transaction->chunk_index] != predecessor ||
	    store->index_generation == U64_MAX)
		return -EBADMSG;
	registration->visible[transaction->chunk_index] = transaction;
	store->index_generation++;
	return 0;
}

static int ffv2_replay_unpublish(struct nfsd_ffv2_store *store,
				 struct ffv2_registration *registration,
				 struct ffv2_transaction *transaction)
{
	struct ffv2_transaction *predecessor = NULL;

	if (registration->visible[transaction->chunk_index] != transaction)
		return -EBADMSG;
	if (transaction->predecessor_present) {
		predecessor = ffv2_replay_version(
			store, transaction->predecessor_object_id);
		if (!predecessor ||
		    memcmp(predecessor->file_key, transaction->file_key, 32) ||
		    predecessor->chunk_index != transaction->chunk_index ||
		    predecessor->version_generation !=
					transaction->predecessor_generation)
			return -EBADMSG;
	}
	if (store->index_generation == U64_MAX)
		return -EBADMSG;
	registration->visible[transaction->chunk_index] = predecessor;
	store->index_generation++;
	return 0;
}

static int ffv2_replay_visible_entry(
	struct nfsd_ffv2_store *store,
	struct ffv2_registration *registration,
	const struct nfsd_ffv2_wal_header *header,
	const struct nfsd_ffv2_entry_record *entry,
	const struct nfsd_ffv2_payload_record *payload, u64 object_end,
	struct ffv2_transaction *new_transaction)
{
	struct ffv2_transaction *transaction, *predecessor;
	u64 prior_eof;
	int error;

	prior_eof = registration->logical_eof;
	if (entry->postcond_present)
		return -EBADMSG;
	if (entry->payload_object_id) {
		if (entry->status != 1 || !entry->txn_id ||
		    store->transaction_count == NFSD_FFV2_MAX_TRANSACTIONS ||
		    !entry->result_visible_object_id ||
		    ffv2_replay_transaction(store, entry->txn_id) ||
		    ffv2_replay_version(store, entry->result_visible_object_id) ||
		    ffv2_replay_owner(store, entry->owner_cohort,
				      entry->owner_client_id,
				      entry->owner_co_id) ||
		    entry->owner_client_id != entry->admission.writer ||
		    registration->pending[entry->chunk_index] ||
		    (entry->transition != NFSD_FFV2_PREPARED &&
		     entry->transition != NFSD_FFV2_COMMITTED) ||
		    entry->result_activated !=
				(entry->transition == NFSD_FFV2_COMMITTED) ||
		    entry->result_effective_len != entry->payload_content_len ||
		    entry->result_checksum_algorithm !=
						payload->checksum_algorithm ||
		    entry->result_checksum_len != payload->checksum_len ||
		    memcmp(entry->result_checksum, payload->checksum,
			   sizeof(entry->result_checksum)) ||
		    entry->generation != entry->result_guard_generation ||
		    entry->result_guard_never_written)
			return -EBADMSG;
		predecessor = registration->visible[entry->chunk_index];
		if (entry->predecessor_present != !!predecessor ||
		    (predecessor &&
		     (entry->predecessor_object_id !=
						predecessor->version_object_id ||
		      entry->predecessor_generation !=
						predecessor->version_generation)))
			return -EBADMSG;
		if (registration->guard[entry->chunk_index].never_written) {
			if (entry->generation)
				return -EBADMSG;
		} else if (registration->guard[entry->chunk_index].generation ==
								     U32_MAX ||
			   entry->generation !=
			     registration->guard[entry->chunk_index].generation + 1) {
			return -EBADMSG;
		}
		if (entry->result_guard_writer != entry->admission.writer)
			return -EBADMSG;
		transaction = new_transaction;
		if (!transaction) {
			transaction = kzalloc_obj(*transaction, GFP_KERNEL);
			if (!transaction)
				return -ENOMEM;
		}
		memcpy(transaction->file_key, entry->file_key, 32);
		transaction->chunk_index = entry->chunk_index;
		transaction->txn_id = entry->txn_id;
		transaction->version_object_id =
						entry->result_visible_object_id;
		transaction->version_generation = entry->generation;
		transaction->predecessor_present = entry->predecessor_present;
		transaction->predecessor_object_id =
						entry->predecessor_object_id;
		transaction->predecessor_generation =
						entry->predecessor_generation;
		transaction->payload_object_id = entry->payload_object_id;
		transaction->writer_payload_id = entry->writer_payload_id;
		transaction->payload_object_offset = entry->payload_object_offset;
		transaction->content_len = entry->payload_content_len;
		transaction->content_crc32c = payload->content_crc32c;
		transaction->checksum_algorithm = payload->checksum_algorithm;
		transaction->checksum_len = payload->checksum_len;
		memcpy(transaction->checksum, payload->checksum,
		       sizeof(transaction->checksum));
		transaction->owner_cohort = entry->owner_cohort;
		transaction->owner_client_id = entry->owner_client_id;
		transaction->owner_co_id = entry->owner_co_id;
		transaction->guard_generation = entry->result_guard_generation;
		transaction->guard_writer = entry->result_guard_writer;
		transaction->guard_never_written =
					entry->result_guard_never_written;
		transaction->payload_bytes = object_end -
					     entry->payload_object_offset;
		transaction->incarnation = header->ds_incarnation;
		transaction->admission_id = entry->admission.client_id;
		transaction->phase = entry->transition;
		list_add_tail(&transaction->node, &store->transactions);
		list_add_tail(&transaction->owner_node, &store->owners);
		store->transaction_count++;
		registration->guard[entry->chunk_index].never_written = false;
		registration->guard[entry->chunk_index].generation =
							 entry->generation;
		registration->guard[entry->chunk_index].writer =
						 entry->result_guard_writer;
		if (entry->transition == NFSD_FFV2_COMMITTED) {
			error = ffv2_replay_publish(store, registration,
						    transaction);
			if (error)
				return error;
		} else {
			registration->pending[entry->chunk_index] = transaction;
		}
		return ffv2_replay_extent(store, registration, entry,
					  prior_eof);
	}
	if (entry->payload_object_offset || entry->payload_content_len ||
	    entry->result_activated || entry->result_effective_len ||
	    entry->result_checksum_algorithm || entry->result_checksum_len ||
	    memchr_inv(entry->result_checksum, 0,
		       sizeof(entry->result_checksum)))
		return -EBADMSG;
	if (entry->transition != NFSD_FFV2_FINALIZED &&
	    entry->transition != NFSD_FFV2_COMMITTED &&
	    entry->transition != NFSD_FFV2_ROLLED_BACK)
		return -EBADMSG;
	transaction = ffv2_replay_transaction(store, entry->txn_id);
	if (!transaction ||
	    memcmp(transaction->file_key, entry->file_key, 32) ||
	    ffv2_replay_entry_identity(transaction, entry))
		return -EBADMSG;
	if (entry->transition == NFSD_FFV2_ROLLED_BACK &&
	    transaction->phase == NFSD_FFV2_COMMITTED) {
		if (!(entry->admission.rights & NFSD_FFV2_RIGHT_REPAIR))
			return -EBADMSG;
	} else if (transaction->incarnation != header->ds_incarnation ||
		   transaction->admission_id != entry->admission.client_id ||
		   !(entry->admission.rights & NFSD_FFV2_RIGHT_WRITE)) {
		return -EBADMSG;
	}
	switch (entry->transition) {
	case NFSD_FFV2_FINALIZED:
		if (transaction->phase != NFSD_FFV2_PREPARED ||
		    registration->pending[entry->chunk_index] != transaction ||
		    entry->result_visible_object_id !=
						transaction->version_object_id)
			return -EBADMSG;
		break;
	case NFSD_FFV2_COMMITTED:
		if (transaction->phase != NFSD_FFV2_FINALIZED ||
		    registration->pending[entry->chunk_index] != transaction ||
		    entry->result_visible_object_id !=
						transaction->version_object_id)
			return -EBADMSG;
		error = ffv2_replay_publish(store, registration, transaction);
		if (error)
			return error;
		registration->pending[entry->chunk_index] = NULL;
		break;
	case NFSD_FFV2_ROLLED_BACK:
		if (transaction->phase == NFSD_FFV2_COMMITTED) {
			if (registration->pending[entry->chunk_index])
				return -EBADMSG;
			predecessor = transaction->predecessor_present ?
				ffv2_replay_version(
					store,
					transaction->predecessor_object_id) : NULL;
			if (entry->result_visible_object_id !=
				(predecessor ? predecessor->version_object_id : 0))
				return -EBADMSG;
			error = ffv2_replay_unpublish(store, registration,
						      transaction);
			if (error)
				return error;
		} else {
			predecessor = transaction->predecessor_present ?
				ffv2_replay_version(
					store,
					transaction->predecessor_object_id) : NULL;
			if ((transaction->predecessor_present && !predecessor) ||
			    (transaction->phase != NFSD_FFV2_PREPARED &&
			     transaction->phase != NFSD_FFV2_FINALIZED) ||
			    entry->result_visible_object_id ||
			    registration->pending[entry->chunk_index] !=
								 transaction ||
			    registration->visible[entry->chunk_index] !=
								 predecessor)
				return -EBADMSG;
			registration->pending[entry->chunk_index] = NULL;
		}
		break;
	default:
		return -EBADMSG;
	}
	transaction->phase = entry->transition;
	return ffv2_replay_extent(store, registration, entry, prior_eof);
}

#ifdef CONFIG_KUNIT
int nfsd_ffv2_store_test_visible_replay(
	const struct nfsd_ffv2_entry_record *entries, size_t count,
	u32 chunk_bytes, u64 max_chunks, u64 query_index,
	struct nfsd_ffv2_visible_chunk *chunk, u64 *eof)
{
	struct nfsd_ffv2_store store = {};
	struct nfsd_ffv2_wal_header header = { .ds_incarnation = 1 };
	struct ffv2_registration *registration;
	size_t i;
	int error = 0;

	if ((!entries && count) || !chunk || !eof || chunk_bytes < 4096 ||
	    chunk_bytes > 1024 * 1024 || !IS_ALIGNED(chunk_bytes, 4096) ||
	    !max_chunks || max_chunks > U64_MAX / chunk_bytes)
		return -EINVAL;
	memset(chunk, 0, sizeof(*chunk));
	*eof = 0;
	INIT_LIST_HEAD(&store.registrations);
	INIT_LIST_HEAD(&store.transactions);
	INIT_LIST_HEAD(&store.owners);
	INIT_LIST_HEAD(&store.admissions);
	INIT_LIST_HEAD(&store.receipts);
	registration = kzalloc_obj(*registration, GFP_KERNEL);
	if (!registration)
		return -ENOMEM;
	if (count)
		memcpy(registration->file_key, entries[0].file_key, 32);
	registration->chunk_bytes = chunk_bytes;
	registration->max_chunks = max_chunks;
	for (i = 0; i < ARRAY_SIZE(registration->guard); i++)
		registration->guard[i].never_written = true;
	list_add_tail(&registration->node, &store.registrations);
	store.registration_count = 1;
	for (i = 0; i < count; i++) {
		struct nfsd_ffv2_payload_record payload = {};
		u64 object_end = 0;

		if (memcmp(entries[i].file_key, registration->file_key, 32) ||
		    entries[i].chunk_index >= max_chunks ||
		    entries[i].chunk_index >= ARRAY_SIZE(registration->visible)) {
			error = -EBADMSG;
			break;
		}
		if (entries[i].payload_object_id) {
			if (!(entries[i].payload_object_id >> 40) ||
			    (entries[i].payload_object_id >> 40) >
							header.ds_incarnation) {
				error = -EBADMSG;
				break;
			}
			payload.checksum_algorithm =
					entries[i].result_checksum_algorithm;
			payload.checksum_len = entries[i].result_checksum_len;
			memcpy(payload.checksum, entries[i].result_checksum,
			       sizeof(payload.checksum));
			object_end = entries[i].payload_object_offset +
				nfsd_ffv2_payload_record_size(
						entries[i].payload_content_len);
		}
		error = ffv2_replay_visible_entry(&store, registration, &header,
						  &entries[i], &payload,
						  object_end, NULL);
		if (error)
			break;
	}
	if (!error) {
		struct ffv2_transaction *version;

		*eof = registration->logical_eof;
		if (query_index >= ARRAY_SIZE(registration->visible)) {
			error = -ENOENT;
		} else {
			version = registration->visible[query_index];
			if (!version) {
				error = -ENOENT;
				goto out;
			}
			chunk->version_object_id = version->version_object_id;
			chunk->version_generation = version->version_generation;
			chunk->payload_object_id = version->payload_object_id;
			chunk->writer_payload_id = version->writer_payload_id;
			chunk->payload_object_offset =
						version->payload_object_offset;
			chunk->content_len = version->content_len;
			chunk->content_crc32c = version->content_crc32c;
			chunk->checksum_algorithm = version->checksum_algorithm;
			chunk->checksum_len = version->checksum_len;
			memcpy(chunk->checksum, version->checksum,
			       sizeof(chunk->checksum));
			chunk->file_eof = registration->logical_eof;
		}
	}
out:
	ffv2_store_replay_free(&store);
	if (error && error != -ENOENT) {
		memset(chunk, 0, sizeof(*chunk));
		*eof = 0;
	}
	return error;
}
#endif

static int ffv2_replay_entry(struct nfsd_ffv2_store *store,
			     const struct nfsd_ffv2_wal_header *header,
			     const struct nfsd_ffv2_entry_record *entry,
			     struct ffv2_scan_result *scan,
			     u64 *highest_payload_id)
{
	struct nfsd_ffv2_payload_record payload = {};
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
	if (entry->transition == NFSD_FFV2_REFUSED ||
	    entry->transition == NFSD_FFV2_ABORTED)
		return entry->payload_object_id ? -EBADMSG : 0;
	if (entry->chunk_index >= registration->max_chunks ||
	    entry->chunk_index >= ARRAY_SIZE(registration->visible))
		return -EBADMSG;
	if (entry->payload_object_id &&
	    !nfsd_ffv2_payload_geometry_valid(entry->chunk_index,
					      entry->payload_content_len,
					      registration->chunk_bytes,
					      registration->max_chunks))
		return -EBADMSG;
	error = ffv2_replay_payload(store, entry, &object_end, &payload);
	if (error)
		return error;
	if (entry->payload_object_id &&
	    entry->payload_object_id <= *highest_payload_id)
		return -EBADMSG;
	error = ffv2_replay_visible_entry(store, registration, header, entry,
					  &payload, object_end, NULL);
	if (error)
		return error;
	error = ffv2_replay_receipt_add(store, entry, NULL);
	if (error)
		return error;
	if (entry->payload_object_id) {
		*highest_payload_id = entry->payload_object_id;
		if (scan->payload_cursor < object_end)
			scan->payload_cursor = object_end;
	}
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
			       struct nfsd_ffv2_wal_header *header,
			       struct ffv2_admission *new_admission)
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
		return ffv2_replay_trust(store, header, &record, new_admission);
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
							    &header, NULL);
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

static int ffv2_store_next_ids(struct nfsd_ffv2_store *store)
{
	struct ffv2_transaction *transaction;
	struct ffv2_admission *admission;
	u64 txn = 0, version = 0;
	u64 admission_id = 0;

	list_for_each_entry(transaction, &store->transactions, node) {
		if (transaction->txn_id > txn)
			txn = transaction->txn_id;
		if (transaction->version_object_id > version)
			version = transaction->version_object_id;
	}
	list_for_each_entry(admission, &store->admissions, node)
		if (admission->id > admission_id)
			admission_id = admission->id;
	if (txn == U64_MAX || version == U64_MAX || admission_id == U64_MAX)
		return -EOVERFLOW;
	store->next_txn_id = txn + 1;
	store->next_version_id = version + 1;
	store->next_payload_sequence = 1;
	store->next_admission_id = admission_id + 1;
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
	INIT_LIST_HEAD(&store->owners);
	INIT_LIST_HEAD(&store->admissions);
	INIT_LIST_HEAD(&store->receipts);
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
	error = ffv2_store_next_ids(store);
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

int nfsd_ffv2_store_lookup_file(struct nfsd_ffv2_store *store,
				const u8 handle[32],
				struct nfsd_ffv2_store_file *file)
{
	struct ffv2_registration *registration;
	int error = -ENOENT;

	if (!store || !handle || !file)
		return -EINVAL;
	error = nfsd_ffv2_reservation_store_begin(store->reservation);
	if (error)
		return error;
	mutex_lock(&store->lock);
	list_for_each_entry(registration, &store->registrations, node) {
		if (memcmp(registration->handle, handle,
			   sizeof(registration->handle)))
			continue;
		memcpy(file->file_key, registration->file_key,
		       sizeof(file->file_key));
		file->chunk_bytes = registration->chunk_bytes;
		file->max_chunks = registration->max_chunks;
		file->logical_eof = registration->logical_eof;
		error = 0;
		break;
	}
	mutex_unlock(&store->lock);
	nfsd_ffv2_reservation_store_end(store->reservation);
	return error;
}

static void ffv2_store_admission_stateid(u64 id, u8 stateid[16])
{
	put_unaligned_be32(0x44324253, stateid);
	memcpy(stateid + 4, "TATE", 4);
	put_unaligned_be64(id, stateid + 8);
}

static void ffv2_store_control_operation(struct nfsd_ffv2_store *store,
					 u32 sequence, const u8 *body,
					 u32 body_len,
					 struct nfsd_ffv2_store_operation *op)
{
	memset(op, 0, sizeof(*op));
	memcpy(op->session, store->super.store_uuid, sizeof(op->session));
	op->session[0] ^= 0xa5;
	op->sequence = sequence;
	sha256(body, body_len, op->request_digest);
}

int nfsd_ffv2_store_admit_writer(struct nfsd_ffv2_store *store, u32 writer,
				 u8 stateid[16])
{
	struct nfsd_ffv2_store_operation operation;
	struct nfsd_ffv2_wal_header header = {
		.family = NFSD_FFV2_WAL_CONTROL,
	};
	struct ffv2_admission *admission;
	struct ffv2_admission *new_admission = NULL;
	struct ffv2_cursor cursor;
	u8 trust_body[84], authority_body[44];
	u8 trust[296], authority[256];
	u64 id, epoch;
	u32 sequence;
	int error;

	if (!store || !stateid || !writer || writer == U32_MAX)
		return -EINVAL;
	error = nfsd_ffv2_reservation_store_begin(store->reservation);
	if (error)
		return error;
	mutex_lock(&store->lock);
	list_for_each_entry(admission, &store->admissions, node) {
		if (admission->incarnation == store->super.ds_incarnation &&
		    admission->authority_seen &&
		    admission->authority.writer == writer &&
		    (admission->authority.rights & (NFSD_FFV2_RIGHT_READ |
						 NFSD_FFV2_RIGHT_WRITE)) ==
					       (NFSD_FFV2_RIGHT_READ |
						 NFSD_FFV2_RIGHT_WRITE)) {
			ffv2_store_admission_stateid(admission->id, stateid);
			error = 0;
			goto out_unlock;
		}
	}
	if (store->next_admission_id == U64_MAX ||
	    store->next_admission_id > U32_MAX / 2 ||
	    store->admission_count == NFSD_FFV2_MAX_ADMISSIONS) {
		error = -ENOSPC;
		goto out_unlock;
	}
	error = ffv2_store_wal_fits(store, sizeof(trust) + sizeof(authority), 0);
	if (error)
		goto out_unlock;
	new_admission = kzalloc_obj(*new_admission, GFP_KERNEL);
	if (!new_admission) {
		error = -ENOMEM;
		goto out_unlock;
	}
	id = store->next_admission_id;
	epoch = store->super.ds_incarnation;
	sequence = (u32)(id * 2 - 1);
	ffv2_store_admission_stateid(id, stateid);

	cursor = (struct ffv2_cursor){
		.data = trust_body,
		.capacity = sizeof(trust_body),
	};
	ffv2_put_u32(&cursor, 0x44324253);
	ffv2_put_bytes(&cursor, stateid + 4, 12);
	ffv2_put_u64(&cursor, epoch);
	ffv2_put_u64(&cursor, 1);
	ffv2_put_u32(&cursor, NFSD_FFV2_RIGHT_READ |
				 NFSD_FFV2_RIGHT_WRITE);
	ffv2_put_bytes(&cursor, store->super.store_uuid, 16);
	ffv2_put_u64(&cursor, id);
	ffv2_put_bytes(&cursor, store->super.export_uuid, 16);
	ffv2_put_u32(&cursor, writer);
	ffv2_put_u32(&cursor, NFSD_FFV2_RIGHT_READ |
				 NFSD_FFV2_RIGHT_WRITE);
	if (cursor.failed || cursor.offset != sizeof(trust_body)) {
		error = -EOVERFLOW;
		goto out_unlock;
	}
	ffv2_store_control_operation(store, sequence, trust_body,
				     sizeof(trust_body), &operation);
	header.lsn = store->next_lsn;
	header.ds_incarnation = epoch;
	memcpy(header.store_uuid, store->super.store_uuid, 16);
	memcpy(header.wal_uuid, store->super.wal_uuid, 16);
	error = ffv2_control_encode(&header, NFSD_FFV2_TRUST_STATEID,
				    &operation, store->super.store_uuid, epoch,
				    id, trust_body, sizeof(trust_body), trust,
				    sizeof(trust));
	if (error)
		goto out_unlock;
	error = ffv2_store_append_wal_locked(store, trust, sizeof(trust));
	if (error)
		goto out_unlock;
	error = ffv2_replay_control(store, trust, sizeof(trust), &header,
				    new_admission);
	if (error)
		goto out_failed;
	new_admission = NULL;

	cursor = (struct ffv2_cursor){
		.data = authority_body,
		.capacity = sizeof(authority_body),
	};
	ffv2_put_bytes(&cursor, store->super.store_uuid, 16);
	ffv2_put_u64(&cursor, epoch);
	ffv2_put_u32(&cursor, 1);
	ffv2_put_bytes(&cursor, stateid, 16);
	if (cursor.failed || cursor.offset != sizeof(authority_body)) {
		error = -EOVERFLOW;
		goto out_failed;
	}
	ffv2_store_control_operation(store, sequence + 1, authority_body,
				     sizeof(authority_body), &operation);
	header.lsn = store->next_lsn;
	error = ffv2_control_encode(&header, NFSD_FFV2_AUTHORITY_ADMIT,
				    &operation, store->super.store_uuid, epoch,
				    id, authority_body, sizeof(authority_body),
				    authority, sizeof(authority));
	if (error)
		goto out_failed;
	error = ffv2_store_append_wal_locked(store, authority,
					     sizeof(authority));
	if (error)
		goto out_unlock;
	error = ffv2_replay_control(store, authority, sizeof(authority),
				    &header, NULL);
	if (error)
		goto out_failed;
	store->next_admission_id++;
	goto out_unlock;
out_failed:
	store->failed = true;
out_unlock:
	kfree(new_admission);
	mutex_unlock(&store->lock);
	nfsd_ffv2_reservation_store_end(store->reservation);
	return error;
}

int nfsd_ffv2_store_visible_chunk(struct nfsd_ffv2_store *store,
				  const u8 file_key[32], u64 chunk_index,
				  struct nfsd_ffv2_visible_chunk *chunk)
{
	struct ffv2_registration *registration;
	struct ffv2_transaction *version;
	int error;

	if (!store || !file_key || !chunk)
		return -EINVAL;
	error = nfsd_ffv2_reservation_store_begin(store->reservation);
	if (error)
		return error;
	mutex_lock(&store->lock);
	registration = ffv2_replay_file(store, file_key);
	if (!registration || chunk_index >= registration->max_chunks) {
		error = -EINVAL;
		goto out_unlock;
	}
	if (chunk_index >= ARRAY_SIZE(registration->visible) ||
	    !registration->visible[chunk_index]) {
		error = -ENOENT;
		goto out_unlock;
	}
	version = registration->visible[chunk_index];
	memset(chunk, 0, sizeof(*chunk));
	chunk->version_object_id = version->version_object_id;
	chunk->version_generation = version->version_generation;
	chunk->payload_object_id = version->payload_object_id;
	chunk->writer_payload_id = version->writer_payload_id;
	chunk->payload_object_offset = version->payload_object_offset;
	chunk->content_len = version->content_len;
	chunk->content_crc32c = version->content_crc32c;
	chunk->checksum_algorithm = version->checksum_algorithm;
	chunk->checksum_len = version->checksum_len;
	memcpy(chunk->checksum, version->checksum, sizeof(chunk->checksum));
	chunk->file_eof = registration->logical_eof;
	chunk->owner_cohort = version->owner_cohort;
	chunk->owner_client_id = version->owner_client_id;
	chunk->owner_co_id = version->owner_co_id;
	chunk->guard_generation = version->guard_generation;
	chunk->guard_writer = version->guard_writer;
	chunk->guard_never_written = version->guard_never_written;
	error = 0;
out_unlock:
	mutex_unlock(&store->lock);
	nfsd_ffv2_reservation_store_end(store->reservation);
	return error;
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

static int ffv2_store_append_wal_locked(struct nfsd_ffv2_store *store,
					const u8 *data, size_t len)
{
	int error;

	if (store->failed || store->wal_cursor !=
				 i_size_read(file_inode(store->wal_file))) {
		store->failed = true;
		return -EIO;
	}
	error = ffv2_store_write_range_valid(store->wal_file,
					     store->super.capacity_wal_bytes,
					     len, store->wal_cursor);
	if (!error)
		error = ffv2_store_write_all(store->wal_file, data, len,
					     store->wal_cursor);
#ifdef CONFIG_NFSD_FFV2_LIVE_TEST
	if (!error && store->fail_next_io) {
		store->fail_next_io = false;
		error = -EIO;
	}
#endif
	if (!error)
		error = vfs_fsync(store->wal_file, 0);
	if (error) {
		store->failed = true;
		return error;
	}
	store->wal_cursor += len;
	store->wal_payload_cursor = store->payload_cursor;
	store->next_lsn++;
	return 0;
}

static int
ffv2_store_append_payload_locked(struct nfsd_ffv2_store *store,
				 const struct nfsd_ffv2_payload_record *record,
				 u64 *offset)
{
	size_t len, written;
	u8 *data;
	int error;

	len = nfsd_ffv2_payload_record_size(record->content_len);
	if (!len)
		return -EOVERFLOW;
	data = kvmalloc(len, GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	error = nfsd_ffv2_payload_encode(record, data, len, &written);
	if (error)
		goto out;
	if (written != len || store->failed || store->payload_cursor !=
				 i_size_read(file_inode(store->payload_file))) {
		store->failed = true;
		error = -EIO;
		goto out;
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
out:
	kvfree(data);
	return error;
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
	int error;

	if (!store || !record || !offset ||
	    memcmp(record->store_uuid, store->super.store_uuid, 16))
		return -EINVAL;
	error = nfsd_ffv2_reservation_store_begin(store->reservation);
	if (error)
		return error;
	mutex_lock(&store->lock);
	error = ffv2_store_append_payload_locked(store, record, offset);
	mutex_unlock(&store->lock);
	nfsd_ffv2_reservation_store_end(store->reservation);
	return error;
}

static int
ffv2_store_operation_key(const struct nfsd_ffv2_store_operation *operation,
			 u8 key[32])
{
	if (!operation || ffv2_all_zero(operation->session, 16) ||
	    !operation->sequence)
		return -EINVAL;
	ffv2_operation_key(operation->session, operation->slot,
			   operation->sequence, operation->ordinal, key);
	return 0;
}

static int
ffv2_store_replay_result(struct nfsd_ffv2_store *store,
			 const struct nfsd_ffv2_store_operation *operation,
			 struct nfsd_ffv2_store_mutation_result *result,
			 bool *replayed)
{
	struct ffv2_receipt *receipt;
	u8 key[32];
	int error;

	*replayed = false;
	error = ffv2_store_operation_key(operation, key);
	if (error)
		return error;
	receipt = ffv2_replay_receipt(store, key);
	if (!receipt)
		return 0;
	if (memcmp(receipt->entry.request_digest, operation->request_digest,
		   sizeof(operation->request_digest)))
		return -EEXIST;
	memset(result, 0, sizeof(*result));
	result->status = receipt->entry.status;
	result->stability = receipt->entry.stability - 1;
	result->activated = receipt->entry.result_activated;
	memcpy(result->verifier, receipt->entry.result_verifier,
	       sizeof(result->verifier));
	result->owner.cohort = receipt->entry.owner_cohort;
	result->owner.client_id = receipt->entry.owner_client_id;
	result->owner.co_id = receipt->entry.owner_co_id;
	*replayed = true;
	return 0;
}

static struct ffv2_admission *
ffv2_store_writer_admission(struct nfsd_ffv2_store *store, u32 writer)
{
	struct ffv2_admission *admission;

	list_for_each_entry(admission, &store->admissions, node)
		if (admission->incarnation == store->super.ds_incarnation &&
		    admission->authority_seen &&
		    admission->authority.writer == writer &&
		    (admission->authority.rights & NFSD_FFV2_RIGHT_WRITE))
			return admission;
	return NULL;
}

static int ffv2_store_extent(const struct nfsd_ffv2_store *store,
			     const struct ffv2_registration *registration,
			     const struct ffv2_transaction *publish,
			     struct nfsd_ffv2_entry_record *entry)
{
	u64 eof = 0, end, highest = 0, prior = registration->logical_eof;
	bool any = false;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(registration->visible); i++) {
		const struct ffv2_transaction *version = registration->visible[i];

		if (publish && publish->chunk_index == i)
			version = publish;
		if (!version)
			continue;
		if (check_mul_overflow((u64)i,
				       (u64)registration->chunk_bytes, &end) ||
		    check_add_overflow(end, (u64)version->content_len, &end))
			return -EOVERFLOW;
		if (end > eof)
			eof = end;
		if (!any || i > highest)
			highest = i;
		any = true;
	}
	entry->extent_kind = eof > prior ? 2 : eof < prior ? 3 : 1;
	entry->extent_high_water = eof;
	entry->extent_highest_index = any ? highest : 0;
	entry->index_generation = store->index_generation + !!publish;
	return 0;
}

static int ffv2_store_wal_fits(struct nfsd_ffv2_store *store,
			       u64 append, u64 additional_reserve)
{
	struct ffv2_scan_result scan = {};
	u64 required;
	int error;

	error = ffv2_replay_account(store, &scan);
	if (error)
		return error;
	if (check_add_overflow(scan.live_wal_reserved, additional_reserve,
			       &required) ||
	    check_add_overflow(required, append, &required) ||
	    check_add_overflow(required, (u64)NFSD_FFV2_START_RECORD_SIZE,
			       &required) ||
	    store->wal_cursor > store->super.capacity_wal_bytes ||
	    required > store->super.capacity_wal_bytes - store->wal_cursor)
		return -ENOSPC;
	return 0;
}

static void
ffv2_store_entry_operation(struct nfsd_ffv2_entry_record *entry,
			   const struct nfsd_ffv2_store_operation *operation)
{
	memcpy(entry->session, operation->session, sizeof(entry->session));
	entry->slot = operation->slot;
	entry->sequence = operation->sequence;
	entry->ordinal = operation->ordinal;
	ffv2_operation_key(operation->session, operation->slot,
			   operation->sequence, operation->ordinal,
			   entry->operation_key);
	memcpy(entry->request_digest, operation->request_digest,
	       sizeof(entry->request_digest));
}

static int
ffv2_store_append_entry_locked(struct nfsd_ffv2_store *store,
			       struct nfsd_ffv2_entry_record *entry,
	const struct nfsd_ffv2_payload_record *payload, u64 object_end,
	struct ffv2_transaction *transaction, struct ffv2_receipt *receipt)
{
	struct nfsd_ffv2_wal_header header = {
		.family = NFSD_FFV2_WAL_ENTRY,
		.lsn = store->next_lsn,
		.ds_incarnation = store->super.ds_incarnation,
	};
	struct ffv2_registration *registration;
	u8 bytes[NFSD_FFV2_ENTRY_RECORD_SIZE];
	int error;

	memcpy(header.store_uuid, store->super.store_uuid, 16);
	memcpy(header.wal_uuid, store->super.wal_uuid, 16);
	error = ffv2_entry_encode(&header, entry, bytes);
	if (error)
		goto out_free;
	error = ffv2_store_append_wal_locked(store, bytes, sizeof(bytes));
	if (error)
		goto out_free;
	registration = ffv2_replay_file(store, entry->file_key);
	error = ffv2_replay_visible_entry(store, registration, &header, entry,
					  payload, object_end, transaction);
	if (!error)
		error = ffv2_replay_receipt_add(store, entry, receipt);
	if (error)
		store->failed = true;
out_free:
	if (transaction &&
	    ffv2_replay_transaction(store, entry->txn_id) != transaction)
		kfree(transaction);
	if (receipt &&
	    ffv2_replay_receipt(store, entry->operation_key) != receipt)
		kfree(receipt);
	return error;
}

int nfsd_ffv2_store_write(struct nfsd_ffv2_store *store,
			  const u8 file_key[32],
			  const struct nfsd_ffv2_store_write *request,
			  struct nfsd_ffv2_store_mutation_result *result)
{
	struct nfsd_ffv2_payload_record payload = {};
	struct nfsd_ffv2_entry_record entry = {
		.status = 1,
		.disposition = 1,
		.batch_count = 1,
	};
	struct ffv2_registration *registration;
	struct ffv2_transaction predicted = {};
	struct ffv2_transaction *transaction = NULL;
	struct ffv2_admission *admission;
	struct ffv2_transaction *predecessor;
	struct ffv2_receipt *receipt = NULL;
	u64 payload_offset, object_end;
	bool replayed, activate;
	int error;

	if (!store || !file_key || !request || !result || !request->content)
		return -EINVAL;
	error = nfsd_ffv2_reservation_store_begin(store->reservation);
	if (error)
		return error;
	mutex_lock(&store->lock);
	error = ffv2_store_replay_result(store, &request->operation, result,
					 &replayed);
	if (error || replayed)
		goto out_unlock;
	registration = ffv2_replay_file(store, file_key);
	admission = ffv2_store_writer_admission(store,
						request->owner_client_id);
	if (!registration || !admission ||
	    !nfsd_ffv2_payload_geometry_valid(request->chunk_index,
					      request->content_len,
					      registration->chunk_bytes,
					      registration->max_chunks) ||
	    request->stability > 2 || request->checksum_len >
						NFSD_FFV2_STORE_CHECKSUM_SIZE ||
	    !nfsd_ffv2_store_checksum_valid(request->checksum_algorithm,
					    request->checksum,
					    request->checksum_len,
					    request->content,
					    request->content_len)) {
		error = -EINVAL;
		goto out_unlock;
	}
	if (ffv2_replay_owner(store, request->owner_cohort,
			      request->owner_client_id, request->owner_co_id) ||
	    registration->pending[request->chunk_index]) {
		error = -EAGAIN;
		goto out_unlock;
	}
	if (request->guard_check) {
		if (request->guard_never_written !=
		    registration->guard[request->chunk_index].never_written ||
		    (request->guard_never_written &&
		     (request->guard_generation || request->guard_writer)) ||
		    (!request->guard_never_written &&
		     (request->guard_generation !=
			registration->guard[request->chunk_index].generation ||
		      request->guard_writer !=
			registration->guard[request->chunk_index].writer))) {
			error = -EAGAIN;
			goto out_unlock;
		}
	}
	if (store->next_txn_id == U64_MAX ||
	    store->next_version_id == U64_MAX ||
	    store->next_payload_sequence > NFSD_FFV2_PAYLOAD_SEQUENCE_MASK ||
	    store->transaction_count == NFSD_FFV2_MAX_TRANSACTIONS ||
	    (!registration->guard[request->chunk_index].never_written &&
	     registration->guard[request->chunk_index].generation == U32_MAX)) {
		error = -ENOSPC;
		goto out_unlock;
	}
	activate = request->activate_if_empty && request->stability &&
		   !registration->visible[request->chunk_index];
	if (activate && store->index_generation == U64_MAX) {
		error = -ENOSPC;
		goto out_unlock;
	}
	error = ffv2_store_wal_fits(store, NFSD_FFV2_ENTRY_RECORD_SIZE,
				    activate ? 0 :
				    2 * NFSD_FFV2_ENTRY_RECORD_SIZE);
	if (error)
		goto out_unlock;
#ifdef CONFIG_NFSD_FFV2_LIVE_TEST
	if (store->fail_next_alloc) {
		store->fail_next_alloc = false;
		error = -ENOMEM;
		goto out_unlock;
	}
#endif
	transaction = kzalloc_obj(*transaction, GFP_KERNEL);
	receipt = kmalloc_obj(*receipt, GFP_KERNEL);
	if (!transaction || !receipt) {
		error = -ENOMEM;
		goto out_free;
	}
	predecessor = registration->visible[request->chunk_index];
	entry.transition = activate ? NFSD_FFV2_COMMITTED :
				      NFSD_FFV2_PREPARED;
	entry.stability = request->stability + 1;
	memcpy(entry.file_key, file_key, sizeof(entry.file_key));
	entry.chunk_index = request->chunk_index;
	entry.txn_id = store->next_txn_id;
	ffv2_store_entry_operation(&entry, &request->operation);
	entry.admission = admission->authority;
	entry.owner_cohort = request->owner_cohort;
	entry.owner_client_id = request->owner_client_id;
	entry.owner_co_id = request->owner_co_id;
	entry.generation =
		registration->guard[request->chunk_index].never_written ? 0 :
		registration->guard[request->chunk_index].generation + 1;
	entry.predecessor_present = !!predecessor;
	if (predecessor) {
		entry.predecessor_object_id = predecessor->version_object_id;
		entry.predecessor_generation = predecessor->version_generation;
	}
	entry.payload_object_id =
		(store->super.ds_incarnation << 40) |
		store->next_payload_sequence;
	entry.writer_payload_id = request->writer_payload_id;
	entry.payload_content_len = request->content_len;
	entry.result_activated = activate;
	entry.result_visible_object_id = store->next_version_id;
	entry.result_effective_len = request->content_len;
	entry.result_checksum_algorithm = request->checksum_algorithm;
	entry.result_checksum_len = request->checksum_len;
	memcpy(entry.result_checksum, request->checksum,
	       sizeof(entry.result_checksum));
	entry.result_guard_generation = entry.generation;
	entry.result_guard_writer = request->owner_client_id;
	memcpy(entry.result_verifier, store->super.write_verifier,
	       sizeof(entry.result_verifier));

	memcpy(payload.store_uuid, store->super.store_uuid,
	       sizeof(payload.store_uuid));
	payload.object_id = entry.payload_object_id;
	payload.checksum_algorithm = request->checksum_algorithm;
	payload.checksum_len = request->checksum_len;
	memcpy(payload.checksum, request->checksum, sizeof(payload.checksum));
	payload.content_len = request->content_len;
	payload.content = request->content;
	payload.content_crc32c = ~crc32c(~0, request->content,
					 request->content_len);
	error = ffv2_store_append_payload_locked(store, &payload,
						 &payload_offset);
	if (error)
		goto out_free;
	entry.payload_object_offset = payload_offset;
	object_end = payload_offset +
		     nfsd_ffv2_payload_record_size(request->content_len);
	predicted.chunk_index = request->chunk_index;
	predicted.content_len = request->content_len;
	error = ffv2_store_extent(store, registration,
				  activate ? &predicted : NULL, &entry);
	if (error)
		goto out_free;
	error = ffv2_store_append_entry_locked(store, &entry, &payload,
					       object_end, transaction, receipt);
	transaction = NULL;
	receipt = NULL;
	if (error)
		goto out_unlock;
	store->next_txn_id++;
	store->next_version_id++;
	store->next_payload_sequence++;
	memset(result, 0, sizeof(*result));
	result->status = 1;
	result->stability = request->stability;
	result->activated = activate;
	memcpy(result->verifier, entry.result_verifier,
	       sizeof(result->verifier));
	result->owner.cohort = request->owner_cohort;
	result->owner.client_id = request->owner_client_id;
	result->owner.co_id = request->owner_co_id;
	goto out_unlock;
out_free:
	kfree(receipt);
	kfree(transaction);
out_unlock:
	mutex_unlock(&store->lock);
	nfsd_ffv2_reservation_store_end(store->reservation);
	return error;
}

static int
ffv2_store_lifecycle(struct nfsd_ffv2_store *store, const u8 file_key[32],
		     const struct nfsd_ffv2_store_lifecycle *request,
		     struct nfsd_ffv2_store_mutation_result *result,
		     u32 transition)
{
	struct nfsd_ffv2_entry_record entry = {
		.status = 1,
		.disposition = 1,
		.stability = 3,
		.batch_count = 1,
	};
	struct ffv2_registration *registration;
	struct ffv2_transaction *transaction;
	struct ffv2_admission *admission;
	struct ffv2_receipt *receipt = NULL;
	bool replayed;
	int error;

	if (!store || !file_key || !request || !result)
		return -EINVAL;
	error = nfsd_ffv2_reservation_store_begin(store->reservation);
	if (error)
		return error;
	mutex_lock(&store->lock);
	error = ffv2_store_replay_result(store, &request->operation, result,
					 &replayed);
	if (error || replayed)
		goto out_unlock;
	registration = ffv2_replay_file(store, file_key);
	admission = ffv2_store_writer_admission(store,
						request->owner_client_id);
	transaction = ffv2_replay_owner(store, request->owner_cohort,
					request->owner_client_id,
					request->owner_co_id);
	if (!registration || !admission || !transaction ||
	    transaction->chunk_index != request->chunk_index ||
	    transaction->admission_id != admission->id ||
	    registration->pending[request->chunk_index] != transaction ||
	    (transition == NFSD_FFV2_FINALIZED &&
	     transaction->phase != NFSD_FFV2_PREPARED) ||
	    (transition == NFSD_FFV2_COMMITTED &&
	     transaction->phase != NFSD_FFV2_FINALIZED)) {
		error = -EINVAL;
		goto out_unlock;
	}
	if (transition == NFSD_FFV2_COMMITTED &&
	    store->index_generation == U64_MAX) {
		error = -ENOSPC;
		goto out_unlock;
	}
	error = ffv2_store_wal_fits(store, 0, 0);
	if (error)
		goto out_unlock;
	receipt = kmalloc_obj(*receipt, GFP_KERNEL);
	if (!receipt) {
		error = -ENOMEM;
		goto out_unlock;
	}
	entry.transition = transition;
	memcpy(entry.file_key, file_key, sizeof(entry.file_key));
	entry.chunk_index = request->chunk_index;
	entry.txn_id = transaction->txn_id;
	ffv2_store_entry_operation(&entry, &request->operation);
	entry.admission = admission->authority;
	entry.owner_cohort = transaction->owner_cohort;
	entry.owner_client_id = transaction->owner_client_id;
	entry.owner_co_id = transaction->owner_co_id;
	entry.generation = transaction->version_generation;
	entry.predecessor_present = transaction->predecessor_present;
	entry.predecessor_object_id = transaction->predecessor_object_id;
	entry.predecessor_generation = transaction->predecessor_generation;
	entry.result_visible_object_id = transaction->version_object_id;
	entry.result_guard_generation = transaction->guard_generation;
	entry.result_guard_writer = transaction->guard_writer;
	entry.result_guard_never_written = transaction->guard_never_written;
	memcpy(entry.result_verifier, store->super.write_verifier,
	       sizeof(entry.result_verifier));
	error = ffv2_store_extent(store, registration,
				  transition == NFSD_FFV2_COMMITTED ?
				  transaction : NULL, &entry);
	if (error)
		goto out_free_receipt;
	error = ffv2_store_append_entry_locked(store, &entry, NULL, 0, NULL,
					       receipt);
	receipt = NULL;
	if (error)
		goto out_unlock;
	memset(result, 0, sizeof(*result));
	result->status = 1;
	result->stability = 2;
	memcpy(result->verifier, entry.result_verifier,
	       sizeof(result->verifier));
	result->owner.cohort = transaction->owner_cohort;
	result->owner.client_id = transaction->owner_client_id;
	result->owner.co_id = transaction->owner_co_id;
	goto out_unlock;
out_free_receipt:
	kfree(receipt);
out_unlock:
	mutex_unlock(&store->lock);
	nfsd_ffv2_reservation_store_end(store->reservation);
	return error;
}

int nfsd_ffv2_store_finalize(struct nfsd_ffv2_store *store,
			     const u8 file_key[32],
			     const struct nfsd_ffv2_store_lifecycle *request,
			     struct nfsd_ffv2_store_mutation_result *result)
{
	return ffv2_store_lifecycle(store, file_key, request, result,
				    NFSD_FFV2_FINALIZED);
}

int nfsd_ffv2_store_commit(struct nfsd_ffv2_store *store,
			   const u8 file_key[32],
			   const struct nfsd_ffv2_store_lifecycle *request,
			   struct nfsd_ffv2_store_mutation_result *result)
{
	return ffv2_store_lifecycle(store, file_key, request, result,
				    NFSD_FFV2_COMMITTED);
}

#ifdef CONFIG_NFSD_FFV2_LIVE_TEST
struct ffv2_visible_snapshot_entry {
	u8 file_key[32];
	u64 chunk_index;
	struct nfsd_ffv2_visible_chunk chunk;
	u8 content_sha256[SHA256_DIGEST_SIZE];
};

int nfsd_ffv2_store_test_visible_snapshot(struct nfsd_ffv2_store *store,
					  u8 **snapshot, size_t *len)
{
	struct ffv2_visible_snapshot_entry *entries;
	struct ffv2_registration *registration;
	u32 count = 0, index;
	int error = 0;

	if (!store || !snapshot || !len)
		return -EINVAL;
	*snapshot = NULL;
	*len = 0;
	entries = kvcalloc(NFSD_FFV2_MAX_OBJECTS * 64, sizeof(*entries),
			   GFP_KERNEL);
	if (!entries)
		return -ENOMEM;
	mutex_lock(&store->lock);
	list_for_each_entry(registration, &store->registrations, node) {
		for (index = 0; index < ARRAY_SIZE(registration->visible);
		     index++) {
			struct ffv2_transaction *version =
						registration->visible[index];
			struct ffv2_visible_snapshot_entry *entry;
			u8 *content;

			if (!version)
				continue;
			entry = &entries[count++];
			memcpy(entry->file_key, registration->file_key, 32);
			entry->chunk_index = index;
			entry->chunk.version_object_id =
						version->version_object_id;
			entry->chunk.version_generation =
						version->version_generation;
			entry->chunk.payload_object_id = version->payload_object_id;
			entry->chunk.writer_payload_id = version->writer_payload_id;
			entry->chunk.payload_object_offset =
						version->payload_object_offset;
			entry->chunk.content_len = version->content_len;
			entry->chunk.content_crc32c = version->content_crc32c;
			entry->chunk.checksum_algorithm = version->checksum_algorithm;
			entry->chunk.checksum_len = version->checksum_len;
			memcpy(entry->chunk.checksum, version->checksum,
			       sizeof(entry->chunk.checksum));
			entry->chunk.file_eof = registration->logical_eof;
			content = kvmalloc(version->content_len, GFP_KERNEL);
			if (!content) {
				error = -ENOMEM;
				goto out_unlock;
			}
			error = ffv2_store_read_all(
				store->payload_file, content, version->content_len,
				version->payload_object_offset +
						NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE);
			if (!error)
				sha256(content, version->content_len,
				       entry->content_sha256);
			kvfree(content);
			if (error)
				goto out_unlock;
		}
	}
out_unlock:
	mutex_unlock(&store->lock);
	if (error) {
		kvfree(entries);
		return error;
	}
	*snapshot = (u8 *)entries;
	*len = count * sizeof(*entries);
	return 0;
}

void nfsd_ffv2_store_test_fail_next_io(struct nfsd_ffv2_store *store)
{
	mutex_lock(&store->lock);
	store->fail_next_io = true;
	mutex_unlock(&store->lock);
}

void nfsd_ffv2_store_test_fail_next_alloc(struct nfsd_ffv2_store *store)
{
	mutex_lock(&store->lock);
	store->fail_next_alloc = true;
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
