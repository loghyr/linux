// SPDX-License-Identifier: GPL-2.0-only
#include <linux/crc32.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/magic.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <crypto/sha2.h>

#include "ffv2.h"
#include "ffv2_store.h"

#define FFV2_SUPER_MAGIC	0x44325342
#define FFV2_WAL_MAGIC		0x4432574c
#define FFV2_PAYLOAD_MAGIC	0x44325059
#define FFV2_MAX_WAL_RECORD	(1024U * 1024U)

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
	    total_size > FFV2_MAX_WAL_RECORD || total_size > len ||
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
	record->verifier_changed = ffv2_get_u8(&cursor);
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
};

static struct file *ffv2_store_open_file(const struct path *root,
					 const char *name)
{
	struct file *file;

	file = file_open_root(root, name, O_RDWR | O_LARGEFILE, 0);
	if (IS_ERR(file))
		return file;
	if (!S_ISREG(file_inode(file)->i_mode) || !file_inode(file)->i_nlink ||
	    file->f_path.mnt != root->mnt ||
	    file_inode(file)->i_sb != root->mnt->mnt_sb ||
	    file->f_path.dentry->d_parent != root->dentry) {
		fput(file);
		return ERR_PTR(-EINVAL);
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
	return 0;
}

static int ffv2_store_validate_files(struct nfsd_ffv2_store *store,
				     const struct path *root)
{
	struct nfsd_ffv2_payload_header payload_header;
	struct nfsd_ffv2_payload_header *header = &payload_header;
	struct nfsd_ffv2_start_record start;
	struct nfsd_ffv2_wal_header wal_header;
	const u8 *store_uuid = store->super.store_uuid;
	u8 *payload_bytes;
	u8 *start_bytes;
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
		   sizeof(store->super.fs_uuid)))
		return -EBADMSG;

	payload_bytes = kmalloc(NFSD_FFV2_PAYLOAD_ALIGN, GFP_KERNEL);
	start_bytes = kmalloc(NFSD_FFV2_START_RECORD_SIZE, GFP_KERNEL);
	if (!payload_bytes || !start_bytes) {
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
	error = ffv2_store_read_all(store->wal_file, start_bytes,
				    NFSD_FFV2_START_RECORD_SIZE, 0);
	if (error)
		goto out;
	error = nfsd_ffv2_start_decode(start_bytes,
				       NFSD_FFV2_START_RECORD_SIZE,
				       store->super.store_uuid,
				       store->super.wal_uuid, &wal_header, &start);
	if (!error && start.ds_incarnation != store->super.ds_incarnation)
		error = -EBADMSG;
out:
	kfree(start_bytes);
	kfree(payload_bytes);
	return error;
}

int nfsd_ffv2_store_open(struct nfsd_ffv2_reservation *reservation,
			 struct nfsd_ffv2_store **result)
{
	struct nfsd_ffv2_store *store = NULL;
	struct path root;
	u8 store_uuid[16];
	int error;

	if (!result)
		return -EINVAL;
	*result = NULL;
	error = nfsd_ffv2_reservation_store_root(reservation, &root, store_uuid);
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
	error = ffv2_store_validate_files(store, &root);
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

	if (offset < 0 || check_add_overflow(offset, (loff_t)len, &end) ||
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
	if (offset < 0 || check_add_overflow(offset, (loff_t)len, &end) ||
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

int nfsd_ffv2_store_write_payload(struct nfsd_ffv2_store *store,
				  const void *data, size_t len, loff_t offset)
{
	int error;

	error = nfsd_ffv2_reservation_store_begin(store->reservation);
	if (error)
		return error;
	mutex_lock(&store->lock);
	error = ffv2_store_write_range_valid(store->payload_file,
					     store->super.capacity_payload_bytes,
					     len, offset);
	if (!error)
		error = ffv2_store_write_all(store->payload_file, data, len, offset);
	mutex_unlock(&store->lock);
	nfsd_ffv2_reservation_store_end(store->reservation);
	return error;
}

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

int nfsd_ffv2_store_write_wal(struct nfsd_ffv2_store *store, const void *data,
			      size_t len, loff_t offset)
{
	int error;

	error = nfsd_ffv2_reservation_store_begin(store->reservation);
	if (error)
		return error;
	mutex_lock(&store->lock);
	error = ffv2_store_write_range_valid(store->wal_file,
					     store->super.capacity_wal_bytes,
					     len, offset);
	if (!error)
		error = ffv2_store_write_all(store->wal_file, data, len, offset);
	mutex_unlock(&store->lock);
	nfsd_ffv2_reservation_store_end(store->reservation);
	return error;
}

int nfsd_ffv2_store_checkpoint(struct nfsd_ffv2_store *store,
			       const struct nfsd_ffv2_super_record *record)
{
	u8 *bytes;
	unsigned int slot;
	int error;

	if (!store || !record)
		return -EINVAL;
	bytes = kmalloc(NFSD_FFV2_SUPER_SLOT_SIZE, GFP_KERNEL);
	if (!bytes)
		return -ENOMEM;
	error = nfsd_ffv2_reservation_store_begin(store->reservation);
	if (error)
		goto out;
	mutex_lock(&store->lock);
	if (memcmp(record->store_uuid, store->super.store_uuid, 16) ||
	    memcmp(record->wal_uuid, store->super.wal_uuid, 16) ||
	    memcmp(record->payload_uuid, store->super.payload_uuid, 16) ||
	    record->generation <= store->super.generation ||
	    record->capacity_wal_bytes != store->super.capacity_wal_bytes ||
	    record->capacity_payload_bytes != store->super.capacity_payload_bytes) {
		error = -EINVAL;
		goto out_unlock;
	}
	error = nfsd_ffv2_super_encode(record, bytes);
	if (error)
		goto out_unlock;
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
		goto out_unlock;
	error = vfs_fsync(store->wal_file, 0);
	if (error)
		goto out_unlock;
	slot = store->newest_slot ^ 1;
	error = ffv2_store_write_all(store->super_file, bytes,
				     NFSD_FFV2_SUPER_SLOT_SIZE,
				     slot * NFSD_FFV2_SUPER_SLOT_SIZE);
	if (error)
		goto out_unlock;
	error = vfs_fsync(store->super_file, 0);
	if (!error) {
		store->super = *record;
		store->newest_slot = slot;
	}
out_unlock:
	mutex_unlock(&store->lock);
	nfsd_ffv2_reservation_store_end(store->reservation);
out:
	kfree(bytes);
	return error;
}
