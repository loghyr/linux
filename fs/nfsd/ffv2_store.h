/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NFSD_FFV2_STORE_H
#define _NFSD_FFV2_STORE_H

#include <linux/bits.h>
#include <linux/types.h>

struct nfsd_ffv2_reservation;
struct nfsd_ffv2_store;

#define NFSD_FFV2_STORE_UUID_SIZE	16
#define NFSD_FFV2_STORE_HANDLE_SIZE	128
#define NFSD_FFV2_STORE_CHECKSUM_SIZE	64

#define NFSD_FFV2_FORMAT_VERSION		1
#define NFSD_FFV2_PROLOGUE_SIZE		36
#define NFSD_FFV2_WAL_HEADER_SIZE	72
#define NFSD_FFV2_SUPER_RECORD_SIZE	360
#define NFSD_FFV2_SUPER_SLOT_SIZE	4096
#define NFSD_FFV2_SUPER_FILE_SIZE	8192
#define NFSD_FFV2_START_RECORD_SIZE	197
#define NFSD_FFV2_PAYLOAD_HEADER_SIZE	80
#define NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE 136
#define NFSD_FFV2_PAYLOAD_ALIGN		4096

#define NFSD_FFV2_MIN_WAL_SIZE		3352780ULL
#define NFSD_FFV2_MAX_INCARNATION	0x00ffffffULL

enum nfsd_ffv2_store_record_type {
	NFSD_FFV2_SUPER_SLOT = 1,
	NFSD_FFV2_PAYLOAD_DATA = 1,
	NFSD_FFV2_PAYLOAD_FILE_HEADER = 2,
	NFSD_FFV2_WAL_START = 1,
};

enum nfsd_ffv2_super_state {
	NFSD_FFV2_SUPER_CLEAN = 1,
	NFSD_FFV2_SUPER_NEEDS_RECOVERY = 2,
	NFSD_FFV2_SUPER_FENCED = 3,
	NFSD_FFV2_SUPER_RETIRED = 4,
};

enum nfsd_ffv2_recovery_decision {
	NFSD_FFV2_RECOVERY_FIRST_PROVISION = BIT(0),
	NFSD_FFV2_RECOVERY_CLEAN_SCAN = BIT(1),
	NFSD_FFV2_RECOVERY_TRUNCATED_TAIL = BIT(2),
	NFSD_FFV2_RECOVERY_DISCARDED_UNSTABLE = BIT(3),
	NFSD_FFV2_RECOVERY_ADMIN_CLEARED_FENCE = BIT(4),
	NFSD_FFV2_RECOVERY_TRUNCATED_NONZERO_TAIL = BIT(5),
};

struct nfsd_ffv2_super_record {
	u8 store_uuid[NFSD_FFV2_STORE_UUID_SIZE];
	u64 generation;
	u8 fs_uuid[NFSD_FFV2_STORE_UUID_SIZE];
	u64 fs_dev_hint;
	u16 root_handle_type;
	u16 root_handle_len;
	u8 root_handle[NFSD_FFV2_STORE_HANDLE_SIZE];
	u8 export_uuid[NFSD_FFV2_STORE_UUID_SIZE];
	u64 ds_incarnation;
	u64 verifier_epoch;
	u8 write_verifier[8];
	u8 wal_uuid[NFSD_FFV2_STORE_UUID_SIZE];
	u8 payload_uuid[NFSD_FFV2_STORE_UUID_SIZE];
	u8 binding_token_digest[32];
	u64 wal_durable_lsn;
	u64 wal_durable_bytes;
	u64 payload_durable_bytes;
	u64 capacity_wal_bytes;
	u64 capacity_payload_bytes;
	u32 state;
	u32 format_floor;
};

struct nfsd_ffv2_wal_header {
	u16 family;
	u32 total_bytes;
	u8 store_uuid[NFSD_FFV2_STORE_UUID_SIZE];
	u8 wal_uuid[NFSD_FFV2_STORE_UUID_SIZE];
	u64 lsn;
	u64 ds_incarnation;
};

struct nfsd_ffv2_start_record {
	u64 ds_incarnation;
	u64 prev_incarnation;
	u64 verifier_epoch;
	bool verifier_changed;
	u32 recovery_decision;
	u64 truncated_bytes;
	u64 last_valid_lsn_before;
	u64 wal_append_cursor;
	u64 payload_append_cursor;
	u64 capacity_wal_bytes;
	u64 capacity_payload_bytes;
	u8 export_uuid[NFSD_FFV2_STORE_UUID_SIZE];
	u64 live_txn_wal_reserved;
	u64 live_txn_payload_outstanding;
	u64 live_txn_payload_staged;
};

struct nfsd_ffv2_payload_header {
	u8 store_uuid[NFSD_FFV2_STORE_UUID_SIZE];
	u8 payload_uuid[NFSD_FFV2_STORE_UUID_SIZE];
	u8 wal_uuid[NFSD_FFV2_STORE_UUID_SIZE];
};

struct nfsd_ffv2_payload_record {
	u8 store_uuid[NFSD_FFV2_STORE_UUID_SIZE];
	u64 object_id;
	u32 content_crc32c;
	u32 checksum_algorithm;
	u32 checksum_len;
	u8 checksum[NFSD_FFV2_STORE_CHECKSUM_SIZE];
	u32 content_len;
	u64 object_bytes;
	const u8 *content;
};

int nfsd_ffv2_super_encode(const struct nfsd_ffv2_super_record *record,
			   u8 out[NFSD_FFV2_SUPER_SLOT_SIZE]);
int nfsd_ffv2_super_decode(const u8 in[NFSD_FFV2_SUPER_SLOT_SIZE],
			   const u8 *expected_store,
			   struct nfsd_ffv2_super_record *record);
int nfsd_ffv2_start_encode(const struct nfsd_ffv2_wal_header *header,
			   const struct nfsd_ffv2_start_record *record,
			   u8 out[NFSD_FFV2_START_RECORD_SIZE]);
int nfsd_ffv2_start_decode(const u8 *in, size_t len,
			   const u8 *expected_store, const u8 *expected_wal,
			   struct nfsd_ffv2_wal_header *header,
			   struct nfsd_ffv2_start_record *record);
int nfsd_ffv2_payload_header_encode(const struct nfsd_ffv2_payload_header *header,
				    u8 out[NFSD_FFV2_PAYLOAD_ALIGN]);
int nfsd_ffv2_payload_header_decode(const u8 in[NFSD_FFV2_PAYLOAD_ALIGN],
				    const u8 *expected_store,
				    struct nfsd_ffv2_payload_header *header);
size_t nfsd_ffv2_payload_record_size(u32 content_len);
int nfsd_ffv2_payload_encode(const struct nfsd_ffv2_payload_record *record,
			     u8 *out, size_t capacity, size_t *written);
int nfsd_ffv2_payload_decode(const u8 *in, size_t len,
			     const u8 *expected_store,
			     struct nfsd_ffv2_payload_record *record,
			     bool *content_valid);

int nfsd_ffv2_store_open(struct nfsd_ffv2_reservation *reservation,
			 struct nfsd_ffv2_store **result);
void nfsd_ffv2_store_close(struct nfsd_ffv2_store *store);
int nfsd_ffv2_store_get_super(struct nfsd_ffv2_store *store,
			      struct nfsd_ffv2_super_record *record);
int nfsd_ffv2_store_read_payload(struct nfsd_ffv2_store *store, void *data,
				 size_t len, loff_t offset);
int nfsd_ffv2_store_write_payload(struct nfsd_ffv2_store *store,
				  const void *data, size_t len, loff_t offset);
int nfsd_ffv2_store_read_wal(struct nfsd_ffv2_store *store, void *data,
			     size_t len, loff_t offset);
int nfsd_ffv2_store_write_wal(struct nfsd_ffv2_store *store, const void *data,
			      size_t len, loff_t offset);
int nfsd_ffv2_store_checkpoint(struct nfsd_ffv2_store *store,
			       const struct nfsd_ffv2_super_record *record);

#endif /* _NFSD_FFV2_STORE_H */
