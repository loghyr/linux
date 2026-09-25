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
#define NFSD_FFV2_STORE_CHECKSUM_NONE	0
#define NFSD_FFV2_STORE_CHECKSUM_CRC32	1
#define NFSD_FFV2_STORE_CHECKSUM_CRC32C	2
#define NFSD_FFV2_STORE_CHECKSUM_FLETCHER4 3
#define NFSD_FFV2_STORE_CHECKSUM_SHA256	4
#define NFSD_FFV2_PAYLOAD_SEQUENCE_MASK	GENMASK_ULL(39, 0)

#define NFSD_FFV2_FORMAT_VERSION		2
#define NFSD_FFV2_PROLOGUE_SIZE		36
#define NFSD_FFV2_WAL_HEADER_SIZE	72
#define NFSD_FFV2_SUPER_RECORD_SIZE	360
#define NFSD_FFV2_SUPER_SLOT_SIZE	4096
#define NFSD_FFV2_SUPER_FILE_SIZE	8192
#define NFSD_FFV2_START_RECORD_SIZE	197
#define NFSD_FFV2_CONTROL_PREFIX_SIZE	136
#define NFSD_FFV2_FILE_REGISTER_BODY_SIZE 184
#define NFSD_FFV2_FILE_REGISTER_RECORD_SIZE 396
#define NFSD_FFV2_ENTRY_BODY_SIZE	464
#define NFSD_FFV2_ENTRY_RECORD_SIZE	540
#define NFSD_FFV2_MAX_WAL_RECORD_SIZE	4236
#define NFSD_FFV2_MAX_DAMAGED_TAIL_SIZE	(1024U * 1024U)
#define NFSD_FFV2_PAYLOAD_HEADER_SIZE	80
#define NFSD_FFV2_PAYLOAD_DATA_HEADER_SIZE 136
#define NFSD_FFV2_PAYLOAD_ALIGN		4096

#define NFSD_FFV2_MIN_WAL_SIZE		3352972ULL
#define NFSD_FFV2_MAX_INCARNATION	0x00ffffffULL
#define NFSD_FFV2_MAX_OBJECTS		4U
#define NFSD_FFV2_MAX_TRANSACTIONS	256U
#define NFSD_FFV2_MAX_ADMISSIONS		32U
#define NFSD_FFV2_MAX_AUTHORITY_STATEIDS 64U
#define NFSD_FFV2_MIN_RESTARTS		64U
#define NFSD_FFV2_RESTART_HEADROOM	51909ULL
#define NFSD_FFV2_RECOVERY_HEADROOM	3322572ULL

#define NFSD_FFV2_RIGHT_READ		BIT(0)
#define NFSD_FFV2_RIGHT_WRITE		BIT(1)
#define NFSD_FFV2_RIGHT_REPAIR		BIT(2)
#define NFSD_FFV2_RIGHT_CONTROL		BIT(3)

enum nfsd_ffv2_store_record_type {
	NFSD_FFV2_SUPER_SLOT = 1,
	NFSD_FFV2_PAYLOAD_DATA = 1,
	NFSD_FFV2_PAYLOAD_FILE_HEADER = 2,
	NFSD_FFV2_WAL_START = 1,
	NFSD_FFV2_WAL_CONTROL = 2,
	NFSD_FFV2_WAL_ENTRY = 3,
	NFSD_FFV2_WAL_COHORT = 4,
};

enum nfsd_ffv2_transition {
	NFSD_FFV2_ADMITTED = 1,
	NFSD_FFV2_PREPARED = 2,
	NFSD_FFV2_FINALIZED = 3,
	NFSD_FFV2_COMMITTED = 4,
	NFSD_FFV2_ABORTED = 5,
	NFSD_FFV2_ROLLED_BACK = 6,
	NFSD_FFV2_REFUSED = 7,
};

enum nfsd_ffv2_control_subtype {
	NFSD_FFV2_FILE_REGISTER = 1,
	NFSD_FFV2_AUTHORITY_ADMIT = 3,
	NFSD_FFV2_TRUST_STATEID = 5,
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

struct nfsd_ffv2_file_register_record {
	u32 transition;
	u32 status;
	u8 file_key[32];
	u16 handle_type;
	u16 handle_len;
	u8 handle[NFSD_FFV2_STORE_HANDLE_SIZE];
	u32 chunk_bytes;
	u64 max_chunks;
	u64 logical_eof;
};

struct nfsd_ffv2_admission_record {
	u8 session[16];
	u8 principal[16];
	u8 issuer[16];
	u64 authority_epoch;
	u64 fence_sequence;
	u64 lease_epoch;
	u64 client_id;
	u32 stateid_seqid;
	u8 stateid_other[12];
	u32 writer;
	u32 rights;
};

struct nfsd_ffv2_control_record {
	u32 subtype;
	u32 transition;
	u32 status;
	u8 session[16];
	u8 admission_issuer[16];
	u64 admission_authority_epoch;
	u64 admission_client_id;
	u32 body_len;
	const u8 *body;
};

struct nfsd_ffv2_entry_record {
	u32 transition;
	u32 status;
	u32 disposition;
	u32 stability;
	u32 batch_ordinal;
	u32 batch_count;
	u8 session[16];
	u32 slot;
	u32 sequence;
	u32 ordinal;
	u8 operation_key[32];
	u8 request_digest[32];
	u8 file_key[32];
	u64 chunk_index;
	u64 txn_id;
	struct nfsd_ffv2_admission_record admission;
	u64 owner_cohort;
	u32 owner_client_id;
	u32 owner_co_id;
	u32 generation;
	bool predecessor_present;
	u64 predecessor_object_id;
	u32 predecessor_generation;
	bool postcond_present;
	u64 postcond_id;
	u64 payload_object_id;
	u32 writer_payload_id;
	u64 payload_object_offset;
	u32 payload_content_len;
	u32 extent_kind;
	u64 extent_high_water;
	u64 extent_highest_index;
	u64 index_generation;
	u8 result_verifier[8];
	bool result_activated;
	u64 result_visible_object_id;
	u32 result_effective_len;
	u32 result_checksum_algorithm;
	u32 result_checksum_len;
	u8 result_checksum[NFSD_FFV2_STORE_CHECKSUM_SIZE];
	bool result_guard_never_written;
	u32 result_guard_generation;
	u32 result_guard_writer;
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

struct nfsd_ffv2_visible_chunk {
	u64 version_object_id;
	u32 version_generation;
	u64 payload_object_id;
	u32 writer_payload_id;
	u64 payload_object_offset;
	u32 content_len;
	u32 content_crc32c;
	u32 checksum_algorithm;
	u32 checksum_len;
	u8 checksum[NFSD_FFV2_STORE_CHECKSUM_SIZE];
	u64 file_eof;
	u64 owner_cohort;
	u32 owner_client_id;
	u32 owner_co_id;
	u32 guard_generation;
	u32 guard_writer;
	bool guard_never_written;
};

struct nfsd_ffv2_store_file {
	u8 file_key[32];
	u32 chunk_bytes;
	u64 max_chunks;
	u64 logical_eof;
};

struct nfsd_ffv2_store_operation {
	u8 session[16];
	u32 slot;
	u32 sequence;
	u32 ordinal;
	u8 request_digest[32];
};

struct nfsd_ffv2_store_write {
	struct nfsd_ffv2_store_operation operation;
	u32 admission_id;
	u64 chunk_index;
	u32 stability;
	u64 owner_cohort;
	u32 owner_client_id;
	u32 owner_co_id;
	u32 writer_payload_id;
	bool guard_check;
	bool guard_never_written;
	u32 guard_generation;
	u32 guard_writer;
	bool activate_if_empty;
	u32 checksum_algorithm;
	u32 checksum_len;
	u8 checksum[NFSD_FFV2_STORE_CHECKSUM_SIZE];
	const u8 *content;
	u32 content_len;
};

struct nfsd_ffv2_store_lifecycle {
	struct nfsd_ffv2_store_operation operation;
	u32 admission_id;
	u64 chunk_index;
	u64 owner_cohort;
	u32 owner_client_id;
	u32 owner_co_id;
};

struct nfsd_ffv2_store_mutation_result {
	u32 status;
	u32 stability;
	bool activated;
	u8 verifier[8];
	struct {
		u64 cohort;
		u32 client_id;
		u32 co_id;
	} owner;
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
int nfsd_ffv2_file_register_decode(const u8 *in, size_t len,
				   const u8 *expected_store,
				   const u8 *expected_wal,
				   struct nfsd_ffv2_wal_header *header,
				   struct nfsd_ffv2_file_register_record *record);
int nfsd_ffv2_control_decode(const u8 *in, size_t len,
			     const u8 *expected_store, const u8 *expected_wal,
			     struct nfsd_ffv2_wal_header *header,
			     struct nfsd_ffv2_control_record *record);
int nfsd_ffv2_entry_decode(const u8 *in, size_t len,
			   const u8 *expected_store, const u8 *expected_wal,
			   struct nfsd_ffv2_wal_header *header,
			   struct nfsd_ffv2_entry_record *record);
int nfsd_ffv2_payload_header_encode(const struct nfsd_ffv2_payload_header *header,
				    u8 out[NFSD_FFV2_PAYLOAD_ALIGN]);
int nfsd_ffv2_payload_header_decode(const u8 in[NFSD_FFV2_PAYLOAD_ALIGN],
				    const u8 *expected_store,
				    struct nfsd_ffv2_payload_header *header);
size_t nfsd_ffv2_payload_record_size(u32 content_len);
bool nfsd_ffv2_store_checksum_valid(u32 algorithm, const u8 *checksum,
				    u32 checksum_len, const u8 *content,
				    u32 content_len);
int nfsd_ffv2_payload_encode(const struct nfsd_ffv2_payload_record *record,
			     u8 *out, size_t capacity, size_t *written);
int nfsd_ffv2_payload_decode(const u8 *in, size_t len,
			     const u8 *expected_store,
			     struct nfsd_ffv2_payload_record *record,
			     bool *content_valid);
bool nfsd_ffv2_restart_fits(u64 valid_bytes, u64 live_wal_reserved,
			    u64 capacity_wal_bytes, u64 *append_cursor);
bool nfsd_ffv2_payload_geometry_valid(u64 chunk_index, u32 content_len,
				      u32 chunk_bytes, u64 max_chunks);

int nfsd_ffv2_store_open(struct nfsd_ffv2_reservation *reservation,
			 struct nfsd_ffv2_store **result);
void nfsd_ffv2_store_close(struct nfsd_ffv2_store *store);
int nfsd_ffv2_store_get_super(struct nfsd_ffv2_store *store,
			      struct nfsd_ffv2_super_record *record);
int nfsd_ffv2_store_lookup_file(struct nfsd_ffv2_store *store,
				const u8 handle[32],
				struct nfsd_ffv2_store_file *file);
int nfsd_ffv2_store_admit_writer(struct nfsd_ffv2_store *store, u32 writer,
				 u8 stateid[16]);
struct nfsd_ffv2_store_admission {
	u32 id;
	u8 stateid[16];
};

int nfsd_ffv2_store_admit_writers(struct nfsd_ffv2_store *store, u32 writer,
				  u32 count,
				  struct nfsd_ffv2_store_admission *result);
int nfsd_ffv2_store_visible_chunk(struct nfsd_ffv2_store *store,
				  const u8 file_key[32], u64 chunk_index,
				  struct nfsd_ffv2_visible_chunk *chunk);
int nfsd_ffv2_store_write(struct nfsd_ffv2_store *store,
			  const u8 file_key[32],
			  const struct nfsd_ffv2_store_write *request,
			  struct nfsd_ffv2_store_mutation_result *result);
int nfsd_ffv2_store_finalize(struct nfsd_ffv2_store *store,
			     const u8 file_key[32],
			     const struct nfsd_ffv2_store_lifecycle *request,
			     struct nfsd_ffv2_store_mutation_result *result);
int nfsd_ffv2_store_commit(struct nfsd_ffv2_store *store,
			   const u8 file_key[32],
			   const struct nfsd_ffv2_store_lifecycle *request,
			   struct nfsd_ffv2_store_mutation_result *result);
#ifdef CONFIG_KUNIT
int nfsd_ffv2_store_test_visible_replay(
	const struct nfsd_ffv2_entry_record *entries, size_t count,
	u32 chunk_bytes, u64 max_chunks, u64 query_index,
	struct nfsd_ffv2_visible_chunk *chunk, u64 *eof);
#endif
int nfsd_ffv2_store_read_payload(struct nfsd_ffv2_store *store, void *data,
				 size_t len, loff_t offset);
int nfsd_ffv2_store_append_payload(struct nfsd_ffv2_store *store,
				   const struct nfsd_ffv2_payload_record *record,
				   u64 *offset);
int nfsd_ffv2_store_read_wal(struct nfsd_ffv2_store *store, void *data,
			     size_t len, loff_t offset);
int nfsd_ffv2_store_checkpoint(struct nfsd_ffv2_store *store,
			       const struct nfsd_ffv2_super_record *record);
#ifdef CONFIG_NFSD_FFV2_LIVE_TEST
void nfsd_ffv2_store_test_fail_next_alloc(struct nfsd_ffv2_store *store);
void nfsd_ffv2_store_test_fail_next_io(struct nfsd_ffv2_store *store);
u64 nfsd_ffv2_store_test_payload_size(struct nfsd_ffv2_store *store);
int nfsd_ffv2_store_test_visible_snapshot(struct nfsd_ffv2_store *store,
					  u8 **snapshot, size_t *len);
#endif

#endif /* _NFSD_FFV2_STORE_H */
