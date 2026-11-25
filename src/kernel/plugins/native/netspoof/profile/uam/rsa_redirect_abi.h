/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef RSA_REDIRECT_ABI_H
#define RSA_REDIRECT_ABI_H
#include <linux/types.h>

#define RSA_REDIRECT_MAX_PROFILES 8U
#define RSA_REDIRECT_READ_MAX 16U
#define RSA_REDIRECT_MAX_ENTRY 4096U
#define RSA_REDIRECT_F_FILE 1U

/* All scalar fields are native-endian. Pointers are zero-extended user VAs.
 * PKCS#1 DER, RSA-2048; no PEM/SPKI. SET copies every buffer before returning.
 * Profiles apply to is_black_user(uid), not package names. capture_pid=0
 * records all selected UIDs; a positive PID filters records, NEVER rewrap.
 * FILE copies the manifest now and validates/binds the file on the first
 * matching successful read by a selected UID using minimum actual-read context.
 * The discovered offset is kernel-private; no caller open or fixed size/digest.
 * Identical FILE original patterns return EEXIST. Distinct patterns coexist, but
 * multiple eligible profiles or locations return ENOTUNIQ before binding/write.
 * Without FILE zero all file-related fields. */
struct rsa_redirect_config {
    __u32 flags;
    __u32 expected_crc;
    __u32 original_crc;
    __u32 key_id;
    __s32 capture_pid;
    __u32 entry_len;
    __aligned_u64 private_der;
    __aligned_u64 public_der;
    __aligned_u64 original_entry;
    __aligned_u64 replacement_entry;
    __u32 private_der_len;
    __u32 public_der_len;
    __u32 reserved[2];
};

/* Only successfully submitted, rewrapped UDP sends produce a record.
 * remote_addr is IPv6 network-order bytes; IPv4 uses ::ffff:a.b.c.d.
 * nonce is the exact 8 bytes following key in the 40-byte RSA plaintext.
 * Only consumer-required fields are exported; profile ownership stays private. */
struct rsa_redirect_result {
    __aligned_u64 sequence;
    __aligned_u64 timestamp_ns;
    __s32 pid;
    __u8 remote_addr[16];
    __u8 key[32];
    __u8 nonce[8];
    __u8 _padding[4];
};

/* DEL: arg3 = expected_crc (u32 value, not a pointer).
 * READ: arg3 = records, arg4 = max_count, arg5 = u64 *dropped.
 * READ returns the consumed count, or a negative errno. No request wrapper.
 * On EFAULT records stay queued;
 * a retry may repeat a copied record, so consumers deduplicate sequence.
 * On overflow the oldest record is zeroed and replaced; dropped is cumulative. */

/* STATS: arg3 points to this output. No version negotiation. */
struct rsa_redirect_stats {
    __u32 profiles;
    __u32 _padding;
    __aligned_u64 rewrapped;
    __aligned_u64 crypto_failed;
    __aligned_u64 send_failed;
    __aligned_u64 rewritten_reads;
    __aligned_u64 read_failed;
    __aligned_u64 captured;
    __aligned_u64 dropped;
};
#endif
