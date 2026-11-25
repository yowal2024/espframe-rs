/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NATIVE_PLUGIN_SDK_H
#define NATIVE_PLUGIN_SDK_H
#include <linux/types.h>
#define PLUGIN_DESCRIPTOR_MAGIC 0x4e4154504c554749ULL
enum plugin_type { PLUGIN_UDP = 1, PLUGIN_READ, PLUGIN_TCP, PLUGIN_CAPTURE, PLUGIN_RSA };
/* String capacities include the terminating NUL. Version is descriptive only. */
#define PLUGIN_NAME_CAP 32U
#define PLUGIN_VERSION_CAP 32U
#define PLUGIN_LICENSE_CAP 32U
#define PLUGIN_AUTHOR_CAP 64U
#define PLUGIN_DESCRIPTION_CAP 256U
/* Every typed descriptor starts with this immutable header. Entry and callbacks
 * are trusted native code; the host validates the header before selecting ops.
 * Entry only returns the descriptor; it must not retain state or start work.
 * No ABI negotiation: rebuild plugins and host together when the SDK changes. */
struct plugin_descriptor {
    __u64 magic;
    __u32 type;
    __u32 reserved;
    const char *name;
    const char *version;
    const char *license;
    const char *author;
    const char *description;
};
typedef const struct plugin_descriptor *(*plugin_entry_fn)(void);
/* Declare each field once in the same translation unit as PLUGIN_*_OPS.
 * Only NAME must be nonempty. Text must be string literals (or literal macros).
 * The typed registration checks callback signatures without function casts. */
#define __PLUGIN_TEXT(field, value, capacity) \
    _Static_assert(sizeof("" value) <= (capacity), "PLUGIN_" #field " is too long"); \
    static const char __plugin_##field[(capacity)] = "" value
#define PLUGIN_NAME(value) \
    _Static_assert(sizeof("" value) > 1, "PLUGIN_NAME must not be empty"); \
    __PLUGIN_TEXT(name, value, PLUGIN_NAME_CAP)
#define PLUGIN_VERSION(value) __PLUGIN_TEXT(version, value, PLUGIN_VERSION_CAP)
#define PLUGIN_LICENSE(value) __PLUGIN_TEXT(license, value, PLUGIN_LICENSE_CAP)
#define PLUGIN_AUTHOR(value) __PLUGIN_TEXT(author, value, PLUGIN_AUTHOR_CAP)
#define PLUGIN_DESCRIPTION(value) __PLUGIN_TEXT(description, value, PLUGIN_DESCRIPTION_CAP)
#define PLUGIN_TYPE(kind) \
    _Static_assert((kind) == PLUGIN_UDP || (kind) == PLUGIN_READ || (kind) == PLUGIN_TCP || (kind) == PLUGIN_CAPTURE || (kind) == PLUGIN_RSA, "invalid plugin type"); \
    enum { __plugin_type = (kind) }
#define __PLUGIN_HEADER { \
    .magic = PLUGIN_DESCRIPTOR_MAGIC, .type = __plugin_type, \
    .name = __plugin_name, .version = __plugin_version, .license = __plugin_license, \
    .author = __plugin_author, .description = __plugin_description \
}
#define __PLUGIN_ENTRY() \
    __attribute__((visibility("default"))) \
    const struct plugin_descriptor *plugin_entry(void) \
    { return &__plugin_descriptor.header; }
#endif
