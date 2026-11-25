/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef UP_FRAMED_CRC_H
#define UP_FRAMED_CRC_H
#include "feature/udp_plugin_abi.h"
/* Example wire: little-endian u16 body length, body, CRC32(header+body).
 * Output removes remove_tail bytes, appends append_bytes, regenerates CRC.
 */
struct up_frame_config {
    __u32 remove_tail;
    __u32 append_bytes;
    __u8 append[64];
};
#endif
