/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/errno.h>
#include "plugins/capture_sdk.h"
static int configure(const void *data, __u32 bytes, struct cp_policy *out)
{
    const struct cp_policy *in = data;
    if (!in || bytes != sizeof(*in) || !in->min_payload ||
        in->min_payload > in->max_payload || in->max_payload > 2048)
        return -EINVAL;
    *out = *in;
    return 0;
}
PLUGIN_NAME("udp-capture");
PLUGIN_VERSION("1");
PLUGIN_LICENSE("GPL-2.0");
PLUGIN_AUTHOR("");
PLUGIN_DESCRIPTION("Length-filtered UDP capture into the caller's shared ring");
PLUGIN_TYPE(PLUGIN_CAPTURE);
PLUGIN_CAPTURE_OPS(configure);
