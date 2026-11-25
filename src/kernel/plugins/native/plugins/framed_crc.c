// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include "sdk.h"
#include "framed_crc.h"

PLUGIN_NAME("framed-crc-example");
PLUGIN_VERSION("1.0.0");
PLUGIN_LICENSE("GPL");
PLUGIN_AUTHOR("");
PLUGIN_DESCRIPTION("Framed CRC UDP example");
PLUGIN_TYPE(PLUGIN_UDP);

static int create(const struct up_host *h,const void *data,__u32 n,void **out)
{
    const struct up_frame_config *c=data;
    if(!data || n!=sizeof(*c) || c->append_bytes>sizeof(c->append) ||
       c->remove_tail>UR_MAX_PAYLOAD)return -EINVAL;
    *out=h->alloc(sizeof(*c));if(!*out)return -ENOMEM;
    up_copy(*out,c,sizeof(*c));return 0;
}
static void destroy(const struct up_host *h,void *p) { h->free(p,sizeof(struct up_frame_config)); }
static __u32 get32(const __u8 *p)
{ return (__u32)p[0]|(__u32)p[1]<<8|(__u32)p[2]<<16|(__u32)p[3]<<24; }
static void put32(__u8 *p,__u32 n)
{ p[0]=n;p[1]=n>>8;p[2]=n>>16;p[3]=n>>24; }
static int process(const struct up_host *h,const void *context,const struct up_packet *p,
                   void *state,__u8 *out,__u32 capacity,struct up_result *r)
{
    const struct up_frame_config *c=context;
    __u32 n,size;
    (void)state;
    if(p->bytes<6)return -EBADMSG;
    n=p->data[0]|(__u32)p->data[1]<<8;
    if(n!=p->bytes-6 || h->crc32(p->data,n+2)!=get32(p->data+n+2))return -EBADMSG;
    if(c->remove_tail>n)return -EINVAL;
    size=n-c->remove_tail+c->append_bytes;
    if(size+6>capacity)return -EMSGSIZE;
    out[0]=size;out[1]=size>>8;
    up_copy(out+2,p->data+2,n-c->remove_tail);
    up_copy(out+2+n-c->remove_tail,c->append,c->append_bytes);
    put32(out+size+2,h->crc32(out,size+2));
    r->bytes=size+6;r->matched=1;return UP_REPLACE;
}
PLUGIN_UDP_OPS(create, destroy, process, 0, UR_MAX_PAYLOAD, 0);
