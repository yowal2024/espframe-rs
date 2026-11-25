// SPDX-License-Identifier: GPL-2.0
#include "sdk.h"
#include "feature/udp_rules_core.h"

PLUGIN_NAME("raw-rules");
PLUGIN_VERSION("1.0.0");
PLUGIN_LICENSE("GPL");
PLUGIN_AUTHOR("");
PLUGIN_DESCRIPTION("UDP byte rules");
PLUGIN_TYPE(PLUGIN_UDP);

struct rule_state { __u64 commits[UR_MAX_RULES]; };
_Static_assert(UR_MAX_RULES <= 32, "parameter-use bitmap capacity");
struct rule_context {
    struct ur_program program;
    __u32 uses_params; /* Indexed after priority sorting; immutable hot-path data. */
};
static int create(const struct up_host *h,const void *data,__u32 n,void **out)
{
    struct rule_context *context;
    struct ur_program *p;
    unsigned int i,j;
    int rc;
    if(!data || n!=sizeof(*p))return -EINVAL;
    rc=ur_validate(data);if(rc)return rc;
    context=h->alloc(sizeof(*context));if(!context)return -ENOMEM;
    p=&context->program;
    up_copy(p,data,sizeof(*p));
    for(i=1;i<p->rule_count;i++) {
        struct ur_rule r=p->rules[i];
        for(j=i;j && (p->rules[j-1].priority>r.priority ||
             (p->rules[j-1].priority==r.priority && p->rules[j-1].id>r.id));j--)
            p->rules[j]=p->rules[j-1];
        p->rules[j]=r;
    }
    context->uses_params=0;
    for(i=0;i<p->rule_count;i++)
        for(j=0;j<p->rules[i].edit_count;j++)
            if(p->rules[i].edits[j].source==UR_PARAMETER)
                context->uses_params|=1U<<i;
    *out=context;return 0;
}
static void destroy(const struct up_host *h,void *p) { h->free(p,sizeof(struct rule_context)); }
static int process(const struct up_host *h,const void *context,const struct up_packet *p,
                   void *state,__u8 *out,__u32 capacity,struct up_result *result)
{
    const struct rule_context *rules=context;
    const struct ur_program *program=&rules->program;
    struct rule_state *st=state;
    unsigned int i;
    (void)h;
    for(i=0;i<program->rule_count;i++) {
        const struct ur_rule *r=&program->rules[i];
        int uses=0;
        if(r->expires_ns && p->now_ns>=r->expires_ns)continue;
        if(!ur_matches(r,p->data,p->bytes))continue;
        result->matched++;result->rule_id=r->id;
        if(!r->edit_count)return UP_OBSERVE;
        uses=!!(rules->uses_params & (1U<<i));
        if(uses && !p->params_available){result->stale++;return -ESTALE;}
        if((r->max_commits && st->commits[i]>=r->max_commits) ||
           (uses && p->params_claimed)){result->limited++;continue;}
        if(p->bytes>capacity)return -EMSGSIZE;
        /* UP_SAME_LENGTH receives the host's independent, initialized copy. */
        ur_edit(r,p->data,out,p->params);
        st->commits[i]++;
        result->bytes=p->bytes;result->flags=uses?UP_USED_PARAMS:0;
        result->expires_ns=r->expires_ns;
        return UP_REPLACE;
    }
    return UP_PASS;
}
PLUGIN_UDP_OPS(create, destroy, process, sizeof(struct rule_state), UR_MAX_PAYLOAD, UP_SAME_LENGTH);
