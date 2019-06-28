#ifndef __NET_TC_TRPROXY_H
#define __NET_TC_TRPROXY_H

#include <net/act_api.h>
#include <linux/tc_act/tc_trproxy.h>

struct tcf_trproxy {
        struct tc_action        common;
        u16             lport;
        u32             mark;
        u32             mask;
        u32             flags;
};
#define to_trproxy(a) ((struct tcf_trproxy *)a)

#endif /* __NET_TC_TRPROXY_H */
