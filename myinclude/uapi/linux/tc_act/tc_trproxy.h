#ifndef __LINUX_TC_TRPROXY_H
#define __LINUX_TC_TRPROXY_H

#include <linux/types.h>
#include <linux/pkt_cls.h>

#define TCA_ACT_TRPROXY 27

#define TRPROXY_LPORT 0x1
#define TRPROXY_MARK 0x2
#define TRPROXY_MASK 0x4

struct tc_trproxy{
        tc_gen;
};

/*XXX: We need to encode the total number of bytes consumed */
enum {
        TCA_TRPROXY_UNSPEC,
        TCA_TRPROXY_PARMS,
        TCA_TRPROXY_TM,
        TCA_TRPROXY_LPORT,
        TCA_TRPROXY_MARK,
        TCA_TRPROXY_MASK,
        TCA_TRPROXY_PAD,
        __TCA_TRPROXY_MAX
};
#define TCA_TRPROXY_MAX (__TCA_TRPROXY_MAX - 1)


#endif

