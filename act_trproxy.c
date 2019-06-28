/*
 * net/sched/act_trproxy.c	Transparent proxy action
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 */

#include <linux/module.h>
#include <linux/stringify.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <linux/ip.h>
#include "trproxy_sk.h"

#include <net/tc_act/tc_trproxy.h>	/* the path to be in LINUX kernel */

#define TRPROXY_TAB_MASK     15
#ifdef GIT_SHA1
#define TC_MODULE_VERSION(maj, min) __stringify(maj) "." __stringify(min) " " "Built " __DATE__" " __TIME__ " sha1 " GIT_SHA1
#else
#define TC_MODULE_VERSION(maj, min) __stringify(maj) "." __stringify(min) " " "Built " __DATE__" " __TIME__
#endif

static unsigned int trproxy_net_id;
static struct tc_action_ops act_trproxy_ops;

static int tcf_trproxy_run(struct sk_buff *skb, const struct tc_action *a,
			   struct tcf_result *res)
{

	struct tcf_trproxy *d = to_trproxy(a);
	u16 protocol = tc_skb_protocol(skb);
	u16 lport;
	u32 mark, mask, laddr_ip4;
	struct in6_addr laddr_ip6;

	spin_lock(&d->tcf_lock);
	tcf_lastuse_update(&d->tcf_tm);
	bstats_update(&d->tcf_bstats, skb);

	if (d->flags & TRPROXY_LPORT) {
		/* print policy 
		 */
		pr_info("trproxy:iface: %s | lport:%u | skbmark: %u | mark:%d | mask:%d | packets:%d\n",
			skb->dev->name, d->lport, skb->mark, d->mark, d->mask,
			d->tcf_bstats.packets);

		lport = htons(d->lport);
		mark = d->mark;
		mask = d->mask;
		spin_unlock(&d->tcf_lock);

		switch (protocol) {
		case cpu_to_be16(ETH_P_IP):
			pr_info("### IPv4 traffic...");
			laddr_ip4 = htonl(0);
			if (!(trproxy_act_ip4(dev_net(skb->dev), skb, laddr_ip4,
					      lport, mask, mark)))
				goto drop;
			break;
		case cpu_to_be16(ETH_P_IPV6):
			pr_info("### IPv6 traffic...");
			memset(&laddr_ip6, 0, sizeof(laddr_ip6));
			if (!(trproxy_act_ip6 (dev_net(skb->dev), skb,
					       &laddr_ip6, lport, mask, mark)))
				goto drop;
			break;
		}
		return d->tcf_action;
	} else {
		/* No listening port configured.
		   Not redirect the packets to sockets.
		 */
		pr_info("### No lport ...");
		skb->mark = (skb->mark & ~d->mask) ^ d->mark;
		spin_unlock(&d->tcf_lock);
		return d->tcf_action;
	}
drop:
	spin_lock(&d->tcf_lock);
	d->tcf_qstats.drops++;
	spin_unlock(&d->tcf_lock);
	return TC_ACT_SHOT;
}

static const struct nla_policy trproxy_policy[TCA_TRPROXY_MAX + 1] = {
	[TCA_TRPROXY_PARMS] = {.len = sizeof(struct tc_trproxy)},
	[TCA_TRPROXY_LPORT] = {.len = sizeof(u16)},
	[TCA_TRPROXY_MARK] = {.len = sizeof(u32)},
	[TCA_TRPROXY_MASK] = {.len = sizeof(u32)},
};

static int tcf_trproxy_init(struct net *net, struct nlattr *nla,
			    struct nlattr *est, struct tc_action **a,
			    int ovr, int bind)
{
	struct tc_action_net *tn = net_generic(net, trproxy_net_id);
	struct nlattr *tb[TCA_TRPROXY_MAX + 1];
	struct tc_trproxy *parm;
	struct tcf_trproxy *d;
	bool exists = false;
	int ret = 0, err;
	u16 *lport = NULL;
	u32 *mark = NULL, *mask = NULL;
	u32 flags = 0;

	if (nla == NULL)
		return -EINVAL;

	err = nla_parse_nested(tb, TCA_TRPROXY_MAX, nla, trproxy_policy, NULL);
	if (err < 0)
		return err;

	if (tb[TCA_TRPROXY_PARMS] == NULL)
		return -EINVAL;

	parm = nla_data(tb[TCA_TRPROXY_PARMS]);
#if 0
	exists = tcf_hash_check(tn, parm->index, a, bind);
#endif
	exists = tcf_idr_check(tn, parm->index, a, bind);
	if (exists && bind)
		return 0;

	if (tb[TCA_TRPROXY_MARK] == NULL || tb[TCA_TRPROXY_MASK] == NULL) {
		return -EINVAL;
	}

	mark = nla_data(tb[TCA_TRPROXY_MARK]);
	mask = nla_data(tb[TCA_TRPROXY_MASK]);
	flags |= (TRPROXY_MARK | TRPROXY_MASK);

	if (tb[TCA_TRPROXY_LPORT] != NULL) {
		lport = nla_data(tb[TCA_TRPROXY_LPORT]);
		flags |= TRPROXY_LPORT;
	}

	if (!exists) {
#if 0
		ret = tcf_hash_create(tn, parm->index, est, a,
				      &act_trproxy_ops, bind, false);
#endif
		ret = tcf_idr_create(tn, parm->index, est, a,
				      &act_trproxy_ops, bind, false);
		if (ret)
			return ret;

		d = to_trproxy(*a);
		ret = ACT_P_CREATED;
  pr_info("### parm->index=%d",parm->index);
	} else {
		d = to_trproxy(*a);
#if 0
		tcf_hash_release(*a, bind);
#endif
		tcf_idr_release(*a, bind);
	}

	spin_lock_bh(&d->tcf_lock);
	d->tcf_action = parm->action;
	if (flags & TRPROXY_LPORT)
		d->lport = *lport;
	d->mark = *mark;
	d->mask = *mask;
	d->flags = flags;
 pr_info("### flags=%d,lport=%d,mark=%d,mask=%d",flags,*lport,*mark,*mask);

	spin_unlock_bh(&d->tcf_lock);

	if (ret == ACT_P_CREATED)
#if 0
		tcf_hash_insert(tn, *a);
#endif
		tcf_idr_insert(tn, *a);
	return ret;
}

static int tcf_trproxy_dump(struct sk_buff *skb, struct tc_action *a,
			    int bind, int ref)
{
	unsigned char *b = skb_tail_pointer(skb);
	struct tcf_trproxy *d = to_trproxy(a);
	struct tc_trproxy opt = {
		.index = d->tcf_index,
		.refcnt = d->tcf_refcnt - ref,
		.bindcnt = d->tcf_bindcnt - bind,
		.action = d->tcf_action,
	};
	struct tcf_t t;

	if (nla_put(skb, TCA_TRPROXY_PARMS, sizeof(opt), &opt) ||
	    nla_put_u32(skb, TCA_TRPROXY_MARK, d->mark) ||
	    nla_put_u32(skb, TCA_TRPROXY_MASK, d->mask))
		goto nla_put_failure;

	if ((d->flags & TRPROXY_LPORT) &&
	    nla_put_u16(skb, TCA_TRPROXY_LPORT, d->lport))
		goto nla_put_failure;

	tcf_tm_dump(&t, &d->tcf_tm);
	if (nla_put_64bit(skb, TCA_TRPROXY_TM, sizeof(t), &t, TCA_TRPROXY_PAD))
		goto nla_put_failure;
	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int tcf_trproxy_walker(struct net *net, struct sk_buff *skb,
			      struct netlink_callback *cb, int type,
			      const struct tc_action_ops *ops)
{
	struct tc_action_net *tn = net_generic(net, trproxy_net_id);

	return tcf_generic_walker(tn, skb, cb, type, ops);
}

static int tcf_trproxy_search(struct net *net, struct tc_action **a, u32 index)
{
	struct tc_action_net *tn = net_generic(net, trproxy_net_id);
#if 0
	return tcf_hash_search(tn, a, index);
#endif
	return tcf_idr_search(tn, a, index);
}

static struct tc_action_ops act_trproxy_ops = {
	.kind = "trproxy",
	.type = TCA_ACT_TRPROXY,
	.owner = THIS_MODULE,
	.act = tcf_trproxy_run,
	.dump = tcf_trproxy_dump,
	.init = tcf_trproxy_init,
	.walk = tcf_trproxy_walker,
	.lookup = tcf_trproxy_search,
	.size = sizeof(struct tcf_trproxy),
};

static __net_init int trproxy_init_net(struct net *net)
{
	struct tc_action_net *tn = net_generic(net, trproxy_net_id);
#if 0
	return tc_action_net_init(tn, &act_trproxy_ops, TRPROXY_TAB_MASK);
#endif
	return tc_action_net_init(tn, &act_trproxy_ops);
}

static void __net_exit trproxy_exit_net(struct net *net)
{
	struct tc_action_net *tn = net_generic(net, trproxy_net_id);

	tc_action_net_exit(tn);
}

static struct pernet_operations trproxy_net_ops = {
	.init = trproxy_init_net,
	.exit_batch = trproxy_exit_net,
	.id = &trproxy_net_id,
	.size = sizeof(struct tc_action_net),
};

static int __init trproxy_init_module(void)
{
	int ret = tcf_register_action(&act_trproxy_ops, &trproxy_net_ops);
	if (!ret)
		pr_info("trproxy TC action Loaded\n");
	return ret;
}

static void __exit trproxy_cleanup_module(void)
{
	tcf_unregister_action(&act_trproxy_ops, &trproxy_net_ops);
}

module_init(trproxy_init_module);
module_exit(trproxy_cleanup_module);

MODULE_DESCRIPTION("Transparent Proxy Action");
MODULE_LICENSE("GPL");
MODULE_VERSION(TC_MODULE_VERSION(1,0));
