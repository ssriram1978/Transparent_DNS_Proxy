#ifndef __NET_TRPROXY_SK_H
#define __NET_TRPROXY_SK_H

#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <net/inet_sock.h>
#include <net/inet_hashtables.h>
#include <linux/inetdevice.h>

#include <net/if_inet6.h>
#include <net/addrconf.h>
#include <net/inet6_hashtables.h>

static void trproxy_assign_sock(struct sk_buff *skb, struct sock *sk)
{
	skb_orphan(skb);
	skb->sk = sk;
	skb->destructor = sock_edemux;
}

static bool trproxy_sk_is_transparent(struct sock *sk)
{
	switch (sk->sk_state) {
	case TCP_TIME_WAIT:
		if (inet_twsk(sk)->tw_transparent)
			return true;
		break;
	case TCP_NEW_SYN_RECV:
		if (inet_rsk(inet_reqsk(sk))->no_srccheck)
			return true;
		break;
	default:
		if (inet_sk(sk)->transparent)
			return true;
	}
	sock_gen_put(sk);
	return false;
}

static inline __be32 trproxy_listener_addr_ip4(struct sk_buff *skb,
					       __be32 listen_addr,
					       __be32 dest_addr)
{
	struct in_device *indev;
	__be32 laddr;

	if (listen_addr)
		return listen_addr;

	laddr = 0;
	rcu_read_lock();
	indev = __in_dev_get_rcu(skb->dev);
	for_primary_ifa(indev) {
		laddr = ifa->ifa_local;
		break;
	}
	endfor_ifa(indev);
	rcu_read_unlock();

	return laddr ? laddr : dest_addr;
}

static inline const struct in6_addr *trproxy_listener_addr_ip6(struct sk_buff
							       *skb, const struct
							       in6_addr
							       *listen_addr, const struct
							       in6_addr *daddr)
{
	struct inet6_dev *indev;
	struct inet6_ifaddr *ifa;
	struct in6_addr *laddr;

	if (!ipv6_addr_any(listen_addr))
		return listen_addr;
	laddr = NULL;

	rcu_read_lock();
	indev = __in6_dev_get(skb->dev);
	if (indev)
		list_for_each_entry(ifa, &indev->addr_list, if_list) {
		if (ifa->flags & (IFA_F_TENTATIVE | IFA_F_DEPRECATED))
			continue;

		laddr = &ifa->addr;
		break;
		}
	rcu_read_unlock();

	return laddr ? laddr : daddr;
}

static unsigned int trproxy_act_ip4(struct net *net, struct sk_buff *skb,
				    __be32 laddr, __be16 lport, u32 mark_mask,
				    u32 mark_value)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct udphdr _hdr, *hp;
	struct tcphdr _tcphdr, *tcphp;
	struct sock *sk;

	hp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_hdr), &_hdr);
	if (hp == NULL)
		return 0;

	laddr = trproxy_listener_addr_ip4(skb, laddr, iph->daddr);
	lport = lport ? lport : hp->dest;
	/* Check if the socket is established. */
	switch (iph->protocol) {
	case IPPROTO_TCP:
		sk = inet_lookup_established(net, &tcp_hashinfo, iph->saddr,
					     hp->source, iph->daddr, hp->dest,
					     skb->dev->ifindex);
		if (sk && sk->sk_state == TCP_TIME_WAIT) {
			tcphp = skb_header_pointer(skb, ip_hdrlen(skb),
						   sizeof(_tcphdr), &_tcphdr);
			if (tcphp == NULL) {
				inet_twsk_put(inet_twsk(sk));
				sk = NULL;
				goto result;
			} else if (tcphp->syn && !tcphp->rst &&
				   !tcphp->ack && !tcphp->fin) {
				struct sock *sk2;
				sk2 =
				    inet_lookup_listener(net, &tcp_hashinfo,
							 skb,
							 ip_hdrlen(skb) +
							 __tcp_hdrlen(&_tcphdr),
							 iph->saddr,
							 tcphp->source, laddr,
							 lport,
							 skb->dev->ifindex,0);
				if (sk2 && atomic_inc_not_zero(&sk2->sk_refcnt)) {
					inet_twsk_deschedule_put(inet_twsk(sk));
					sk = sk2;
				}
			}
		}
		break;
	case IPPROTO_UDP:
		sk = udp4_lib_lookup(net, iph->saddr, hp->source, iph->daddr,
				     hp->dest, skb->dev->ifindex);
		if (sk && (!(sk->sk_state == TCP_ESTABLISHED)
			   || !inet_sk(sk)->inet_rcv_saddr)) {
			sock_put(sk);
			sk = NULL;
		}
		break;
	default:
		WARN_ON(1);
		sk = NULL;
	}

	if (!sk) {
		/* If no established socket, look up a listening socket */
		switch (iph->protocol) {
		case IPPROTO_TCP:
			sk = inet_lookup_listener(net, &tcp_hashinfo, skb,
						  ip_hdrlen(skb) +
						  __tcp_hdrlen(&_tcphdr),
						  iph->saddr, hp->source, laddr,
						  lport, skb->dev->ifindex);
			if (sk && !atomic_inc_not_zero(&sk->sk_refcnt))
				sk = NULL;
			break;
		case IPPROTO_UDP:
			sk = udp4_lib_lookup(net, iph->saddr, hp->source,
					     laddr, lport, skb->dev->ifindex);
			if (sk && sk->sk_state == TCP_ESTABLISHED) {
				sock_put(sk);
				sk = NULL;
			}
			break;
		default:
			WARN_ON(1);
			sk = NULL;
		}
	}

result:
	if (sk && trproxy_sk_is_transparent(sk)) {
		skb->mark = (skb->mark & ~mark_mask) ^ mark_value;

		//assign a value to tc_index
		skb->tc_index = 0xFFFF;

		/*
		 * Kernel allows sk_mark to be initialized from skb->mark value,
		 * to achieve this set sysctl net.ipv4.fwmark_reflect=1
		 * */
                
                if(iph->protocol == IPPROTO_TCP) {
                    struct tcphdr _tcphdr2, *tcphp2;
                    tcphp2 = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(_tcphdr2), &_tcphdr2);
                    if (tcphp2 != NULL) {
                       if(tcphp2->syn) {
                           if(tcphp2->ack) {
                               pr_info("redirecting: sk %p, | proto TCP,SYN-ACK src:%pI4:%hu dest:%pI4:%hu -> %pI4:%hu, mark: %x\n",
                               sk, &iph->saddr, ntohs(tcphp2->source), &iph->daddr, ntohs(tcphp2->dest),
                               &laddr, ntohs(lport), skb->mark);
                           } else {
                               pr_info("redirecting: sk %p, | proto TCP,SYN src:%pI4:%hu dest:%pI4:%hu -> %pI4:%hu, mark: %x\n",
                               sk, &iph->saddr, ntohs(tcphp2->source), &iph->daddr, ntohs(tcphp2->dest),
                               &laddr, ntohs(lport), skb->mark);
                           }
                       }
                       else if(tcphp2->fin) {
                           if(tcphp2->ack) {
                               pr_info("redirecting: sk %p, | proto TCP,FIN-ACK src:%pI4:%hu dest:%pI4:%hu -> %pI4:%hu, mark: %x\n",
                               sk, &iph->saddr, ntohs(tcphp2->source), &iph->daddr, ntohs(tcphp2->dest),
                               &laddr, ntohs(lport), skb->mark);
                           } else {
                               pr_info("redirecting: sk %p, | proto TCP,FIN src:%pI4:%hu dest:%pI4:%hu -> %pI4:%hu, mark: %x\n",
                               sk, &iph->saddr, ntohs(tcphp2->source), &iph->daddr, ntohs(tcphp2->dest),
                               &laddr, ntohs(lport), skb->mark);
                           }
                       }
                       else if(tcphp2->rst) {
                           if(tcphp2->ack) {
                               pr_info("redirecting: sk %p, | proto TCP,RST-ACK src:%pI4:%hu dest:%pI4:%hu -> %pI4:%hu, mark: %x\n",
                               sk, &iph->saddr, ntohs(tcphp2->source), &iph->daddr, ntohs(tcphp2->dest),
                               &laddr, ntohs(lport), skb->mark);
                           } else {
                               pr_info("redirecting: sk %p, | proto TCP,RST src:%pI4:%hu dest:%pI4:%hu -> %pI4:%hu, mark: %x\n",
                               sk, &iph->saddr, ntohs(tcphp2->source), &iph->daddr, ntohs(tcphp2->dest),
                               &laddr, ntohs(lport), skb->mark);
                           }
                       }
                       else if(tcphp2->ack) {
                               pr_info("redirecting: sk %p, | proto TCP,ACK src:%pI4:%hu dest:%pI4:%hu -> %pI4:%hu, mark: %x\n",
                               sk, &iph->saddr, ntohs(tcphp2->source), &iph->daddr, ntohs(tcphp2->dest),
                               &laddr, ntohs(lport), skb->mark);
                       }
                    }
                }                 else {                   
                pr_info("redirecting: sk %p, | proto %hhu src:%p dest:%pI4:%hu -> %pI4:%hu, mark: %x\n",
                sk, iph->protocol, &iph->saddr, &iph->daddr, ntohs(hp->dest),
                &laddr, ntohs(lport), skb->mark);
                }
		trproxy_assign_sock(skb, sk);
		return 1;
	}

	pr_info("no socket: proto %hhu %pI4:%hu -> %pI4:%hu, mark: %x\n",
		 iph->protocol, &iph->saddr, ntohs(hp->source),
		 &iph->daddr, ntohs(hp->dest), skb->mark);
	return 0;
}

static unsigned int trproxy_act_ip6(struct net *net, struct sk_buff *skb,
				    struct in6_addr *listen_addr, __be16 lport,
				    u32 mark_mask, u32 mark_value)
{
	const struct ipv6hdr *iph = ipv6_hdr(skb);
	struct udphdr _hdr, *hp;
	struct tcphdr _tcphdr, *tcphp;
	struct sock *sk;
	int thoff = 0;
	int tcproto;
	const struct in6_addr *laddr;

	tcproto = ipv6_find_hdr(skb, &thoff, -1, NULL, NULL);
	if (tcproto < 0) {
		pr_info("unable to find transport header in IPv6 packet.\n");
		return 0;
	}

	hp = skb_header_pointer(skb, thoff, sizeof(_hdr), &_hdr);
	if (hp == NULL) {
		pr_info
		    ("unable to grab transport header contents in IPv6 packet\n");
		return 0;
	}

	laddr = trproxy_listener_addr_ip6(skb, listen_addr, &iph->daddr);
	lport = lport ? lport : hp->dest;
	/* Check if the socket is established. */
	switch (tcproto) {
	case IPPROTO_TCP:
		sk = __inet6_lookup_established(net, &tcp_hashinfo, &iph->saddr,
						hp->source, &iph->daddr,
						ntohs(hp->dest),
						skb->dev->ifindex);
		if (sk && sk->sk_state == TCP_TIME_WAIT) {
			tcphp =
			    skb_header_pointer(skb, thoff, sizeof(_tcphdr),
					       &_tcphdr);
			if (tcphp == NULL) {
				inet_twsk_put(inet_twsk(sk));
				sk = NULL;
				goto result;
			} else if (tcphp->syn && !tcphp->rst &&
				   !tcphp->ack && !tcphp->fin) {
				struct sock *sk2;
				sk2 = inet6_lookup_listener(net, &tcp_hashinfo,
							    skb,
							    thoff +
							    __tcp_hdrlen
							    (&_tcphdr),
							    &iph->saddr,
							    tcphp->source,
							    laddr, ntohs(lport),
							    skb->dev->ifindex);
				if (sk2 && atomic_inc_not_zero(&sk2->sk_refcnt)) {
					inet_twsk_deschedule_put(inet_twsk(sk));
					sk = sk2;
				}
			}
		}
		break;
	case IPPROTO_UDP:
		sk = udp6_lib_lookup(net, &iph->saddr, hp->source, &iph->daddr,
				     hp->dest, skb->dev->ifindex);
		if (sk && (!(sk->sk_state == TCP_ESTABLISHED)
			   || ipv6_addr_any(&sk->sk_v6_rcv_saddr))) {
			sock_put(sk);
			sk = NULL;
		}
		break;
	default:
		WARN_ON(1);
		sk = NULL;
	}

	if (sk)
		pr_info("### ipv6 socket is established.");

	if (!sk) {
		pr_info("### Looking up ipv6 listening socket .");
		switch (tcproto) {
		case IPPROTO_TCP:
			sk = inet6_lookup_listener(net, &tcp_hashinfo, skb,
						   thoff +
						   __tcp_hdrlen(&_tcphdr),
						   &iph->saddr, hp->source,
						   laddr, ntohs(lport),
						   skb->dev->ifindex);
			if (sk)
				pr_info("###listening socket refcount %u",
					atomic_read(&sk->sk_refcnt));
			if (sk && !atomic_inc_not_zero(&sk->sk_refcnt))
				sk = NULL;
			if (sk) {
				pr_info
				    ("### Obtained IPv6 TCP listening socket %u",
				     atomic_read(&sk->sk_refcnt));

				//skb->tc_index = 0xFFFF;
			}
			break;
		case IPPROTO_UDP:
			sk = udp6_lib_lookup(net, &iph->saddr, hp->source,
					     laddr, lport, skb->dev->ifindex);
			if (sk && sk->sk_state == TCP_ESTABLISHED) {
				sock_put(sk);
				sk = NULL;
			}
			break;
		default:
			WARN_ON(1);
			sk = NULL;
		}
	}

result:
	if (sk && trproxy_sk_is_transparent(sk)) {
		skb->mark = (skb->mark & ~mark_mask) ^ mark_value;
		skb->tc_index = 0xFFFF;

		pr_info("redirecting: sk %p, sk_mark %x | proto %hhu %pI6:%hu -> %pI6:%hu, mark: %x\n",
			sk, sk->sk_mark, tcproto, &iph->daddr, ntohs(hp->dest),
			laddr, ntohs(lport), skb->mark);

		trproxy_assign_sock(skb, sk);

		if (skb->sk)
			pr_info ("### trproxy_act_ip6: assigned skb->sk->sk_dport=%hu, skb->sk->sk_v6_daddr=%pI6, skb->sk->sk_v6_rcv_saddr=%pI6.",
				 ntohs(skb->sk->sk_dport),
				 &skb->sk->sk_v6_daddr,
				 &skb->sk->sk_v6_rcv_saddr);
		else
			pr_info("### trproxy_act_ip6: NULL sk.");

		return 1;
	}

	pr_info("no socket: proto %hhu %pI6:%hu -> %pI6:%hu, mark: %x\n",
		tcproto, &iph->saddr, ntohs(hp->source),
		&iph->daddr, ntohs(hp->dest), skb->mark);
	return 0;
}

#endif /* __NET_TRPROXY_SK_H */
