#!/bin/bash
# set -x   # Uncomment if you want the shell to echo all commands
#
#  Network topology used to protype a new datapath architecture
#
#  +----------------+   +-----------------------------------------------------------------------+   +-----------------+
#  |                |   |             +============================+                            |   |                 |
# -+Client    PGW   +---+ens160 ... MOBHOST-+-MOBCONT HAproxy BBICONT-+-BBIHOST...   host ens160+---+ External world
#  |                |   |             +============================+                            |   |                 |
#  +----------------+   +-----------------------------------------------------------------------+   +-----------------+
#
# A small box with HAproxy in it represents a Linux container with two veth pairs,
#
# Build haproxy as:
# $ make TARGET=linux26 USE_LINUX_SPLICE=1 USE_LINUX_TPROXY=1 USE_TPROXY=1


sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

IP="sudo $HOME/costco-iproute2-5.0/ip/ip"
TC="sudo $HOME/costco-iproute2-5.0/tc/tc"
HA="/usr/local/sbin/haproxy"
HACFG="$HOME/haproxy-1.8/haproxy.cfg"
NSCMD="sudo $HOME/costco-iproute2-5.0/ip/ip netns exec"
#TUNTAP="/home/ssridhar/git/VISP/coco/cloudapps/routingsvc/src/unittest/tuntap_c/TUNTAP -e 2 -f 2 -d 7"

WHITELIST_BLACKLIST="/usr/bin/python3.6 /home/istguser1/whitelist_blacklist.py -d warning"
TRANSPARENT_DNS_PROXY="/usr/bin/python3.6 /home/istguser1/dnsserver_10_136_5_60.py"

#MOB_IFACE=em49
#MOB_MAC="58:20:b1:85:82:e0"
#MAC_OF_BBI_NEXT_HOP="44:03:a7:11:98:81"
#MAC_OF_BBI_NEXT_HOP="d8:67:d9:07:76:c1"

MOB_WET_CONT_NAMESPACE=MOBWGET
MOB_WGET_CONT_VETH=MOBWGETCONT
MOB_WGET_HOST_VETH=MOBWGETHOST
MOB_WGET_CONT_MAC="52:00:00:00:00:e3"
MOB_WGET_HOST_MAC="52:00:00:00:00:e4"
MOB_WGET_HOST_IPADDR="127.0.0.12"
MOB_WGET_CONT_IPADDR="127.0.0.13"

MOB_HOST_VETH=MOBHOST
MOB_CNT_VETH=MOBCONT  # Virtual container interface - MOB side.
BBI_HOST_VETH=BBIHOST
BBI_CNT_VETH=BBICONT  # Virtual container interface - BBI side.
HAPROXY_NAMESPACE=haproxy
HAPROXY_MOB_HOST_IP_ADDR="128.0.0.2"
HAPROXY_MOB_CONT_IP_ADDR="128.0.0.1"
HAPROXY_BBI_HOST_IP_ADDR="129.0.0.2"
HAPROXY_BBI_CONT_IP_ADDR="129.0.0.1"

DNS_HOST_VETH=DNSHOST
DNS_CNT_VETH=DNSCONT  # Virtual container interface - MOB side.
DNSPROXY_NAMESPACE=dnsproxy
DNSPROXY_MOB_HOST_IP_ADDR="140.0.0.2"
DNSPROXY_MOB_CONT_IP_ADDR="140.0.0.1"


veth_dnsproxy_ns=($DNS_HOST_VETH 60:11:00:00:00:00 $DNS_CNT_VETH 60:00:00:00:00:00)
DNS_PORT=53

MTUSIZE=32768
STARTING_QE_INDEX=1
ENDING_QE_INDEX=10
veth_haproxy_ns=($MOB_HOST_VETH 30:11:00:00:00:00 $MOB_CNT_VETH 30:00:00:00:00:00 $BBI_HOST_VETH 50:01:00:00:00:00 $BBI_CNT_VETH 50:00:00:00:00:00)

MOB_IFACE=ens160
MOB_MAC="00:50:56:ac:72:cd"
MAC_OF_MOB_NEXT_HOP="e4:d3:f1:b1:b4:81"
MAC_OF_BBI_NEXT_HOP="e4:d3:f1:fc:75:00"


MOBILE_TRAFFIC_SRC="10.136.66.8/32"
MOBILE_TRAFFIC_SRC2="10.136.66.22/32"

VETH_SWAP1=VETHSWAP1
VETH_SWAP1_MAC="80:00:00:00:00:00"
VETH_SWAP2=VETHSWAP2
VETH_SWAP2_MAC="90:00:00:00:00:00"

#
# setup_two_paired_veth takes the following args:
# $1 - MOB veth host interface, e.g. MOB
# $2 - MOB veth host iface MAC
# $3 - MOB veth container iface
# $4 - MOB veth container iface MAC
# $5 - BBI veth host interface, e.g. BBI
# $6 - BBI veth host iface MAC
# $7 - BBI veth container iface
# $8 - BBI veth container iface MAC
#
setup_two_paired_veth() {
  host_mob_veth=$1
  host_mob_veth_mac=$2
  ns_mob_veth=$3
  ns_mob_veth_mac=$4
  host_bbi_veth=$5
  host_bbi_veth_mac=$6
  ns_bbi_veth=$7
  ns_bbi_veth_mac=$8
  mtu=$MTUSIZE

  echo "Adding link $host_mob_veth with mac $host_mob_veth_mac type veth with the peer link named as $ns_mob_veth"
  $IP link add $host_mob_veth address $host_mob_veth_mac type veth peer name $ns_mob_veth

  echo "setting $ns_mob_veth mac $ns_mob_veth_mac"
  $IP link set $ns_mob_veth address $ns_mob_veth_mac

  echo "Adding link $host_bbi_veth with mac $host_bbi_veth_mac type veth with the peer link named as $ns_bbi_veth"
  $IP link add $host_bbi_veth address $host_bbi_veth_mac type veth peer name $ns_bbi_veth

  echo "setting $ns_bbi_veth mac $ns_bbi_veth_mac"
  $IP link set $ns_bbi_veth address $ns_bbi_veth_mac

  echo "Bring $host_mob_veth link up with mtu $mtu"
  $IP link set $host_mob_veth up mtu $mtu

  echo "Bring $host_bbi_veth link up with mtu $mtu"
  $IP link set $host_bbi_veth up mtu $mtu

}

setup_single_paired_veth() {
  host_mob_veth=$1
  host_mob_veth_mac=$2
  ns_mob_veth=$3
  ns_mob_veth_mac=$4
  mtu=$MTUSIZE

  echo "Adding link $host_mob_veth with mac $host_mob_veth_mac type veth with the peer link named as $ns_mob_veth"
  $IP link add $host_mob_veth address $host_mob_veth_mac type veth peer name $ns_mob_veth

  echo "setting $ns_mob_veth mac $ns_mob_veth_mac"
  $IP link set $ns_mob_veth address $ns_mob_veth_mac

  echo "Bring $host_mob_veth link up with mtu $mtu"
  $IP link set $host_mob_veth up mtu $mtu

  echo "Bring $ns_mob_veth link up with mtu $mtu"
  $IP link set $ns_mob_veth up mtu $mtu
}

# create_tc_actions_on_mobile_container_veth takes the following arguments
#  $1 - skbmark
#  $2 - namespace
#  $3 - port
#  $4 - MOB veth container iface
#

create_tc_actions_on_mobile_container_veth() {
  skbmark=$1
  namespace=$2
  port=$3
  mob_veth=$4
  mob_host_mac=$5

   #echo "inserting kernel modules"
   # Environment Setup
   #sudo insmod /home/ssridhar/Downloads/act-trproxy/act_trproxy.ko
   #sudo insmod /home/ssridhar/git/QE-ACT-5.0/act_qe.ko

  echo "Setting up ingress filter on $MOB_CNT_VETH to match protocol 0xfefe and perform ife decode and reclassify"
  $TC -n $namespace filter add dev $MOB_CNT_VETH prio 1 parent ffff: protocol 0xfefe \
      u32 match u32 0 0 classid 1:1 \
      action ife decode allow mark type 0xfefe reclassify index 1

  echo "Setting up ingress filter on $MOB_CNT_VETH to match protocol tcp, destination port 80,443 and tcp flag as SYN"
  $TC -n $namespace filter add dev $MOB_CNT_VETH prio 2 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x2 0xff at 33 \
      action skbedit ptype host \
      action trproxy lport $port mark 0 mask 0 index 1
      #action pass
      #action skbedit ptype host index 1 \
      #action trproxy lport $port mark 0 mask 0 index 1
      #handle $skbmark/0xffff fw \

  echo "Setting up ingress filter on $MOB_CNT_VETH to match protocol tcp, destination port 80,443 and tcp flag as ACK"
  $TC -n $namespace filter add dev $MOB_CNT_VETH prio 4 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x10 0xff at 33 \
      action skbedit ptype host \
      action trproxy lport $port mark 0 mask 0 index 1
      #action pass
      #action skbedit ptype host index 1 \
      #action trproxy lport $port mark 0 mask 0 index 1
      #handle $skbmark/0xffff fw \

  echo "Setting up ingress filter on $MOB_CNT_VETH to match protocol tcp, destination port 80,443 and tcp flag as FIN "
  $TC -n $namespace filter add dev $MOB_CNT_VETH prio 5 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x1 0xff at 33 \
      action skbedit ptype host \
      action trproxy lport $port mark 0 mask 0 index 1

  echo "Setting up ingress filter on $MOB_CNT_VETH to match protocol tcp, destination port 80,443 and tcp flag as FIN ACK "
  $TC -n $namespace filter add dev $MOB_CNT_VETH prio 6 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x11 0xff at 33 \
      action skbedit ptype host \
      action trproxy lport $port mark 0 mask 0 index 1

  echo "Creating ingress filter for $MOB_CNT_VETH to match protocol tcp and GET and dest port 80,443."
  $TC -n $namespace filter add dev $MOB_CNT_VETH parent ffff: prio 7 protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x47 0xff at 52 \
      match u8 0x45 0xff at 53 \
      match u8 0x54 0xff at 54 \
      action skbedit ptype host \
      action trproxy lport $port mark 0 mask 0 index 1

  # FW cls with mask
  echo "Setting up ingress filter on $MOB_CNT_VETH to match protocol ip"
  $TC -n $namespace filter add dev $MOB_CNT_VETH prio 10 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      action skbedit ptype host \
      action trproxy lport $port mark 0 mask 0 index 1
      #action pass
      #action skbedit ptype host index 1 \
      #action trproxy lport $port mark 0 mask 0 index 1

#  echo "Setting up egress filter on $MOB_CNT_VETH to match protocol tcp, source port 80,443 and tcp flag as SYN-ACK and perform ife encode to wrap a l2 header with protocol 0xfefe and dest mac as $MAC_OF_MOB_NEXT_HOP"
#  $TC -n $namespace filter add dev $MOB_CNT_VETH prio 1 parent 1: protocol ip u32 \
#      match ip protocol 0x6 0xff \
#      match u8 0x12 0xff at 33 \
#      action ife encode allow mark type 0xfefe allow mark dst $MAC_OF_MOB_NEXT_HOP index 10

#  echo "Setting up egress filter on $MOB_CNT_VETH to match protocol tcp, destination port 80,443 and tcp flag as FIN and perform ife encode to wrap a l2 header with protocol 0xfefe and dest mac as $MAC_OF_MOB_NEXT_HOP "
#  $TC -n $namespace filter add dev $MOB_CNT_VETH prio 2 parent 1: protocol ip u32 \
#      match ip protocol 0x6 0xff \
#      match u8 0x1 0xff at 33 \
#      action ife encode allow mark type 0xfefe allow mark dst $MAC_OF_MOB_NEXT_HOP index 10

#  echo "Setting up egress filter on $MOB_CNT_VETH to match protocol tcp, destination port 80,443 and tcp flag as FIN ACK and perform ife encode to wrap a l2 header with protocol 0xfefe and dest mac as $MAC_OF_MOB_NEXT_HOP "
#  $TC -n $namespace filter add dev $MOB_CNT_VETH prio 3 parent 1: protocol ip u32 \
#      match ip protocol 0x6 0xff \
#      match u8 0x11 0xff at 33 \
#      action ife encode allow mark type 0xfefe allow mark dst $MAC_OF_MOB_NEXT_HOP index 10

#  echo "Creating egress filter for $MOB_CNT_VETH to match protocol tcp and HTTP and source port 80,443 and perform ife encode to wrap a l2 header with protocol 0xfefe and dest mac as $MAC_OF_MOB_NEXT_HOP"
#  $TC -n $namespace filter add dev $MOB_CNT_VETH parent 1: prio 4 protocol ip u32 \
#      match ip protocol 0x6 0xff \
#      match u8 0x48 0xff at 52 \
#      match u8 0x54 0xff at 53 \
#      match u8 0x54 0xff at 54 \
#      match u8 0x50 0xff at 55 \
#      action ife encode allow mark type 0xfefe allow mark dst $MAC_OF_MOB_NEXT_HOP index 10 

#  echo "Setting up egress filter on $MOB_CNT_VETH to match protocol tcp and perform ife encode to wrap a l2 header with protocol 0xfefe and dest mac as $MOB_WGET_CONT_MAC"
#  $TC -n $namespace filter add dev $MOB_CNT_VETH prio 20 parent 1: protocol ip u32 \
#      match ip protocol 0x6 0xff \
#      action ife encode allow mark type 0xfefe allow mark dst $MAC_OF_MOB_NEXT_HOP index 10

}


create_tc_actions_on_bbi_container_veth() {
  skbmark=$1
  namespace=$2
  port=$3
  bbi_veth=$4

   #echo "inserting kernel modules"
   # Environment Setup
   #sudo insmod /home/ssridhar/Downloads/act-trproxy/act_trproxy.ko
   #sudo insmod /home/ssridhar/git/QE-ACT-5.0/act_qe.ko

   echo "Setting up ingress filter on $BBI_CNT_VETH to match protocol 0xfefe and perform ife decode and reclassify"
   $TC -n $namespace filter add dev $BBI_CNT_VETH prio 1 parent ffff: protocol 0xfefe \
      u32 match u32 0 0 classid 1:1 \
      action ife decode allow mark type 0xfefe reclassify

  echo "Setting up ingress filter on $BBI_CNT_VETH to match protocol tcp, src port 80,443 and tcp flag as SYN-ACK"
  $TC -n $namespace filter add dev $BBI_CNT_VETH prio 2 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x12 0xff at 33 \
      action skbedit ptype host \
      action trproxy lport $port mark 0 mask 0 index 1
      #action pass
      #action skbedit ptype host index 1 \
      #action trproxy lport $port mark 0 mask 0 index 1

  echo "Setting up ingress filter on $BBI_CNT_VETH to match protocol tcp, src port 80,443 and tcp flag as FIN"
  $TC -n $namespace filter add dev $BBI_CNT_VETH prio 3 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x01 0xff at 33 \
      action skbedit ptype host \
      action trproxy lport $port mark 0 mask 0 index 1

  echo "Setting up ingress filter on $BBI_CNT_VETH to match protocol tcp, src port 80,443 and tcp flag as FIN ACK"
  $TC -n $namespace filter add dev $BBI_CNT_VETH prio 4 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x11 0xff at 33 \
      action skbedit ptype host \
      action trproxy lport $port mark 0 mask 0 index 1

  echo "Creating ingress filter for $BBI_CNT_VETH to match protocol tcp and HTTP and source port 80,443 and accept it"
  $TC -n $namespace filter add dev $BBI_CNT_VETH parent ffff: prio 5 protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x48 0xff at 52 \
      match u8 0x54 0xff at 53 \
      match u8 0x54 0xff at 54 \
      match u8 0x50 0xff at 55 \
      action skbedit ptype host \
      action trproxy lport $port mark 0 mask 0 index 1

  echo "Setting up ingress filter on $BBI_CNT_VETH to match protocol ip"
  $TC -n $namespace filter add dev $BBI_CNT_VETH prio 10 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      action skbedit ptype host \
      action trproxy lport $port mark 0 mask 0 index 1
      #action pass
      #action skbedit ptype host index 1 \
      #action trproxy lport $port mark 0 mask 0 index 1

#  echo "Setting up egress filter on $BBI_CNT_VETH to match protocol tcp dest port 80,443 and tcp flag as SYN and perform ife encode to wrap a l2 header with protocol 0xfefe and dest mac as $MAC_OF_BBI_NEXT_HOP"
#  $TC -n $namespace filter add dev $BBI_CNT_VETH prio 1 parent 1: protocol ip u32 \
#      match ip protocol 0x6 0xff \
#      match u8 0x2 0xff at 33 \
#      action ife encode allow mark type 0xfefe dst $MAC_OF_BBI_NEXT_HOP

#  echo "Setting up egress filter on $BBI_CNT_VETH to match protocol tcp dest port 80,443 and tcp flag as ACK and perform ife encode to wrap a l2 header with protocol 0xfefe and dest mac as $MAC_OF_BBI_NEXT_HOP"
#  $TC -n $namespace filter add dev $BBI_CNT_VETH prio 2 parent 1: protocol ip u32 \
#      match ip protocol 0x6 0xff \
#      match u8 0x10 0xff at 33 \
#      action ife encode allow mark type 0xfefe dst $MAC_OF_BBI_NEXT_HOP

#  echo "Setting up egress filter on $BBI_CNT_VETH to match protocol tcp, destination port 80,443 and tcp flag as FIN and perform ife encode to wrap a l2 header with protocol 0xfefe and dest mac as $MAC_OF_BBI_NEXT_HOP "
#  $TC -n $namespace filter add dev $BBI_CNT_VETH prio 3 parent 1: protocol ip u32 \
#      match ip protocol 0x6 0xff \
#      match u8 0x1 0xff at 33 \
#      action ife encode allow mark type 0xfefe dst $MAC_OF_BBI_NEXT_HOP

#  echo "Setting up egress filter on $BBI_CNT_VETH to match protocol tcp, destination port 80,443 and tcp flag as FIN ACK and perform ife encode to wrap a l2 header with protocol 0xfefe and dest mac as $MAC_OF_BBI_NEXT_HOP "
#  $TC -n $namespace filter add dev $BBI_CNT_VETH prio 4 parent 1: protocol ip u32 \
#      match ip protocol 0x6 0xff \
#      match u8 0x11 0xff at 33 \
#      action ife encode allow mark type 0xfefe dst $MAC_OF_BBI_NEXT_HOP

#echo "Creating egress filter for $BBI_CNT_VETH to match protocol tcp and GET and dest port 80,443 and perform ife encode to wrap a l2 header with protocol 0xfefe and with dest mac $MAC_OF_BBI_NEXT_HOP"
#  $TC -n $namespace filter add dev $BBI_CNT_VETH parent 1: prio 5 protocol ip u32 \
#      match ip protocol 0x6 0xff \
#      match u8 0x47 0xff at 52 \
#      match u8 0x45 0xff at 53 \
#      match u8 0x54 0xff at 54 \
#      action skbedit ptype host \
#      action ife encode allow mark type 0xfefe dst $MAC_OF_BBI_NEXT_HOP

#  echo "Setting up egress filter on $BBI_CNT_VETH to match protocol tcp and perform ife encode to wrap a l2 header with protocol 0xfefe and dest mac as $MAC_OF_BBI_NEXT_HOP"
#  $TC -n $namespace filter add dev $BBI_CNT_VETH prio 10 parent 1: protocol ip \
#      u32 match ip protocol 6 0xff \
#      action ife encode allow mark type 0xfefe dst $MAC_OF_BBI_NEXT_HOP

}

# setup_ns takes the following arguments
#  $1 - skbmark that will be set in the container.
#  $2 - namespace - name of namespace to create
#  $3 - MOB veth container iface
#  $4 - BBI veth container iface
#  $5 - MOB veth host iface
#  $6 - BBI veth host iface
#
setup_namespace_container() {
  skbmark=$1
  namespace=$2
  ns_mob_veth=$3
  ns_bbi_veth=$4
  host_mob_veth=$5
  host_bbi_veth=$6
  host_mob_ip=$7  
  ns_mob_ip=$8
  host_bbi_ip=$9
  ns_bbi_ip=${10}
  port=3128
  mtu=$MTUSIZE

  echo "Creating namespace $namespace"
  $IP netns add $namespace

  echo "Setting device local up in $namespace"
  $IP -n $namespace link set dev lo up

  echo "Setting veth devices $ns_mob_veth to namespace $namespace"
  $IP link set dev $ns_mob_veth netns $namespace

  echo "Setting veth devices $ns_bbi_veth to namespace $namespace"
  $IP link set dev $ns_bbi_veth netns $namespace

  echo "Bring up links $ns_mob_veth with mtu $mtu in namespace $namespace"
  $IP -n $namespace link set dev $ns_mob_veth mtu $mtu

  echo "Bring up links $ns_bbi_veth with mtu $mtu in namespace $namespace"
  $IP -n $namespace link set dev $ns_bbi_veth mtu $mtu

  echo "Bring up device $ns_mob_veth up in namespace $namespace"
  $IP -n $namespace link set dev $ns_mob_veth up
 
  echo "Bring up device $ns_bbi_veth up in namespace $namespace"
  $IP -n $namespace link set dev $ns_bbi_veth up

  echo "Echo 0 to /proc/sys/net/ipv4/conf/$ns_mob_veth/rp_filter"
  $IP netns exec $namespace sudo sh -c "echo 0 > /proc/sys/net/ipv4/conf/$ns_mob_veth/rp_filter"

  echo "Echo 0 to /proc/sys/net/ipv4/conf/$ns_bbi_veth/rp_filter"
  $IP netns exec $namespace sudo sh -c "echo 0 > /proc/sys/net/ipv4/conf/$ns_bbi_veth/rp_filter"

  echo "Echo 0 to /proc/sys/net/ipv4/conf/all/rp_filter"
  $IP netns exec $namespace sudo sh -c "echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter"

  echo "set fwmark_accept=1"
  $IP netns exec $namespace sysctl -w net.ipv4.tcp_fwmark_accept=1

  echo "set fwmark_reflect=1"
  $IP netns exec $namespace sysctl -w net.ipv4.fwmark_reflect=1

  echo "Just making sure that directory /run/haproxy exist."
  $IP netns exec $namespace mkdir /run/haproxy

  echo "Launching $HA"
  $IP netns exec $namespace sudo $HA -f $HACFG -D

  echo "Creating tables."
  # Packets entering netns will have IFE-encoded skbmark, send those marked
  # packets to routing table 100 after decoding
  #echo "rule add fwmark $skbmark/0xffff iif $ns_mob_veth lookup 100"
  #$IP -n $namespace rule add fwmark $skbmark/0xffff iif $ns_mob_veth lookup 100
  #echo "rule add fwmark $((skbmark + 1))/0xffff iif $ns_mob_veth lookup 100"
  #$IP -n $namespace rule add fwmark $((skbmark + 1))/0xffff iif $ns_mob_veth lookup 100
  #echo "$namespace rule add fwmark $skbmark/0xffff iif $ns_bbi_veth lookup 100"
  #$IP -n $namespace rule add fwmark $skbmark/0xffff iif $ns_bbi_veth lookup 100
  #echo "rule add fwmark $((skbmark + 1))/0xffff iif $ns_bbi_veth lookup 100"
  #$IP -n $namespace rule add fwmark $((skbmark + 1))/0xffff iif $ns_bbi_veth lookup 100
  #echo "rule add fwmark $skbmark/0xffff iif $ns_mob_veth lookup 100"
  #$IP -n $namespace -6 rule add fwmark $skbmark/0xffff iif $ns_mob_veth lookup 100
  #echo "rule add fwmark $((skbmark + 1))/0xffff iif $ns_mob_veth lookup 100"
  #$IP -n $namespace -6 rule add fwmark $((skbmark + 1))/0xffff iif $ns_mob_veth lookup 100
  #echo "rule add fwmark $skbmark/0xffff iif $ns_bbi_veth lookup 100"
  #$IP -n $namespace -6 rule add fwmark $skbmark/0xffff iif $ns_bbi_veth lookup 100
  #echo "rule add fwmark $skbmark/0xffff iif $ns_bbi_veth lookup 100"
  #$IP -n $namespace -6 rule add fwmark $((skbmark + 1))/0xffff iif $ns_bbi_veth lookup 100

  $IP -n $namespace rule add iif $ns_mob_veth lookup 100
  $IP -n $namespace rule add iif $ns_bbi_veth lookup 100
  $IP -n $namespace -6 rule add iif $ns_mob_veth lookup 100
  $IP -n $namespace -6 rule add iif $ns_bbi_veth lookup 100

  # Declare all IPv4 packets locally, i.e. dests are assigned to this host,
  # so packets will be delivered locally
  echo "Declaring all ipv4 packet locally to this host. 0.0.0.0/0 dev lo table 100 in $namespace"
  $IP -n $namespace route add local 0.0.0.0/0 dev lo table 100
  
  echo "Declaring all ipv6 packet locally to this host. 0.0.0.0/0 dev lo table 100 in $namespace"
  $IP -n $namespace -6 route add local ::/0 dev lo table 100 

  echo "Assigning IP address $ns_mob_ip/16 dev $ns_mob_veth"
  $IP -n $namespace addr add $ns_mob_ip/16 dev $ns_mob_veth

  echo "Assigning IP address $ns_bbi_ip/16 dev $ns_bbi_veth"
  $IP -n $namespace addr add $ns_bbi_ip/16 dev $ns_bbi_veth

  echo "Adding a default route for $host_mob_ip in $namespace"
  $IP -n $namespace route add default via $host_mob_ip

  echo "Assigning IP address $host_mob_ip/16 via dev $host_mob_veth"
  $IP addr add $host_mob_ip/16 dev $host_mob_veth

  echo "Assigning IP address $host_bbi_ip/16 via dev $host_bbi_veth"
  $IP addr add $host_bbi_ip/16 dev $host_bbi_veth
  
  echo "echo 0 > /proc/sys/net/ipv4/conf/$MOB_IFACE/rp_filter"
  sudo sh -c "echo 0 > /proc/sys/net/ipv4/conf/$MOB_IFACE/rp_filter"

  echo "echo 0 > /proc/sys/net/ipv4/conf/$host_mob_veth/rp_filter"
  sudo sh -c "echo 0 > /proc/sys/net/ipv4/conf/$host_mob_veth/rp_filter"

  echo "echo 0 > /proc/sys/net/ipv4/conf/$host_bbi_veth/rp_filter"
  sudo sh -c "echo 0 > /proc/sys/net/ipv4/conf/$host_bbi_veth/rp_filter"

  echo "echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter"
  sudo sh -c "echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter"

  echo "Turn off arp on $ns_mob_veth"
  $IP netns exec $namespace ip link set $ns_mob_veth arp off

  echo "Turn off arp on $ns_bbi_veth"
  $IP netns exec $namespace ip link set $ns_bbi_veth arp off

  echo "Creating ingress QDiscs for $ns_mob_veth"
  $IP netns exec $namespace $TC qdisc add dev $ns_mob_veth ingress

  echo "Creating egress QDiscs for $ns_mob_veth"
  $IP netns exec $namespace $TC qdisc add dev $ns_mob_veth root handle 1: fq

  echo "Creating ingress QDiscs for $ns_bbi_veth"
  $IP netns exec $namespace $TC qdisc add dev $ns_bbi_veth ingress

  echo "Creating egress QDiscs for $ns_bbi_veth"
  $IP netns exec $namespace $TC qdisc add dev $ns_bbi_veth root handle 1: fq

}



delete_veth() {
  host_mob_veth=$1
  ns_mob_veth=$2

  echo "Deleting link for $host_mob_veth"
  $IP link del $host_mob_veth

  echo "Deleting link for $ns_mob_veth"
  $IP link del $ns_mob_veth
}

create_ingress_qdiscs() {
  veth=$1
  echo "Creating ingress QDiscs for $veth"
  $TC qdisc add dev $veth ingress
}

create_egress_fq_qdiscs() {
  veth=$1
  echo "Creating egress QDiscs for $veth"
  #$TC qdisc add dev $veth root handle 1: fq
  $TC qdisc add dev $veth root handle 1: fq
}

create_egress_prio_qdiscs() {
  veth=$1
  echo "Creating egress QDiscs for $veth"
  $TC qdisc add dev $veth root handle 1: prio
}

delete_qdiscs() {
  veth=$1
  echo "Deleting ingress QDiscs for $veth"
  $TC qdisc del dev $veth ingress
  echo "Deleting egress QDiscs for $veth"
  #$TC qdisc del dev $veth root handle 1: prio
  $TC qdisc del dev $veth root handle 1: fq
  $TC qdisc del dev $veth root handle 1: prio
}


create_tc_actions_on_specified_veth() {
  veth_src=$1
  mob_veth_dest=$2
  bbi_veth_dest=$3
  srcmac=$4
  dmac=$5
  mob_traffic_src=$6
  starting_prio=$7
  ingress='ffff:'
  egress='1:'


 echo "Creating Ingress filter on $veth_src to route the MOBILE TCP packets with source ip $mob_traffic_src entering this interface to the container veth $mob_veth_dest."
  $TC filter add dev $veth_src prio $starting_prio parent $ingress protocol ip u32 \
      match ip src $mob_traffic_src \
      match ip protocol 0x6 0xff \
      action skbmod smac $MOB_MAC \
      action skbmod dmac ${veth_haproxy_ns[3]} \
      action skbedit ptype host \
      action mirred egress redirect dev $mob_veth_dest
      #action skbedit mark 1 \
      #action ife encode type 0xfefe allow mark dst ${veth_haproxy_ns[3]}\

  starting_prio=$((starting_prio+1))

  echo "Creating Ingress filter on $veth_src to route the Internet TCP packets with dst ip $mob_traffic_src entering this interface to the container veth $bbi_veth_dest."
  $TC filter add dev $veth_src prio $starting_prio parent $ingress protocol ip u32 \
      match ip dst $mob_traffic_src \
      match ip protocol 0x6 0xff \
      action skbmod smac $MOB_MAC \
      action skbmod dmac ${veth_haproxy_ns[7]} \
      action skbedit ptype host \
      action mirred egress redirect dev $bbi_veth_dest
      #action skbedit mark 2 \
      #action ife encode type 0xfefe allow mark dst ${veth_haproxy_ns[7]}\

  starting_prio=$((starting_prio+1))

  echo "Creating ingress filter for $mob_veth match udp and dest port $DNS_PORT and mirror it to $DNS_HOST_VETH"
  $TC filter add dev $veth_src parent $ingress_filter prio $starting_prio protocol ip u32 \
      match ip protocol 0x11 0xff \
      match ip dport $DNS_PORT 0xff \
      action skbedit ptype host \
      action skbmod dmac ${veth_dnsproxy_ns[3]} \
      action mirred egress redirect dev $DNS_HOST_VETH

  starting_prio=$((starting_prio+1))

  echo "Creating Ingress filter on $veth_src to route the MOBILE packets with source ip $mob_traffic_src entering this interface to the container veth $VETH_SWAP1."
  $TC filter add dev $veth_src prio $starting_prio parent $ingress protocol ip u32 \
      match ip src $mob_traffic_src \
      action skbedit ptype host \
      action mirred egress redirect dev $VETH_SWAP1

  starting_prio=$((starting_prio+1))

  echo "Creating Ingress filter on $veth_src to route the Internet packets with dst ip $mob_traffic_src entering this interface to the container veth $VETH_SWAP1."
  $TC filter add dev $veth_src prio $starting_prio parent $ingress protocol ip u32 \
      match ip dst $mob_traffic_src \
      action skbedit ptype host \
      action mirred egress redirect dev $VETH_SWAP1

  starting_prio=$((starting_prio+1))
}

create_tc_actions_on_veth_swap() {
mob_traffic_src=$1
starting_prio=$2

 echo "Creating Egress filter on $VETH_SWAP1 to route the traffic with src ip $mob_traffic_src and udp and dest port 443 (QUIC) and egress to HAPROXY veth ${veth_haproxy_ns[0]} ."
  $TC filter add dev $VETH_SWAP1 parent 1: prio $starting_prio protocol ip u32 \
  match ip src $mob_traffic_src \
  match ip dport 443 0xff \
  action skbedit ptype host \
  action skbmod smac $MOB_MAC  \
  action skbmod dmac ${veth_haproxy_ns[3]} \
  action mirred egress redirect dev ${veth_haproxy_ns[0]}

starting_prio=$((starting_prio+1))

 echo "Creating Egress filter on $VETH_SWAP1 to route the regular traffic with src ip $mob_traffic_src and udp egress to the internet with src mac  $MOB_MAC and dst mac $MAC_OF_BBI_NEXT_HOP."
  $TC filter add dev $VETH_SWAP1 parent 1: prio $starting_prio protocol ip u32 \
  match ip src $mob_traffic_src \
  action skbedit ptype host \
  action skbmod smac $MOB_MAC  \
  action skbmod dmac $MAC_OF_BBI_NEXT_HOP \
  action mirred egress redirect dev $MOB_IFACE

starting_prio=$((starting_prio+1))

 echo "Creating Egress filter on $VETH_SWAP1 to route the traffic with dst ip $mob_traffic_src and udp and src port 443 (QUIC) and egress to HAPROXY veth ${veth_haproxy_ns[4]} ."
  $TC filter add dev $VETH_SWAP1 parent 1: prio $starting_prio protocol ip u32 \
  match ip src $mob_traffic_src \
  match ip sport 443 0xff \
  action skbedit ptype host \
  action skbmod smac $MOB_MAC  \
  action skbmod dmac ${veth_haproxy_ns[7]} \
  action mirred egress redirect dev ${veth_haproxy_ns[4]}

starting_prio=$((starting_prio+1))

echo "Creating Egress filter on $VETH_SWAP1 to route the regular traffic with dst ip $mob_traffic_src and udp egress to mobile with src mac  $MOB_MAC and dst mac $MAC_OF_MOB_NEXT_HOP."
  $TC filter add dev $VETH_SWAP1 parent 1: prio $starting_prio protocol ip u32 \
  match ip dst $mob_traffic_src \
  action skbedit ptype host \
  action skbmod smac $MOB_MAC  \
  action skbmod dmac $MAC_OF_MOB_NEXT_HOP \
  action mirred egress redirect dev $MOB_IFACE
}

create_tc_actions_on_dnsproxy_host_interface() {
  dns_veth=$1
  vm_iface=$2
  dns_port=$3
  ingress_filter='ffff:'
  egress_filter='1:'

  echo "Creating ingress filter for $dns_veth to match protocol udp and dest port $dns_port and send it to $vm_iface so that the dns request is sent to the internet untouched."
  $TC filter add dev $dns_veth parent $ingress_filter prio 1 protocol ip u32 \
      match ip protocol 0x11 0xff \
      match ip dport $dns_port 0xff \
      action skbedit ptype host \
      action skbmod dmac $MAC_OF_BBI_NEXT_HOP \
      action skbmod smac $MOB_MAC \
      action mirred egress redirect dev $vm_iface

  echo "Creating ingress filter for $dns_veth to match protocol udp and src port $dns_port and send it to $mob_veth so that the DNS reject is sent to the mobile phone."
  $TC filter add dev $dns_veth parent $ingress_filter prio 2 protocol ip u32 \
      match ip protocol 0x11 0xff \
      match ip sport $dns_port 0xff \
      action skbedit ptype host \
      action skbmod dmac $MAC_OF_MOB_NEXT_HOP \
      action skbmod smac $MOB_MAC \
      action mirred egress redirect dev $vm_iface

  echo "Creating egress filter for $dns_veth to match protocol udp and dest port $dns_port and accept it"
  $TC filter add dev $dns_veth parent $egress_filter prio 1 protocol ip u32 \
      match ip protocol 0x11 0xff \
      match ip dport $dns_port 0xff \
      action skbedit ptype host
}

create_tc_actions_on_dnsproxy_container_interface() {
  dns_veth=$1  
  dns_port=$2
  namespace=$3
  ingress_filter='ffff:'
  egress_filter='1:'
  port=53

  #echo "Setting up ingress qisc on $dns_veth"
  #$TC -n $namespace qdisc add dev $dns_veth ingress

  #echo "Setting up egress qisc 1: on $dns_veth"
  #$TC -n $namespace qdisc add dev $dns_veth root handle 1: prio

  #echo "Creating ingress filter for $dns_veth to match protocol icmp and drop it."
  #$TC -n $namespace filter add dev $dns_veth prio 1 parent ffff: protocol ip u32 \
  #    match ip protocol 0x1 0xff \
  #    action drop

  echo "Creating ingress filter for $dns_veth to match protocol udp and dest port $dns_port and send it to tproxy."
  $TC -n $namespace filter add dev $dns_veth prio 2 parent ffff: protocol ip u32 \
      match ip protocol 0x11 0xff \
      match ip dport $dns_port 0xff \
      action skbedit ptype host \
      action trproxy lport $port mark 0 mask 0 index 1

  #echo "Creating ingress filter for $dns_veth to match protocol udp and src port $dns_port and send it to tproxy."
  #$TC -n $namespace filter add dev $dns_veth prio 2 parent ffff: protocol ip u32 \
  #    match ip protocol 0x11 0xff \
  #    match ip sport $dns_port 0xff \
  #    action skbedit ptype host \
  #    action trproxy lport $port mark 0 mask 0 index 1
}


create_tc_actions_on_bbi_host_veth() {
  src_veth=$1
  dst_veth=$2
  srcmac=$3
  dmac=$4
  mac_addr_next_hop=$5
  match_reverse='src_port 80,443'


 # Decode everything coming off the container
  echo "Creating ingress filter on $src_veth to perform ife decode to strip off the l2 wrap and reclassify."
  $TC filter add dev $src_veth parent ffff: prio 1 protocol 0xfefe \
      u32 match u32 0 0 classid 1:1 \
      action ife decode allow mark reclassify

 echo "Creating ingress filter on $src_veth and match packet tcp source port 80,443 and the TCP flag is SYN and perform an ife encode to add a l2 wrap with protocol 0xfefe and source mac  $srcmac and dest mac as the next hop $mac_addr_next_hop and mirror it to $dst_veth."
 $TC filter add dev $src_veth prio 2 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x2 0xff at 33 \
      action skbmod smac $srcmac  \
      action skbmod dmac $mac_addr_next_hop \
      action mirred egress redirect dev $dst_veth
      #action qe index 5 \
      #action police index 5 \

 echo "Creating ingress filter on $src_veth and match packet tcp source port 80,443 and and the TCP flag is ACK and perform an ife encode to add a l2 wrap with protocol 0xfefe and source mac  $srcmac and dest mac as the next hop $mac_addr_next_hop and mirror it to $dst_veth."
 $TC filter add dev $src_veth prio 3 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x10 0xff at 33 \
      action skbmod smac $srcmac  \
      action skbmod dmac $mac_addr_next_hop \
      action mirred egress redirect dev $dst_veth
      #action qe index 5 \
      #action police index 5 \

 echo "Creating ingress filter on $src_veth and match packet tcp source port 80,443 and and the TCP flag is FIN and perform an ife encode to add a l2 wrap with protocol 0xfefe and source mac  $srcmac and dest mac as the next hop $mac_addr_next_hop and mirror it to $dst_veth."
 $TC filter add dev $src_veth prio 4 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x01 0xff at 33 \
      action skbmod smac $srcmac  \
      action skbmod dmac $mac_addr_next_hop \
      action mirred egress redirect dev $dst_veth
      #action qe index 5 \
      #action police index 5 \

 echo "Creating ingress filter on $src_veth and match packet tcp source port 80,443 and and the TCP flag is FIN ACK and perform an ife encode to add a l2 wrap with protocol 0xfefe and source mac $srcmac and dest mac as the next hop $mac_addr_next_hop and mirror it to $dst_veth."
 $TC filter add dev $src_veth prio 5 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x11 0xff at 33 \
      action skbmod smac $srcmac  \
      action skbmod dmac $mac_addr_next_hop \
      action mirred egress redirect dev $dst_veth
      #action qe index 5 \
      #action police index 5 \

  echo "Creating ingress filter for $src_veth to match protocol tcp and GET and dest port 80,443 and perform ife encode to wrap a l2 header with protocol 0xfefe and with src mac $srcmac dest mac $mac_addr_next_hop and mirror it to $dst_veth"
  $TC filter add dev $src_veth parent ffff: prio 6 protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x47 0xff at 52 \
      match u8 0x45 0xff at 53 \
      match u8 0x54 0xff at 54 \
      action skbmod smac $srcmac  \
      action skbmod dmac $mac_addr_next_hop \
      action mirred egress redirect dev $dst_veth
      #action qe index 5 \
      #action police index 5 \


 echo "Creating ingress filter on $src_veth and match packet tcp source port 80,443 and perform an ife encode to add a l2 wrap with protocol 0xfefe and source mac mac $srcmac and dest mac as the next hop $MAC_OF_BBI_NEXT_HOP and mirror it to $dst_veth."
 $TC filter add dev $src_veth prio 10 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      action skbmod smac $srcmac  \
      action skbmod dmac $mac_addr_next_hop \
      action mirred egress redirect dev $dst_veth
      #action qe index 5 \
      #action police index 5 \


#echo "Creating Egress filter on $src_veth to route the regular traffic with dst ip $MOBILE_TRAFFIC_SRC and icmp egress to mobile with src mac  $MOB_MAC and dst mac $MAC_OF_MOB_NEXT_HOP."
#  $TC filter add dev $src_veth parent 1: prio 19 protocol ip u32 \
#  match ip dst $MOBILE_TRAFFIC_SRC \
#  match ip protocol 0x6 0xff \
#  action skbmod smac $MOB_MAC  \
#  action skbmod dmac $MAC_OF_MOB_NEXT_HOP \
#  action mirred egress redirect dev $MOB_IFACE

#echo "Creating Egress filter on $src_veth to route the regular traffic with dst ip $MOBILE_TRAFFIC_SRC egress to mobile with src mac  $MOB_MAC and dst mac $MAC_OF_MOB_NEXT_HOP."
#  $TC filter add dev $src_veth parent 1: prio 30 protocol ip u32 \
#  match ip dst $MOBILE_TRAFFIC_SRC \
#  action skbmod smac $MOB_MAC  \
#  action skbmod dmac $MAC_OF_MOB_NEXT_HOP \
#  action mirred egress redirect dev $MOB_IFACE


}

create_tc_actions_on_tuntap_interface() {
  tuntap_if=$1
  tuntap_next_hop=$2
  echo "Creating ingress filter on $tuntap_if to mirror the packets to the specified next hop."
  $TC filter add dev $tuntap_if parent ffff: prio 1 protocol 0xfefe \
      u32 match u32 0 0 classid 1:1 \
      action skbedit ptype host \
      action mirred egress redirect dev $tuntap_next_hop
}


create_tc_actions_on_mobile_host_veth() {
  skbmark=$1
  host_src_veth=$2  
  dest_veth=$3
  smac=$4
  dmac=$5

  # Create MOB Ingress filter.
  # match_string = 'u32 0 0'    # Uncomment this for all traffic
  match_string='ip protocol 1 0xff'  # Uncomment for only ICMP traffic.
  match='dst_port 80,443'  # replace ICMP with TCP if needed.
  match_reverse='src_port 80,443'

  echo "Creating ingress filter on $host_src_veth to perform ife decode to strip off the l2 wrap and reclassify."
  $TC filter add dev $host_src_veth parent ffff: prio 1 protocol 0xfefe \
      u32 match u32 0 0 classid 1:1 \
      action ife decode allow mark reclassify

  echo "Creating ingress filter on $host_src_veth to check for dest ip $MOB_WGET_CONT_IPADDR and redirect to $MOB_WGET_HOST_VETH."
  sudo tc filter add dev $host_src_veth prio 2 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      match ip dst $MOB_WGET_CONT_IPADDR \
      action skbmod smac $MOB_WGET_HOST_MAC  \
      action skbmod dmac $MOB_WGET_CONT_MAC \
      action mirred egress redirect dev $MOB_WGET_HOST_VETH
        #action qe index 2 \
        #action police index 2 \

  echo "Creating ingress filter on $host_src_veth to  check if protocol is tcp, source port is 80,443 and the TCP flag is SYN-ACK and set src mac as $smac dest mac as $dmac and mirror it to $dest_veth."
  $TC filter add dev $host_src_veth prio 3 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x12 0xff at 33 \
      action skbmod smac $smac \
      action skbmod dmac $dmac \
      action mirred egress redirect dev $dest_veth
      #action qe index 4 \
      #action police index 4 \

 echo "Creating ingress filter on $host_src_veth to  check if protocol is tcp, source port is 80,443 and the TCP flag is FIN and set src mac as $smac dest mac as $dmac and mirror it to $dest_veth."
  $TC filter add dev $host_src_veth prio 4 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x01 0xff at 33 \
      action skbmod smac $smac  \
      action skbmod dmac $dmac \
      action mirred egress redirect dev $dest_veth
      #action qe index 4 \
      #action police index 4 \

 echo "Creating ingress filter on $host_src_veth to  check if protocol is tcp, source port is 80,443 and the TCP flag is FIN-ACK and set src mac as $smac dest mac as $dmac and mirror it to $dest_veth."
  $TC filter add dev $host_src_veth prio 5 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x11 0xff at 33 \
      action skbmod smac $smac  \
      action skbmod dmac $dmac \
      action mirred egress redirect dev $dest_veth
      #action qe index 4 \
      #action police index 4 \

  echo "Creating ingress filter for $host_src_veth to match protocol tcp and HTTP and source port 80,443 and accept it"
  $TC filter add dev $host_src_veth parent ffff: prio 6 protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x48 0xff at 52 \
      match u8 0x54 0xff at 53 \
      match u8 0x54 0xff at 54 \
      match u8 0x50 0xff at 55 \
      action skbmod smac $smac  \
      action skbmod dmac $dmac \
      action mirred egress redirect dev $dest_veth
      #action qe index 4 \
      #action police index 4 \

  echo "Creating ingress filter on $host_src_veth to perform ife decode to strip off the l2 wrap and set src mac as $smac dest mac as $dmac and mirror it to $dest_veth."
  $TC filter add dev $host_src_veth prio 10 parent ffff: protocol ip u32 \
      match ip protocol 0x6 0xff \
      action skbmod smac $smac  \
      action skbmod dmac $dmac \
      action mirred egress redirect dev $dest_veth
      #action qe index 4 \
      #action police index 4 \



#echo "Creating Egress filter on $host_src_veth to route the regular traffic with src ip $MOBILE_TRAFFIC_SRC and tcp egress to the internet with src mac  $MOB_MAC and dst mac $MAC_OF_BBI_NEXT_HOP."
#  $TC filter add dev $host_src_veth parent 1: prio 19 protocol ip u32 \
#  match ip src $MOBILE_TRAFFIC_SRC \
#  match ip protocol 0x6 0xff \
#  action skbmod smac $MOB_MAC  \
#  action skbmod dmac $MAC_OF_BBI_NEXT_HOP \
#  action mirred egress redirect dev $MOB_IFACE



#  echo "Creating Egress filter on $host_src_veth to route the regular traffic with src ip $MOBILE_TRAFFIC_SRC egress to the internet with src mac  $MOB_MAC and dst mac $MAC_OF_BBI_NEXT_HOP."
#  $TC filter add dev $host_src_veth prio 30 parent 1: protocol ip u32 \
#  match ip src $MOBILE_TRAFFIC_SRC \
#  action skbmod smac $MOB_MAC  \
#  action skbmod dmac $MAC_OF_BBI_NEXT_HOP \
#  action mirred egress redirect dev $MOB_IFACE


# echo "Creating Egress filter on $host_src_veth to perform QE Byte counting."
#  $TC filter add dev $host_src_veth parent 1: prio 1 protocol 0xfefe \
#      u32 match u32 0 0 classid 1:1 \
#      action skbedit ptype host
      #action qe index 3 \
      #action police index 3
}


create_qe() {
starting_qe_index=$1
ending_qe_index=$2
current_qe_index=$starting_qe_index
while [ $current_qe_index -le $ending_qe_index ]
do
	echo "setting up QE with index $current_qe_index"
	sudo tc -s actions add action qe bucket 10000000  multiplier 0 credit 1000000 exceedact pipe index $current_qe_index
	(( current_qe_index ++ ))
done
}

delete_qe() {
starting_qe_index=$1
ending_qe_index=$2
current_qe_index=$starting_qe_index
while [ $current_qe_index -le $ending_qe_index ]
do
	echo "Deleting QE with index $current_qe_index"
	sudo tc -s actions del action qe index $current_qe_index
	(( current_qe_index ++ ))
done
}

create_police() {
starting_police_index=$1
ending_police_index=$2
current_police_index=$starting_police_index
while [ $current_police_index -le $ending_police_index ]
do
	echo "setting up Police with index $current_police_index"
	sudo tc -s actions add action police rate 1000000  burst 2000000 mtu 1500 peakrate 100000 conform-exceed pipe index $current_police_index
	(( current_police_index ++ ))
done
}

delete_police() {
starting_police_index=$1
ending_police_index=$2
current_police_index=$starting_police_index
while [ $current_police_index -le $ending_police_index ]
do
	echo "Deleting police with index $current_police_index"
	sudo tc -s actions del action police index $current_police_index
	(( current_police_index ++ ))
done
}


setup_single_veth_namespace_container() {
  skbmark=$1
  namespace=$2
  ns_mob_veth=$3
  host_mob_veth=$4
  host_mob_ip=$5
  ns_mob_ip=$6
  mtu=$MTUSIZE

  echo "Creating namespace $namespace"
  $IP netns add $namespace

  echo "Setting device local up in $namespace"
  $IP -n $namespace link set dev lo up

  echo "Setting veth devices $ns_mob_veth to namespace $namespace"
  $IP link set dev $ns_mob_veth netns $namespace

  echo "Bring up links $ns_mob_veth with mtu $mtu in namespace $namespace"
  $IP -n $namespace link set dev $ns_mob_veth mtu $mtu

  echo "Bring up device $ns_mob_veth up in namespace $namespace"
  $IP -n $namespace link set dev $ns_mob_veth up
 
  echo "Echo 0 to /proc/sys/net/ipv4/conf/$ns_mob_veth/rp_filter"
  $IP netns exec $namespace sudo sh -c "echo 0 > /proc/sys/net/ipv4/conf/$ns_mob_veth/rp_filter"

  echo "Echo 0 to /proc/sys/net/ipv4/conf/all/rp_filter"
  $IP netns exec $namespace sudo sh -c "echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter"

  echo "set fwmark_accept=1"
  $IP netns exec $namespace sysctl -w net.ipv4.tcp_fwmark_accept=1

  echo "set fwmark_reflect=1"
  $IP netns exec $namespace sysctl -w net.ipv4.fwmark_reflect=1

  echo "Creating tables."
  $IP -n $namespace rule add iif $ns_mob_veth lookup 100
  $IP -n $namespace -6 rule add iif $ns_mob_veth lookup 100

  # Declare all IPv4 packets locally, i.e. dests are assigned to this host,
  # so packets will be delivered locally
  echo "Declaring all ipv4 packet locally to this host. 0.0.0.0/0 dev lo table 100 in $namespace"
  $IP -n $namespace route add local 0.0.0.0/0 dev lo table 100
  
  echo "Declaring all ipv6 packet locally to this host. 0.0.0.0/0 dev lo table 100 in $namespace"
  $IP -n $namespace -6 route add local ::/0 dev lo table 100 

  echo "Assigning IP address $ns_mob_ip/16 dev $ns_mob_veth"
  $IP -n $namespace addr add $ns_mob_ip/16 dev $ns_mob_veth

  echo "Adding a default route for $host_mob_ip in $namespace"
  $IP -n $namespace route add default via $host_mob_ip

  echo "Assigning IP address $host_mob_ip/16 via dev $host_mob_veth"
  $IP addr add $host_mob_ip/16 dev $host_mob_veth

  echo "echo 0 > /proc/sys/net/ipv4/conf/$host_mob_veth/rp_filter"
  sudo sh -c "echo 0 > /proc/sys/net/ipv4/conf/$host_mob_veth/rp_filter"

  echo "echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter"
  sudo sh -c "echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter"

  #echo "Turn off arp on $ns_mob_veth"
  $IP netns exec $namespace ip link set $ns_mob_veth arp off
  
  echo "sudo ip route add 10.1.100.107 via 10.1.1.1 dev MOBWGETHOST"
  #sudo ip route add $MOB_WGET_CONT_IPADDR via 10.1.100.100 dev eth0
  #sudo ip route add $MOB_WGET_CONT_IPADDR via 10.1.100.100 dev MOBWGETHOST

  sudo sh -c "ip link set $MOB_WGET_HOST_VETH arp off"

}


create_tc_actions_on_mobile_interface() {
  skbmark=$1
  mob_veth=$2
  dst_veth=$3
  dst_veth_mac=$4

  # Create MOB Ingress filter.
  # match_string = 'u32 0 0'    # Uncomment this for all traffic
  match_string='ip protocol 1 0xff'  # Uncomment for only ICMP traffic.
  match='dst_port 80'  # replace ICMP with TCP if needed.
  match_reverse='src_port 80'
  ingress_filter='ffff:'
  egress_filter='1:'


  echo "Creating ingress filter for $mob_veth to match protocol tcp and tcp flag SYN and dest port 80 and perform ife encode to wrap a l2 header with protocol 0xfefe and with dest mac $dst_veth_mac and mirror it to $dst_veth"
  $TC filter add dev $mob_veth parent $ingress_filter prio 1 protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x2 0xff at 33 \
      action skbmod smac $MOB_MAC  \
      action skbmod dmac ${veth_haproxy_ns[7]} \
      action skbedit ptype host \
      action skbedit mark 8 \
      action ife encode type 0xfefe allow mark dst $dst_veth_mac\
      action mirred egress redirect dev $dst_veth

  echo "Creating ingress filter for $mob_veth to match protocol tcp and tcp flag ACK and dest port 80 and perform ife encode to wrap a l2 header with protocol 0xfefe and with dest mac $dst_veth_mac and mirror it to $dst_veth"
  $TC filter add dev $mob_veth parent $ingress_filter prio 2 protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x10 0xff at 33 \
      action skbmod smac $MOB_MAC  \
      action skbmod dmac ${veth_haproxy_ns[7]} \
      action skbedit ptype host \
      action skbedit mark 8 \
      action ife encode type 0xfefe allow mark dst $dst_veth_mac\
      action mirred egress redirect dev $dst_veth

  echo "Creating ingress filter for $mob_veth to match protocol tcp and tcp flag FIN and dest port 80 and perform ife encode to wrap a l2 header with protocol 0xfefe and with dest mac $dst_veth_mac and mirror it to $dst_veth"
  $TC filter add dev $mob_veth parent $ingress_filter prio 3 protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x01 0xff at 33 \
      action skbmod smac $MOB_MAC  \
      action skbmod dmac ${veth_haproxy_ns[7]} \
      action skbedit ptype host \
      action skbedit mark 8 \
      action ife encode type 0xfefe allow mark dst $dst_veth_mac\
      action mirred egress redirect dev $dst_veth

  echo "Creating ingress filter for $mob_veth to match protocol tcp and tcp flag FIN ACK and dest port 80 and perform ife encode to wrap a l2 header with protocol 0xfefe and with dest mac $dst_veth_mac and mirror it to $dst_veth"
  $TC filter add dev $mob_veth parent $ingress_filter prio 4 protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x11 0xff at 33 \
      action skbmod smac $MOB_MAC  \
      action skbmod dmac ${veth_haproxy_ns[7]} \
      action skbedit ptype host \
      action skbedit mark 8 \
      action ife encode type 0xfefe dst $dst_veth_mac\
      action mirred egress redirect dev $dst_veth

  echo "Creating ingress filter for $mob_veth to match protocol tcp and GET and dest port 80 and perform ife encode to wrap a l2 header with protocol 0xfefe and with dest mac $dst_veth_mac and mirror it to $dst_veth"
  $TC filter add dev $mob_veth parent $ingress_filter prio 6 protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x47 0xff at 52 \
      match u8 0x45 0xff at 53 \
      match u8 0x54 0xff at 54 \
      action skbmod smac $MOB_MAC  \
      action skbmod dmac ${veth_haproxy_ns[7]} \
      action skbedit ptype host \
      action skbedit mark 8 \
      action ife encode type 0xfefe allow mark dst $dst_veth_mac \
      action mirred egress redirect dev $dst_veth


  echo "Creating ingress filter for $mob_veth to match protocol tcp and dest port 80 and perform ife encode to wrap a l2 header with protocol 0xfefe and with dest mac $dst_veth_mac and mirror it to $dst_veth"
  $TC filter add dev $mob_veth parent $ingress_filter prio 10 protocol ip u32 \
      match ip protocol 0x6 0xff \
      action skbmod smac $MOB_MAC  \
      action skbmod dmac ${veth_haproxy_ns[7]} \
      action skbedit ptype host \
      action skbedit mark 8 \
      action ife encode type 0xfefe allow mark dst $dst_veth_mac\
      action mirred egress redirect dev $dst_veth

  echo "Creating egress filter for $mob_veth to match protocol tcp and tcp flag SYN-ACK and source port 80 and accept it"
  $TC filter add dev $mob_veth parent $egress_filter prio 1 protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x12 0xff at 33 \
      action skbedit ptype host

  echo "Creating egress filter for $mob_veth to match protocol tcp and tcp flag FIN and source port 80 and accept it"
  $TC filter add dev $mob_veth parent $egress_filter prio 2 protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x01 0xff at 33 \
      action skbedit ptype host 

  echo "Creating egress filter for $mob_veth to match protocol tcp and tcp flag FIN ACK and source port 80 and accept it"
  $TC filter add dev $mob_veth parent $egress_filter prio 3 protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x11 0xff at 33 \
      action skbedit ptype host 

  echo "Creating egress filter for $mob_veth to match protocol tcp and HTTP and source port 80/443 and accept it"
  $TC filter add dev $mob_veth parent $egress_filter prio 5 protocol ip u32 \
      match ip protocol 0x6 0xff \
      match u8 0x48 0xff at 52 \
      match u8 0x54 0xff at 53 \
      match u8 0x54 0xff at 54 \
      match u8 0x50 0xff at 55 \
      action skbedit ptype host 

  echo "Creating egress filter for $mob_veth to match protocol tcp and source port 80/443 and accept it"
  $TC filter add dev $mob_veth parent $egress_filter prio 40 protocol ip u32 \
      match ip protocol 0x6 0xff \
      action skbedit ptype host

}


create_qdiscs() {
  veth=$1
  echo "Creating ingress QDiscs for $veth"
  $TC qdisc add dev $veth ingress
  echo "Creating egress QDiscs for $veth"
  $TC qdisc add dev $veth root handle 1: prio
}

delete_qdiscs() {
  veth=$1
  echo "Deleting ingress QDiscs for $veth"
  $TC qdisc del dev $veth ingress
  echo "Deleting egress QDiscs for $veth"
  $TC qdisc del dev $veth root handle 1: prio
}

create_infrastructure() {

   #echo "inserting kernel modules"
   # Environment Setup
   #sudo insmod /home/ssridhar/Downloads/act-trproxy/act_trproxy.ko
   #sudo insmod /home/istguser1/QE-ACT-5.0/act_qe.ko

#echo "creating QE"
#create_qe \
#   $STARTING_QE_INDEX \
#   $ENDING_QE_INDEX

#echo "creating Police"
#create_police \
#   $STARTING_QE_INDEX \
#   $ENDING_QE_INDEX

echo "setup_two_paired_veth for haproxy"
  setup_two_paired_veth \
     ${veth_haproxy_ns[0]} \
     ${veth_haproxy_ns[1]} \
     ${veth_haproxy_ns[2]} \
     ${veth_haproxy_ns[3]} \
     ${veth_haproxy_ns[4]} \
     ${veth_haproxy_ns[5]} \
     ${veth_haproxy_ns[6]} \
     ${veth_haproxy_ns[7]}

echo "setup veth for swapping"
  setup_single_paired_veth \
     $VETH_SWAP1 \
     $VETH_SWAP1_MAC \
     $VETH_SWAP2 \
     $VETH_SWAP2_MAC


echo "setup_single pair veth for wget container."
  setup_single_paired_veth \
     $MOB_WGET_HOST_VETH \
     $MOB_WGET_HOST_MAC \
     $MOB_WGET_CONT_VETH \
     $MOB_WGET_CONT_MAC


echo "setup_single pair veth for dnsproxy container."
  setup_single_paired_veth \
     ${veth_dnsproxy_ns[0]} \
     ${veth_dnsproxy_ns[1]} \
     ${veth_dnsproxy_ns[2]} \
     ${veth_dnsproxy_ns[3]}

 #create_qdiscs \
 #    ${veth_dnsproxy_ns[0]}

 #create_qdiscs \
 #    ${veth_dnsproxy_ns[2]}

  create_ingress_qdiscs \
     $VETH_SWAP1

  create_egress_prio_qdiscs \
     $VETH_SWAP1

  create_ingress_qdiscs \
     $MOB_IFACE

  create_ingress_qdiscs \
     ${veth_dnsproxy_ns[0]}

  create_egress_fq_qdiscs \
     ${veth_dnsproxy_ns[0]}

  create_ingress_qdiscs \
     ${veth_dnsproxy_ns[2]}

  create_egress_fq_qdiscs \
     ${veth_dnsproxy_ns[2]}

  create_ingress_qdiscs \
     ${veth_haproxy_ns[0]}

  create_egress_fq_qdiscs \
     ${veth_haproxy_ns[0]}

  create_ingress_qdiscs \
     ${veth_haproxy_ns[2]}

  create_egress_fq_qdiscs \
     ${veth_haproxy_ns[2]}

  create_ingress_qdiscs \
     ${veth_haproxy_ns[4]}

  create_egress_fq_qdiscs \
     ${veth_haproxy_ns[4]}

  create_ingress_qdiscs \
     ${veth_haproxy_ns[6]}

 create_egress_fq_qdiscs \
   ${veth_haproxy_ns[6]}


 create_ingress_qdiscs \
     $MOB_WGET_HOST_VETH

 create_egress_prio_qdiscs \
     $MOB_WGET_HOST_VETH

  echo "setup name space for $HAPROXY_NAMESPACE."
  setup_namespace_container \
     7 \
     $HAPROXY_NAMESPACE \
     ${veth_haproxy_ns[2]} \
     ${veth_haproxy_ns[6]} \
     ${veth_haproxy_ns[0]} \
     ${veth_haproxy_ns[4]} \
     $HAPROXY_MOB_HOST_IP_ADDR \
     $HAPROXY_MOB_CONT_IP_ADDR \
     $HAPROXY_BBI_HOST_IP_ADDR \
     $HAPROXY_BBI_CONT_IP_ADDR

 echo "setup name space for $MOB_WET_CONT_NAMESPACE."
  setup_single_veth_namespace_container \
     7 \
     $MOB_WET_CONT_NAMESPACE \
     $MOB_WGET_CONT_VETH \
     $MOB_WGET_HOST_VETH \
     $MOB_WGET_HOST_IPADDR \
     $MOB_WGET_CONT_IPADDR 


echo "setup name space for $DNSPROXY_NAMESPACE."
  setup_single_veth_namespace_container \
     7 \
     $DNSPROXY_NAMESPACE \
     ${veth_dnsproxy_ns[2]} \
     ${veth_dnsproxy_ns[0]} \
     $DNSPROXY_MOB_HOST_IP_ADDR \
     $DNSPROXY_MOB_CONT_IP_ADDR 

  echo "Setting up tc rules for mobile interface. $MOB_WGET_HOST_VETH"
  create_tc_actions_on_mobile_interface \
      7 \
      $MOB_WGET_HOST_VETH \
      ${veth_haproxy_ns[0]} \
      ${veth_haproxy_ns[1]}

  echo "Setting up tc rules for DNS host interface ${veth_dnsproxy_ns[0]}"
  create_tc_actions_on_dnsproxy_host_interface \
      ${veth_dnsproxy_ns[0]} \
      $MOB_IFACE \
      $DNS_PORT


  #echo "Setting up tc rules for DNS container interface ${veth_dnsproxy_ns[2]}"
  #create_tc_actions_on_dnsproxy_container_interface \
  #    ${veth_dnsproxy_ns[2]} \
  #    $DNS_PORT \
  #    $DNSPROXY_NAMESPACE

  echo "Setting up tc rules for mobile veth container inside the namespace $HAPROXY_NAMESPACE."
  create_tc_actions_on_mobile_container_veth \
     7 \
     $HAPROXY_NAMESPACE \
     $port \
     ${veth_haproxy_ns[2]} \
     ${veth_haproxy_ns[1]}

  echo "Setting up tc rules for bbi veth container inside the namespace $HAPROXY_NAMESPACE."
  create_tc_actions_on_bbi_container_veth \
     7 \
     $HAPROXY_NAMESPACE \
     $port \
     ${veth_haproxy_ns[6]}

  echo "Setting up tc rules for mobile veth that is attached to namespace $HAPROXY_NAMESPACE."
  create_tc_actions_on_mobile_host_veth \
     7 \
     ${veth_haproxy_ns[0]} \
     $MOB_IFACE \
     $MOB_MAC \
     $MAC_OF_MOB_NEXT_HOP

  echo "Setting up tc rules for bbi veth that is attached to namespace $HAPROXY_NAMESPACE."
  create_tc_actions_on_bbi_host_veth \
      ${veth_haproxy_ns[4]} \
      $MOB_IFACE \
      $MOB_MAC \
      ${veth_haproxy_ns[7]} \
      $MAC_OF_BBI_NEXT_HOP


  echo "Setting up tc rules for mobile traffic simulator for MOB IP $MOBILE_TRAFFIC_SRC." 
  create_tc_actions_on_specified_veth \
      $MOB_IFACE \
      $MOB_HOST_VETH \
      $BBI_HOST_VETH \
      $MOB_MAC \
      ${veth_haproxy_ns[7]} \
      $MOBILE_TRAFFIC_SRC \
      1

  echo "Setting up tc rules for mobile traffic simulator MOB IP $MOBILE_TRAFFIC_SRC2." 
  create_tc_actions_on_specified_veth \
      $MOB_IFACE \
      $MOB_HOST_VETH \
      $BBI_HOST_VETH \
      $MOB_MAC \
      ${veth_haproxy_ns[7]} \
      $MOBILE_TRAFFIC_SRC2 \
      10
  
  echo "Setting up tc rules for veth swap for $MOBILE_TRAFFIC_SRC ." 
  create_tc_actions_on_veth_swap \
   $MOBILE_TRAFFIC_SRC \
   1

  echo "Setting up tc rules for veth swap for $MOBILE_TRAFFIC_SRC2." 
  create_tc_actions_on_veth_swap \
   $MOBILE_TRAFFIC_SRC2 \
   10

  echo "Launching $WHITELIST_BLACKLIST python script to convert domain name to ip and feed it to haproxy."  
  sudo nohup $WHITELIST_BLACKLIST &

  echo "Launching $TRANSPARENT_DNS_PROXY python script in $DNSPROXY_NAMESPACE container to catch all DNS requests and send a DNS reject if the content is black listed."  
  sudo $IP netns exec $DNSPROXY_NAMESPACE nohup $TRANSPARENT_DNS_PROXY &

  #echo "Deleting trace.out"
  #sudo rm -f trace.out

}



teardown_infrastructure() {
  echo "Deleting namespace $HAPROXY_NAMESPACE"
  $IP netns del $HAPROXY_NAMESPACE

  echo "Deleting namespace $DNSPROXY_NAMESPACE"
  $IP netns del $DNSPROXY_NAMESPACE

  delete_qdiscs \
     $MOB_IFACE

  delete_qdiscs \
     $MOB_WGET_CONT_VETH

 delete_qdiscs \
     $MOB_WGET_HOST_VETH

  delete_qdiscs \
     $DNS_HOST_VETH

  delete_qdiscs \
     $DNS_CNT_VETH

  delete_qdiscs \
     ${veth_haproxy_ns[0]}

  delete_qdiscs \
     ${veth_haproxy_ns[2]}

  delete_qdiscs \
     ${veth_haproxy_ns[4]}

  delete_qdiscs \
     ${veth_haproxy_ns[6]}

  delete_qdiscs \
     ${veth_web_server_ns[0]}

  delete_qdiscs \
     ${veth_web_server_ns[2]}


  delete_veth \
     $DNS_HOST_VETH \
     $DNS_CNT_VETH

  delete_veth \
     ${veth_haproxy_ns[0]} \
     ${veth_haproxy_ns[4]}

  delete_veth \
     ${veth_haproxy_ns[2]} \
     ${veth_haproxy_ns[6]}

  delete_veth \
     ${veth_web_server_ns[0]} \
     ${veth_web_server_ns[2]}

  delete_veth \
     $VETH_SWAP1 \
     $VETH_SWAP2

 delete_veth \
     $MOB_WGET_HOST_VETH \
     $MOB_WGET_CONT_VETH


  echo "Deleting ingress filters for $VETH_SWAP"
  sudo tc filter del dev $VETH_SWAP1 parent ffff:

  echo "Deleting egress filters for $VETH_SWAP"
  sudo tc filter del dev $VETH_SWAP1 parent 1:

  delete_qdiscs \
     $VETH_SWAP1

  echo "Deleting ingress filters for MOB_IFACE"
  sudo tc filter del dev $MOB_IFACE parent ffff:

  echo "Deleting egress filters for MOB_IFACE"
  sudo tc filter del dev $MOB_IFACE parent 1:

  echo "Deleting QE"
  delete_qe \
   $STARTING_QE_INDEX \
   $ENDING_QE_INDEX

  echo "Deleting Kernel modules"
  sudo rmmod act_qe

  echo "Deleting Police"
  delete_police \
   $STARTING_QE_INDEX \
   $ENDING_QE_INDEX

  echo "Kill $HAPROXY_NAMESPACE" 
  sudo pkill $HAPROXY_NAMESPACE

  echo "Deleting namespace $HAPROXY_NAMESPACE"
  $IP netns del $HAPROXY_NAMESPACE

  echo "Deleting namespace $MOB_WET_CONT_NAMESPACE"
  $IP netns del $MOB_WET_CONT_NAMESPACE

  echo "Deleting $WHITELIST_BLACKLIST"  
  sudo pkill python3.6

}


#
# $1 - endpoint to dump stats at
# $2 - namespace id
show_infrastructure() {
#  show_infrastructure_actions
  if [ "$1" == "ifmob-in" ]; then
$TC -s filter ls dev $MOB_IFACE parent ffff:
  elif [ "$1" == "ifmob-out" ]; then
$TC -s filter ls dev $MOB_IFACE parent 1:
  elif [ "$1" == "mob-in" ]; then
$TC -s filter ls dev $MOB_HOST_VETH parent ffff:
  elif [ "$1" == "mob-out" ]; then
$TC -s filter ls dev $MOB_HOST_VETH parent 1:
  elif [ "$1" == "nsmob-in" ]; then
$IP netns exec $HAPROXY_NAMESPACE $TC -s filter ls dev $MOB_CNT_VETH parent ffff:
  elif [ "$1" == "nsmob-out" ]; then
$IP netns exec $HAPROXY_NAMESPACE $TC -s filter ls dev $MOB_CNT_VETH parent 1:
  elif [ "$1" == "bbi-in" ]; then
$TC -s filter ls dev $BBI_HOST_VETH parent ffff:
  elif [ "$1" == "bbi-out" ]; then
$TC -s filter ls dev $BBI_HOST_VETH parent 1:
  elif [ "$1" == "nsbbi-in" ]; then
$IP netns exec $HAPROXY_NAMESPACE $TC -s filter ls dev $BBI_CNT_VETH parent ffff:
  elif [ "$1" == "nsbbi-out" ]; then
$IP netns exec $HAPROXY_NAMESPACE $TC -s filter ls dev $BBI_CNT_VETH parent 1:
  elif [ "$1" == "NetTx" ]; then
$TC -s filter ls dev NetTx parent ffff:
  elif [ "$1" == "SubTx" ]; then
$TC -s filter ls dev SubTx parent ffff:
  elif [ "$1" == "qdisc" ]; then
$TC -s qdisc ls
  elif [ "$1" == "nsqdisc" ]; then
$TC -n $2 -s qdisc ls
  elif [ "$1" == "vethswp-in" ]; then
$TC -s filter ls dev $VETH_SWAP1 parent ffff:
  elif [ "$1" == "vethswp-out" ]; then
$TC -s filter ls dev $VETH_SWAP1 parent 1:
  elif [ "$1" == "ifmobwgethost-in" ]; then
$TC -s filter ls dev $MOB_WGET_HOST_VETH parent ffff:
  elif [ "$1" == "ifmobwgethost-out" ]; then
$TC -s filter ls dev $MOB_WGET_HOST_VETH parent 1:
  elif [ "$1" == "dnshost-in" ]; then
$TC -s filter ls dev $DNS_HOST_VETH parent ffff:
  elif [ "$1" == "dnshost-out" ]; then
$TC -s filter ls dev $DNS_HOST_VETH parent 1:
  elif [ "$1" == "dnscont-in" ]; then
$IP netns exec $DNSPROXY_NAMESPACE $TC -s filter ls dev $DNS_CNT_VETH parent ffff:
  elif [ "$1" == "dnscont-out" ]; then
$IP netns exec $DNSPROXY_NAMESPACE $TC -s filter ls dev $DNS_CNT_VETH parent 1:
  fi
}

case "$1" in
  start) create_infrastructure ;;
  stats) show_infrastructure $2 $3 ;;
  stop) teardown_infrastructure ;;
  *) echo "usage: $0 start|stats <ifmob-in|ifmob-out|mob-in|mob-out|nsmob-in|nsmob-out|ifbbi-in|ifbbi-out|bbi-in|bbi-out|nsbbi-in|nsbbi-out|SubTx|NetTx|qdisc|dnshost-in|dnshost-out|dnscont-in|dnscont-out|nsqdisc> <NS>|stop"
     exit 1
     ;;
esac

