The Python files are: 
dnsserver_10_136_5_60.py
whitelist_blacklist.py

The corresponding log files for them are:
dns_server_10_136_5_60.log
whitelist_blacklist.log

The corresponding input text files for them are:
whitelist_blacklist2.txt
Whitelist_blacklist.txt

Functionality:

dnsserver_10_136_5_60.py

This is a Transparent DNS Transparent Proxy server.
It acts as a middle man and intercepts the DNS request from the client and takes corresponding action.
It uses scapy module to be installed.
It reads a file whitelist_blacklist2.txt to know the domains that are Blacklisted.
It sniffs out packets coming on its host interface and if the packets are DNS request packets (dest port 53), it parses the DNS packet and checks if the domain is blacklisted. 
If the Domain is Blacklisted, then, the script sends a DNS reject response.
If the Domain is whitelisted, then, the scripts allows the DNS request to be forwarded to the original destination.

Log file:
Whitelisted content: (MainThread:DEBUG:02/27/2018 12:31:45 PM:110:dnsserver_10_136_5_60.py:sniff_packet:Composing and forwarding DNS request for domain name =43-courier.push.apple.com to the original dest.
Blacklisted content: (MainThread:DEBUG:02/27/2018 12:32:22 PM:83:dnsserver_10_136_5_60.py:sniff_packet:line=facebook and qname=graph.facebook.com match.Composing and sending DNS Reject response

whitelist_blacklist.py:

This acts as a helper tool to do the following:
Read a file whitelist_blacklist.txt to know the domains that are blacklisted.
It resolves the url’s to valid IP address using DNSpy module.
It gets those IP addresses and feeds it to another application (HAPROXY) via socat command.

Log file:
(MainThreadWARNING:02/27/2018 12:29:45 PM:186:whitelist_blacklist.py:convert_dnsname_to_ip2:For domain name (www.facebook.com), appending IP address (31.13.69.228) to the list.
(MainThreadWARNING:02/27/2018 12:29:45 PM:186:whitelist_blacklist.py:convert_dnsname_to_ip2:For domain name (www.facebook.com), appending IP address (2a03:2880:f103:83:face:b00c:0:25de) to the list.
(MainThreadWARNING:02/27/2018 12:29:45 PM:256:whitelist_blacklist.py:refresh_acl:Added www.facebook.com->31.13.69.228 to acl in HAPROXY.
(MainThreadWARNING:02/27/2018 12:29:45 PM:256:whitelist_blacklist.py:refresh_acl:Added www.facebook.com->2a03:2880:f103:83:face:b00c:0:25de to acl in HAPROXY.


