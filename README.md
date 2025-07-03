# xdpass

Traffic control utility powered by XDP, matching TCP/IP protocol fields and jumping to targets based on rules.

## Features
- Matches for protocol: arp/tcp/udp/icmp/http
- Matches for fields:
    - L2: MAC address
    - L3: IPv4Prefix(e.g. 127.0.0.1 or 127.0.0.1/8) and IPv4Range (e.g. 127.0.0.1-128.0.0.1)
    - L4: PortRange (e.g. 80 or 1:1024) and MultiPort (e.g. 80,443,8000)
    - L7: HTTP method/uri/version/host
- Targets:
    - ARP: arp reply spoof
    - TCP: handshake reset or block
    - ICMP: echo reply spoof
- Easy to use:
    - Rules are similar in style to iptables
    - Use TCP/IP protocols as subcommands to isolate supplied matches and targets.

## Quick Start

Specify iface to run **xdpassd** (recommended virtual nic).
```shell
$ xdpassd -i br1 --filter <Interested IP> -v
```

Use command tool **xdpass** to add/del rules.
```shell
# Spoof ARP reply for a target MAC
$ xdpass rule arp add --spoof-arp-reply 6a:10:e9:37:63:ac

# Block TCP handshake (RST) on port 80
$ xdpass rule tcp add --dports 80 --reset-handshake

# Delete rule for specified id
$ xdpass rule del <ID>
```

Use command tool **xdpass** to list/get rules.
```shell
# Show rules
$ xdpass rule list

# Show rules of TCP protocol
$ xdpass rule tcp list

# Get rule for specified id
$ xdpass rule get <ID>
```

## TODO
- xdpassd supports API updates for IP lpm trie.
- xdp kernel module supports ip lpm trie of *pass*/*redirect* .
- rule add packet statistics info.
- implement stdout/tap/udp mirror target.
- xdpassd supports multiple interface.