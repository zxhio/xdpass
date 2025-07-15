# xdpass

Traffic control utility powered by XDP, matching TCP/IP protocol fields and jumping to targets based on rules.

## Features
- Rule
    - Matches for protocol
        - ARP/TCP/UDP/ICMP/HTTP
    - Matches for fields
        - L2
            - MAC address
        - L3
            - IPv4Prefix (e.g. 127.0.0.1 or 127.0.0.1/8)
            - IPv4Range (e.g. 127.0.0.1-128.0.0.1)
        - L4
            - PortRange (e.g. 80 or 1:1024) and MultiPort (e.g. 80,443,8000)
            - TCP flags (ACK/PSH/SYN/FIN/RST)
        - L7
            - HTTP method/uri/version/host
    - Targets:
        - Reply
            - ARP mac ARP-Reply spoofing
            - TCP flags (ACK/PSH/SYN/FIN/RST) reply spoofing
            - ICMP echo reply spoof
        - Mirror
            - Stdout mirror
            - Tap device mirror
- REST API:
    - XDP attachment management
    - XDP attachment kernel ip management
    - Rule management

## Quick Start

1. Clone
```shell
$ git clone https://github.com/zxhio/xdpass.git
```

2. Build and install
```shell
$ cd xdpass && bash scripts/pack.sh
$ cd build && tar -xvzf xdpass.tar.gz && bash install.sh
```

3. Create test env(recommended)
```shell
$ bash scripts/make_test_env.sh add
```

4. XDP Attachment
```shell
$ xdpass xdp attach br1 --generic
$ xdpass xdp list --all
 NAME   MODE    TIMEOUT  CORES  QUEUES         FLAGS         
 br1   generic  10ms     1      1       use-need-wakeup,copy 
```

5. XDP kernel ip set
```shell
# set ip for XDP_ACTION action
$ xdpass xdp ip add 172.16.23.0/24 -i br1 --redirect
$ xdpass xdp ip list --all
 NAME   ACTION         IP       
 br1   REDIRECT  172.16.23.0/24
```

6. Rule (e.g. respond http 404)

A complete rule is as follows
```shell
# ARP spoof
$ xdpass arp add --spoof-arp-reply $(cat /sys/class/net/br1/address)

# TCP handshake spoof (syn-ack)
$ xdpass rule tcp add --flag-syn -d 172.16.23.0/24 --dports 1:1024 --spoof-syn-ack

# HTTP 404 spoof
$ xdpass rule http add --spoof-not-found

# TCP 4-way handshake spoof (fin-ack)
$ xdpass rule tcp add --flag-fin -d 172.16.23.0/24 --dports 1:1024 --spoof-fin-ack
```

Add add mirror target to watch triffic
```shell
$ xdpass rule add -d 172.16.23.0/24 --mirror-tap tap0
$ tcpdump -s0 -i tap0 -nn
```

7. Attachment stats

Get attachment stats (display a live stream stats dur 1s)
```shell
$ xdpass xdp stats br1 -d 1s
```

## TODO
- Rule support specify interface