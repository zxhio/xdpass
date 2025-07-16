# xdpass - XDP-based Traffic Control Utility

## Overview
xdpass is a high-performance network traffic control utility powered by XDP (eXpress Data Path), enabling granular packet matching across protocol layers and flexible rule-based actions.

The overall logic is shown in the following figure:
```txt

                            ┌── mirror
                xdpassd  ───│
                   ^        └── reply
  User             │ RX           │
───────────────────│──────────────│─────────
  Kernel           │       TX     │
                 UMEM    <-----   ┘
                   ^ 
                   │ y
                   │      n
           REDIRECT TRIE ---> DROP
                   ^
                   │ n
                   │      y
               PASS TRIE ---> TCP/IP stack
                   │
                  pkt
                   │
                  NIC

```

## Applicable scenarios
- Traffic mirroring machine

## Features

### Rule (User space)

#### Protocol Matching
- **​Protocol Support**​​:
    - ARP, TCP, UDP, ICMP, and HTTP protocols
- ​**​Multi-layer Field Matching**​​:
    - ​​Layer 2​​:
        - MAC address matching
    - ​​Layer 3​​:
        - IPv4Prefix matching (e.g., 127.0.0.1 or 127.0.0.1/8)
        - IPv4Range matching (e.g., 127.0.0.1-128.0.0.1)
    - ​​Layer 4​​:
        - PortRange matching (single port 1024 or range like 1:1024)
        - MultiPort matching (comma-separated list like 80,443,8000)
        - TCP flag matching (ACK/PSH/SYN/FIN/RST)
    ​- ​Layer 7​​:
        - HTTP method, URI, version, and host header matching

#### Action Targets
- ​**​Response Spoofing**​​:
    - ARP reply spoofing with custom MAC
    - TCP flag response spoofing (SYN-ACK, FIN-ACK, etc.)
    - ICMP echo reply spoofing
    - HTTP 404 response spoofing
- ​​**Traffic Mirroring**​​:
    - Output to stdout
    - Mirror to tap interface

### XDP kernel prog ip set
- Pass ip lpm trie: pass to kernel by matching the source IP of the packet
- Redirect ip lpm trie: redirect to userspace by matching the source IP of the packet

### RESTful API
- XDP program attachment management
- Kernel IP address set configuration
- Rule management

## Quick Start

### Build && Installation

Get source
```shell
$ git clone https://github.com/zxhio/xdpass.git
$ cd xdpass
```

Pack binary with systemd service release file
```shell
$ bash scripts/pack.sh
```

Install on server
```shell
$ cd build && tar -xvzf xdpass.tar.gz && bash install.sh
```

### Test (recommended)

Run test env build script
```shell
$ bash scripts/make_test_env.sh add
```

The testing environment is as follows
```txt
┌─────────────────────────────┐ 
│ Host                        │ 
│     ┌─────────────────┐     │ 
│     │ ns11            │     │ 
│     │  172.16.23.2/24 │     │ 
│     │      eth0       │     │ 
│     └────────|────────┘     │ 
│              │              │ 
│           veth11            │ 
│              │              │ 
│             br1             │ 
│       172.16.23.1/24        │ 
│                             │ 
└─────────────────────────────┘ 
```

### Basic Usage

#### XDP Attachment

Attach xdp program attachment
```shell
$ xdpass xdp attach br1 --generic --timeout 10us
```

Detach xdp program attachment
```shell
$ xdpass xdp detach br1
```

List xdp program attachments
```shell
$ xdpass xdp list --all
 NAME   MODE    TIMEOUT  CORES  QUEUES       FLAGS      
 br1   generic  10ms     -1     0,1     use-need-wakeup
```

#### XDP kernel ip

Add ip to xdp prog kernel ipset (specify attachment name and xdp action)
```shell
$ xdpass xdp ip add 172.16.23.0/24 --interface br1 --redirect
```

Delete ip from xdp prog kernel ipset
```shell
$ xdpass xdp ip delete 172.16.23.0/24 --interface br1 --redirect
```

List ip from xdp prog kernel ipset
```shell
$ xdpass xdp ip list --all
 NAME   ACTION         IP       
 br1   REDIRECT  172.16.23.0/24
```

#### Rule spoofing

ARP reply spoofing (specify destination 172.16.23.0/24)
```shell
$ xdpass rule arp add -d 172.16.23.0/24 --spoof-arp-reply $(cat /sys/class/net/br1/address)
```

TCP 3-way handshake spoofing (syn-ack)
```shell
$ xdpass rule tcp add -d 172.16.23.0/24 --dports 1:1024 --flag-syn --spoof-syn-ack
```

TCP 4-way handshake spoofing (fin-ack)
```shell
$ xdpass rule tcp add -d 172.16.23.0/24 --dports 1:1024 --flag-fin --spoof-fin-ack
```

HTTP 404 response spoofing
```shell
$ xdpass rule http add -d 172.16.23.0/24 --uri / --method GET --spoof-not-found
```

ICMP echo reply spoofing
```shell
$ xdpass rule icmp add -d 172.16.23.0/24 --spoof-echo-reply
```

List all rules
```shell
$ xdpass rule list --all
 ID  PKTS  BYTES  PROTO  SOURCE   DESTINATION    SOURCE PORTS  DESTINATION PORTS       TARGET      
 1    0      0     arp     *     172.16.23.0/24       *                *          spoof-arp-reply  
 2    0      0     tcp     *     172.16.23.0/24       *             1:1024         spoof-syn-ack   
 3    0      0     tcp     *     172.16.23.0/24       *             1:1024         spoof-fin-ack   
 4    0      0    http     *     172.16.23.0/24       *                *          spoof-not-found  
 5    0      0    icmp     *     172.16.23.0/24       *                *          spoof-echo-reply
```

##### Test effective

**ping** br1 ip once inside netns.
```shell
$ ip netns exec ns11 ping -c 1 172.16.23.1
```

**curl** br1 ip once inside netns.
```shell
$ ip netns exec ns11 curl http://172.16.23.1:1024
```

And observe field **PKTS/BYTES** changes in rule list result.

#### Observability

##### XDP statistics

view xdp attachment statistics
```shell
$ xdpass xdp stats br1 -d 1s
 INTERFACE  QUEUE  RX PPS  TX PPS    RX BPS       TX BPS    
────────────────────────────────────────────────────────────
    br1       0      6       3     3.4 KBits/s  2.6 KBits/s 
    br1       1      0       0      0 Bits/s     0 Bits/s   
────────────────────────────────────────────────────────────
       SUM      2       6       3  3.4 KBits/s  2.6 KBits/s 
```

##### Rule mirror

Mirror destination 172.16.23.0/24 traffic to **tap** device tap0
```shell
$ xdpass rule add -d 172.16.23.0/24 --mirror-tap tap0
```
Provided a foundation for subsequent processing of *tcpdump* and even *suricata*.

Mirror destination 172.16.23.0/24 traffic to **stdout** (for debug)
```shell
$ xdpass rule add -d 172.16.23.0/24 --mirror-stdout
```

## TODO
- [ ] XDP kernel prog ipset add destination IP set
- [ ] XDP kernel prog add port matching
- [ ] User mode rule support specify interface name