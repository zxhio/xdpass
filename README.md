# xdpass

Utilizing XDP for manipulating network packets in user mode.


## xdpassd

Using XDP to filter or redirect packets to user space.

Specific features, see **xdpass**.

### usage

Edit the config file in `/etc/xdpass/xdpassd.toml`.
```toml
poll_timeout_ms = 10

[[interfaces]]
  name = "eth0"
  queue_id = 0
  attach_mode = "generic"
  force_copy = true
  no_need_wakeup = false

[log]
  path = "/var/log/xdpass/xdpassd.log"
  level = "info"
  level_check_path = "/etc/xdpass/xdpassd.log.level"
  level_check_interval_sec = 30
  max_size = 100
  max_backups = 3
  max_age = 30
  compress = true
```

Interface config:
- `name`: specify the interface name.
- `queue_id`: specify the queue id for the interface, -1 means using all queues.
- `attach_mode`: specify the attach mode for the interface, could be `generic`(aka skb), `native` or `offload`.
- `force_copy`: force the copy mode for the interface.
- `force_zero_copy`: force the zero copy mode for the interface.
- `no_need_wakeup`: specify whether the interface needs to wakeup the kernel.

Log config `level_check_path` could be a file path, allow dynamic change log level.

## xdpass

A tool for interacting with **xdpassd**.

### benchmark

> Run independently without interacting with **xdpassd**.

Construct packets based on command-line parameters for transmit benchmark.

Construct packets with at least two parameters
1. `--interface -i`, special the interface
2. `--dst-ip`, special the destination ip

Use the protocol( **icmp**, **tcp** and **udp**) as a subcommand, where different
subcommands correspond to specific protocol details, such as `--dst-port` for the **tcp** subcommand.

Additionally, use
- `--queue-id -q` to specify the queue id
- `--total -n` to specify the number of packets to send
- `--batch -b` to specify the batch size when *--rate-limit* is -1
- `--rate-limit -r` to control the sending rate
- `--rate-limit-prec -p` to specify the rate limit precision
- `--stats-dur -s` to enable sending statistics
- `--cores -c` to specify the cpu cores

For `--xdp-copy` and `--xdp-zero-copy` options:
> Some drivers require specifying the use of copy mode to consume TX data.
> Similarly, these drivers may only support loading XDP programs in generic mode.

To get detailed usage of the commands mentioned, you can follow these commands:
```shell
$ xdpass bench --help
```

#### examples

To send udp packets to 127.0.0.1 via the *lo* interface unlimited rate and tx packets.
```shell
$ xdpass bench udp -i lo --dst-ip 127.0.0.1 -s 1
```

To send 1000 icmp packets to 127.0.0.1 via the *lo* interface at 10 packets per second.
```shell
$ xdpass bench icmp -i lo --dst-ip 127.0.0.1 -n 1000 -r 10 -s 1
```

To send tcp packets to 127.0.0.1 via the *lo* interface unlimited rate and tx packets.
Specify the source port and destination port and tcp flags.
```shell
$ xdpass bench tcp -i lo --dst-ip 127.0.0.1 --src-port 1234 --dst-port 1234 --SYN -s 1
```

Specify complete network parameters
```shell
$ xdpass bench tcp -i br1 --src-mac 6a:10:e9:37:63:ac --dst-mac 72:18:fd:f4:fa:b8 \
    --src-ip 172.16.23.1 --dst-ip 172.16.23.2 \
    --src-port 1234 --dst-port 1234 --PSH --ACK --seq 1234567890 --payload "hello"
```

Then you can see the statistics output (with `-s 1`)
```txt
| QUEUE | TX PKTS | TX PPS |   TX BYTES   |    TX BPS     | TX IOPS | TX ERR IOPS |
+-------+---------+--------+--------------+---------------+---------+-------------+
|     0 |  720896 | 179933 |  46.9 MBytes |  93.6 MBits/s |    5615 |           0 |
|     1 |  720896 | 179997 |  46.9 MBytes |  93.6 MBits/s |    5612 |           0 |
|     2 |  720896 | 179997 |  46.9 MBytes |  93.6 MBits/s |    5612 |           0 |
|     3 |  720896 | 179996 |  46.9 MBytes |  93.6 MBits/s |    5612 |           0 |
|   SUM | 2883584 | 719924 | 187.4 MBytes | 374.4 MBits/s |   22451 |           0 |
```

### firewall

Manage access to the XDP program IP filter.

The IP filter key could be `IP`, e.g. 192.168.1.1. Or `CIDR`, e.g. 192.168.1.0/24.

- `--interface -i` specify the network interface to operate on; empty means operating on all network interfaces.
- `--add -a / --del -d` specify operation type.
- `--key` specify filter ip key.

e.g. Add 192.168.1.2 (or 192.168.1.2/32) to firewall on interface br1.
```shell
$ xdpass fw -i br1 --add --key 192.168.1.2
```

### stats

Display a live stream of network traffic statistics.

Specify interface by `--interface -i`, empty interface means output all interface's stats.

Specify output duration by `--duration -d`, e.g. output per 10s on interface br1
```shell
$ xdpass stats -i br1 -d 10s
```


### dump

Redirect network traffic and output in a more human-friendly format to the standard output.

Specify interface by `--interface -i`, empty interface means output all interface's packets.

e.g. Dump packets on interface br1.
```shell
$ ./xdpass dump -i br1
```

### spoof

Redirect network traffic and response spoofed traffic based on rule spoof types.

- `--interface -i` specify interface, alse could be empty.
- `--list` `--add` or `--del` manage spoof rules.
- `--source -s` `--iprange-src` `--smac` `--sport` `--sports` special rule match destination addresses.
- `--destination -d` `--iprange-dst` `--dmac` `--dport` `--dports` special rule match destination addresses.
- `--target` special spoof target
- `--list-target` show supported target
    - tcp-reset
    - arp-reply
    - icmp-echo-reply

e.g. Return ICMP echo reply packet for ICMP echo packets originating from interface br1 with source IPs in the 172.16.23.0/24 range and destination IPs in the 172.16.23.0/24 range.
```shell
$ xdpass spoof -i br1 --add -s 172.16.23.0/24 -d 172.16.23.0/24 --target icmp-echo-reply
```

Detail see [make_test_commands.sh](scripts/make_test_commands.sh) 

### tuntap

Redirect network traffic to tuntap devices.

- `--add-tun -U` add tun devices.
- `--add-tap -A` add tap devices.
- `--del -D` delete tuntap devices
- `--list` show tuntap devices info.

e.g. Add tun devices tun0 and tun1
```shell
$ ./xdpass tuntap --add-tun tun0,tun1
```

You can see the packets on this tun/tap devices by capture services.

e.g. tcpdump
```shell
$ tcpdump -i tun0 -nne
18:16:13.908935 ip: 172.16.23.1 > 172.16.23.2: ICMP echo reply, id 32641, seq 1, length 64

$ tcpdump -i tap0 -nne
18:17:23.324136 6a:10:e9:37:63:ac > 72:18:fd:f4:fa:b8, ethertype IPv4 (0x0800), length 4096: 172.16.23.1 > 172.16.23.2: ICMP echo reply, id 19116, seq 1, length 64
```

e.g. suricata
```shell
$ cat /etc/suricata/rules/suricata.rules
alert icmp any any -> $HOME_NET any (msg:"ICMP echo v4 connection"; itype:8; sid:9010012; rev:1; metadata:created_at 2020_01_07;)

# default config
$ suricata -i tap0

$ tail -n 1 /var/log/suricata/fast.log
02/24/2025-09:32:26.634435  [**] [1:9010012:1] ICMP echo v4 connection [**] [Classification: (null)] [Priority: 3] {ICMP} 172.16.23.2:8 -> 172.16.23.1:0
```

## scripts

### make_test_env.sh

Create a environment with a bridge and namespaces for testing.

```shell
$ ./scripts/make_test_env.sh add
```

## TODO
- Add xdpassd redirect traffic to remote support
- Add whitelist and blacklist firewall support
- Add IPv6 support
- Add xdpassd gRPC API support
- Add xdpassd RESTful API support
