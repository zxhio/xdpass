# xdpass-bench

RX/TX benchmark tool.

## Usage

l4 protoco as *subcommand*.
- icmp
- tcp

Basic command option
- **--iface** network interface name.
- **--dst-ip** packet destination ip address.

The most basic command to transmit l4_proto packet.
```shell
$ xdpass-bench <l4_proto> -i <iface> --dst-ip <dst-ip>
```

e.g.
```shell
$ xdpass-bench icmp -i lo --dst-ip 127.0.0.1
```

### TX benchmark option

Specify queue id with **queue-id**.
```shell
$ xdpass-bench <l4_proto> -i <iface> --dst-ip <dst-ip> \
    --queue-id <queue-id>
```

Specify packet total with **--num**, -1 not limit.
```shell
$ xdpass-bench <l4_proto> -i <iface> --dst-ip <dst-ip> \
    --num <num>
```

Specify the batch size for each transmission with **--batch-size**.
```shell
$ xdpass-bench <l4_proto> -i <iface> --dst-ip <dst-ip> \
    --num <num> --batch-size <batch-size>
```

Specify rate limit with **--rate-limit**.
```shell
$ xdpass-bench <l4_proto> -i <iface> --dst-ip <dst-ip> \
    --num <num> --batch-size <batch-size> \
    --rate-limit <rate-limit>
```

Specify rate limit calculate precision with **--rate-limit-prec**.
```shell
$ xdpass-bench <l4_proto> -i <iface> --dst-ip <dst-ip> \
    --num <num> --batch-size <batch-size> \
    --rate-limit <rate-limit> --rate-limit-prec <low|mid|high>
```

Specify affinity cpu cores with **--cpu**.
```shell
$ xdpass-bench <l4_proto> -i <iface> --dst-ip <dst-ip> \
    --cpu <core1,core2,...>
```

Specify statistics output duration with **--stats**.
```shell
$ xdpass-bench <l4_proto> -i <iface> --dst-ip <dst-ip> \
    --stats <stats>
```

### Packet build

If not specified, it will be queried from the routing table, arp table or network interface information.

Specify MAC address with **--src-mac** and **--dst-mac**
```shell
$ xdpass-bench <l4_proto> -i <iface> --dst-ip <dst-ip> \
    --src-mac <src-mac> --dst-mac <dst-mac>
```

Specify VLAN id with **--vlan**
```shell
$ xdpass-bench <l4_proto> -i <iface> --dst-ip <dst-ip> \
    --src-mac <src-mac> --dst-mac <dst-mac> \
    --vlan <vlan>
```

Specify IP source address with **--src-ip**.
```shell
$ xdpass-bench <l4_proto> -i <iface> --dst-ip <dst-ip> \
    --src-mac <src-mac> --dst-mac <dst-mac> \
    --src-ip <src-ip>
```

#### Packet build for icmp

Specify echo request id with **--id**
```shell
$ xdpass-bench icmp -i <iface> --dst-ip <dst-ip> \
    --src-mac <src-mac> --dst-mac <dst-mac> \
    --src-ip <src-ip> \
    --id <id>
```

Specify echo request sequence with **--seq**
```shell
$ xdpass-bench icmp -i <iface> --dst-ip <dst-ip> \
    --src-mac <src-mac> --dst-mac <dst-mac> \
    --src-ip <src-ip> \
    --id <id> --seq <seq>
```

#### Packet build for tcp

Specify tcp port with **--src-port** and **--dst-port**.
```shell
$ xdpass-bench tcp -i <iface> --dst-ip <dst-ip> \
    --src-mac <src-mac> --dst-mac <dst-mac> \
    --src-ip <src-ip> \
    --src-port <src-port> --dst-port <dst-port>
```

Multiple TCP flags can be specified simultaneously with **--ACK**, **--FIN**, **--PSH**, **--RST** and **--SYN**.
```shell
$ xdpass-bench tcp -i <iface> --dst-ip <dst-ip> \
    --src-mac <src-mac> --dst-mac <dst-mac> \
    --src-ip <src-ip> \
    --src-port <src-port> --dst-port <dst-port> \
    --PSH --ACK
```

Specify tcp sequence with **--seq**.
```shell
$ xdpass-bench tcp -i <iface> --dst-ip <dst-ip> \
    --src-mac <src-mac> --dst-mac <dst-mac> \
    --src-ip <src-ip> \
    --src-port <src-port> --dst-port <dst-port> \
    --PSH --ACK \
    --seq <seq>
```

Specify tcp payload with **--payload** or **--payload-hex**.
```shell
$ xdpass-bench tcp -i <iface> --dst-ip <dst-ip> \
    --src-mac <src-mac> --dst-mac <dst-mac> \
    --src-ip <src-ip> \
    --src-port <src-port> --dst-port <dst-port> \
    --PSH --ACK \
    --seq <seq> \
    --payload-hex <hex-payload>
```

## TODO
- Add RX benchmark