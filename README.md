# xdpass

Network tools.

## xdpass-bench

Benchmark rx/tx tool.

### Usage

The most basic command to transmit l4_proto packet
```shell
$ xdpass-bench <l4_proto> -i <iface-name> --dst-ip <dst-ip>
```

e.g.
```shell
$ xdpass-bench icmp -i lo --dst-ip 127.0.0.1 -n -1 --rate-limit -1 -s 1 --cpu 10
```