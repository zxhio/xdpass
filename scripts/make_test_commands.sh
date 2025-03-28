#! /bin/bash

set -x

interface=br1
hwaddr=$(cat /sys/class/net/$interface/address)

# Firewall
xdpass firewall -i $interface --add --ip 172.16.23.0/24
xdpass firewall -i $interface --list

# Redirect

## Tuntap
xdpass redirect tuntap -i $interface --add-tun tun0
xdpass redirect tuntap -i $interface --add-tap tap0,tap1
xdpass redirect tuntap -i $interface --list

## Spoof
### ARP
xdpass spoof --add --smac "$hwaddr" -s 172.16.23.2 -d 172.16.23.1 --target arp-reply
xdpass spoof --add --smac "$hwaddr" -s 172.16.23.0/24 -d 172.16.23.1 --target arp-reply
xdpass spoof --add --smac "$hwaddr" -s 172.16.23.0/24 -d 172.16.23.0/24 --target arp-reply

### ICMP
xdpass spoof --add -s 172.16.23.2 -d 172.16.23.1 --target icmp-echo-reply
xdpass spoof --add --iprange-src 172.16.23.2-172.16.23.3 -d 172.16.23.1 --target icmp-echo-reply
xdpass spoof --add --iprange-src 172.16.23.1-172.16.23.3 --iprange-dst 172.16.23.1-172.16.23.3 --target icmp-echo-reply
xdpass spoof --add -s 172.16.23.0/24 -d 172.16.23.0/24 --target icmp-echo-reply

### TCP
xdpass spoof --add -s 172.16.23.2 -d 172.16.23.1 --dport 80 --target tcp-reset
xdpass spoof --add -s 172.16.23.2 -d 172.16.23.1 --sport 32768:65535 --dport 80 --target tcp-reset
xdpass spoof --add -s 172.16.23.2 -d 172.16.23.1 --dports 80,443,8000,8001,8002,8080 --target tcp-reset
xdpass spoof --add -s 172.16.23.3 -d 172.16.23.0/24 --dport 22 --target tcp-reset

### List
xdpass spoof --list
