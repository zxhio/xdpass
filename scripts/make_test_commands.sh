#!/bin/bash

interface=br1
hwaddr=$(cat /sys/class/net/$interface/address)

set -xe

# xdp attachment
xdpass xdp attach $interface
xdpass xdp attachment ls --all
xdpass xdp ls --all
xdpass ls --all

# xdp ip
xdpass xdp ip add 172.16.23.3 -i $interface --pass
xdpass xdp ip add 172.16.23.0/24 -i $interface --redirect
xdpass xdp ip ls --all
xdpass ip ls --all

# mirror rule
xdpass rule add -d 172.16.23.1 --mirror-tap tap0

# protocol rule
xdpass arp add --spoof-arp-reply "$hwaddr"
xdpass icmp add --spoof-echo-reply
xdpass rule http add --spoof-not-found
xdpass rule tcp add --syn -d 172.16.23.0/24 --dports 1:1024 --spoof-syn-ack
xdpass rule tcp add --fin -d 172.16.23.0/24 --dports 1:1024 --spoof-fin-ack
xdpass rule tcp add --syn --ack -d 172.16.23.0/24 --dports 1025 --spoof-rst-ack
xdpass rule tcp add --psh --ack -d 172.16.23.0/24 --dports 1025 --spoof-ack
xdpass rule tcp add --syn --ack -d 172.16.23.0/24 --dports 1026:65525 --spoof-rst-ack

xdpass rule ls --all