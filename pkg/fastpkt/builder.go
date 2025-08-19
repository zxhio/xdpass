package fastpkt

import "unsafe"

// DataPtr is a helper function to cast a data type to a pointer
func DataPtr[T any](data []byte, off int) *T { return (*T)(unsafe.Pointer(&data[off])) }

// Convenience typed accessors relative to RxData/TxData
func EthernetPtr(pkt *Packet, data []byte) *Ethernet { return DataPtr[Ethernet](data, 0) }
func VLANPtr(pkt *Packet, data []byte) *VLAN         { return DataPtr[VLAN](data, SizeofEthernet) }
func ARPPtr(pkt *Packet, data []byte) *ARP           { return DataPtr[ARP](data, int(pkt.L2Len)) }
func IPv4Ptr(pkt *Packet, data []byte) *IPv4         { return DataPtr[IPv4](data, int(pkt.L2Len)) }
func IPv6Ptr(pkt *Packet, data []byte) *IPv6         { return DataPtr[IPv6](data, int(pkt.L2Len)) }
func TCPPtr(pkt *Packet, data []byte) *TCP           { return DataPtr[TCP](data, int(pkt.L2Len+pkt.L3Len)) }
func UDPPtr(pkt *Packet, data []byte) *UDP           { return DataPtr[UDP](data, int(pkt.L2Len+pkt.L3Len)) }
func ICMPPtr(pkt *Packet, data []byte) *ICMP         { return DataPtr[ICMP](data, int(pkt.L2Len+pkt.L3Len)) }

// PacketBuilder allocates memory from end to beginning for building network packets
type PacketBuilder struct {
	buf      []byte
	writePos int
}

// NewPacketBuilder creates a new packet builder
func NewPacketBuilder(data []byte) *PacketBuilder {
	cap := cap(data)
	return &PacketBuilder{buf: data[:cap], writePos: cap}
}

// Reset reinitializes the builder
func (pb *PacketBuilder) Reset() { pb.writePos = cap(pb.buf) }

func (pb *PacketBuilder) Bytes() []byte { return pb.buf[pb.writePos:] }
func (pb *PacketBuilder) Len() int      { return cap(pb.buf) - pb.writePos }

func (pb *PacketBuilder) alloc(n int) []byte {
	pb.writePos -= n
	return pb.buf[pb.writePos:]
}

func (pb *PacketBuilder) Alloc(n int) []byte       { return pb.alloc(n) }
func (pb *PacketBuilder) AllocEthernet() *Ethernet { return alloc[Ethernet](pb) }
func (pb *PacketBuilder) AllocVLAN() *VLAN         { return alloc[VLAN](pb) }
func (pb *PacketBuilder) AllocARP() *ARP           { return alloc[ARP](pb) }
func (pb *PacketBuilder) AllocIPv4() *IPv4         { return alloc[IPv4](pb) }
func (pb *PacketBuilder) AllocTCP() *TCP           { return alloc[TCP](pb) }
func (pb *PacketBuilder) AllocUDP() *UDP           { return alloc[UDP](pb) }
func (pb *PacketBuilder) AllocICMP() *ICMP         { return alloc[ICMP](pb) }

func alloc[T any](pb *PacketBuilder) *T {
	var v T
	return DataPtr[T](pb.alloc(int(unsafe.Sizeof(v))), 0)
}
