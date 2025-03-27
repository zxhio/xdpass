package fastpkt

import "unsafe"

// DataPtr is a helper function to cast a data type to a pointer
func DataPtr[T any](data []byte, off int) *T             { return (*T)(unsafe.Pointer(&data[off])) }
func DataPtrEthHeader(data []byte, off int) *EthHeader   { return DataPtr[EthHeader](data, off) }
func DataPtrARPHeader(data []byte, off int) *ARPHeader   { return DataPtr[ARPHeader](data, off) }
func DataPtrVLANHeader(data []byte, off int) *VLANHeader { return DataPtr[VLANHeader](data, off) }
func DataPtrIPv4Header(data []byte, off int) *IPv4Header { return DataPtr[IPv4Header](data, off) }
func DataPtrIPv6Header(data []byte, off int) *IPv6Header { return DataPtr[IPv6Header](data, off) }
func DataPtrTCPHeader(data []byte, off int) *TCPHeader   { return DataPtr[TCPHeader](data, off) }
func DataPtrUDPHeader(data []byte, off int) *UDPHeader   { return DataPtr[UDPHeader](data, off) }
func DataPtrICMPHeader(data []byte, off int) *ICMPHeader { return DataPtr[ICMPHeader](data, off) }

type Buffer struct {
	buf   []byte
	start int
}

// NewBuildBuffer
// return value instead of pointer, in order to avoid memory allocation
func NewBuildBuffer(data []byte) Buffer {
	return Buffer{buf: data[:cap(data)], start: cap(data)}
}

func (b *Buffer) alloc(n int) []byte {
	b.start -= n
	return b.buf[b.start:]
}

func (b *Buffer) Bytes() []byte { return b.buf[b.start:] }
func (b *Buffer) Len() int      { return len(b.buf) - b.start }

func (b *Buffer) AllocPayload(n int) []byte    { return b.alloc(n) }
func (b *Buffer) AllocEthHeader() *EthHeader   { return DataPtr[EthHeader](b.alloc(SizeofEthernet), 0) }
func (b *Buffer) AllocVLANHeader() *VLANHeader { return DataPtr[VLANHeader](b.alloc(SizeofVLAN), 0) }
func (b *Buffer) AllocARPHeader() *ARPHeader   { return DataPtr[ARPHeader](b.alloc(SizeofARP), 0) }
func (b *Buffer) AllocIPv4Header() *IPv4Header { return DataPtr[IPv4Header](b.alloc(SizeofIPv4), 0) }
func (b *Buffer) AllocTCPHeader() *TCPHeader   { return DataPtr[TCPHeader](b.alloc(SizeofTCP), 0) }
func (b *Buffer) AllocUDPHeader() *UDPHeader   { return DataPtr[UDPHeader](b.alloc(SizeofUDP), 0) }
func (b *Buffer) AllocICMPHeader() *ICMPHeader { return DataPtr[ICMPHeader](b.alloc(SizeofICMP), 0) }
