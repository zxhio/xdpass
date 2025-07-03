package netutil

import (
	"encoding/binary"
	"unsafe"
)

func Ntohs(v uint16) uint16 { return Htons(v) }
func Htons(v uint16) uint16 { return binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&v))[:]) }

func Ntohl(v uint32) uint32 { return Htonl(v) }
func Htonl(v uint32) uint32 { return binary.BigEndian.Uint32((*[4]byte)(unsafe.Pointer(&v))[:]) }
