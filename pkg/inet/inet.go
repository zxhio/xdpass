package inet

func Ntohs(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

func Ntohl(v uint32) uint32 {
	return (v>>24)&0xff | (v>>8)&0xff00 | (v<<8)&0xff0000 | (v << 24)
}

func Htons(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

func Htonl(v uint32) uint32 {
	return (v>>24)&0xff | (v>>8)&0xff00 | (v<<8)&0xff0000 | (v << 24)
}
