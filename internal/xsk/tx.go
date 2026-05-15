package xsk

// WriteTX sends a packet via the XSK TX ring. It implements response.TXWriter.
func (s *Socket) WriteTX(pkt []byte) error {
	return s.WriteFrame(pkt)
}
