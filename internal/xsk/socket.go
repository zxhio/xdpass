package xsk

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const invalidUMEMFrame = ^uint64(0)

// Socket is an AF_XDP socket bound to a single queue.
type Socket struct {
	sockfd int
	umem   *umem
	rx     rxQueue
	tx     txQueue
	opts   Options

	txStanding uint32
	rxBorrowed bool
	rxFrame    uint64
}

// umem manages the shared user-space memory region for AF_XDP frames.
type umem struct {
	mem []byte

	frameAddrs   []uint64
	frameFreeNum uint32

	fill fillQueue
	comp completionQueue
}

// NewSocket creates and binds an AF_XDP socket for the given queue.
func NewSocket(ifIndex uint32, queueID uint32, opts Options) (*Socket, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	sockfd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("xsk: create socket: %w", err)
	}

	u, err := newUMEM(sockfd, opts)
	if err != nil {
		unix.Close(sockfd)
		return nil, err
	}

	off, err := loadOffsets(sockfd)
	if err != nil {
		u.close()
		unix.Close(sockfd)
		return nil, err
	}

	// Create RX ring.
	var rx rxQueue
	if opts.RXRingSize != 0 {
		if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_RX_RING, int(opts.RXRingSize)); err != nil {
			u.close()
			unix.Close(sockfd)
			return nil, fmt.Errorf("xsk: setsockopt XDP_RX_RING: %w", err)
		}
		rxMem, err := unix.Mmap(sockfd, unix.XDP_PGOFF_RX_RING,
			ringMmapSize(off.Rx, opts.RXRingSize, sizeofXDPDesc),
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			u.close()
			unix.Close(sockfd)
			return nil, fmt.Errorf("xsk: mmap rx ring: %w", err)
		}
		initQueueByOffset(rx.raw(), rxMem, &off.Rx, opts.RXRingSize)
		rx.mask = opts.RXRingSize - 1
		rx.size = opts.RXRingSize
		rx.cachedProd = atomic.LoadUint32(rx.producer)
		rx.cachedCons = atomic.LoadUint32(rx.consumer)
	}

	// Create TX ring.
	var tx txQueue
	if opts.TXRingSize != 0 {
		if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_TX_RING, int(opts.TXRingSize)); err != nil {
			unix.Munmap(rx.raw().mem)
			u.close()
			unix.Close(sockfd)
			return nil, fmt.Errorf("xsk: setsockopt XDP_TX_RING: %w", err)
		}
		txMem, err := unix.Mmap(sockfd, unix.XDP_PGOFF_TX_RING,
			ringMmapSize(off.Tx, opts.TXRingSize, sizeofXDPDesc),
			unix.PROT_READ|unix.PROT_WRITE,
			unix.MAP_SHARED|unix.MAP_POPULATE)
		if err != nil {
			unix.Munmap(rx.raw().mem)
			u.close()
			unix.Close(sockfd)
			return nil, fmt.Errorf("xsk: mmap tx ring: %w", err)
		}
		initQueueByOffset(tx.raw(), txMem, &off.Tx, opts.TXRingSize)
		tx.mask = opts.TXRingSize - 1
		tx.size = opts.TXRingSize
		tx.cachedProd = atomic.LoadUint32(tx.producer)
		tx.cachedCons = atomic.LoadUint32(tx.consumer) + opts.TXRingSize
	}

	// Bind socket to interface and queue.
	addr := &unix.SockaddrXDP{
		Ifindex: ifIndex,
		QueueID: queueID,
		Flags:   unix.XDP_COPY,
	}
	if err := unix.Bind(sockfd, addr); err != nil {
		unix.Munmap(rx.raw().mem)
		unix.Munmap(tx.raw().mem)
		u.close()
		unix.Close(sockfd)
		return nil, fmt.Errorf("xsk: bind queue %d: %w", queueID, err)
	}

	return &Socket{
		sockfd: sockfd,
		umem:   u,
		rx:     rx,
		tx:     tx,
		opts:   opts,
	}, nil
}

// FD returns the AF_XDP socket file descriptor.
func (s *Socket) FD() uint32 {
	return uint32(s.sockfd)
}

// ReadFrame polls the RX ring and returns one metadata-prefixed redirected
// frame. The returned slice is copied out of UMEM so callers do not hold
// AF_XDP frame ownership across response execution.
func (s *Socket) ReadFrame(ctx context.Context) ([]byte, error) {
	frame, err := s.ReadBorrowedFrame(ctx)
	if err != nil {
		return nil, err
	}
	if len(frame) == 0 {
		s.ReleaseBorrowedFrame()
		return nil, nil
	}
	out := append([]byte(nil), frame...)
	s.ReleaseBorrowedFrame()
	return out, nil
}

// ReadBorrowedFrame polls the RX ring and returns one metadata-prefixed
// redirected frame borrowed directly from UMEM. Callers must release the frame
// with ReleaseBorrowedFrame after synchronous use.
func (s *Socket) ReadBorrowedFrame(ctx context.Context) ([]byte, error) {
	if s.rxBorrowed {
		return nil, fmt.Errorf("xsk: borrowed frame not released")
	}

	pollFds := [1]unix.PollFd{
		{Fd: int32(s.sockfd), Events: unix.POLLIN},
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil, nil
		}

		_, err := unix.Poll(pollFds[:], 100)
		if err != nil && err != unix.EINTR {
			return nil, fmt.Errorf("xsk: poll: %w", err)
		}

		s.drainCompletions()
		frame, handled, err := s.receiveFrameBorrowed()
		if err != nil {
			return nil, err
		}
		if handled {
			return frame, nil
		}
	}
}

// ReleaseBorrowedFrame releases the currently borrowed RX frame back to UMEM.
func (s *Socket) ReleaseBorrowedFrame() {
	if !s.rxBorrowed {
		return
	}

	s.umem.freeFrame(s.rxFrame)
	s.rx.Release(1)
	s.refillFill()

	s.rxBorrowed = false
	s.rxFrame = 0
}

// WriteFrame sends a response frame by allocating a UMEM slot, copying data,
// submitting a TX descriptor, and kicking the TX ring if needed.
func (s *Socket) WriteFrame(frame []byte) error {
	maxPayloadSize := int(s.opts.FrameSize) - xskMetadataHeadroom
	if len(frame) > maxPayloadSize {
		return fmt.Errorf("xsk: frame length %d exceeds payload size %d", len(frame), maxPayloadSize)
	}

	frameBase := s.allocTXFrame()
	if frameBase == invalidUMEMFrame {
		return fmt.Errorf("xsk: no free TX frames")
	}
	addr := txFrameAddr(frameBase)

	data := s.umem.frameData(addr, uint32(len(frame)))
	copy(data, frame)

	var idx uint32
	if s.tx.Reserve(1, &idx) == 0 {
		s.umem.freeFrame(frameBase)
		return fmt.Errorf("xsk: tx ring full")
	}

	desc := s.tx.GetDesc(idx)
	desc.Addr = addr
	desc.Len = uint32(len(frame))
	s.tx.Submit(1)
	s.txStanding++

	if s.tx.NeedWakeup() {
		if err := unix.Sendto(s.sockfd, nil, unix.MSG_DONTWAIT, nil); err != nil {
			if !isExpectedErrno(err) {
				return fmt.Errorf("xsk: sendto: %w", err)
			}
		}
	}

	return nil
}

// Close completes pending TX, unmaps all rings and UMEM, and closes the socket.
func (s *Socket) Close() error {
	s.completeAll()
	unix.Munmap(s.rx.raw().mem)
	unix.Munmap(s.tx.raw().mem)
	s.umem.close()
	return unix.Close(s.sockfd)
}

func (s *Socket) receiveFrameBorrowed() ([]byte, bool, error) {
	var rxIdx uint32
	rcvd := s.rx.Peek(1, &rxIdx)
	if rcvd == 0 {
		return nil, false, nil
	}

	desc := s.rx.GetDesc(rxIdx)
	addr, length, err := s.rxFrameData(desc.Addr, desc.Len)
	frameBase := frameBaseAddr(desc.Addr, s.opts.FrameSize)
	if err != nil {
		s.umem.freeFrame(frameBase)
		s.rx.Release(rcvd)
		s.refillFill()
		return nil, true, err
	}

	s.rxBorrowed = true
	s.rxFrame = frameBase
	return s.umem.frameData(addr, length), true, nil
}

func (s *Socket) rxFrameData(addr uint64, length uint32) (uint64, uint32, error) {
	frameBase := frameBaseAddr(addr, s.opts.FrameSize)
	frameOffset := addr - frameBase
	if frameOffset < xskMetadataHeadroom {
		return 0, 0, fmt.Errorf("xsk: rx addr %d smaller than headroom %d", addr, xskMetadataHeadroom)
	}

	maxPayloadSize := s.opts.FrameSize - uint32(xskMetadataHeadroom)
	if length > maxPayloadSize {
		return 0, 0, fmt.Errorf("xsk: rx len %d exceeds payload size %d", length, maxPayloadSize)
	}

	return addr - xskMetadataHeadroom, length + uint32(xskMetadataHeadroom), nil
}

func (s *Socket) refillFill() {
	toFill := s.umem.fill.GetFreeNum(s.umem.frameFreeCount())
	if toFill == 0 {
		return
	}

	var idx uint32
	if s.umem.fill.Reserve(toFill, &idx) < toFill {
		return
	}

	for i := uint32(0); i < toFill; i++ {
		*s.umem.fill.GetAddr(idx + i) = s.umem.allocFrame()
	}
	s.umem.fill.Submit(toFill)
}

func (s *Socket) drainCompletions() {
	if s.txStanding == 0 {
		return
	}

	if s.tx.NeedWakeup() {
		_ = unix.Sendto(s.sockfd, nil, unix.MSG_DONTWAIT, nil)
	}

	var idx uint32
	completed := s.umem.comp.Peek(s.txStanding, &idx)
	if completed == 0 {
		return
	}

	for i := uint32(0); i < completed; i++ {
		s.umem.freeFrame(frameBaseAddr(*s.umem.comp.GetAddr(idx+i), s.opts.FrameSize))
	}
	s.umem.comp.Release(completed)
	s.txStanding -= completed
}

func (s *Socket) completeAll() {
	retries := max(s.txStanding/64, 1)
	for s.txStanding != 0 && retries > 0 {
		s.drainCompletions()
		time.Sleep(10 * time.Millisecond)
		retries--
	}
}

func (s *Socket) allocTXFrame() uint64 {
	// Try draining completions first if no free frames.
	frame := s.umem.allocFrame()
	if frame == invalidUMEMFrame {
		s.drainCompletions()
		frame = s.umem.allocFrame()
	}
	return frame
}

func isExpectedErrno(err error) bool {
	if errno, ok := err.(unix.Errno); ok {
		return errno == unix.ENOBUFS || errno == unix.EAGAIN ||
			errno == unix.EBUSY || errno == unix.ENETDOWN
	}
	return false
}

// newUMEM creates a UMEM, registers it with the socket, mmaps the fill and
// completion rings, and pre-fills the fill ring with all available frames.
func newUMEM(sockfd int, opts Options) (*umem, error) {
	area, err := unix.Mmap(-1, 0, int(opts.umemSize()),
		unix.PROT_READ|unix.PROT_WRITE,
		int(unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE))
	if err != nil {
		return nil, fmt.Errorf("xsk: mmap umem: %w", err)
	}

	if err := registerUMem(sockfd, area, opts); err != nil {
		unix.Munmap(area)
		return nil, fmt.Errorf("xsk: register umem: %w", err)
	}

	if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING, int(opts.FillRingSize)); err != nil {
		unix.Munmap(area)
		return nil, fmt.Errorf("xsk: setsockopt XDP_UMEM_FILL_RING: %w", err)
	}
	if err := unix.SetsockoptInt(sockfd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING, int(opts.CompletionRingSize)); err != nil {
		unix.Munmap(area)
		return nil, fmt.Errorf("xsk: setsockopt XDP_UMEM_COMPLETION_RING: %w", err)
	}

	off, err := loadOffsets(sockfd)
	if err != nil {
		unix.Munmap(area)
		return nil, err
	}

	// mmap fill ring.
	fillMem, err := unix.Mmap(sockfd, unix.XDP_UMEM_PGOFF_FILL_RING,
		ringMmapSize(off.Fr, opts.FillRingSize, sizeofUint64),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		unix.Munmap(area)
		return nil, fmt.Errorf("xsk: mmap fill ring: %w", err)
	}

	var fill fillQueue
	initQueueByOffset(fill.raw(), fillMem, &off.Fr, opts.FillRingSize)
	fill.mask = opts.FillRingSize - 1
	fill.size = opts.FillRingSize
	fill.cachedCons = opts.FillRingSize

	// mmap completion ring.
	compMem, err := unix.Mmap(sockfd, unix.XDP_UMEM_PGOFF_COMPLETION_RING,
		ringMmapSize(off.Cr, opts.CompletionRingSize, sizeofUint64),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		unix.Munmap(area)
		unix.Munmap(fillMem)
		return nil, fmt.Errorf("xsk: mmap completion ring: %w", err)
	}

	var comp completionQueue
	initQueueByOffset(comp.raw(), compMem, &off.Cr, opts.CompletionRingSize)
	comp.mask = opts.CompletionRingSize - 1
	comp.size = opts.CompletionRingSize

	// Build free frame stack.
	frameAddrs := make([]uint64, opts.FrameCount)
	for i := range opts.FrameCount {
		frameAddrs[i] = uint64(i * opts.FrameSize)
	}

	u := &umem{
		mem:          area,
		frameAddrs:   frameAddrs,
		frameFreeNum: opts.FrameCount,
		fill:         fill,
		comp:         comp,
	}

	// Pre-fill the fill ring with all available frames.
	var idx uint32
	u.fill.Reserve(opts.FillRingSize, &idx)
	for i := range opts.FillRingSize {
		*u.fill.GetAddr(idx + i) = u.allocFrame()
	}
	u.fill.Submit(opts.FillRingSize)

	return u, nil
}

// registerUMem registers a UMEM region with the AF_XDP socket via setsockopt.
func registerUMem(sockfd int, area []byte, opts Options) error {
	reg := unix.XDPUmemReg{
		Addr:     uint64(uintptr(unsafe.Pointer(unsafe.SliceData(area)))),
		Len:      uint64(len(area)),
		Size:     opts.FrameSize,
		Headroom: xskMetadataHeadroom,
		Flags:    0,
	}
	return setsockopt(sockfd, unix.SOL_XDP, unix.XDP_UMEM_REG, unsafe.Pointer(&reg), unsafe.Sizeof(reg))
}

func (u *umem) allocFrame() uint64 {
	if u.frameFreeNum == 0 {
		return invalidUMEMFrame
	}
	u.frameFreeNum--
	addr := u.frameAddrs[u.frameFreeNum]
	u.frameAddrs[u.frameFreeNum] = invalidUMEMFrame
	return addr
}

func (u *umem) freeFrame(addr uint64) {
	u.frameAddrs[u.frameFreeNum] = addr
	u.frameFreeNum++
}

func (u *umem) frameData(addr uint64, length uint32) []byte {
	return u.mem[addr : addr+uint64(length)]
}

func (u *umem) frameFreeCount() uint32 {
	return u.frameFreeNum
}

func (u *umem) close() {
	unix.Munmap(u.mem)
	unix.Munmap(u.fill.raw().mem)
	unix.Munmap(u.comp.raw().mem)
}
