package main

import (
	"net"
	"syscall"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type rawSockTxBench struct {
	fd   int
	addr unix.SockaddrLinklayer
}

func newRawSockTxBench(ifaceName string) (*rawSockTxBench, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, errors.Wrap(err, "net.InterfaceByName")
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, unix.ETH_P_ALL)
	if err != nil {
		return nil, errors.Wrap(err, "unix.Socket")
	}
	logrus.WithField("fd", fd).Info("New raw socket")

	return &rawSockTxBench{
		fd: fd,
		addr: unix.SockaddrLinklayer{
			Protocol: uint16(syscall.ETH_P_ALL),
			Ifindex:  iface.Index,
			Hatype:   1, // ARPHRD_ETHER
			Pkttype:  syscall.PACKET_OUTGOING,
		},
	}, nil
}

func (r *rawSockTxBench) runBatch(b *txBenchmarkData) {
	for i := uint32(0); i < b.batchSize; i++ {
		err := unix.Sendto(r.fd, b.data, 0, &r.addr)
		if err != nil {
			b.stat.IOFailCount++
		} else {
			b.stat.Packets++
			b.stat.Bytes += uint64(b.batchSize)
		}
		b.stat.IOCount++
	}
}

func (r *rawSockTxBench) wait(b *txBenchmarkData) {}
