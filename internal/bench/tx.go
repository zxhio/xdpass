package bench

import (
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/zxhio/xdpass/pkg/netutil"
	"github.com/zxhio/xdpass/pkg/utils"
	"golang.org/x/sys/unix"
)

func hasXDP() bool {
	out, err := utils.RunCommand("uname", "-r")
	if err != nil {
		return false
	}

	confPath := path.Join("/boot", fmt.Sprintf("config-%s", strings.TrimSpace(string(out))))
	content, err := os.ReadFile(confPath)
	if err != nil {
		return false
	}
	return strings.Contains(string(content), "CONFIG_XDP_SOCKETS=y")
}

type Tx interface {
	Fd() int
	QueueID() int
	Transmit([]byte)
	Close() error
	Stats() netutil.Statistics
}

func NewTx(ifaceName string) (Tx, error) {
	return newAFPTx(ifaceName)
}

type afXDPTx struct{}

type afpTx struct {
	fd   int
	addr unix.SockaddrLinklayer
	stat netutil.Statistics
}

func newAFPTx(ifaceName string) (*afpTx, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, errors.Wrap(err, "net.InterfaceByName")
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, unix.ETH_P_ALL)
	if err != nil {
		return nil, errors.Wrap(err, "unix.Socket")
	}
	utils.VerbosePrintln("New AF_PACKET socket, fd: %d", fd)

	return &afpTx{
		fd: fd,
		addr: unix.SockaddrLinklayer{
			Protocol: uint16(syscall.ETH_P_ALL),
			Ifindex:  iface.Index,
			Hatype:   1, // ARPHRD_ETHER
			Pkttype:  syscall.PACKET_OUTGOING,
		},
	}, nil
}

func (p *afpTx) Fd() int { return p.fd }

func (p *afpTx) QueueID() int { return -1 }

func (p *afpTx) Transmit(data []byte) {
	err := unix.Sendto(p.fd, data, 0, &p.addr)
	if err != nil {
		p.stat.TxErrors++
	} else {
		p.stat.TxBytes += uint64(len(data))
		p.stat.TxPackets++
	}
	p.stat.TxIOs++
}

func (p *afpTx) Stats() netutil.Statistics {
	p.stat.Timestamp = time.Now()
	return p.stat
}

func (p *afpTx) Close() error {
	return unix.Close(p.fd)
}
