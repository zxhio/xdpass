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
	"github.com/zxhio/xdpass/pkg/xdp"
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

type TxData struct {
	Batch   uint32
	Queues  []uint32
	XDPOpts []xdp.XDPOpt
	Data    []byte
}

type Tx interface {
	Fd() int
	QueueID() int
	Transmit(*TxData)
	Close() error
	Stats() netutil.Statistics
}

func NewTxList(ifaceName string, td *TxData) ([]Tx, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, errors.Wrap(err, "net.InterfaceByName")
	}

	var txList []Tx
	if hasXDP() {
		if len(td.Queues) == 0 {
			queues, err := netutil.GetTxQueues(ifaceName)
			if err != nil {
				return nil, err
			}
			for _, q := range queues {
				td.Queues = append(td.Queues, uint32(q))
			}
		}

		for _, queueID := range td.Queues {
			tx, err := newXDPTx(uint32(iface.Index), queueID)
			if err != nil {
				return nil, err
			}
			txList = append(txList, tx)
			utils.VerbosePrintln("New AF_XDP socket %d for tx queue %d", tx.SocketFD(), queueID)
		}
	} else {
		tx, err := newAFPTx(iface.Index)
		if err != nil {
			return nil, err
		}
		txList = append(txList, tx)
		utils.VerbosePrintln("New AF_PACKET socket %d", tx.fd)
	}

	return txList, nil
}

type afXDPTx struct{}

type afpTx struct {
	fd   int
	addr unix.SockaddrLinklayer
	stat netutil.Statistics
}

func newAFPTx(ifaceIdx int) (*afpTx, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, unix.ETH_P_ALL)
	if err != nil {
		return nil, errors.Wrap(err, "unix.Socket")
	}
	return &afpTx{
		fd: fd,
		addr: unix.SockaddrLinklayer{
			Protocol: uint16(syscall.ETH_P_ALL),
			Ifindex:  ifaceIdx,
			Hatype:   1, // ARPHRD_ETHER
			Pkttype:  syscall.PACKET_OUTGOING,
		},
	}, nil
}

func (p *afpTx) Fd() int { return p.fd }

func (p *afpTx) QueueID() int { return -1 }

func (p *afpTx) Transmit(td *TxData) {
	for i := uint32(0); i < td.Batch; i++ {
		err := unix.Sendto(p.fd, td.Data, 0, &p.addr)
		if err != nil {
			p.stat.TxErrors++
		} else {
			p.stat.TxBytes += uint64(len(td.Data))
			p.stat.TxPackets++
		}
		p.stat.TxIOs++
	}
}

func (p *afpTx) Stats() netutil.Statistics {
	p.stat.Timestamp = time.Now()
	return p.stat
}

func (p *afpTx) Close() error {
	return unix.Close(p.fd)
}

type xdpTx struct {
	*xdp.XDPSocket
	dataVec [][]byte
}

func newXDPTx(ifaceIdx, queueID uint32, opts ...xdp.XDPOpt) (*xdpTx, error) {
	s, err := xdp.NewXDPSocket(ifaceIdx, queueID, opts...)
	if err != nil {
		return nil, err
	}
	return &xdpTx{XDPSocket: s}, nil
}

func (x *xdpTx) Fd() int {
	return x.SocketFD()
}

func (x *xdpTx) QueueID() int {
	return int(x.XDPSocket.QueueID())
}

func (x *xdpTx) Transmit(td *TxData) {
	if len(x.dataVec) < int(td.Batch) {
		x.dataVec = make([][]byte, td.Batch)
		for i := uint32(0); i < td.Batch; i++ {
			x.dataVec[i] = make([]byte, len(td.Data))
			copy(x.dataVec[i], td.Data)
		}
	}

	remain := td.Batch
	for remain > 0 {
		n := x.Writev(x.dataVec[:min(td.Batch, remain)])
		remain -= n
	}
}

func (x *xdpTx) Close() error {
	return x.XDPSocket.Close()
}
