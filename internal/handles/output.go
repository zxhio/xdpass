package handles

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
)

type LogHandler struct{}

func (*LogHandler) ProcessData(data []byte) {
	logrus.Debugf("Rx frame layers\n%+v", gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default))
}
