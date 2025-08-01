package service

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zxhio/xdpass/pkg/utils"
)

const irqData = `
127:          0          0     IR-PCI-MSI 524288-edge      enp1s0
128:          7          0    IR-PCI-MSI 524288-edge      enp1s0
129:          0    5214704    IR-PCI-MSI 524289-edge      enp1s0-rx-0
130:   10123973          0    IR-PCI-MSI 524290-edge      enp1s0-rx-1
131:          0   11679892    IR-PCI-MSI 524291-edge      enp1s0-tx-0
132:    5151333          0    IR-PCI-MSI 524292-edge      enp1s0-tx-1
35:          0        0       PCI-MSI 2621440-edge     enp2s0
36:   55627941        0       PCI-MSI 2621441-edge     enp2s0-TxRx-0
37:          0        0       PCI-MSI 2621442-edge     enp2s0-TxRx-1
38:          0        0       PCI-MSI 2621443-edge     enp2s0-TxRx-2
39:          0        0       PCI-MSI 2621444-edge     enp2s0-TxRx-3
40:          0        0       PCI-MSI 2621445-edge     enp2s0-TxRx-4
41:          0        0       PCI-MSI 2621446-edge     enp2s0-TxRx-5
42:          0        0       PCI-MSI 2621447-edge     enp2s0-TxRx-6
43:          0        0       PCI-MSI 2621448-edge     enp2s0-TxRx-7
`

func Test_getQueueIRQs(t *testing.T) {
	var testCases = []struct {
		linkName  string
		queues    []int
		queueIRQs []queueIRQ
	}{
		{"enp1s0", []int{0}, []queueIRQ{{0, 127, "TxRx"}}},
		{"enp1s0", []int{0, 1}, []queueIRQ{{0, 129, "rx"}, {0, 131, "tx"}, {1, 130, "rx"}, {1, 132, "tx"}}},
		{"enp2s0", []int{0, 1}, []queueIRQ{{0, 36, "TxRx"}, {1, 37, "TxRx"}}},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s_%s", tc.linkName, utils.SliceString(tc.queues)), func(t *testing.T) {
			res, err := getQueueIRQsFromData(irqData, tc.linkName, tc.queues)
			if !assert.NoError(t, err) {
				return
			}
			assert.Equal(t, tc.queueIRQs, res)
		})
	}
}

const ethtoolLData = `
Channel parameters for enp4s0:
Pre-set maximums:
RX:             n/a
TX:             n/a
Other:          1
Combined:       2
Current hardware settings:
RX:             n/a
TX:             n/a
Other:          1
Combined:       1
`

func Test_getMaxQueueNumByContent(t *testing.T) {
	combined, err := getMaxQueueNumByContent(ethtoolLData)
	if !assert.NoError(t, err) {
		return
	}
	assert.Equal(t, 2, combined)
}
