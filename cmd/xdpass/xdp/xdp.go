package xdp

import (
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/cmd/xdpass/xdp/attachment"
	"github.com/zxhio/xdpass/cmd/xdpass/xdp/ip"
)

var xdpCmd = &cobra.Command{
	Use:   "xdp",
	Short: "Manage XDP program",
}

func Export(parent *cobra.Command) {
	attachment.Export(xdpCmd)
	ip.Export(xdpCmd)
	parent.AddCommand(xdpCmd)
}
