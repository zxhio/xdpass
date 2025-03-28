package fwcmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/exports"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/pkg/inet"
)

func init() {
	commands.SetFlagsInterface(fwCmd.Flags(), &opt.Interface)
	commands.SetFlagsList(fwCmd.Flags(), &opt.ShowList, "List lpm ipv4")
	commands.SetFlagsAdd(fwCmd.Flags(), &opt.Add, "Add lpm ipv4")
	commands.SetFlagsDel(fwCmd.Flags(), &opt.Del, "Del lpm ipv4")
	fwCmd.Flags().Var(&opt.IPKey, "ip", "LPM IPv4")

	commands.Register(fwCmd)
}

var fwCmd = &cobra.Command{
	Use:     protos.TypeFirewall.String(),
	Short:   "Manage network traffic firewall",
	Aliases: []string{"fw"},
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()
		return FirewallCommand{}.DoReq(&opt)
	},
}

type FirwallOpt struct {
	Interface string
	ShowList  bool
	Add       bool
	Del       bool
	IPKey     inet.LPMIPv4
}

var opt FirwallOpt

type firewallReq struct {
	Operation   commands.Operation `json:"operation"`
	Interface   string             `json:"interface,omitempty"`
	LPMIPv4List []inet.LPMIPv4     `json:"lpm_ipv4_list,omitempty"`
}

type firewallResp struct {
	Interfaces []firewallLPMIPv4List `json:"interfaces,omitempty"`
}

type firewallLPMIPv4List struct {
	Interface   string         `json:"interface,omitempty"`
	LPMIPv4List []inet.LPMIPv4 `json:"lpm_ipv4_list,omitempty"`
}

type FirewallCommand struct{}

func (f FirewallCommand) DoReq(opt *FirwallOpt) error {
	if opt.ShowList {
		return f.DoReqListIPKey(opt.Interface)
	} else if opt.Add {
		return f.DoReqEditIPKey(commands.OperationAdd, opt.Interface, opt.IPKey)
	} else if opt.Del {
		return f.DoReqEditIPKey(commands.OperationDel, opt.Interface, opt.IPKey)
	} else {
		return fmt.Errorf("no operation specified")
	}
}

func (FirewallCommand) DoReqListIPKey(ifaceName string) error {
	req := firewallReq{Operation: commands.OperationList, Interface: ifaceName}
	resp, err := commands.GetMessage[firewallReq, firewallResp](protos.TypeFirewall, "", &req)
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Interface", "IP"})
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	table.SetAutoMergeCells(true)

	for _, fw := range resp.Interfaces {
		for _, lpm := range fw.LPMIPv4List {
			table.Append([]string{fw.Interface, lpm.String()})
		}
	}
	table.Render()

	return nil
}

func (FirewallCommand) DoReqEditIPKey(op commands.Operation, iface string, lpmIPv4 inet.LPMIPv4) error {
	if lpmIPv4.Equal(inet.LPMIPv4{}) {
		return fmt.Errorf("no non-nil ip specified")
	}
	req := firewallReq{Operation: op, Interface: iface, LPMIPv4List: []inet.LPMIPv4{lpmIPv4}}
	_, err := commands.GetMessage[firewallReq, firewallResp](protos.TypeFirewall, "", &req)
	return err
}

type FirewallCommandHandle struct{}

func (FirewallCommandHandle) CommandType() protos.Type {
	return protos.TypeFirewall
}

func (f FirewallCommandHandle) HandleReqData(client *commands.MessageClient, data []byte) error {
	var req firewallReq
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}

	var err error
	switch req.Operation {
	case commands.OperationNop:
		data, err = []byte("{}"), nil
	case commands.OperationList:
		data, err = f.handleOpShowList(req.Interface)
	case commands.OperationAdd:
		data, err = f.handleOpAddDel(req, commands.OperationAdd, func(api exports.FirewallAPI, lpm inet.LPMIPv4) error {
			return api.AddIPKey(lpm)
		})
	case commands.OperationDel:
		data, err = f.handleOpAddDel(req, commands.OperationDel, func(api exports.FirewallAPI, lpm inet.LPMIPv4) error {
			return api.DelIPKey(lpm)
		})
	}
	if err != nil {
		return commands.ResponseError(client, err)
	}
	return commands.Response(client, &commands.MessageResp{Data: data})
}

func (f FirewallCommandHandle) getAPIs(ifaceName string) (map[string]exports.FirewallAPI, error) {
	var apis map[string]exports.FirewallAPI
	if ifaceName != "" {
		api, ok := exports.GetFirewallAPI(ifaceName)
		if !ok {
			return nil, fmt.Errorf("interface %s not found", ifaceName)
		}
		apis = map[string]exports.FirewallAPI{ifaceName: api}
	} else {
		apis = exports.GetFirewallAPIs()
	}
	return apis, nil
}

func (f FirewallCommandHandle) handleOpShowList(ifaceName string) ([]byte, error) {
	apis, err := f.getAPIs(ifaceName)
	if err != nil {
		return nil, err
	}

	resp := firewallResp{}
	for name, api := range apis {
		lpms, err := api.ListIPKey()
		if err != nil {
			return nil, err
		}
		resp.Interfaces = append(resp.Interfaces, firewallLPMIPv4List{
			Interface:   name,
			LPMIPv4List: lpms,
		})
	}
	return json.Marshal(resp)
}

func (f FirewallCommandHandle) handleOpAddDel(req firewallReq, op commands.Operation, fn func(exports.FirewallAPI, inet.LPMIPv4) error) ([]byte, error) {
	apis, err := f.getAPIs(req.Interface)
	if err != nil {
		return nil, err
	}

	for _, api := range apis {
		for _, lpm := range req.LPMIPv4List {
			logrus.WithFields(logrus.Fields{"lpm": lpm, "iface": req.Interface, "op": op}).Debug("Operate lpm ipv4")
			err := fn(api, lpm)
			if err != nil {
				return nil, err
			}
		}
	}
	return []byte("{}"), nil
}
