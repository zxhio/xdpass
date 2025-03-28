package redirectcmd

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"

	"github.com/olekukonko/tablewriter"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/zxhio/xdpass/internal/commands"
	"github.com/zxhio/xdpass/internal/exports"
	"github.com/zxhio/xdpass/internal/protos"
	"github.com/zxhio/xdpass/internal/redirect/spoof"
	"github.com/zxhio/xdpass/pkg/inet"
)

// IPv4LPM  IPv4

func init() {
	commands.SetFlagsInterface(spoofCmd.Flags(), &spoofOpt.Interface)
	commands.SetFlagsList(spoofCmd.Flags(), &spoofOpt.ShowList, "Show spoof rule list")
	spoofCmd.Flags().BoolVar(&spoofOpt.ShowTypes, "list-target", false, "Show supported spoof target type list")
	spoofCmd.Flags().BoolVarP(&spoofOpt.Add, "add", "A", false, "Add spoof rule")
	spoofCmd.Flags().BoolVarP(&spoofOpt.Del, "del", "D", false, "Delete spoof rule")
	spoofCmd.Flags().Var(&spoofOpt.SrcMAC, "smac", "Source mac address")
	spoofCmd.Flags().Var(&spoofOpt.DstMAC, "dmac", "Destination mac address")
	spoofCmd.Flags().VarP(&spoofOpt.Source, "source", "s", "Source ip address")
	spoofCmd.Flags().VarP(&spoofOpt.Dest, "destination", "d", "Destination ip address")
	spoofCmd.Flags().Var(&spoofOpt.IPRangeSrc, "iprange-src", "Source iprange address, IP1-IP2")
	spoofCmd.Flags().Var(&spoofOpt.IPRangeDst, "iprange-dst", "Destination iprange address, IP1-IP2")
	spoofCmd.Flags().Var(&spoofOpt.SPort, "sport", "Source port, PORT1[:PORT2]")
	spoofCmd.Flags().Var(&spoofOpt.DPort, "dport", "Destination port, PORT1[:PORT2]")
	spoofCmd.Flags().Var(&spoofOpt.SPorts, "sports", "Source multiport, PORT1[,PORT2...]")
	spoofCmd.Flags().Var(&spoofOpt.DPorts, "dports", "Destination multiport, PORT1[,PORT2...]")
	spoofCmd.Flags().Var(&spoofOpt.TargetType, "target", "")

	commands.Register(spoofCmd)
	redirectCmd.AddCommand(spoofCmd)

	registerHandle(SpoofCommandHandle{})
}

var spoofOpt SpoofOpt

type SpoofOpt struct {
	Interface  string
	ShowList   bool
	ShowTypes  bool
	Add        bool
	Del        bool
	SrcMAC     inet.HwAddr
	DstMAC     inet.HwAddr
	Source     inet.LPMIPv4
	Dest       inet.LPMIPv4
	IPRangeSrc spoof.IPRangeV4
	IPRangeDst spoof.IPRangeV4
	SPort      spoof.PortRange
	DPort      spoof.PortRange
	SPorts     spoof.MultiPort
	DPorts     spoof.MultiPort
	TargetType spoof.TargetType
}

var spoofCmd = &cobra.Command{
	Use:     protos.RedirectTypeSpoof.String(),
	Short:   "Traffic spoof based on rules",
	Aliases: []string{"redirect spoof"},
	RunE: func(cmd *cobra.Command, args []string) error {
		commands.SetVerbose()
		var s SpoofCommandClient
		return s.DoReq(&spoofOpt)
	},
}

type spoofBaseReq struct {
	Operation commands.Operation `json:"operation"`
	Interface string             `json:"interface,omitempty"`
}

type spoofShowListReq struct {
	spoofBaseReq
}

type spoofShowListResp struct {
	Interfaces []spoofShowListIface `json:"interfaces"`
}

type spoofListTargetTypeReq struct {
	spoofBaseReq
}

type spoofListTargetTypeResp struct {
	Targets []spoofListTargetMatch `json:"targets"`
}

type spoofListTargetMatch struct {
	TargetType spoof.TargetType  `json:"target_type"`
	MatchTypes []spoof.MatchType `json:"match_types"`
}

type spoofShowListIface struct {
	Interface string       `json:"interface,omitempty"`
	Rules     []spoof.Rule `json:"rules"`
}

type spoofEditRuleReq struct {
	spoofBaseReq
	Rule spoof.Rule `json:"rule"`
}

type spoofEditRuleResp struct{}

type SpoofCommandClient struct{}

func (s *SpoofCommandClient) DoReq(opt *SpoofOpt) error {
	if opt.ShowList {
		return s.DoReqShowList(opt.Interface)
	}

	if opt.ShowTypes {
		return s.DoReqShowTargets()
	}

	if opt.Add {
		return s.DoReqEditRule(commands.OperationAdd, opt)
	}

	if opt.Del {
		return s.DoReqEditRule(commands.OperationDel, opt)
	}
	return nil
}

func (SpoofCommandClient) DoReqShowList(ifaceName string) error {
	req := spoofShowListReq{spoofBaseReq{Operation: commands.OperationList, Interface: ifaceName}}
	resp, err := doRequest[spoofShowListReq, spoofShowListResp](protos.RedirectTypeSpoof, &req)
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Interface", "ID", "Source", "Destination", "SPort", "DPort", "Target", "Data"})
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	table.SetAutoMergeCellsByColumnIndex([]int{0})
	for _, iface := range resp.Interfaces {
		sort.Sort(spoof.RuleSlice(iface.Rules))
		for _, rule := range iface.Rules {
			var (
				source string
				dest   string
				sport  string
				dport  string
			)

			for _, match := range rule.Matchs {
				if !slices.Contains(rule.Target.MatchTypes(), match.MatchType()) {
					continue
				}

				switch match.MatchType() {
				case spoof.MatchTypeLPMIPv4Src:
					valueIfEmpty(&source, inet.LPMIPv4(match.(spoof.MatchLPMIPv4Src)).String())
				case spoof.MatchTypeLPMIPv4Dst:
					valueIfEmpty(&dest, inet.LPMIPv4(match.(spoof.MatchLPMIPv4Dst)).String())
				case spoof.MatchTypeIPRangeV4Src:
					valueIfEmpty(&source, spoof.IPRangeV4(match.(spoof.MatchIPRangeV4Src)).String())
				case spoof.MatchTypeIPRangeV4Dst:
					valueIfEmpty(&dest, spoof.IPRangeV4(match.(spoof.MatchIPRangeV4Dst)).String())
				case spoof.MatchTypeMultiPortSrc:
					valueIfEmpty(&sport, spoof.MultiPort(match.(spoof.MatchMultiPortSrc)).String())
				case spoof.MatchTypeMultiPortDst:
					valueIfEmpty(&dport, spoof.MultiPort(match.(spoof.MatchMultiPortDst)).String())
				case spoof.MatchTypePortRangeSrc:
					valueIfEmpty(&sport, spoof.PortRange(match.(spoof.MatchPortRangeSrc)).String())
				case spoof.MatchTypePortRangeDst:
					valueIfEmpty(&dport, spoof.PortRange(match.(spoof.MatchPortRangeDst)).String())
				case spoof.MatchTypeTCP, spoof.MatchTypeUDP, spoof.MatchTypeICMP, spoof.MatchTypeHTTP:
					//
				}
			}
			tgtData, err := json.Marshal(rule.Target)
			if err != nil {
				return err
			}

			table.Append([]string{
				iface.Interface, fmt.Sprintf("%d", rule.ID),
				source, dest, sport, dport, rule.Target.TargetType().String(), string(tgtData),
			})
		}
	}
	table.Render()

	return nil
}

const operationListTarget = commands.OperationCustom + 1

func (SpoofCommandClient) DoReqShowTargets() error {
	req := spoofListTargetTypeReq{spoofBaseReq{Operation: operationListTarget}}
	resp, err := doRequest[spoofListTargetTypeReq, spoofListTargetTypeResp](protos.RedirectTypeSpoof, &req)
	if err != nil {
		return err
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"TargetType", "MatchType"})
	table.SetAlignment(tablewriter.ALIGN_CENTER)
	table.SetAutoMergeCellsByColumnIndex([]int{0})
	for _, tgt := range resp.Targets {
		for _, matchType := range tgt.MatchTypes {
			table.Append([]string{tgt.TargetType.String(), matchType.String()})
		}
	}
	table.Render()

	return nil
}

func (SpoofCommandClient) DoReqEditRule(op commands.Operation, opt *SpoofOpt) error {
	var matchs []spoof.Match
	if !opt.Source.Equal(inet.LPMIPv4{}) {
		matchs = append(matchs, spoof.MatchLPMIPv4Src(opt.Source))
	}
	if !opt.Dest.Equal(inet.LPMIPv4{}) {
		matchs = append(matchs, spoof.MatchLPMIPv4Dst(opt.Dest))
	}
	if !opt.IPRangeSrc.Equal(spoof.IPRangeV4{}) {
		matchs = append(matchs, spoof.MatchIPRangeV4Src(opt.IPRangeSrc))
	}
	if !opt.IPRangeDst.Equal(spoof.IPRangeV4{}) {
		matchs = append(matchs, spoof.MatchIPRangeV4Dst(opt.IPRangeDst))
	}
	if !opt.SPorts.Equal(spoof.MultiPort{}) {
		matchs = append(matchs, spoof.MatchMultiPortSrc(opt.SPorts))
	}
	if !opt.DPorts.Equal(spoof.MultiPort{}) {
		matchs = append(matchs, spoof.MatchMultiPortDst(opt.DPorts))
	}
	if !opt.SPort.Equal(spoof.PortRange{}) {
		matchs = append(matchs, spoof.MatchPortRangeSrc(opt.SPort))
	}
	if !opt.DPort.Equal(spoof.PortRange{}) {
		matchs = append(matchs, spoof.MatchPortRangeDst(opt.DPort))
	}

	var target spoof.Target
	switch opt.TargetType {
	case spoof.TargetTypeARPReply:
		target = spoof.TargetARPReply{HwAddr: opt.SrcMAC}
		matchs = append(matchs, spoof.MatchARP{Operation: spoof.ARPOperationRequest})
	case spoof.TargetTypeTCPReset:
		target = spoof.TargetTCPReset{}
		matchs = append(matchs, spoof.MatchTCP{})
	case spoof.TargetTypeICMPEchoReply:
		target = spoof.TargetICMPEchoReply{}
		matchs = append(matchs, spoof.MatchICMP{Type: spoof.ICMPv4TypeEchoRequest})
	default:
		return fmt.Errorf("invalid target type: %d", opt.TargetType)
	}

	req := spoofEditRuleReq{
		spoofBaseReq: spoofBaseReq{Operation: op, Interface: opt.Interface},
		Rule:         spoof.Rule{Matchs: matchs, Target: target},
	}
	_, err := doRequest[spoofEditRuleReq, spoofEditRuleResp](protos.RedirectTypeSpoof, &req)
	return err
}

type SpoofCommandHandle struct{}

func (SpoofCommandHandle) RedirectType() protos.RedirectType {
	return protos.RedirectTypeSpoof
}

func (s SpoofCommandHandle) HandleReqData(client *commands.MessageClient, data []byte) error {
	var req spoofBaseReq
	err := json.Unmarshal(data, &req)
	if err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}

	switch req.Operation {
	case commands.OperationNop:
		data, err = []byte("{}"), nil
	case commands.OperationList:
		data, err = s.handleOpList(req.Interface)
	case commands.OperationAdd, commands.OperationDel:
		data, err = s.handleReqEdit(data)
	case operationListTarget:
		data, err = s.handleOpListTargets()
	}
	if err != nil {
		return commands.ResponseErrorCode(client, err, protos.ErrorCode_InvalidRequest)
	}
	return response(client, data)
}

func (s SpoofCommandHandle) getAPIs(ifaceName string) (map[string]exports.RedirectSpoofAPI, error) {
	var apis map[string]exports.RedirectSpoofAPI
	if ifaceName != "" {
		api, ok := exports.GetSpoofAPI(ifaceName)
		if !ok {
			return nil, fmt.Errorf("interface %s not found", ifaceName)
		}
		apis = map[string]exports.RedirectSpoofAPI{ifaceName: api}
	} else {
		apis = exports.GetAllSpoofAPIs()
	}
	return apis, nil
}

func (s SpoofCommandHandle) handleOpList(ifaceName string) ([]byte, error) {
	apis, err := s.getAPIs(ifaceName)
	if err != nil {
		return nil, err
	}

	resp := spoofShowListResp{Interfaces: make([]spoofShowListIface, 0, len(apis))}
	for name, api := range apis {
		resp.Interfaces = append(resp.Interfaces, spoofShowListIface{
			Interface: name,
			Rules:     api.GetSpoofRules(),
		})
	}
	return json.Marshal(resp)
}

func (s SpoofCommandHandle) handleOpListTargets() ([]byte, error) {
	supportedTargets := []spoof.Target{
		spoof.TargetARPReply{},
		spoof.TargetICMPEchoReply{},
		spoof.TargetTCPReset{},
	}

	targets := []spoofListTargetMatch{}
	for _, tgt := range supportedTargets {
		targets = append(targets, spoofListTargetMatch{TargetType: tgt.TargetType(), MatchTypes: tgt.MatchTypes()})
	}
	resp := spoofListTargetTypeResp{Targets: targets}
	return json.Marshal(resp)
}

func (s SpoofCommandHandle) handleReqEdit(data []byte) ([]byte, error) {
	var req spoofEditRuleReq
	err := json.Unmarshal(data, &req)
	if err != nil {
		return nil, err
	}

	apis, err := s.getAPIs(req.Interface)
	if err != nil {
		return nil, err
	}

	for ifaceName, api := range apis {
		logrus.WithFields(logrus.Fields{"interface": ifaceName, "op": req.Operation, "rule": req.Rule.String()}).Debug("Edit spoof rule")
		switch req.Operation {
		case commands.OperationAdd:
			err = api.AddSpoofRule(req.Rule)
		case commands.OperationDel:
			err = api.DelSpoofRule(req.Rule)
		default:
			err = fmt.Errorf("invalid operation: %d", req.Operation)
		}
		if err != nil {
			return nil, err
		}
	}
	return []byte("{}"), nil
}

func valueIfEmpty[T comparable](v *T, newValue T) {
	var empty T
	if *v == empty {
		*v = newValue
	}
}
