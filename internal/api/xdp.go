package api

import (
	"fmt"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/zxhio/xdpass/pkg/netaddr"
)

type XDPAction string

const (
	XDPActionPass     XDPAction = "pass"
	XDPActionRedirect XDPAction = "redirect"
)

type QueryIPsReq struct {
	Page
	Action XDPAction
}

type QueryIPsResp struct {
	Page
	IPs []IPAction `json:"ips"`
}

type IPAction struct {
	Action XDPAction          `json:"action"`
	IP     netaddr.IPv4Prefix `json:"ip"`
}

type AddIPReq struct {
	IP netaddr.IPv4Prefix `json:"ip"`
}

type AddIPResp IPAction

type DeleteIPResp IPAction

type XDPAPI interface {
	QueryIPs(*QueryIPsReq) (*QueryIPsResp, error)
	AddIP(ip netaddr.IPv4Prefix, action XDPAction) error
	DeleteIP(ip netaddr.IPv4Prefix, action XDPAction) error
}

type httpXDPWrapper struct {
	impl XDPAPI
}

func (w httpXDPWrapper) QueryIPs(c *gin.Context) {
	action := XDPAction(c.Param("action"))
	if action != XDPActionPass && action != XDPActionRedirect {
		SetResponseError(c, ErrorCodeInvalid, fmt.Errorf("unsupported action: %s", action))
		return
	}

	req := &QueryIPsReq{Page: NewPageFromRequest(c.Request), Action: action}
	resp, err := w.impl.QueryIPs(req)
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}
	SetResponseData(c, resp)
}

func (w httpXDPWrapper) AddIP(c *gin.Context) {
	action := XDPAction(c.Param("action"))
	if action != XDPActionPass && action != XDPActionRedirect {
		SetResponseError(c, ErrorCodeInvalid, fmt.Errorf("unsupported action: %s", action))
		return
	}

	var req AddIPReq
	if err := c.ShouldBindJSON(&req); err != nil {
		SetResponseError(c, ErrorCodeInvalid, errors.Wrap(err, "json.Unmarshal"))
		return
	}

	err := w.impl.AddIP(req.IP, action)
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}
	SetResponseData(c, AddIPResp{IP: req.IP, Action: action})
}

func (w httpXDPWrapper) DeleteIP(c *gin.Context) {
	action := XDPAction(c.Param("action"))
	if action != XDPActionPass && action != XDPActionRedirect {
		SetResponseError(c, ErrorCodeInvalid, fmt.Errorf("unsupported action: %s", action))
		return
	}

	ip, err := IPv4PrefixFromPath(c.Param("ip"))
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}

	err = w.impl.DeleteIP(ip, action)
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}
	SetResponseData(c, DeleteIPResp{IP: ip, Action: action})
}

func IPv4PrefixToPath(ip netaddr.IPv4Prefix) string {
	return strings.ReplaceAll(ip.String(), "/", "-")
}

func IPv4PrefixFromPath(s string) (netaddr.IPv4Prefix, error) {
	return netaddr.NewIPv4PrefixFromStr(strings.ReplaceAll(s, "-", "/"))
}
