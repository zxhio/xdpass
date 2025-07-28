package api

import (
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/zxhio/xdpass/internal/errcode"
	"github.com/zxhio/xdpass/internal/model"
	"github.com/zxhio/xdpass/internal/service"
	"github.com/zxhio/xdpass/pkg/netaddr"
)

type QueryIPResp QueryPageResp[AttachmentIP]

type AddIPReq struct {
	Attachments []AttachmentIP `json:"attachments" binding:"required"`
}

type AttachmentIP struct {
	Name    string        `json:"name" binding:"required"`
	Actions []XDPActionIP `json:"actions" binding:"required"`
}

type XDPActionIP struct {
	Action model.XDPAction      `json:"action" binding:"required,oneof=pass redirect"`
	IPs    []netaddr.IPv4Prefix `json:"ips" binding:"required,min=1"`
}

type AddIPResp struct{}

type DeleteIPReq struct {
	AttachmentName string             `json:"attachment_name" binding:"required"`
	Action         model.XDPAction    `json:"action" binding:"required"`
	IP             netaddr.IPv4Prefix `json:"ip" binding:"required"`
}

type DeleteIPResp struct{}

type IPHandler struct {
	service *service.AttachmentService
}

func (h *IPHandler) QueryIP(c *gin.Context) {
	p := NewPageFromRequest(c.Request)
	attachmentID := c.Request.URL.Query().Get("attachment-name")
	action := model.XDPAction(c.Request.URL.Query().Get("action"))

	ips, total, err := h.service.QueryIP(attachmentID, action, p.Page, p.Limit)
	if err != nil {
		Error(c, err)
		return
	}

	resp := QueryIPResp{
		QueryPage: QueryPage{
			Page:  p.Page,
			Limit: p.Limit,
			Total: total,
		},
	}

	for _, ip := range ips {
		attachmentIdx := slices.IndexFunc(resp.Data, func(a AttachmentIP) bool { return a.Name == ip.AttachmentName })
		if attachmentIdx == -1 {
			resp.Data = append(resp.Data, AttachmentIP{Name: ip.AttachmentName})
			attachmentIdx = len(resp.Data) - 1
		}
		actionIdx := slices.IndexFunc(resp.Data[attachmentIdx].Actions, func(a XDPActionIP) bool { return a.Action == ip.Action })
		if actionIdx == -1 {
			resp.Data[attachmentIdx].Actions = append(resp.Data[attachmentIdx].Actions, XDPActionIP{
				Action: ip.Action,
			})
			actionIdx = len(resp.Data[attachmentIdx].Actions) - 1
		}
		resp.Data[attachmentIdx].Actions[actionIdx].IPs = append(resp.Data[attachmentIdx].Actions[actionIdx].IPs, ip.IP)
	}
	Success(c, resp)
}

func (h *IPHandler) AddIP(c *gin.Context) {
	var req AddIPReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, errcode.NewError(errcode.CodeInvalid, err))
		return
	}

	ips := []*model.IP{}
	for _, attachment := range req.Attachments {
		for _, action := range attachment.Actions {
			for _, ip := range action.IPs {
				ips = append(ips, &model.IP{
					AttachmentName: attachment.Name,
					Action:         action.Action,
					IP:             ip,
				})
			}
		}
	}

	if err := h.service.AddIP(ips); err != nil {
		Error(c, err)
		return
	}
	Success(c, AddIPResp{})
}

func (h *IPHandler) DeleteIP(c *gin.Context) {
	var req DeleteIPReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, errcode.NewError(errcode.CodeInvalid, err))
		return
	}

	ip := model.IP{
		AttachmentName: req.AttachmentName,
		Action:         req.Action,
		IP:             req.IP,
	}

	if err := h.service.DeleteIP(&ip); err != nil {
		Error(c, err)
		return
	}
	Success(c, DeleteIPResp{})
}
