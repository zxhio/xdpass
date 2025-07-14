package api

import (
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/zxhio/xdpass/internal/model"
	"github.com/zxhio/xdpass/internal/service"
	"github.com/zxhio/xdpass/pkg/netaddr"
)

type QueryIPResp QueryPageResp[AttachmentIP]

type AddIPReq struct {
	Attachments []AttachmentIP `json:"attachments" binding:"required"`
}

type AttachmentIP struct {
	ID      string        `json:"id"`
	Actions []XDPActionIP `json:"actions" binding:"required"`
}

type XDPActionIP struct {
	Action model.XDPAction      `json:"action" binding:"required,oneof=pass redirect"`
	IPs    []netaddr.IPv4Prefix `json:"ips" binding:"required,min=1"`
}

type AddIPResp struct{}

type DeleteIPReq struct {
	AttachmentID string             `json:"attachment_id"`
	Action       model.XDPAction    `json:"action"`
	IP           netaddr.IPv4Prefix `json:"ip"`
}

type DeleteIPResp struct{}

type IPHandler struct {
	service *service.AttachmentService
}

func (h *IPHandler) QueryIP(c *gin.Context) {
	p := NewPageFromRequest(c.Request)
	attachmentID := c.Request.URL.Query().Get("attachment-id")
	action := model.XDPAction(c.Request.URL.Query().Get("action"))

	ips, total, err := h.service.QueryIP(attachmentID, action, p.Page, p.Limit)
	if err != nil {
		Error(c, ErrorCodeInternal, errors.Wrap(err, "Query IP"))
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
		attachmentIdx := slices.IndexFunc(resp.Data, func(a AttachmentIP) bool { return a.ID == ip.AttachmentID })
		if attachmentIdx == -1 {
			resp.Data = append(resp.Data, AttachmentIP{ID: ip.AttachmentID})
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
		Error(c, ErrorCodeInvalid, errors.Wrap(err, "json.Unmarshal"))
		return
	}

	ips := []*model.IP{}
	for _, attachment := range req.Attachments {
		for _, action := range attachment.Actions {
			for _, ip := range action.IPs {
				ips = append(ips, &model.IP{
					AttachmentID: attachment.ID,
					Action:       action.Action,
					IP:           ip,
				})
			}
		}
	}

	if err := h.service.AddIP(ips); err != nil {
		Error(c, ErrorCodeInvalid, errors.Wrap(err, "Add IP"))
		return
	}
	Success(c, AddIPResp{})
}

func (h *IPHandler) DeleteIP(c *gin.Context) {
	var req DeleteIPReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, ErrorCodeInvalid, errors.Wrap(err, "json.Unmarshal"))
		return
	}

	ip := model.IP{
		AttachmentID: req.AttachmentID,
		Action:       req.Action,
		IP:           req.IP,
	}

	if err := h.service.DeleteIP(&ip); err != nil {
		Error(c, ErrorCodeInvalid, errors.Wrap(err, "Delete IP"))
		return
	}
	Success(c, DeleteIPResp{})
}
