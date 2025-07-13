package api

import (
	"slices"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/zxhio/xdpass/internal/model"
	"github.com/zxhio/xdpass/internal/service"
	"github.com/zxhio/xdpass/pkg/netaddr"
)

type QueryIPResp struct {
	QueryPage
	Attachments []AttachmentIP `json:"attachments"`
}

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
		SetResponseError(c, ErrorCodeInternal, errors.Wrap(err, "Query IP"))
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
		attachmentIdx := slices.IndexFunc(resp.Attachments, func(a AttachmentIP) bool { return a.ID == ip.AttachmentID })
		if attachmentIdx == -1 {
			resp.Attachments = append(resp.Attachments, AttachmentIP{ID: ip.AttachmentID})
			attachmentIdx = len(resp.Attachments) - 1
		}
		actionIdx := slices.IndexFunc(resp.Attachments[attachmentIdx].Actions, func(a XDPActionIP) bool { return a.Action == ip.Action })
		if actionIdx == -1 {
			resp.Attachments[attachmentIdx].Actions = append(resp.Attachments[attachmentIdx].Actions, XDPActionIP{
				Action: ip.Action,
			})
			actionIdx = len(resp.Attachments[attachmentIdx].Actions) - 1
		}
		resp.Attachments[attachmentIdx].Actions[actionIdx].IPs = append(resp.Attachments[attachmentIdx].Actions[actionIdx].IPs, ip.IP)
	}
	SetResponseData(c, resp)
}

func (h *IPHandler) AddIP(c *gin.Context) {
	var req AddIPReq
	if err := c.ShouldBindJSON(&req); err != nil {
		SetResponseError(c, ErrorCodeInvalid, errors.Wrap(err, "json.Unmarshal"))
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
		SetResponseError(c, ErrorCodeInvalid, errors.Wrap(err, "Add IP"))
		return
	}
	SetResponseData(c, AddIPResp{})
}

func (h *IPHandler) DeleteIP(c *gin.Context) {
	var req DeleteIPReq
	if err := c.ShouldBindJSON(&req); err != nil {
		SetResponseError(c, ErrorCodeInvalid, errors.Wrap(err, "json.Unmarshal"))
		return
	}

	ip := model.IP{
		AttachmentID: req.AttachmentID,
		Action:       req.Action,
		IP:           req.IP,
	}

	if err := h.service.DeleteIP(&ip); err != nil {
		SetResponseError(c, ErrorCodeInvalid, errors.Wrap(err, "Delete IP"))
		return
	}
	SetResponseData(c, DeleteIPResp{})
}
