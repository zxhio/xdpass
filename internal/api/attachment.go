package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/zxhio/xdpass/internal/model"
	"github.com/zxhio/xdpass/internal/service"
)

type AddAttachmentReq struct {
	Interface   string        `json:"interface" binding:"required"`
	Mode        string        `json:"mode"`
	PullTimeout time.Duration `json:"pull_timeout,omitempty"`
}

type AddAttachmentResp struct{}

type DeleteAttachmentResp struct{}

type QueryAttachmentResp QueryPageResp[AttachmentInfo]

type AttachmentInfo struct {
	ID          string        `json:"id"`
	Mode        string        `json:"mode"`
	PullTimeout time.Duration `json:"pull_timeout,omitempty"`
}

type AttachmentHandler struct {
	service *service.AttachmentService
}

func (h *AttachmentHandler) AddAttachment(c *gin.Context) {
	var req AddAttachmentReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Error(c, ErrorCodeInvalid, errors.Wrap(err, "json.Unmarshal"))
		return
	}

	err := h.service.AddAttachment(&model.Attachment{
		ID:          req.Interface,
		Mode:        req.Mode,
		PullTimeout: req.PullTimeout,
	})
	if err != nil {
		Error(c, ErrorCodeInternal, err)
	} else {
		Success(c, AddAttachmentResp{})
	}
}

func (h *AttachmentHandler) DeleteAttachment(c *gin.Context) {
	err := h.service.DeleteAttachment(c.Param("id"))
	if err != nil {
		Error(c, ErrorCodeInternal, err)
	} else {
		Success(c, AddAttachmentResp{})
	}
}

func (h *AttachmentHandler) QueryAttachment(c *gin.Context) {
	var resp QueryAttachmentResp

	id := c.Request.URL.Query().Get("id")
	if id != "" {
		attachment, err := h.service.QueryAttachment(id)
		if err != nil {
			Error(c, ErrorCodeInternal, err)
			return
		}
		resp.Data = append(resp.Data, AttachmentInfo{
			ID:          attachment.ID,
			Mode:        attachment.Mode,
			PullTimeout: attachment.PullTimeout,
		})
	} else {
		p := NewPageFromRequest(c.Request)
		attachments, total, err := h.service.QueryAttachments(p.Page, p.Limit)
		if err != nil {
			Error(c, ErrorCodeInternal, err)
			return
		}
		resp.Total = total
		for _, a := range attachments {
			resp.Data = append(resp.Data, AttachmentInfo{
				ID:          a.ID,
				Mode:        a.Mode,
				PullTimeout: a.PullTimeout,
			})
		}
	}
	Success(c, resp)
}
