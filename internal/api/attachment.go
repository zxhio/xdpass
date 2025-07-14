package api

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/zxhio/xdpass/internal/model"
	"github.com/zxhio/xdpass/internal/service"
)

type AddAttachmentReq struct {
	Interface     string        `json:"interface" binding:"required"`
	Mode          string        `json:"mode"`
	PullTimeout   time.Duration `json:"pull_timeout,omitempty"`
	Queues        []int         `json:"queues,omitempty"`
	Cores         []int         `json:"cores,omitempty"`
	ForceZeroCopy bool          `json:"force_zero_copy,omitempty"`
	ForceCopy     bool          `json:"force_copy,omitempty"`
	NoNeedWakeup  bool          `json:"no_need_wakeup,omitempty"`
}

type AddAttachmentResp struct{}

type DeleteAttachmentResp struct{}

type QueryAttachmentResp QueryPageResp[AttachmentInfo]

type AttachmentInfo struct {
	Name        string        `json:"name"`
	Mode        string        `json:"mode"`
	PullTimeout time.Duration `json:"pull_timeout"`
	Queues      []int         `json:"queues"`
	Cores       []int         `json:"cores"`
	BindFlags   uint16        `json:"bind_flags"`
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

	err := h.service.AddAttachment(
		&model.Attachment{
			Name:        req.Interface,
			Mode:        req.Mode,
			PullTimeout: req.PullTimeout,
			Queues:      req.Queues,
			Cores:       req.Cores,
		},
		req.ForceCopy,
		req.ForceZeroCopy,
		req.NoNeedWakeup,
	)
	if err != nil {
		Error(c, ErrorCodeInternal, err)
	} else {
		Success(c, AddAttachmentResp{})
	}
}

func (h *AttachmentHandler) DeleteAttachment(c *gin.Context) {
	err := h.service.DeleteAttachment(c.Param("name"))
	if err != nil {
		Error(c, ErrorCodeInternal, err)
	} else {
		Success(c, AddAttachmentResp{})
	}
}

func (h *AttachmentHandler) QueryAttachment(c *gin.Context) {
	var resp QueryAttachmentResp

	name := c.Request.URL.Query().Get("name")
	if name != "" {
		attachment, err := h.service.QueryAttachment(name)
		if err != nil {
			Error(c, ErrorCodeInternal, err)
			return
		}
		resp.Data = append(resp.Data, AttachmentInfo{
			Name:        attachment.Name,
			Mode:        attachment.Mode,
			PullTimeout: attachment.PullTimeout,
			Queues:      attachment.Queues,
			Cores:       attachment.Cores,
			BindFlags:   attachment.BindFlags,
		})
	} else {
		p := NewPageFromRequest(c.Request)
		attachments, total, err := h.service.QueryAttachments(p.Page, p.Limit)
		if err != nil {
			Error(c, ErrorCodeInternal, err)
			return
		}
		resp.Total = total
		for _, attachment := range attachments {
			resp.Data = append(resp.Data, AttachmentInfo{
				Name:        attachment.Name,
				Mode:        attachment.Mode,
				PullTimeout: attachment.PullTimeout,
				Queues:      attachment.Queues,
				Cores:       attachment.Cores,
				BindFlags:   attachment.BindFlags,
			})
		}
	}
	Success(c, resp)
}
