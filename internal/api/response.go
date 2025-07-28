package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/zxhio/xdpass/internal/errcode"
)

type Response struct {
	Code    errcode.Code `json:"code"`
	Message string       `json:"message"`
	Data    any          `json:"data"`
}

func Error(c *gin.Context, err error) {
	ec, ok := err.(errcode.ErrorCode)
	if !ok {
		ec = errcode.NewError(errcode.CodeInternal, err)
	}
	c.JSON(500, Response{
		Code:    ec.Code(),
		Message: ec.Message(),
	})
}

func Success(c *gin.Context, v any) {
	c.JSON(http.StatusOK, Response{
		Code:    errcode.CodeSuccess,
		Message: errcode.CodeSuccess.String(),
		Data:    v,
	})
}

func GetBodyData[T any](data []byte) (*T, error) {
	var (
		resp Response
		v    T
	)
	err := json.Unmarshal(data, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != errcode.CodeSuccess {
		return nil, fmt.Errorf(resp.Message)
	}

	data, err = json.Marshal(resp.Data)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &v)
	return &v, err
}

// QueryPage defines pagination request parameters
type QueryPage struct {
	Page  int `json:"page"`  // Current page number (1-based)
	Limit int `json:"limit"` // Items per page
	Total int `json:"total"` // Total items count (usually set by server)
}

func (p QueryPage) ToQuery() string {
	s := []string{}
	if p.Page != 0 {
		s = append(s, fmt.Sprintf("page=%d", p.Page))
	}
	if p.Limit != 0 {
		s = append(s, fmt.Sprintf("limit=%d", p.Limit))
	}
	return strings.Join(s, "&")
}

func NewPageFromRequest(req *http.Request) QueryPage {
	var p QueryPage

	page, err := strconv.Atoi(req.URL.Query().Get("page"))
	if err != nil {
		page = 1
	}
	p.Page = page

	limit, err := strconv.Atoi(req.URL.Query().Get("limit"))
	if err != nil {
		limit = 100
	}
	p.Limit = limit

	return p
}

// QueryPageResp represents a paginated response with generic data type
type QueryPageResp[T any] struct {
	QueryPage
	Data []T `json:"data"`
}
