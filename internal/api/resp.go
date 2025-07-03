package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type ErrorCode int

const (
	ErrorCodeOk       ErrorCode = 200
	ErrorCodeInternal ErrorCode = 1001
	ErrorCodeInvalid  ErrorCode = 1002
)

var err2msg = map[ErrorCode]string{
	ErrorCodeOk:       "success",
	ErrorCodeInternal: "internal error",
	ErrorCodeInvalid:  "invalid argument",
}

func (c ErrorCode) String() string {
	msg, ok := err2msg[c]
	if ok {
		return msg
	}
	return fmt.Sprintf("unknown error(%d)", c)
}

type Response struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Data    any       `json:"data"`
}

func SetResponseError(c *gin.Context, code ErrorCode, err error) {
	var msg string
	if err != nil {
		msg = fmt.Sprintf("%s: %s", code.String(), err)
	} else {
		msg = code.String()
	}
	c.JSON(500, Response{
		Code:    code,
		Message: msg,
	})
}

func SetResponseData(c *gin.Context, v any) {
	c.JSON(http.StatusOK, Response{
		Code:    ErrorCodeOk,
		Message: ErrorCodeOk.String(),
		Data:    v,
	})
}
