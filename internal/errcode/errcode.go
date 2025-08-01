package errcode

import "fmt"

type Code int

const (
	CodeSuccess  Code = 200
	CodeInternal Code = iota + 1001
	CodeInvalid
	CodeNotExist
	CodeExist
)

var code2str = map[Code]string{
	CodeSuccess:  "success",
	CodeInternal: "internal error",
	CodeInvalid:  "invalid argument",
	CodeNotExist: "not exist",
	CodeExist:    "already exists",
}

func (c Code) String() string {
	s, ok := code2str[c]
	if !ok {
		return fmt.Sprintf("unknwon code: %d", c)
	}
	return s
}

type ErrorCode struct {
	code    Code
	message string
}

func (e ErrorCode) Code() Code { return e.code }
func (e ErrorCode) Message() string {
	if e.code == CodeSuccess {
		return e.Code().String()
	}
	return fmt.Sprintf("%s: %s", e.code, e.message)
}

func (e ErrorCode) Error() string {
	if e.code == CodeSuccess {
		return e.code.String()
	}
	return fmt.Sprintf("error_code: %d, message: %s", e.Code(), e.Message())
}

func New(code Code, format string, a ...any) ErrorCode {
	return ErrorCode{
		code:    code,
		message: fmt.Sprintf(format, a...),
	}
}

func NewMessage(code Code, msg string) ErrorCode {
	return New(code, msg)
}

func NewError(code Code, err error) ErrorCode {
	return New(code, err.Error())
}
