package api

import "net/http"

// ProblemDetails is the RFC 7807-style error response.
type ProblemDetails struct {
	Type   string `json:"type,omitempty"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Code   string `json:"code"`
}

const (
	CodeBadRequest       = "bad_request"
	CodeValidationFailed = "validation_failed"
	CodeNotFound         = "not_found"
	CodeConflict         = "conflict"
	CodeRuntimeFailed    = "runtime_failed"
	CodeInternalError    = "internal_error"
	CodeNotImplemented   = "not_implemented"
)

func writeError(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, ProblemDetails{
		Type:   "about:blank",
		Title:  http.StatusText(status),
		Status: status,
		Detail: detail,
		Code:   code,
	})
}

func writeBadRequest(w http.ResponseWriter, detail string) {
	writeError(w, http.StatusBadRequest, CodeBadRequest, detail)
}

func writeValidationFailed(w http.ResponseWriter, detail string) {
	writeError(w, http.StatusBadRequest, CodeValidationFailed, detail)
}

func writeNotFound(w http.ResponseWriter, detail string) {
	writeError(w, http.StatusNotFound, CodeNotFound, detail)
}

func writeConflict(w http.ResponseWriter, detail string) {
	writeError(w, http.StatusConflict, CodeConflict, detail)
}

func writeNotImplemented(w http.ResponseWriter, detail string) {
	writeError(w, http.StatusNotImplemented, CodeNotImplemented, detail)
}

func writeInternalError(w http.ResponseWriter, detail string) {
	writeError(w, http.StatusInternalServerError, CodeInternalError, detail)
}
