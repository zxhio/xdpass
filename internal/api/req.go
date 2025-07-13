package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zxhio/xdpass/pkg/utils"
)

// QueryPage defines pagination request parameters
type QueryPage struct {
	Page  int `json:"page"`  // Current page number (1-based)
	Limit int `json:"limit"` // Items per page
	Total int `json:"total"` // Total items count (usually set by server)
}

func (p QueryPage) ToQuery() string {
	return strings.Join([]string{
		fmt.Sprintf("page=%d", p.Page),
		fmt.Sprintf("limit=%d", p.Limit),
	}, "&")
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

// QueryWithPage performs pagination on a dataset with optional filtering
// Parameters:
//   - data: The full dataset to paginate
//   - req: Pagination request parameters (page/limit)
//   - filter: Optional filter function (nil means no filtering)
//
// Returns:
//   - Paginated response with metadata
//   - Error if pagination parameters are invalid
func QueryWithPage[T any](data []T, req *QueryPage, filter func(T) bool) *QueryPageResp[T] {
	// Initialize default values if request is nil
	if req == nil {
		req = &QueryPage{Page: 1, Limit: 100}
	}

	// Validate and normalize pagination parameters
	if req.Page < 1 {
		req.Page = 1
	}
	if req.Limit < 1 {
		req.Limit = 100
	} else {
		req.Limit = min(req.Limit, 100)
	}

	// First pass: count total matches (no allocation)
	total := 0
	if filter != nil {
		for _, item := range data {
			if filter(item) {
				total++
			}
		}
	} else {
		total = len(data)
	}

	resp := &QueryPageResp[T]{
		QueryPage: QueryPage{
			Page:  req.Page,
			Limit: req.Limit,
			Total: total,
		},
		Data: make([]T, 0, min(req.Limit, total)),
	}

	// Early return if no data or page out of range
	if total == 0 || (req.Page-1)*req.Limit >= total {
		return resp
	}

	// Second pass: collect only needed items
	itemsNeeded := req.Limit
	itemsSkipped := (req.Page - 1) * req.Limit
	currentPos := 0

	for _, item := range data {
		if filter == nil || filter(item) {
			if currentPos >= itemsSkipped && itemsNeeded > 0 {
				resp.Data = append(resp.Data, item)
				itemsNeeded--
			}
			currentPos++
			if itemsNeeded == 0 {
				break
			}
		}
	}
	return resp
}

type reqOpts struct {
	addr   string
	method string
	query  string
	body   io.Reader
}

type reqOpt func(opts *reqOpts)

func WithReqAddr(addr string) reqOpt {
	return func(opts *reqOpts) {
		if !strings.HasPrefix(addr, "http") {
			opts.addr = "http://" + addr
		} else {
			opts.addr = addr
		}
	}
}

func WithReqMethod(method string) reqOpt {
	return func(opts *reqOpts) { opts.method = method }
}

func WithReqQuery(fields ...string) reqOpt {
	return func(opts *reqOpts) { opts.query = strings.Join(fields, "&") }
}

func WithReqBody(body io.Reader) reqOpt {
	return func(opts *reqOpts) { opts.body = body }
}

func NewReqMessage[T any](uri string, opts ...reqOpt) (*T, error) {
	resp, err := newReq(uri, opts...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, err
	}
	utils.VerbosePrintln("")
	utils.VerbosePrintln(addPrefixToHTTPLine(string(data), "< "))

	b := bytes.NewBuffer(nil)
	_, err = io.Copy(b, resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, errors.New(b.String())
	}

	return respValue[T](b.Bytes())
}

func newReq(reqURI string, opts ...reqOpt) (*http.Response, error) {
	var o reqOpts
	for _, opt := range opts {
		opt(&o)
	}
	if o.method == "" {
		o.method = http.MethodGet
	}

	// Get api address from env
	addr := os.Getenv("HTTP_API_ADDR")
	if addr != "" {
		o.addr = addr
	}
	if o.addr == "" {
		return nil, fmt.Errorf("empty api address")
	}

	reqURI, err := url.JoinPath(o.addr, reqURI)
	if err != nil {
		return nil, err
	}

	reqURL := reqURI
	if o.query != "" {
		reqURL = fmt.Sprintf("%s?%s", reqURI, o.query)
	}
	req, err := http.NewRequest(o.method, reqURL, o.body)
	if err != nil {
		return nil, err
	}

	data, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	utils.VerbosePrintln(addPrefixToHTTPLine(string(data), "> "))

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		Timeout: time.Second * 10,
	}
	return client.Do(req)
}

func respValue[T any](data []byte) (*T, error) {
	var (
		resp Response
		v    T
	)
	err := json.Unmarshal(data, &resp)
	if err != nil {
		return nil, err
	}
	if resp.Code != ErrorCodeOk {
		return nil, fmt.Errorf(resp.Message)
	}

	data, err = json.Marshal(resp.Data)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &v)
	return &v, err
}

func addPrefixToHTTPLine(s, prefix string) string {
	lines := strings.Split(s, "\r\n")
	for k, line := range lines {
		lines[k] = prefix + line
	}
	return strings.Join(lines, "\r\n")
}
