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

type Page struct {
	PageNumber int `json:"page_number"`
	PageSize   int `json:"page_size"`
	Total      int `json:"total"`
}

func (p Page) ToQuery() string {
	s := []string{}
	s = append(s, fmt.Sprintf("page=%d", p.PageNumber))
	s = append(s, fmt.Sprintf("page-size=%d", p.PageSize))
	return strings.Join(s, "&")
}

func NewPageFromRequest(req *http.Request) Page {
	var p Page

	pageNumber, err := strconv.Atoi(req.URL.Query().Get("page"))
	if err != nil {
		pageNumber = 1
	}
	p.PageNumber = pageNumber

	size, err := strconv.Atoi(req.URL.Query().Get("page-size"))
	if err != nil {
		size = 100
	}
	p.PageSize = size

	return p
}

type reqOpts struct {
	addr   string
	method string
	query  string
	body   io.Reader
}

type reqOpt func(opts *reqOpts)

func WithReqAddr(addr string) reqOpt {
	return func(opts *reqOpts) { opts.addr = addr }
}

func WithReqMethod(method string) reqOpt {
	return func(opts *reqOpts) { opts.method = method }
}

func WithReqQuery(query string) reqOpt {
	return func(opts *reqOpts) { opts.query = query }
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
	addr := os.Getenv("XDPASS_API_ADDR")
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
