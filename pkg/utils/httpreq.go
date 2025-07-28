package utils

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

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

type QueryKV struct {
	K string
	V any
}

func WithReqQuery(s string) reqOpt {
	return func(opts *reqOpts) {
		if opts.query != "" {
			opts.query = fmt.Sprintf("%s&%s", opts.query, s)
		} else {
			opts.query = s
		}
	}
}

func WithReqQueryKVs(kvs ...QueryKV) reqOpt {
	var s []string
	for _, kv := range kvs {
		s = append(s, fmt.Sprintf("%s=%v", kv.K, kv.V))
	}
	return WithReqQuery(strings.Join(s, "&"))
}

func WithReqQueryKV(k string, v any) reqOpt {
	return WithReqQuery(fmt.Sprintf("%s=%v", k, v))
}

func WithReqBody(body io.Reader) reqOpt {
	return func(opts *reqOpts) { opts.body = body }
}

type BodyToValue[T any] func(body []byte) (*T, error)

func NewHTTPRequestMessage[T any](uri string, b2v BodyToValue[T], opts ...reqOpt) (*T, error) {
	resp, err := NewHTTPRequest(uri, opts...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, err
	}
	VerbosePrintln("")
	VerbosePrintln(addPrefixToHTTPLine(string(data), "< "))

	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return b2v(data)
}

func NewHTTPRequest(uri string, opts ...reqOpt) (*http.Response, error) {
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

	return newHTTPReq(uri, &o)
}

func newHTTPReq(reqURI string, opts *reqOpts) (*http.Response, error) {
	reqURI, err := url.JoinPath(opts.addr, reqURI)
	if err != nil {
		return nil, err
	}

	reqURL := reqURI
	if opts.query != "" {
		reqURL = fmt.Sprintf("%s?%s", reqURI, opts.query)
	}
	req, err := http.NewRequest(opts.method, reqURL, opts.body)
	if err != nil {
		return nil, err
	}

	data, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	VerbosePrintln(addPrefixToHTTPLine(string(data), "> "))

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		Timeout: time.Second * 10,
	}
	return client.Do(req)
}

func addPrefixToHTTPLine(s, prefix string) string {
	lines := strings.Split(s, "\r\n")
	for k, line := range lines {
		lines[k] = prefix + line
	}
	return strings.Join(lines, "\r\n")
}
