package main

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
	"strings"
	"time"

	"github.com/zxhio/xdpass/internal/api"
	"github.com/zxhio/xdpass/internal/rule"
)

type client struct {
	Addr   string
	Path   string
	Method string
	Query  string
	Body   io.Reader
}

func (c *client) QueryRule(ruleID int) (*rule.Rule, error) {
	c.Path = api.InstantiateRuleAPIURL(api.APIPathQueryRule, ruleID)
	c.Method = http.MethodGet
	return doRequestMessage[rule.Rule](c)
}

func (c *client) QueryRules(page, size int, proto string) (*api.QueryRulesResp, error) {
	c.Path = api.APIPathQueryRules
	c.Method = http.MethodGet
	c.Query = fmt.Sprintf("?page=%d&page-size=%d&proto=%s", page, size, proto)
	return doRequestMessage[api.QueryRulesResp](c)
}

func (c *client) AddRule(rule *rule.Rule) (int, error) {
	c.Path = api.APIPathAddRule
	c.Method = http.MethodPost

	data, err := json.Marshal(rule)
	if err != nil {
		return 0, err
	}
	c.Body = bytes.NewBuffer(data)

	ruleID, err := doRequestMessage[int](c)
	if err != nil {
		return 0, err
	}
	return *ruleID, nil
}

func (c *client) DeletePacetRule(ruleID int) error {
	c.Path = api.InstantiateRuleAPIURL(api.APIPathDeleteRule, ruleID)
	c.Method = http.MethodDelete
	_, err := doRequestMessage[int](c)
	return err
}

func doRequest(c *client) (*http.Response, error) {
	reqURL, err := url.JoinPath(c.Addr, c.Path)
	if err != nil {
		return nil, err
	}

	b := bytes.NewBuffer(nil)
	if c.Body != nil {
		io.Copy(b, c.Body)
	}

	req, err := http.NewRequest(c.Method, reqURL+c.Query, b)
	if err != nil {
		return nil, err
	}

	data, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	verbosePrintln(addPrefixToHTTPLine(string(data), "> "))

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		Timeout: time.Second * 10,
	}
	return client.Do(req)
}

func doRequestMessage[T any](c *client) (*T, error) {
	resp, err := doRequest(c)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return nil, err
	}
	verbosePrintln("")
	verbosePrintln(addPrefixToHTTPLine(string(data), "< "))

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

func respValue[T any](data []byte) (*T, error) {
	var (
		resp api.Response
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
