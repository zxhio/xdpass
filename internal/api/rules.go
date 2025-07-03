package api

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/zxhio/xdpass/internal/rule"
)

type QueryRulesReq struct {
	Page       int
	PageSize   int
	MatchTypes []rule.MatchType
}

type QueryRulesResp struct {
	Page     int          `json:"page"`
	PageSize int          `json:"page_size"`
	Total    int          `json:"total"`
	Rules    []*rule.Rule `json:"rules"`
}

type RuleAPI interface {
	QueryRule(int) (*rule.Rule, error)
	QueryRules(*QueryRulesReq) (*QueryRulesResp, error)
	AddRule(*rule.Rule) (int, error)
	DeleteRule(int) error
}

type httpRuleWrapper struct {
	impl RuleAPI
}

func (w httpRuleWrapper) QueryRule(c *gin.Context) {
	ruleID, err := strconv.Atoi(c.Param("rule_id"))
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}

	rule, err := w.impl.QueryRule(ruleID)
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}
	SetResponseData(c, rule)
}

func (w httpRuleWrapper) QueryRules(c *gin.Context) {
	var req QueryRulesReq

	pageNumber, err := strconv.Atoi(c.Request.URL.Query().Get("page"))
	if err != nil {
		pageNumber = 1
	}
	req.Page = pageNumber

	pageSize, err := strconv.Atoi(c.Request.URL.Query().Get("page-size"))
	if err != nil {
		pageSize = 100
	}
	req.PageSize = pageSize

	var mt rule.MatchType
	if err := mt.Set(c.Request.URL.Query().Get("proto")); err == nil {
		req.MatchTypes = append(req.MatchTypes, mt)
	}

	resp, err := w.impl.QueryRules(&req)
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}
	SetResponseData(c, resp)
}

func (w httpRuleWrapper) AddRule(c *gin.Context) {
	var rule rule.Rule
	if err := c.ShouldBindJSON(&rule); err != nil {
		SetResponseError(c, ErrorCodeInvalid, errors.Wrap(err, "json.Unmarshal"))
		return
	}

	ruleID, err := w.impl.AddRule(&rule)
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}
	SetResponseData(c, ruleID)
}

func (w httpRuleWrapper) DeletePacetRule(c *gin.Context) {
	ruleID, err := strconv.Atoi(c.Param("rule_id"))
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}

	err = w.impl.DeleteRule(ruleID)
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}
	SetResponseData(c, ruleID)
}
