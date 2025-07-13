package api

import (
	"slices"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/zxhio/xdpass/internal/rule"
	"github.com/zxhio/xdpass/internal/service"
)

type QueryRulesResp QueryPageResp[*rule.Rule]

type RuleHandler struct {
	service *service.RuleService
}

func (h *RuleHandler) QueryRule(c *gin.Context) {
	ruleID, err := strconv.Atoi(c.Param("rule_id"))
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}

	rule, err := h.service.QueryRule(ruleID)
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}
	SetResponseData(c, rule)
}

func (h RuleHandler) QueryRules(c *gin.Context) {
	queryPage := NewPageFromRequest(c.Request)

	matchTypes := []rule.MatchType{}
	protos := rule.GetProtocolMatchTypes()
	idx := slices.IndexFunc(protos, func(mt rule.MatchType) bool {
		return strings.EqualFold(mt.String(), c.Request.URL.Query().Get("proto"))
	})
	if idx != -1 {
		matchTypes = append(matchTypes, protos[idx])
	}

	rules, total, err := h.service.QueryRules(matchTypes, queryPage.Page, queryPage.Limit)
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}
	resp := QueryRulesResp{
		QueryPage: QueryPage{
			Page:  queryPage.Page,
			Limit: queryPage.Limit,
			Total: total,
		},
		Data: rules,
	}
	SetResponseData(c, resp)
}

func (h RuleHandler) AddRule(c *gin.Context) {
	var rule rule.Rule
	if err := c.ShouldBindJSON(&rule); err != nil {
		SetResponseError(c, ErrorCodeInvalid, errors.Wrap(err, "json.Unmarshal"))
		return
	}

	ruleID, err := h.service.AddRule(&rule)
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}
	SetResponseData(c, ruleID)
}

func (h RuleHandler) DeletePacetRule(c *gin.Context) {
	ruleID, err := strconv.Atoi(c.Param("rule_id"))
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}

	err = h.service.DeleteRule(ruleID)
	if err != nil {
		SetResponseError(c, ErrorCodeInvalid, err)
		return
	}
	SetResponseData(c, ruleID)
}
