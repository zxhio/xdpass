package api

import (
	"encoding/json"
	"io"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/zxhio/xdpass/internal/errcode"
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
		Error(c, errcode.NewError(errcode.CodeInvalid, err))
		return
	}

	rule, err := h.service.QueryRule(ruleID)
	if err != nil {
		Error(c, err)
	} else {
		Success(c, rule)
	}
}

func (h RuleHandler) QueryRules(c *gin.Context) {
	var r rule.Rule

	data, err := io.ReadAll(c.Request.Body)
	if err != nil && err != io.EOF {
		Error(c, errcode.NewError(errcode.CodeInternal, err))
		return
	}
	if len(data) != 0 {
		err = json.Unmarshal(data, &r)
		if err != nil {
			Error(c, errcode.NewError(errcode.CodeInvalid, err))
			return
		}
	}

	queryPage := NewPageFromRequest(c.Request)
	rules, total, err := h.service.QueryRules(r.Matchers, r.Target, queryPage.Page, queryPage.Limit)
	if err != nil {
		Error(c, err)
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
	Success(c, resp)
}

func (h RuleHandler) AddRule(c *gin.Context) {
	var rule rule.Rule
	if err := c.ShouldBindJSON(&rule); err != nil {
		Error(c, errcode.NewError(errcode.CodeInvalid, err))
		return
	}

	ruleID, err := h.service.AddRule(&rule)
	if err != nil {
		Error(c, err)
	} else {
		Success(c, ruleID)
	}
}

func (h RuleHandler) DeletePacketRule(c *gin.Context) {
	ruleID, err := strconv.Atoi(c.Param("rule_id"))
	if err != nil {
		Error(c, errcode.NewError(errcode.CodeInvalid, err))
		return
	}

	err = h.service.DeleteRule(ruleID)
	if err != nil {
		Error(c, err)
	} else {
		Success(c, ruleID)
	}
}
