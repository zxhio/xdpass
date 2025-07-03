package api

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	APIPathQueryRules = "/api/rules"
	APIPathQueryRule  = "/api/rules/:rule_id"
	APIPathAddRule    = "/api/rules"
	APIPathDeleteRule = "/api/rules/:rule_id"
)

func SetRuleRouter(g *gin.Engine, rule RuleAPI) {
	w := httpRuleWrapper{impl: rule}
	g.GET(APIPathQueryRules, w.QueryRules)
	g.GET(APIPathQueryRule, w.QueryRule)
	g.POST(APIPathAddRule, w.AddRule)
	g.DELETE(APIPathDeleteRule, w.DeletePacetRule)
}

func InstantiateRuleAPIURL(apiPath string, ruleID int) string {
	return strings.ReplaceAll(apiPath, ":rule_id", strconv.Itoa(ruleID))
}
