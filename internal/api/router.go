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

	APIPathQueryIPsAction = "/api/xdp/:action/ips"
	APIPathAddIPAction    = "/api/xdp/:action/ips"
	APIPathDeleteIPAction = "/api/xdp/:action/ips/:ip"
)

func SetRuleRouter(g *gin.Engine, rule RuleAPI) {
	w := httpRuleWrapper{impl: rule}
	g.GET(APIPathQueryRules, w.QueryRules)
	g.GET(APIPathQueryRule, w.QueryRule)
	g.POST(APIPathAddRule, w.AddRule)
	g.DELETE(APIPathDeleteRule, w.DeletePacetRule)
}

func SetIPRouter(g *gin.Engine, ip XDPAPI) {
	w := httpXDPWrapper{impl: ip}
	g.GET(APIPathQueryIPsAction, w.QueryIPs)
	g.POST(APIPathAddIPAction, w.AddIP)
	g.DELETE(APIPathDeleteIPAction, w.DeleteIP)
}

func InstantiateRuleAPIURL(apiPath string, ruleID int) string {
	return InstantiateAPIURL(apiPath, map[string]string{":rule_id": strconv.Itoa(ruleID)})
}

func InstantiateAPIURL(apiPath string, params map[string]string) string {
	for k, v := range params {
		apiPath = strings.ReplaceAll(apiPath, k, v)
	}
	return strings.TrimSuffix(apiPath, "/")
}
