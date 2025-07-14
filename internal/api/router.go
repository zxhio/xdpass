package api

import (
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/zxhio/xdpass/internal/service"
)

const (
	DefaultAPIAddr = "127.0.0.1:9921"
)

const (
	APIPathQueryRules = "/api/rules"
	APIPathQueryRule  = "/api/rules/:rule_id"
	APIPathAddRule    = "/api/rules"
	APIPathDeleteRule = "/api/rules/:rule_id"

	PathXDPAttachment = "/api/xdp/attachments"
	PathXDPIP         = "/api/xdp/ips"
)

var (
	ipHandler         IPHandler
	ruleHandler       RuleHandler
	attachemtnHandler AttachmentHandler
)

func SetRuleRouter(g *gin.Engine, s *service.RuleService) {
	ruleHandler.service = s

	g.GET(APIPathQueryRules, ruleHandler.QueryRules)
	g.GET(APIPathQueryRule, ruleHandler.QueryRule)
	g.POST(APIPathAddRule, ruleHandler.AddRule)
	g.DELETE(APIPathDeleteRule, ruleHandler.DeletePacetRule)
}

func SetIPRouter(r *gin.Engine, s *service.AttachmentService) {
	ipHandler.service = s

	r.GET(PathXDPIP, ipHandler.QueryIP)
	r.POST(PathXDPIP, ipHandler.AddIP)
	r.DELETE(PathXDPIP, ipHandler.DeleteIP)
}

func SetAttachmentRouter(r *gin.Engine, s *service.AttachmentService) {
	attachemtnHandler.service = s

	r.GET(PathXDPAttachment, attachemtnHandler.QueryAttachment)
	r.POST(PathXDPAttachment, attachemtnHandler.AddAttachment)
	r.DELETE(PathXDPAttachment+"/:name", attachemtnHandler.DeleteAttachment)
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
