package api

import (
	"encoding/json"
	"net/http"
)

// RouterDeps holds the service dependencies for the HTTP router.
type RouterDeps struct {
	Status      StatusService
	Attachments AttachmentService
	Ruleset     RulesetService
	Stats       StatsService
	Egress      EgressService
}

// NewRouter creates the HTTP handler with all API routes registered.
func NewRouter(deps RouterDeps) http.Handler {
	mux := http.NewServeMux()

	// Health / Status
	mux.HandleFunc("GET /api/v1/health", handleHealth)
	mux.HandleFunc("GET /api/v1/status", handleStatus(deps.Status))

	// Attachments
	mux.HandleFunc("GET /api/v1/attachments", handleListAttachments(deps.Attachments))
	mux.HandleFunc("POST /api/v1/attachments", handleCreateAttachment(deps.Attachments))
	mux.HandleFunc("GET /api/v1/attachments/{ifindex}", handleGetAttachment(deps.Attachments))
	mux.HandleFunc("PATCH /api/v1/attachments/{ifindex}", handlePatchAttachment(deps.Attachments))
	mux.HandleFunc("DELETE /api/v1/attachments/{ifindex}", handleDeleteAttachment(deps.Attachments))

	// Ruleset
	mux.HandleFunc("GET /api/v1/ruleset", handleGetRuleset(deps.Ruleset))
	mux.HandleFunc("PUT /api/v1/ruleset", handlePutRuleset(deps.Ruleset))
	mux.HandleFunc("DELETE /api/v1/ruleset", handleDeleteRuleset(deps.Ruleset))

	// Events
	mux.HandleFunc("GET /api/v1/events/stream", handleEventsStream)

	// Stats
	mux.HandleFunc("GET /api/v1/stats", handleGetStats(deps.Stats))

	// Response Egress
	mux.HandleFunc("GET /api/v1/response/egress", handleGetEgress(deps.Egress))
	mux.HandleFunc("PUT /api/v1/response/egress", handlePutEgress(deps.Egress))
	mux.HandleFunc("DELETE /api/v1/response/egress", handleDeleteEgress(deps.Egress))

	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return
	}
}
