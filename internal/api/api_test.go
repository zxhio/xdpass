package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStore implements all service interfaces for testing.
type mockStore struct {
	attachments map[uint32]AttachmentResponse
	rules       []RuleResponse
}

func newMockStore() *mockStore {
	return &mockStore{attachments: make(map[uint32]AttachmentResponse)}
}

func (m *mockStore) Status(_ context.Context) (StatusResponse, error) {
	return StatusResponse{Status: "degraded", Attachments: len(m.attachments)}, nil
}

func (m *mockStore) ListAttachments(_ context.Context) ([]AttachmentResponse, error) {
	var result []AttachmentResponse
	for _, a := range m.attachments {
		result = append(result, a)
	}
	return result, nil
}

func (m *mockStore) GetAttachment(_ context.Context, ifIndex uint32) (AttachmentResponse, error) {
	a, ok := m.attachments[ifIndex]
	if !ok {
		return AttachmentResponse{}, errors.New("not found")
	}
	return a, nil
}

func (m *mockStore) CreateAttachment(_ context.Context, req AttachmentRequest) (AttachmentResponse, error) {
	if _, exists := m.attachments[req.IfIndex]; exists {
		return AttachmentResponse{}, errors.New("already exists")
	}
	resp := AttachmentResponse{IfIndex: req.IfIndex, Enabled: true, AttachMode: "native", MissVerdict: "pass"}
	m.attachments[req.IfIndex] = resp
	return resp, nil
}

func (m *mockStore) PatchAttachment(_ context.Context, ifIndex uint32, enabled bool) (AttachmentResponse, error) {
	a, ok := m.attachments[ifIndex]
	if !ok {
		return AttachmentResponse{}, errors.New("not found")
	}
	a.Enabled = enabled
	m.attachments[ifIndex] = a
	return a, nil
}

func (m *mockStore) DeleteAttachment(_ context.Context, ifIndex uint32) error {
	if _, ok := m.attachments[ifIndex]; !ok {
		return errors.New("not found")
	}
	delete(m.attachments, ifIndex)
	return nil
}

func (m *mockStore) DryRunAttachment(_ context.Context, req AttachmentRequest) (AttachmentResponse, error) {
	if req.IfIndex == 0 {
		return AttachmentResponse{}, errors.New("ifindex must be greater than 0")
	}
	return AttachmentResponse{IfIndex: req.IfIndex, Enabled: true, AttachMode: "native", MissVerdict: "pass"}, nil
}

func (m *mockStore) GetRuleset(_ context.Context) (RulesetResponse, error) {
	return RulesetResponse{Rules: m.rules}, nil
}

func (m *mockStore) ReplaceRuleset(_ context.Context, rules []RuleResponse) (RulesetResponse, error) {
	m.rules = rules
	return RulesetResponse{Rules: m.rules}, nil
}

func (m *mockStore) DeleteRuleset(_ context.Context) error {
	m.rules = nil
	return nil
}

func (m *mockStore) GetStats(_ context.Context) (StatsResponse, error) {
	return StatsResponse{}, nil
}

func (m *mockStore) GetEgress(_ context.Context) (EgressResponse, error) {
	return EgressResponse{VLANMode: "preserve"}, nil
}

func (m *mockStore) ReplaceEgress(_ context.Context, ifIndex uint32, _, vlanMode string) (EgressResponse, error) {
	return EgressResponse{Configured: true, IfIndex: ifIndex, VLANMode: vlanMode}, nil
}

func (m *mockStore) DeleteEgress(_ context.Context) error {
	return nil
}

func newTestRouter() http.Handler {
	s := newMockStore()
	return NewRouter(RouterDeps{
		Status: s, Attachments: s, Ruleset: s, Stats: s, Egress: s,
	})
}

func doRequest(handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	var buf *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		buf = bytes.NewBuffer(b)
	} else {
		buf = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

func TestHealthEndpoint(t *testing.T) {
	w := doRequest(newTestRouter(), "GET", "/api/v1/health", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp healthResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "ok", resp.Status)
}

func TestStatusEndpoint(t *testing.T) {
	w := doRequest(newTestRouter(), "GET", "/api/v1/status", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp StatusResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "degraded", resp.Status)
}

func TestErrorFormatIsProblemDetails(t *testing.T) {
	w := doRequest(newTestRouter(), "GET", "/api/v1/attachments/999", nil)
	require.Equal(t, http.StatusNotFound, w.Code)

	var resp ProblemDetails
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "about:blank", resp.Type)
	assert.Equal(t, "not_found", resp.Code)
	assert.Equal(t, http.StatusNotFound, resp.Status)
}

func TestCreateAttachment(t *testing.T) {
	w := doRequest(newTestRouter(), "POST", "/api/v1/attachments", map[string]any{"ifindex": 3})
	require.Equal(t, http.StatusCreated, w.Code)

	var resp AttachmentResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, uint32(3), resp.IfIndex)
	assert.True(t, resp.Enabled)
	assert.Equal(t, "native", resp.AttachMode)
	assert.Equal(t, "pass", resp.MissVerdict)
}

func TestCreateAttachmentConflict(t *testing.T) {
	router := newTestRouter()
	w := doRequest(router, "POST", "/api/v1/attachments", map[string]any{"ifindex": 3})
	require.Equal(t, http.StatusCreated, w.Code)

	w2 := doRequest(router, "POST", "/api/v1/attachments", map[string]any{"ifindex": 3})
	assert.Equal(t, http.StatusConflict, w2.Code)
}

func TestCreateAttachmentValidation(t *testing.T) {
	w := doRequest(newTestRouter(), "POST", "/api/v1/attachments", map[string]any{"ifindex": 0})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateAttachmentDryRun(t *testing.T) {
	router := newTestRouter()
	w := doRequest(router, "POST", "/api/v1/attachments?dry_run=true", map[string]any{"ifindex": 3})
	require.Equal(t, http.StatusOK, w.Code)

	// Should not persist.
	w2 := doRequest(router, "GET", "/api/v1/attachments/3", nil)
	assert.Equal(t, http.StatusNotFound, w2.Code)
}

func TestDeleteAttachment204(t *testing.T) {
	router := newTestRouter()
	w := doRequest(router, "POST", "/api/v1/attachments", map[string]any{"ifindex": 5})
	require.Equal(t, http.StatusCreated, w.Code)

	w2 := doRequest(router, "DELETE", "/api/v1/attachments/5", nil)
	assert.Equal(t, http.StatusNoContent, w2.Code)
	assert.Empty(t, w2.Body.String())
}

func TestPatchAttachment(t *testing.T) {
	router := newTestRouter()
	doRequest(router, "POST", "/api/v1/attachments", map[string]any{"ifindex": 7})

	falseVal := false
	w := doRequest(router, "PATCH", "/api/v1/attachments/7", map[string]any{"enabled": falseVal})
	require.Equal(t, http.StatusOK, w.Code)

	var resp AttachmentResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Enabled)
}

func TestPatchAttachmentNotFound(t *testing.T) {
	w := doRequest(newTestRouter(), "PATCH", "/api/v1/attachments/999", map[string]any{"enabled": true})
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestRulesetCRUD(t *testing.T) {
	router := newTestRouter()

	// GET empty
	w := doRequest(router, "GET", "/api/v1/ruleset", nil)
	require.Equal(t, http.StatusOK, w.Code)
	var getResp RulesetResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &getResp))
	assert.Empty(t, getResp.Rules)

	// PUT
	w2 := doRequest(router, "PUT", "/api/v1/ruleset", RulesetResponse{
		Rules: []RuleResponse{{RuleID: 1, Response: ResponseResponse{Action: "alert"}}},
	})
	require.Equal(t, http.StatusOK, w2.Code)

	// GET after PUT
	w3 := doRequest(router, "GET", "/api/v1/ruleset", nil)
	require.Equal(t, http.StatusOK, w3.Code)
	var getResp2 RulesetResponse
	require.NoError(t, json.Unmarshal(w3.Body.Bytes(), &getResp2))
	require.Len(t, getResp2.Rules, 1)
	assert.Equal(t, uint32(1), getResp2.Rules[0].RuleID)

	// DELETE
	w4 := doRequest(router, "DELETE", "/api/v1/ruleset", nil)
	assert.Equal(t, http.StatusNoContent, w4.Code)
}

func TestEventsStreamNotImplemented(t *testing.T) {
	w := doRequest(newTestRouter(), "GET", "/api/v1/events/stream", nil)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestStatsZeroed(t *testing.T) {
	w := doRequest(newTestRouter(), "GET", "/api/v1/stats", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp StatsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, uint64(0), resp.Ingress.Packets)
	assert.Equal(t, uint64(0), resp.Match.HitPackets)
}

func TestEgressCRUD(t *testing.T) {
	router := newTestRouter()

	// GET default
	w := doRequest(router, "GET", "/api/v1/response/egress", nil)
	require.Equal(t, http.StatusOK, w.Code)
	var getResp EgressResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &getResp))
	assert.Equal(t, "preserve", getResp.VLANMode)
	assert.False(t, getResp.Configured)

	// PUT
	w2 := doRequest(router, "PUT", "/api/v1/response/egress", putEgressRequest{IfIndex: 3})
	require.Equal(t, http.StatusOK, w2.Code)
	var putResp EgressResponse
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &putResp))
	assert.True(t, putResp.Configured)
	assert.Equal(t, uint32(3), putResp.IfIndex)

	// DELETE
	w3 := doRequest(router, "DELETE", "/api/v1/response/egress", nil)
	assert.Equal(t, http.StatusNoContent, w3.Code)
}

func TestAllRoutesRegistered(t *testing.T) {
	router := newTestRouter()
	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/health"},
		{"GET", "/api/v1/status"},
		{"GET", "/api/v1/attachments"},
		{"POST", "/api/v1/attachments"},
		{"GET", "/api/v1/attachments/1"},
		{"PATCH", "/api/v1/attachments/1"},
		{"DELETE", "/api/v1/attachments/1"},
		{"GET", "/api/v1/ruleset"},
		{"PUT", "/api/v1/ruleset"},
		{"DELETE", "/api/v1/ruleset"},
		{"GET", "/api/v1/events/stream"},
		{"GET", "/api/v1/stats"},
		{"GET", "/api/v1/response/egress"},
		{"PUT", "/api/v1/response/egress"},
		{"DELETE", "/api/v1/response/egress"},
	}

	for _, r := range routes {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			var body any
			if r.method == "PUT" || r.method == "POST" {
				body = map[string]any{}
			}
			w := doRequest(router, r.method, r.path, body)
			assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code, "route not registered")
		})
	}
}
