package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStore implements all service interfaces for testing.
type mockStore struct {
	attachments map[uint32]AttachmentResponse
	rules       []RuleResponse
	dispatch    *DispatchResponse
}

func newMockStore() *mockStore {
	return &mockStore{attachments: make(map[uint32]AttachmentResponse)}
}

func boolPtr(v bool) *bool { return &v }

func (m *mockStore) Status(_ context.Context) (StatusResponse, error) {
	return StatusResponse{Status: "running", Attachments: len(m.attachments)}, nil
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
	if req.IfIndex == 0 {
		return AttachmentResponse{}, &ServiceValidationError{Detail: "ifindex must be greater than 0"}
	}
	if _, exists := m.attachments[req.IfIndex]; exists {
		return AttachmentResponse{}, errors.New("already exists")
	}
	resp := AttachmentResponse{IfIndex: req.IfIndex, Enabled: true, AttachMode: "generic", MissVerdict: "pass"}
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
		return AttachmentResponse{}, &ServiceValidationError{Detail: "ifindex must be greater than 0"}
	}
	return AttachmentResponse{IfIndex: req.IfIndex, Enabled: true, AttachMode: "generic", MissVerdict: "pass"}, nil
}

func (m *mockStore) GetRuleset(_ context.Context) (RulesetResponse, error) {
	return RulesetResponse{Rules: m.rules}, nil
}

func (m *mockStore) ReplaceRuleset(_ context.Context, rules []RuleResponse) (RulesetResponse, error) {
	m.rules = rules
	return RulesetResponse{Rules: m.rules}, nil
}

func (m *mockStore) DryRunRuleset(_ context.Context, rules []RuleResponse) (RulesetResponse, error) {
	return RulesetResponse{Rules: rules}, nil
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

func (m *mockStore) Subscribe() *EventSubscription {
	return &EventSubscription{
		Events: make(chan EventData, 64),
		Done:   make(chan struct{}),
	}
}

func (m *mockStore) Unsubscribe(sub *EventSubscription) {
	close(sub.Done)
}

func (m *mockStore) GetDispatch(_ context.Context) (DispatchResponse, error) {
	if m.dispatch != nil {
		return *m.dispatch, nil
	}
	return DispatchResponse{QueueSize: 4096}, nil
}

func (m *mockStore) ReplaceDispatch(_ context.Context, req PutDispatchRequest) (DispatchResponse, error) {
	resp := DispatchResponse{
		Enabled:    req.Enabled,
		Configured: true,
		IfIndex:    req.IfIndex,
		IfName:     req.IfName,
		QueueSize:  req.QueueSize,
	}
	if resp.QueueSize == 0 {
		resp.QueueSize = 4096
	}
	m.dispatch = &resp
	return resp, nil
}

func (m *mockStore) DeleteDispatch(_ context.Context) error {
	m.dispatch = nil
	return nil
}

func newTestRouter() http.Handler {
	s := newMockStore()
	return NewRouter(RouterDeps{
		Status: s, Attachments: s, Ruleset: s, Stats: s, Egress: s, Dispatch: s, Events: s,
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
	assert.Equal(t, "running", resp.Status)
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
	assert.Equal(t, "generic", resp.AttachMode)
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
		Rules: []RuleResponse{{
			RuleID: 1,
			Match: &MatchResponse{
				Protocol: "tcp",
				TCP: &TCPMatch{
					Flags: &TCPFlags{SYN: boolPtr(true)},
				},
			},
			Response: ResponseResponse{Action: "alert"},
		}},
	})
	require.Equal(t, http.StatusOK, w2.Code)

	// GET after PUT
	w3 := doRequest(router, "GET", "/api/v1/ruleset", nil)
	require.Equal(t, http.StatusOK, w3.Code)
	var getResp2 RulesetResponse
	require.NoError(t, json.Unmarshal(w3.Body.Bytes(), &getResp2))
	require.Len(t, getResp2.Rules, 1)
	assert.Equal(t, uint32(1), getResp2.Rules[0].RuleID)
	require.NotNil(t, getResp2.Rules[0].Match)
	require.NotNil(t, getResp2.Rules[0].Match.TCP)
	require.NotNil(t, getResp2.Rules[0].Match.TCP.Flags)
	assert.True(t, *getResp2.Rules[0].Match.TCP.Flags.SYN)

	// DELETE
	w4 := doRequest(router, "DELETE", "/api/v1/ruleset", nil)
	assert.Equal(t, http.StatusNoContent, w4.Code)
}

func TestPutRulesetRejectsLegacyMatchFields(t *testing.T) {
	router := newTestRouter()

	tests := []struct {
		name  string
		match map[string]any
	}{
		{name: "tcp_flags", match: map[string]any{"protocol": "tcp", "tcp_flags": map[string]any{"syn": true}}},
		{name: "icmp_type", match: map[string]any{"protocol": "icmp", "icmp_type": "echo_request"}},
		{name: "arp_op", match: map[string]any{"protocol": "arp", "arp_op": "request"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := doRequest(router, "PUT", "/api/v1/ruleset", map[string]any{
				"rules": []map[string]any{
					{
						"rule_id":  1,
						"match":    tt.match,
						"response": map[string]any{"action": "alert"},
					},
				},
			})
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestEventsStreamSSE(t *testing.T) {
	handler := newTestRouter()
	req := httptest.NewRequest("GET", "/api/v1/events/stream", nil)
	ctx, cancel := context.WithCancel(req.Context())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		handler.ServeHTTP(w, req)
		close(done)
	}()

	// Give the handler time to set headers, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/event-stream", w.Header().Get("Content-Type"))
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

func TestEgressPutIfIndexZero(t *testing.T) {
	router := newTestRouter()
	w := doRequest(router, "PUT", "/api/v1/response/egress", putEgressRequest{IfIndex: 0})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ProblemDetails
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, CodeValidationFailed, resp.Code)
}

func TestEgressPutInvalidVLANMode(t *testing.T) {
	// Use a mock that validates vlanMode.
	s := &mockEgressValidator{}
	router := NewRouter(RouterDeps{
		Status: s, Attachments: s, Ruleset: s, Stats: s, Egress: s, Dispatch: s, Events: s,
	})
	w := doRequest(router, "PUT", "/api/v1/response/egress", putEgressRequest{IfIndex: 3, VLANMode: "invalid"})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestEgressDeleteIdempotent(t *testing.T) {
	router := newTestRouter()
	// DELETE when not configured should still return 204.
	w := doRequest(router, "DELETE", "/api/v1/response/egress", nil)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

// mockEgressValidator returns validation errors for invalid vlan_mode.
type mockEgressValidator struct {
	mockStore
}

func (m *mockEgressValidator) ReplaceEgress(_ context.Context, ifIndex uint32, _, vlanMode string) (EgressResponse, error) {
	if vlanMode != "" && vlanMode != "preserve" && vlanMode != "access" {
		return EgressResponse{}, &ServiceValidationError{Detail: "invalid vlan_mode: " + vlanMode}
	}
	return EgressResponse{Configured: true, IfIndex: ifIndex, VLANMode: vlanMode}, nil
}

func TestDispatchCRUD(t *testing.T) {
	router := newTestRouter()

	// GET default (not configured)
	w := doRequest(router, "GET", "/api/v1/dispatch", nil)
	require.Equal(t, http.StatusOK, w.Code)
	var getResp DispatchResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &getResp))
	assert.False(t, getResp.Configured)
	assert.False(t, getResp.Enabled)
	assert.Equal(t, 4096, getResp.QueueSize)

	// PUT
	w2 := doRequest(router, "PUT", "/api/v1/dispatch", PutDispatchRequest{
		Enabled:   true,
		IfIndex:   3,
		QueueSize: 1024,
	})
	require.Equal(t, http.StatusOK, w2.Code)
	var putResp DispatchResponse
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &putResp))
	assert.True(t, putResp.Configured)
	assert.True(t, putResp.Enabled)
	assert.Equal(t, uint32(3), putResp.IfIndex)
	assert.Equal(t, 1024, putResp.QueueSize)

	// GET after PUT
	w3 := doRequest(router, "GET", "/api/v1/dispatch", nil)
	require.Equal(t, http.StatusOK, w3.Code)
	var getResp2 DispatchResponse
	require.NoError(t, json.Unmarshal(w3.Body.Bytes(), &getResp2))
	assert.True(t, getResp2.Configured)
	assert.Equal(t, uint32(3), getResp2.IfIndex)

	// DELETE
	w4 := doRequest(router, "DELETE", "/api/v1/dispatch", nil)
	assert.Equal(t, http.StatusNoContent, w4.Code)

	// GET after DELETE
	w5 := doRequest(router, "GET", "/api/v1/dispatch", nil)
	require.Equal(t, http.StatusOK, w5.Code)
	var getResp3 DispatchResponse
	require.NoError(t, json.Unmarshal(w5.Body.Bytes(), &getResp3))
	assert.False(t, getResp3.Configured)
}

func TestDispatchPutIfIndexZero(t *testing.T) {
	w := doRequest(newTestRouter(), "PUT", "/api/v1/dispatch", PutDispatchRequest{
		Enabled: true,
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp ProblemDetails
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, CodeValidationFailed, resp.Code)
}

func TestDispatchDeleteIdempotent(t *testing.T) {
	router := newTestRouter()
	w := doRequest(router, "DELETE", "/api/v1/dispatch", nil)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestDispatchStatsInStatsResponse(t *testing.T) {
	w := doRequest(newTestRouter(), "GET", "/api/v1/stats", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp StatsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, uint64(0), resp.Dispatch.EnqueuePackets)
	assert.Equal(t, uint64(0), resp.Dispatch.Packets)
	assert.Equal(t, uint64(0), resp.Dispatch.DroppedPackets)
}

func TestDispatchConfiguredInStatus(t *testing.T) {
	w := doRequest(newTestRouter(), "GET", "/api/v1/status", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp StatusResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.DispatchConfigured)
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
		{"GET", "/api/v1/dispatch"},
		{"PUT", "/api/v1/dispatch"},
		{"DELETE", "/api/v1/dispatch"},
	}

	for _, r := range routes {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			// Skip SSE endpoint as it blocks waiting for events.
			if r.path == "/api/v1/events/stream" {
				t.Skip("SSE endpoint blocks, tested separately")
			}
			var body any
			if r.method == "PUT" || r.method == "POST" {
				body = map[string]any{}
			}
			w := doRequest(router, r.method, r.path, body)
			assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code, "route not registered")
		})
	}
}
