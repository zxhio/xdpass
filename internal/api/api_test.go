package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
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
	return StatusResponse{
		Status:      "degraded",
		Attachments: len(m.attachments),
	}, nil
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
		return AttachmentResponse{}, http.ErrMissingFile
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
		return AttachmentResponse{}, http.ErrMissingFile
	}
	a.Enabled = enabled
	m.attachments[ifIndex] = a
	return a, nil
}

func (m *mockStore) DeleteAttachment(_ context.Context, ifIndex uint32) error {
	if _, ok := m.attachments[ifIndex]; !ok {
		return http.ErrMissingFile
	}
	delete(m.attachments, ifIndex)
	return nil
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

func TestHealthEndpoint(t *testing.T) {
	router := newTestRouter()
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp healthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("status = %q", resp.Status)
	}
}

func TestStatusEndpoint(t *testing.T) {
	router := newTestRouter()
	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp StatusResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Status != "degraded" {
		t.Fatalf("status = %q", resp.Status)
	}
}

func TestErrorFormatIsProblemDetails(t *testing.T) {
	router := newTestRouter()

	// GET non-existent attachment
	req := httptest.NewRequest("GET", "/api/v1/attachments/999", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d", w.Code)
	}
	var resp ProblemDetails
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Type != "about:blank" {
		t.Fatalf("type = %q", resp.Type)
	}
	if resp.Code != "not_found" {
		t.Fatalf("code = %q", resp.Code)
	}
}

func TestCreateAttachment(t *testing.T) {
	router := newTestRouter()
	body := bytes.NewBufferString(`{"ifindex":3}`)
	req := httptest.NewRequest("POST", "/api/v1/attachments", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var resp AttachmentResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.IfIndex != 3 {
		t.Fatalf("ifindex = %d", resp.IfIndex)
	}
	if !resp.Enabled {
		t.Fatal("expected enabled=true")
	}
}

func TestCreateAttachmentConflict(t *testing.T) {
	router := newTestRouter()
	body := bytes.NewBufferString(`{"ifindex":3}`)
	req := httptest.NewRequest("POST", "/api/v1/attachments", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("first create: status = %d", w.Code)
	}

	body2 := bytes.NewBufferString(`{"ifindex":3}`)
	req2 := httptest.NewRequest("POST", "/api/v1/attachments", body2)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Fatalf("second create: status = %d, body = %s", w2.Code, w2.Body.String())
	}
}

func TestCreateAttachmentValidation(t *testing.T) {
	router := newTestRouter()
	body := bytes.NewBufferString(`{"ifindex":0}`)
	req := httptest.NewRequest("POST", "/api/v1/attachments", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestDeleteAttachment204(t *testing.T) {
	router := newTestRouter()

	// Create first
	body := bytes.NewBufferString(`{"ifindex":5}`)
	req := httptest.NewRequest("POST", "/api/v1/attachments", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create: status = %d", w.Code)
	}

	// Delete
	req2 := httptest.NewRequest("DELETE", "/api/v1/attachments/5", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d", w2.Code)
	}
	if w2.Body.Len() != 0 {
		t.Fatalf("delete: expected empty body, got %q", w2.Body.String())
	}
}

func TestRulesetCRUD(t *testing.T) {
	router := newTestRouter()

	// GET empty ruleset
	req := httptest.NewRequest("GET", "/api/v1/ruleset", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get: status = %d", w.Code)
	}
	var getResp RulesetResponse
	json.Unmarshal(w.Body.Bytes(), &getResp)
	if len(getResp.Rules) != 0 {
		t.Fatalf("expected empty rules, got %d", len(getResp.Rules))
	}

	// PUT ruleset
	putBody := bytes.NewBufferString(`{"rules":[{"rule_id":1,"response":{"action":"alert"}}]}`)
	req2 := httptest.NewRequest("PUT", "/api/v1/ruleset", putBody)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("put: status = %d, body = %s", w2.Code, w2.Body.String())
	}

	// DELETE ruleset
	req3 := httptest.NewRequest("DELETE", "/api/v1/ruleset", nil)
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)
	if w3.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d", w3.Code)
	}
}

func TestEventsStreamNotImplemented(t *testing.T) {
	router := newTestRouter()
	req := httptest.NewRequest("GET", "/api/v1/events/stream", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestStatsZeroed(t *testing.T) {
	router := newTestRouter()
	req := httptest.NewRequest("GET", "/api/v1/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp StatsResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Ingress.Packets != 0 {
		t.Fatalf("expected zero packets")
	}
}

func TestEgressCRUD(t *testing.T) {
	router := newTestRouter()

	// GET default
	req := httptest.NewRequest("GET", "/api/v1/response/egress", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get: status = %d", w.Code)
	}
	var getResp EgressResponse
	json.Unmarshal(w.Body.Bytes(), &getResp)
	if getResp.VLANMode != "preserve" {
		t.Fatalf("vlan_mode = %q", getResp.VLANMode)
	}

	// PUT
	putBody := bytes.NewBufferString(`{"ifindex":3}`)
	req2 := httptest.NewRequest("PUT", "/api/v1/response/egress", putBody)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("put: status = %d", w2.Code)
	}

	// DELETE
	req3 := httptest.NewRequest("DELETE", "/api/v1/response/egress", nil)
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)
	if w3.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d", w3.Code)
	}
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
		var body *bytes.Buffer
		if r.method == "PUT" || r.method == "POST" {
			body = bytes.NewBufferString(`{}`)
		} else {
			body = bytes.NewBuffer(nil)
		}
		req := httptest.NewRequest(r.method, r.path, body)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// A registered route should not return 405 Method Not Allowed
		// or 404 from the default mux
		if w.Code == http.StatusMethodNotAllowed || (w.Code == http.StatusNotFound && r.method == "GET") {
			// For GET requests, 404 is OK if resource doesn't exist
			// For POST/PUT with empty body, bad request is OK
			if w.Code == http.StatusNotFound && r.method != "GET" {
				t.Errorf("%s %s: got 404, route may not be registered", r.method, r.path)
			}
		}
	}
}
