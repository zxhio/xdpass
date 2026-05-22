package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// --- Health ---

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
}

// --- Status ---

func handleStatus(svc StatusService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp, err := svc.Status(r.Context())
		if err != nil {
			logrus.WithError(err).Error("Fail to get status")
			writeInternalError(w, "fail to get status")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// --- Attachments ---

func handleListAttachments(svc AttachmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		items, err := svc.ListAttachments(r.Context())
		if err != nil {
			logrus.WithError(err).Error("Fail to list attachments")
			writeInternalError(w, "fail to list attachments")
			return
		}
		writeJSON(w, http.StatusOK, items)
	}
}

func handleGetAttachment(svc AttachmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ifIndex, err := parseIfIndex(r.PathValue("ifindex"))
		if err != nil {
			writeValidationFailed(w, "ifindex must be a positive integer")
			return
		}

		resp, err := svc.GetAttachment(r.Context(), ifIndex)
		if err != nil {
			writeNotFound(w, "attachment not found")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleCreateAttachment(svc AttachmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req AttachmentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBadRequest(w, "invalid JSON body")
			return
		}

		if r.URL.Query().Get("dry_run") == "true" {
			resp, err := svc.DryRunAttachment(r.Context(), req)
			if err != nil {
				var validationErr *ServiceValidationError
				if errors.As(err, &validationErr) {
					writeValidationFailed(w, validationErr.Detail)
					return
				}
				writeValidationFailed(w, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}

		resp, err := svc.CreateAttachment(r.Context(), req)
		if err != nil {
			var validationErr *ServiceValidationError
			if errors.As(err, &validationErr) {
				writeValidationFailed(w, validationErr.Detail)
				return
			}
			if isRuntimeFailed(err) {
				logrus.WithError(err).Error("Fail to create attachment")
				writeRuntimeFailed(w, err.Error())
				return
			}
			writeConflict(w, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, resp)
	}
}

func handlePatchAttachment(svc AttachmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ifIndex, err := parseIfIndex(r.PathValue("ifindex"))
		if err != nil {
			writeValidationFailed(w, "ifindex must be a positive integer")
			return
		}

		var req patchAttachmentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBadRequest(w, "invalid JSON body")
			return
		}
		if req.Enabled == nil {
			writeValidationFailed(w, "enabled is required")
			return
		}

		resp, err := svc.PatchAttachment(r.Context(), ifIndex, *req.Enabled)
		if err != nil {
			writeNotFound(w, "attachment not found")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleDeleteAttachment(svc AttachmentService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ifIndex, err := parseIfIndex(r.PathValue("ifindex"))
		if err != nil {
			writeValidationFailed(w, "ifindex must be a positive integer")
			return
		}

		if err := svc.DeleteAttachment(r.Context(), ifIndex); err != nil {
			writeNotFound(w, "attachment not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- Ruleset ---

func handleGetRuleset(svc RulesetService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp, err := svc.GetRuleset(r.Context())
		if err != nil {
			logrus.WithError(err).Error("Fail to get ruleset")
			writeInternalError(w, "fail to get ruleset")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handlePutRuleset(svc RulesetService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RulesetResponse
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeBadRequest(w, fmt.Sprintf("invalid JSON body: %s", err))
			return
		}

		if r.URL.Query().Get("dry_run") == "true" {
			resp, err := svc.DryRunRuleset(r.Context(), req.Rules)
			if err != nil {
				writeValidationFailed(w, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}

		resp, err := svc.ReplaceRuleset(r.Context(), req.Rules)
		if err != nil {
			if isRuntimeFailed(err) {
				writeRuntimeFailed(w, err.Error())
				return
			}
			writeValidationFailed(w, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleDeleteRuleset(svc RulesetService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := svc.DeleteRuleset(r.Context()); err != nil {
			logrus.WithError(err).Error("Fail to delete ruleset")
			writeInternalError(w, "fail to delete ruleset")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- Events ---

func handleEventsStream(stream EventStreamer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeInternalError(w, "streaming not supported")
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		sub := stream.Subscribe()
		defer stream.Unsubscribe(sub)

		for {
			select {
			case <-r.Context().Done():
				return
			case <-sub.Done:
				return
			case event, ok := <-sub.Events:
				if !ok {
					return
				}
				data, err := json.Marshal(event)
				if err != nil {
					continue
				}
				fmt.Fprintf(w, "event: rule_event\ndata: %s\n\n", data)
				flusher.Flush()
			}
		}
	}
}

// --- Stats ---

func handleGetStats(svc StatsService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp, err := svc.GetStats(r.Context())
		if err != nil {
			logrus.WithError(err).Error("Fail to get stats")
			writeInternalError(w, "fail to get stats")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// --- Response Egress ---

func handleGetEgress(svc EgressService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp, err := svc.GetEgress(r.Context())
		if err != nil {
			logrus.WithError(err).Error("Fail to get response egress")
			writeInternalError(w, "fail to get response egress")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handlePutEgress(svc EgressService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req putEgressRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBadRequest(w, "invalid JSON body")
			return
		}

		if req.IfIndex == 0 {
			writeValidationFailed(w, "ifindex must be greater than 0")
			return
		}

		resp, err := svc.ReplaceEgress(r.Context(), req.IfIndex, req.IfName, req.VLANMode)
		if err != nil {
			var sve *ServiceValidationError
			if errors.As(err, &sve) {
				writeValidationFailed(w, err.Error())
			} else {
				logrus.WithError(err).Error("Fail to replace response egress")
				writeRuntimeFailed(w, err.Error())
			}
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleDeleteEgress(svc EgressService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := svc.DeleteEgress(r.Context()); err != nil {
			logrus.WithError(err).Error("Fail to delete response egress")
			writeInternalError(w, "fail to delete response egress")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- Dispatch ---

func handleGetDispatch(svc DispatchService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp, err := svc.GetDispatch(r.Context())
		if err != nil {
			logrus.WithError(err).Error("Fail to get dispatch")
			writeInternalError(w, "fail to get dispatch")
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handlePutDispatch(svc DispatchService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req PutDispatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeBadRequest(w, "invalid JSON body")
			return
		}

		if req.IfIndex == 0 {
			writeValidationFailed(w, "ifindex must be greater than 0")
			return
		}

		resp, err := svc.ReplaceDispatch(r.Context(), req)
		if err != nil {
			var sve *ServiceValidationError
			if errors.As(err, &sve) {
				writeValidationFailed(w, err.Error())
			} else {
				logrus.WithError(err).Error("Fail to replace dispatch")
				writeRuntimeFailed(w, err.Error())
			}
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func handleDeleteDispatch(svc DispatchService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := svc.DeleteDispatch(r.Context()); err != nil {
			logrus.WithError(err).Error("Fail to delete dispatch")
			writeInternalError(w, "fail to delete dispatch")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- helpers ---

func parseIfIndex(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil || v == 0 {
		return 0, strconv.ErrSyntax
	}
	return uint32(v), nil
}

func isRuntimeFailed(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "write maps") ||
		strings.Contains(msg, "clear maps") ||
		strings.Contains(msg, "load bpf") ||
		strings.Contains(msg, "attach xdp") ||
		strings.Contains(msg, "xsk start")
}
