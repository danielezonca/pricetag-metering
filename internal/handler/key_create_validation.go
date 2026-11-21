package handler

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/maasapi"
)

// rejectIncompleteKey keeps the returned ID available for compensation when
// MaaS accepted a create but omitted its one-time secret. Neither an unknown
// key nor an undeliverable secret may be reported as a successful issuance.
func rejectIncompleteKey(w http.ResponseWriter, r *http.Request, client *maasapi.Client, key *maasapi.APIKeyResponse, username, group string) bool {
	if key == nil || strings.TrimSpace(key.ID) == "" {
		slog.Error("key create returned no id; operator reconciliation required", "user", username)
		http.Error(w, "key creation outcome unknown; operator reconciliation required", http.StatusServiceUnavailable)
		return true
	}
	if strings.TrimSpace(key.Key) != "" {
		return false
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancel()
	status, err := client.RevokeUserAPIKey(cleanup, key.ID, username, group)
	if err != nil || (status != http.StatusNotFound && (status < 200 || status >= 300)) {
		slog.Error("unusable key compensation failed; operator reconciliation required", "user", username, "key_id", key.ID, "status", status, "error", err)
		http.Error(w, "key creation failed; operator reconciliation required", http.StatusServiceUnavailable)
		return true
	}
	http.Error(w, "created key is unusable; it was revoked", http.StatusBadGateway)
	return true
}
