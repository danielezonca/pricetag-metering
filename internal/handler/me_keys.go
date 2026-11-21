package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/maasapi"
	"github.com/redhat-et/pricetag-metering/internal/metrics"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

// Self-service key endpoints. They are deliberately separate from
// /api/v1/admin/keys: the admin surface accepts a target username, this one
// derives everything from the signed session and can never mint for someone
// else. The MaaS identity headers come from that derived identity.

func (h *AdminHandler) HandleMyKeys(w http.ResponseWriter, r *http.Request) {
	if h.cfg.StandaloneManagement() {
		w.Header().Set("Cache-Control", "no-store")
	}
	if h.maasClient == nil {
		http.Error(w, "key service is not configured", http.StatusServiceUnavailable)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/me/keys")
	if path == r.URL.Path {
		// Legacy alias: the old /me/keys proxy forwarded raw upstream calls.
		// Route it through the same self-scoped, validated handler instead.
		path = strings.TrimPrefix(r.URL.Path, "/me/keys")
	}
	path = strings.TrimSuffix(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "":
		h.myKeysList(w, r)
	case r.Method == http.MethodPost && path == "":
		h.myKeysCreate(w, r)
	case r.Method == http.MethodDelete && path != "":
		h.myKeysRevoke(w, r, strings.TrimPrefix(path, "/"))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// myKeyIdentity resolves the caller, their normalized groups, and the MaaS
// group to scope the request. MaaS requires one non-empty group header; a
// user with several groups is scoped to the first group that the live
// MaaSSubscription lists. Group MEMBERSHIP is not revalidated here: the
// groups come from the signed session (IdP assertion at login) and are only
// intersected with the subscription's group list, so an IdP removal takes
// effect when the session expires. See docs/oidc-rollout.md.
func (h *AdminHandler) myKeyIdentity(w http.ResponseWriter, r *http.Request) (username, group string, groups []string, ok bool) {
	username = strings.TrimSpace(caller(r, h.cfg))
	if username == "" {
		http.Error(w, "who are you?", http.StatusUnauthorized)
		return "", "", nil, false
	}
	if h.cfg.StandaloneManagement() {
		// Standalone keys always use the operator-configured unprivileged
		// group, never a stale administrator group from the browser session.
		if h.store == nil || h.cfg.PartnerUserKeyGroup == "" {
			http.Error(w, "personal key management unavailable", http.StatusServiceUnavailable)
			return "", "", nil, false
		}
		profile, err := h.store.PartnerUserByMaaSUsername(r.Context(), username)
		switch {
		case errors.Is(err, storage.ErrPartnerUserNotFound):
			http.Error(w, "active account required", http.StatusForbidden)
			return "", "", nil, false
		case err != nil:
			// A directory outage is not a verdict about the caller: answer
			// 503, like the current-user check in RequireAuth, instead of
			// presenting the caller's own account as inactive.
			http.Error(w, "account directory unavailable", http.StatusServiceUnavailable)
			return "", "", nil, false
		}
		if !profile.Active || profile.KeyRevocationPending {
			http.Error(w, "active account required", http.StatusForbidden)
			return "", "", nil, false
		}
		group = h.cfg.PartnerUserKeyGroup
		return username, group, []string{group}, true
	}
	groups = NormalizeGroups(sessionGroups(r, h.cfg))
	if len(groups) == 0 {
		http.Error(w, "your session has no EnMaaS group; sign in again", http.StatusForbidden)
		return "", "", nil, false
	}
	group = groups[0]
	// Prefer a group that the cluster's MaaSSubscription actually lists. When
	// the platform list is available, a session group that is not on it must
	// not fall through: that would let a forged/stale header scope a key.
	if h.k8sClient != nil {
		if platform, err := h.platformGroups(r.Context()); err == nil && len(platform) > 0 {
			for _, g := range groups {
				for _, pg := range platform {
					if strings.EqualFold(g, pg) {
						group = pg
						return username, group, groups, true
					}
				}
			}
			http.Error(w, "your session has no EnMaaS group enabled for key management", http.StatusForbidden)
			return "", "", nil, false
		}
	}
	return username, group, groups, true
}

// matchSessionGroup returns the session-cased group that equals requested, or
// an empty string when the caller is not a member. Case-insensitive matching
// preserves the platform's canonical spelling for the X-MaaS-Group header.
func matchSessionGroup(groups []string, requested string) string {
	for _, g := range groups {
		if strings.EqualFold(g, requested) {
			return g
		}
	}
	return ""
}

// keyGroupEnabled applies the live MaaSSubscription allow-list when it is
// available. A missing/unreadable list keeps the legacy behavior; the
// application-level session membership check still applies.
func (h *AdminHandler) keyGroupEnabled(ctx context.Context, group string) bool {
	if h.k8sClient == nil {
		return true
	}
	platform, err := h.platformGroups(ctx)
	if err != nil || len(platform) == 0 {
		return true
	}
	for _, pg := range platform {
		if strings.EqualFold(group, pg) {
			return true
		}
	}
	return false
}

func (h *AdminHandler) myKeysList(w http.ResponseWriter, r *http.Request) {
	username, group, _, ok := h.myKeyIdentity(w, r)
	if !ok {
		return
	}
	keys, err := h.maasClient.ListUserAPIKeys(r.Context(), username, group)
	if err != nil {
		slog.Error("self-service key list failed", "user", username, "error", err)
		http.Error(w, "could not load your keys", http.StatusBadGateway)
		return
	}
	if h.cfg.StandaloneManagement() {
		owned := []maasapi.APIKeyResponse{}
		for _, key := range keys {
			if strings.EqualFold(key.Username, username) {
				key.Key = ""
				owned = append(owned, key)
			}
		}
		keys = owned
	} else if keys == nil {
		keys = []maasapi.APIKeyResponse{}
	}
	writeJSON(w, map[string]any{"data": keys})
}

func (h *AdminHandler) myKeysCreate(w http.ResponseWriter, r *http.Request) {
	username, group, groups, ok := h.myKeyIdentity(w, r)
	if !ok {
		return
	}
	var body struct {
		Name      string `json:"name"`
		Group     string `json:"group"`
		ExpiresIn string `json:"expiresIn"`
	}
	var dec *json.Decoder
	if h.cfg.StandaloneManagement() {
		dec = json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	} else {
		dec = json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	}
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if h.cfg.StandaloneManagement() {
		if dec.Decode(new(any)) != io.EOF {
			http.Error(w, "expected one JSON object", http.StatusBadRequest)
			return
		}
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" || len(body.Name) > 64 {
		http.Error(w, "key name is required (max 64 characters)", http.StatusBadRequest)
		return
	}
	if body.Group != "" {
		matched := matchSessionGroup(groups, body.Group)
		if matched == "" {
			http.Error(w, "you are not a member of that group", http.StatusForbidden)
			return
		}
		if !h.keyGroupEnabled(r.Context(), matched) {
			http.Error(w, "that group is not enabled for key management", http.StatusForbidden)
			return
		}
		group = matched
	}

	expiresIn, err := h.validatedExpiry(body.ExpiresIn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	result, err := h.maasClient.CreateUserAPIKey(r.Context(), username, group, maasapi.CreateKeyRequest{
		Name:      body.Name,
		ExpiresIn: expiresIn,
		Labels:    map[string]string{"created_by": "pricetag-dashboard"},
	})
	if err != nil {
		// The MaaS error body is not echoed: it can contain request context.
		if errors.Is(err, maasapi.ErrUnknownCreateOutcome) {
			// The key may exist without a record: a retry could mint a second
			// key. Tell the user reconciliation is required instead of
			// suggesting they try again.
			slog.Error("self-service key create outcome unknown; operator reconciliation required", "user", username, "error", err)
			http.Error(w, "key creation outcome unknown; operator reconciliation required", http.StatusServiceUnavailable)
			return
		}
		slog.Error("self-service key create failed", "user", username, "error", err)
		http.Error(w, "could not create the key; try again", http.StatusBadGateway)
		return
	}
	// A 2xx create that omits the key id would leave standalone mode holding
	// a credential it cannot record, revoke, or reconcile by id. Fail the
	// mint instead of persisting an unaddressable reference. Cluster mode
	// uses the shared incomplete-response check above.
	if !h.cfg.StandaloneManagement() && rejectIncompleteKey(w, r, h.maasClient, result, username, group) {
		return
	}
	if h.cfg.StandaloneManagement() && strings.TrimSpace(result.ID) == "" {
		slog.Error("self-service key create returned no key id", "user", username)
		http.Error(w, "created key is missing its identifier; contact an administrator", http.StatusBadGateway)
		return
	}
	// A 2xx create that returns an id but not the one-time key leaves the
	// user with a credential nobody can ever use, and a record of it would
	// outlive the dismissal. Revoke by the returned id and fail the mint —
	// the same gate the management issuance applies. A failed cleanup
	// leaves a live key with no record, which the operator must reconcile.
	if h.cfg.StandaloneManagement() && strings.TrimSpace(result.Key) == "" {
		slog.Error("self-service key create returned no one-time key; revoking", "user", username, "key_id", result.ID)
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
		defer cancel()
		status, revokeErr := h.maasClient.RevokeUserAPIKey(cleanupCtx, result.ID, username, group)
		if revokeErr != nil || status < 200 || status > 299 {
			slog.Error("post-mint revocation failed; operator reconciliation required",
				"user", username, "key_id", result.ID, "status", status, "error", revokeErr)
			http.Error(w, "created key is unusable and could not be revoked; contact an administrator", http.StatusBadGateway)
			return
		}
		http.Error(w, "created key is unusable; it was revoked", http.StatusBadGateway)
		return
	}
	metrics.KeysMintedTotal.Inc()
	// The post-mint recheck is standalone-only: cluster mode keeps the
	// pre-standalone behavior of minting with no directory lookup afterward,
	// so a cluster mint is never revoked or rejected because of
	// partner-record state (docs/deployment-modes.md).
	if h.cfg.StandaloneManagement() && h.store != nil {
		// The identity check above does not lock the account; a deactivation
		// can commit while the mint is in flight. Re-check and revoke a key
		// that slipped past the revocation sweep rather than hand out a live
		// credential. This fails closed: an unreadable account state revokes
		// a freshly minted key the caller can simply re-request. The
		// state-returning lookup keeps deactivated and revocation-pending
		// accounts distinguishable from absent ones, so the no-record
		// exception below can never cover them.
		profile, err := h.store.ManagedUserByLogin(r.Context(), username)
		noRecord := errors.Is(err, storage.ErrPartnerUserNotFound)
		lookupFailed := err != nil && !noRecord
		var recordErr error
		if err == nil && profile.Active && !profile.KeyRevocationPending {
			recordErr = h.store.RecordPartnerUserKey(r.Context(), username, profile.UserID, result.ID, strings.ToLower(strings.TrimSpace(username)), body.Name)
		}
		if lookupFailed || noRecord ||
			(!noRecord && (!profile.Active || profile.KeyRevocationPending || errors.Is(recordErr, storage.ErrPartnerUserInactive))) {
			// The response must not claim a revocation that did not happen:
			// a failed cleanup leaves a live key with no local record, which
			// is exactly what the operator must reconcile.
			outcome := "key revoked"
			if result.ID != "" {
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
				defer cancel()
				status, revokeErr := h.maasClient.RevokeUserAPIKey(cleanupCtx, result.ID, username, group)
				if revokeErr != nil || status < 200 || status > 299 {
					outcome = "key revocation failed; operator reconciliation required"
					slog.Error("post-mint revocation failed; operator reconciliation required",
						"user", username, "key_id", result.ID, "status", status, "error", revokeErr)
				}
			}
			if lookupFailed {
				http.Error(w, "could not verify account state; "+outcome, http.StatusInternalServerError)
			} else {
				http.Error(w, "account is no longer active; "+outcome, http.StatusForbidden)
			}
			return
		}
		if recordErr != nil {
			outcome := "it was revoked"
			if result.ID != "" {
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
				defer cancel()
				status, revokeErr := h.maasClient.RevokeUserAPIKey(cleanupCtx, result.ID, username, group)
				if revokeErr != nil || status < 200 || status > 299 {
					outcome = "its revocation failed; operator reconciliation required"
					slog.Error("post-mint key recording failed; operator reconciliation required",
						"user", username, "key_id", result.ID, "status", status, "error", revokeErr)
				}
			}
			http.Error(w, "could not record the new key; "+outcome, http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, result)
}

// validatedExpiry enforces the deployment's key-expiry policy. The request
// may omit expiresIn (deployment default), or send a Go duration string.
func (h *AdminHandler) validatedExpiry(raw string) (string, error) {
	return validateKeyExpiry(h.cfg, raw)
}

// validateKeyExpiry is dependency-free so management endpoints can enforce
// the same policy without constructing an AdminHandler. Overflowing the
// configured maximum into a negative time.Duration would silently disable
// the cap, so the conversion saturates instead.
func validateKeyExpiry(cfg config.Config, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "default") {
		hours := cfg.KeyPolicy.DefaultExpiryHours
		if hours <= 0 {
			hours = 90 * 24
		}
		if cfg.StandaloneManagement() {
			if cfg.KeyPolicy.MaxExpiryHours > 0 && hours > cfg.KeyPolicy.MaxExpiryHours {
				return "", errText("default key lifetime exceeds the maximum allowed lifetime")
			}
			if hours > int((1<<63-1)/time.Hour) {
				return "", errText("default key lifetime is too large")
			}
		}
		return (time.Duration(hours) * time.Hour).String(), nil
	}
	if strings.EqualFold(raw, "none") || raw == "0" {
		if !cfg.KeyPolicy.AllowNoExpiry {
			return "", errText("keys must expire; choose a duration")
		}
		return "", nil
	}
	// MaaS and the standalone CLI also accept whole days. Normalize before
	// applying the same maximum used for native Go durations.
	if cfg.StandaloneManagement() && strings.HasSuffix(raw, "d") {
		days, err := strconv.ParseInt(strings.TrimSuffix(raw, "d"), 10, 64)
		if err != nil || days <= 0 || days > (1<<63-1)/int64(24*time.Hour) {
			return "", errText("invalid day duration")
		}
		raw = (time.Duration(days) * 24 * time.Hour).String()
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return "", errText("expiresIn must be a positive Go duration such as 720h")
	}
	var max time.Duration
	if maxHours := cfg.KeyPolicy.MaxExpiryHours; maxHours > 0 {
		if maxHours > int((1<<63-1)/time.Hour) {
			maxHours = int((1<<63 - 1) / time.Hour)
		}
		max = time.Duration(maxHours) * time.Hour
	}
	if max > 0 && d > max {
		return "", errText("expiresIn exceeds the maximum allowed lifetime")
	}
	return d.String(), nil
}

func (h *AdminHandler) myKeysRevoke(w http.ResponseWriter, r *http.Request, keyID string) {
	username, group, _, ok := h.myKeyIdentity(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(keyID) == "" {
		http.Error(w, "key id is required", http.StatusBadRequest)
		return
	}
	if h.cfg.StandaloneManagement() {
		owned, err := h.maasClient.OwnsKey(r.Context(), username, group, keyID)
		if err != nil {
			http.Error(w, "could not verify key ownership", http.StatusBadGateway)
			return
		}
		if !owned {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
	}
	status, err := h.maasClient.RevokeUserAPIKey(r.Context(), keyID, username, group)
	if err != nil {
		slog.Error("self-service key revoke failed", "user", username, "error", err)
		http.Error(w, "could not revoke the key", http.StatusBadGateway)
		return
	}
	switch status {
	case http.StatusNotFound, http.StatusForbidden:
		http.Error(w, "key not found", http.StatusNotFound)
	case http.StatusNoContent, http.StatusOK:
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "could not revoke the key", http.StatusBadGateway)
	}
}

// errText keeps the error strings out of the handler's HTTP write path.
type errText string

func (e errText) Error() string { return string(e) }
