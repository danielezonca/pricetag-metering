package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/maasapi"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

// NewManagementKeysHandler is protected by RequireManagement. It issues an
// onboarding key as the selected user, never as the operator's MaaS identity.
func NewManagementKeysHandler(store *storage.Store, cfg config.Config, maas *maasapi.Client) http.HandlerFunc {
	slots := make(chan struct{}, partnerMintConcurrency)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		if cfg.PartnerUserKeyGroup == "" {
			http.Error(w, "key group not configured", 503)
			return
		}
		// Minting a key for an arbitrary active user is an operator
		// privilege: RequireManagement gates this endpoint on the shared
		// management credential or a super-admin browser session, either of
		// which is trusted to act for every account. Self-service minting
		// stays on /api/v1/me/keys, which derives the subject from the
		// signed session and can never target another user.
		var body struct {
			Subject   string `json:"subject"`
			Name      string `json:"name"`
			ExpiresIn string `json:"expiresIn"`
		}
		if !decodeStandaloneJSON(w, r, &body) {
			return
		}
		if strings.TrimSpace(body.Name) == "" || len(body.Name) > 128 || body.ExpiresIn == "" || len(body.ExpiresIn) > 64 {
			http.Error(w, "name and finite lifetime are required", 400)
			return
		}
		if strings.TrimSpace(body.Subject) == "" || len(body.Subject) > 128 {
			http.Error(w, "subject is required", 400)
			return
		}
		user, err := store.PartnerUserByMaaSUsername(r.Context(), body.Subject)
		switch {
		case errors.Is(err, storage.ErrPartnerUserNotFound):
			http.Error(w, "active user required", 409)
			return
		case err != nil:
			// A directory outage is not a verdict about the subject: answer
			// 503, like the current-user check in RequireAuth, so a
			// retryable failure is not reported as a validation error.
			http.Error(w, "account directory unavailable", 503)
			return
		}
		if !user.Active || user.KeyRevocationPending {
			http.Error(w, "active user required", 409)
			return
		}
		// The storage lookup matches logins case-insensitively and ignores
		// surrounding whitespace, but the key service and the audit record
		// must use the account's stored login spelling: forwarding the raw
		// request value could mint and record the key against two
		// differently-normalized spellings of the same identity. Only the
		// current login is mintable — a retained (renamed-away) spelling
		// still attributes usage to the account, but new credentials for it
		// would outlive the rename that retired it, so a request naming
		// only a retained spelling is rejected instead of canonicalized
		// onto it.
		current, err := store.CurrentPartnerUserLogin(r.Context(), user.UserID)
		if err != nil {
			if errors.Is(err, storage.ErrPartnerUserNotFound) {
				http.Error(w, "active user required", 409)
			} else {
				http.Error(w, "account directory unavailable", 503)
			}
			return
		}
		if !strings.EqualFold(current, strings.TrimSpace(body.Subject)) {
			http.Error(w, "subject is not the account's current login", 409)
			return
		}
		subject := current
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "key issuance busy", 429)
			return
		}
		expiry, err := validateKeyExpiry(cfg, body.ExpiresIn)
		if err != nil || expiry == "" {
			http.Error(w, "invalid finite lifetime", 400)
			return
		}
		key, err := maas.CreateUserAPIKey(r.Context(), subject, cfg.PartnerUserKeyGroup, maasapi.CreateKeyRequest{Name: body.Name, ExpiresIn: expiry})
		if err != nil {
			if errors.Is(err, maasapi.ErrUnknownCreateOutcome) {
				// A 2xx whose body could not be decoded: the key may exist in
				// MaaS without a local record. Report reconciliation rather
				// than a definitive rejection the operator might "fix" by
				// minting a second key.
				slog.Error("key issuance outcome unknown; operator reconciliation required",
					"user_id", user.UserID, "subject", subject, "key_name", body.Name)
				http.Error(w, "key issuance failed; operator reconciliation required", 503)
				return
			}
			http.Error(w, "key service rejected issuance", 502)
			return
		}
		// A 2xx create that omits the key id cannot be recorded, revoked, or
		// reconciled by id. Fail the issuance with the subject and key name
		// as the reconciliation signal instead of attempting a revocation
		// that cannot identify the key.
		if strings.TrimSpace(key.ID) == "" {
			slog.Error("key issuance returned no key id; operator reconciliation required",
				"user_id", user.UserID, "subject", subject, "key_name", body.Name)
			http.Error(w, "key issuance failed; operator reconciliation required", 503)
			return
		}
		// A 2xx create that returns an id but not the one-time secret leaves
		// the account with a key nobody can ever use: the secret is shown
		// exactly once, at issuance. Unlike the missing-id case the key can
		// be identified, so revoke it and refuse the issuance instead of
		// recording a "successfully issued" key with no deliverable secret.
		if strings.TrimSpace(key.Key) == "" {
			slog.Error("key issuance returned no key secret; operator reconciliation required",
				"user_id", user.UserID, "subject", subject, "key_name", body.Name, "key_id", key.ID)
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
			defer cancel()
			status, revokeErr := maas.RevokeUserAPIKey(cleanupCtx, key.ID, subject, cfg.PartnerUserKeyGroup)
			if revokeErr != nil || status < 200 || status > 299 {
				slog.Error("key issuance compensation failed; operator reconciliation required",
					"user_id", user.UserID, "key_id", key.ID, "status", status, "error", revokeErr)
				http.Error(w, "key issuance failed; operator reconciliation required", 503)
				return
			}
			http.Error(w, "key issuance cancelled", 409)
			return
		}
		if err = store.RecordPartnerUserKey(r.Context(), r.Header.Get(cfg.UserHeader), user.UserID, key.ID, subject, body.Name); err != nil {
			// The compensating revocation must run even when the caller has
			// disconnected mid-request: detach from the (possibly cancelled)
			// request context and bound the cleanup. RevokeUserAPIKey reports
			// upstream HTTP failures as a status, not an error, so a non-2xx
			// answer must take the reconciliation path too.
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
			defer cancel()
			status, revokeErr := maas.RevokeUserAPIKey(cleanupCtx, key.ID, subject, cfg.PartnerUserKeyGroup)
			if revokeErr != nil || status < 200 || status > 299 {
				// The key is live in MaaS but unrecorded here. Log the id
				// (never the secret) as the durable reconciliation signal.
				slog.Error("key issuance compensation failed; operator reconciliation required",
					"user_id", user.UserID, "key_id", key.ID, "status", status, "error", revokeErr)
				http.Error(w, "key issuance failed; operator reconciliation required", 503)
				return
			}
			http.Error(w, "key issuance cancelled", 409)
			return
		}
		writeJSON(w, key)
	}
}

// NewManagementKeyRevocationsHandler is administrator-only via RequireManagement.
// Every login attached to the selected stable identity is covered, even after
// suspension. MaaS revokes
// each login atomically; a partial upstream failure is explicit and safely retryable.
func NewManagementKeyRevocationsHandler(store *storage.Store, cfg config.Config, maas *maasapi.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		if cfg.PartnerUserKeyGroup == "" {
			http.Error(w, "key group not configured", http.StatusServiceUnavailable)
			return
		}
		var body struct {
			Subject string `json:"subject"`
			DryRun  bool   `json:"dry_run"`
		}
		if !decodeStandaloneJSON(w, r, &body) {
			return
		}
		if strings.TrimSpace(body.Subject) == "" || len(body.Subject) > 128 {
			http.Error(w, "invalid subject", 400)
			return
		}
		user, err := store.ManagedUserByLogin(r.Context(), body.Subject)
		if err != nil {
			if errors.Is(err, storage.ErrPartnerUserNotFound) {
				http.Error(w, "user not found", 404)
			} else {
				// A directory outage is not a verdict about the subject:
				// answer 503, like the issuance handler above, so a
				// retryable failure is not reported as a missing user.
				http.Error(w, "account directory unavailable", 503)
			}
			return
		}
		logins, err := store.ListPartnerUsernames(r.Context(), user.UserID)
		if err != nil || len(logins) == 0 {
			http.Error(w, "user logins unavailable", 503)
			return
		}
		if !body.DryRun {
			if err := store.Audit(r.Context(), r.Header.Get(cfg.UserHeader), "partner_user.keys_revoke_requested", user.UserID, map[string]any{"logins": logins}); err != nil {
				http.Error(w, "revocation audit unavailable", 503)
				return
			}
		}
		total := 0
		countKnown := true
		seen := make(map[string]bool)
		stable := false
		// Renames retain old logins and may add new ones while MaaS is
		// processing a sweep. Re-read after each round and cover new logins;
		// fail explicitly if directory churn prevents a bounded completion.
		for round := 0; round < 3; round++ {
			for _, login := range logins {
				if seen[login] {
					continue
				}
				count, known, err := maas.RevokeAllUserAPIKeys(r.Context(), login, cfg.PartnerUserKeyGroup, body.DryRun)
				if err != nil {
					http.Error(w, "key service failed; revocation may be partial, retry this user", 502)
					return
				}
				total += count
				if !known {
					countKnown = false
				}
				seen[login] = true
			}
			logins, err = store.ListPartnerUsernames(r.Context(), user.UserID)
			if err != nil || len(logins) == 0 {
				http.Error(w, "user logins unavailable; revocation may be partial", 503)
				return
			}
			stable = true
			for _, login := range logins {
				if !seen[login] {
					stable = false
					break
				}
			}
			if stable {
				break
			}
		}
		if !stable {
			http.Error(w, "user logins changed during revocation; retry this user", http.StatusConflict)
			return
		}
		// A bodyless revocation succeeds but reports no count: represent it as
		// unknown rather than auditing or answering with a fabricated zero.
		var countValue any = total
		if !countKnown {
			countValue = nil
		}
		if !body.DryRun {
			if err := store.Audit(r.Context(), r.Header.Get(cfg.UserHeader), "partner_user.keys_revoked", user.UserID, map[string]any{"count": countValue}); err != nil {
				http.Error(w, "keys revoked; audit completion unavailable", 503)
				return
			}
		}
		writeJSON(w, map[string]any{"count": countValue, "dry_run": body.DryRun})
	}
}
