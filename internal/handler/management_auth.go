package handler

import (
	"crypto/subtle"
	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/storage"
	"net/http"
	"strings"
)

// RequireBrowserOrigin protects cookie-authenticated mutations. The origin is
// deployment configuration, never inferred from caller-controlled proxy headers.
func RequireBrowserOrigin(origin string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			if origin == "" || r.Header.Get("Origin") != origin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				http.Error(w, "same-origin request required", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

// RequireManagement accepts a dedicated operator credential OR a super-admin
// browser session. It must never be used on inference or ordinary user routes.
func RequireManagement(cfg config.Config, store *storage.Store, auth func(http.HandlerFunc) http.HandlerFunc, next http.HandlerFunc) http.HandlerFunc {
	browser := auth(RequirePartnerSuperAdmin(cfg, store, RequireBrowserOrigin(cfg.ManagementPublicOrigin, next)))
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if cfg.ManagementAPISecret == "" {
			http.Error(w, "management API is not configured", 503)
			return
		}
		// Only the Bearer scheme carries the management credential (the scheme
		// is case-insensitive per RFC 7235). Any other Authorization value
		// (for example a browser's Basic header) belongs to the session path
		// and must not be read as a failed token attempt.
		raw := r.Header.Get("Authorization")
		const bearerScheme = "bearer "
		if len(raw) >= len(bearerScheme) && strings.EqualFold(raw[:len(bearerScheme)], bearerScheme) {
			// RFC 7235 allows one or more spaces between scheme and token.
			token := strings.TrimSpace(raw[len(bearerScheme):])
			if subtle.ConstantTimeCompare([]byte(token), []byte(cfg.ManagementAPISecret)) != 1 {
				http.Error(w, "unauthorized", 401)
				return
			}
			r.Header.Set(cfg.UserHeader, "management-service")
			// The session path deletes caller-supplied identity headers
			// before rebuilding them (RequireAuth); match that invariant so
			// a bearer request cannot carry forged group state past this
			// middleware even if a future handler reads it.
			r.Header.Del(cfg.GroupsHeader)
			// Delegated handlers derive their audit actor from other identity
			// headers (quotaAdminActor reads realUserHeader, falling back to
			// X-Forwarded-User). Overwrite those too, exactly like the
			// session path's RequireAuth rebuilds them, so a bearer-
			// authenticated caller cannot forge audit attribution.
			r.Header.Set(realUserHeader, "management-service")
			r.Header.Set("X-Forwarded-User", "management-service")
			next(w, r)
			return
		}
		browser(w, r)
	}
}
