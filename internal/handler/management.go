package handler

import (
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

func NewManagementHandler(store *storage.Store, cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor := r.Header.Get(cfg.UserHeader)
		route := strings.TrimPrefix(r.URL.Path, "/api/v1/management/")
		switch route {
		case "policy":
			NewQuotaAdminHandler(store).HandlePolicy(w, r)
		case "users":
			if r.Method == http.MethodGet {
				// Management must retain suspended accounts so administrators can
				// inspect and reactivate them. Ordinary directory views stay active-only.
				// Like the budgets listing, the directory is paginated: a single
				// request reads a bounded window instead of walking the whole
				// directory, which would be an unbounded read on large tenants.
				query := r.URL.Query()
				for name, values := range query {
					if (name != "limit" && name != "offset") || len(values) != 1 {
						http.Error(w, "invalid user query", 400)
						return
					}
				}
				limit := 100
				if raw, ok := query["limit"]; ok {
					var err error
					limit, err = strconv.Atoi(raw[0])
					if err != nil || (limit != 50 && limit != 100 && limit != 250 && limit != 500) {
						http.Error(w, "invalid limit", 400)
						return
					}
				}
				offset := 0
				if raw, ok := query["offset"]; ok {
					var err error
					offset, err = strconv.Atoi(raw[0])
					if err != nil || offset < 0 || offset > 1000000 {
						http.Error(w, "invalid offset", 400)
						return
					}
				}
				page, err := store.ListPartnerUsers(r.Context(), nil, true, limit, offset)
				if err != nil {
					http.Error(w, "user query failed", 500)
					return
				}
				type managedUser struct {
					adminPartnerUserResponse
					Logins []string `json:"logins"`
				}
				userIDs := make([]string, 0, len(page.Users))
				for _, u := range page.Users {
					userIDs = append(userIDs, u.UserID)
				}
				loginsByUser, err := store.ListPartnerUsernamesBatch(r.Context(), userIDs)
				if err != nil {
					http.Error(w, "user query failed", 500)
					return
				}
				rows := make([]managedUser, 0, len(page.Users))
				for _, u := range page.Users {
					rows = append(rows, managedUser{adminPartnerUser(u), loginsByUser[u.UserID]})
				}
				writeJSON(w, map[string]any{"data": rows, "has_more": page.HasMore})
				return
			}
			if r.Method != http.MethodPut {
				http.Error(w, "method not allowed", 405)
				return
			}
			var body storage.LoginProvision
			if !decodeStandaloneJSON(w, r, &body) {
				return
			}
			// Compare stable identities, not login spellings: a renamed
			// administrator can submit one of their retained logins as the
			// subject, and ProvisionLogin resolves it back to their own
			// account, which a plain string comparison would miss.
			actorID, actorErr := store.PartnerUserIDByLogin(r.Context(), actor)
			targetID, targetErr := store.PartnerUserIDByLogin(r.Context(), body.Subject)
			if actorErr == nil && targetErr == nil && actorID == targetID && ((body.Active != nil && !*body.Active) || (body.Role != "" && body.Role != storage.PartnerRoleSuperAdmin)) {
				http.Error(w, "cannot remove own management access", 400)
				return
			}
			// Like key issuance, provisioning accepts only the account's
			// current login: a retained (renamed-away) spelling resolves to
			// the owning account, so accepting it would silently edit that
			// account instead of reporting that the requested login is
			// taken. A suspended target keeps the permissive path — its
			// current login is not resolvable while inactive, and
			// reactivating a suspended account by its listed login is a
			// supported flow.
			if targetErr == nil {
				if current, curErr := store.CurrentPartnerUserLogin(r.Context(), targetID); curErr == nil &&
					!strings.EqualFold(current, strings.TrimSpace(body.Subject)) {
					http.Error(w, "subject is not the account's current login", http.StatusConflict)
					return
				}
			}
			user, err := store.ProvisionLogin(r.Context(), actor, body)
			if err != nil {
				http.Error(w, "user update rejected", 400)
				return
			}
			writeJSON(w, adminPartnerUser(user))
		case "budgets":
			if r.Method == http.MethodGet {
				query := r.URL.Query()
				for name, values := range query {
					if (name != "offset" && name != "search" && name != "subject" && name != "limit") || len(values) != 1 {
						http.Error(w, "invalid budget query", 400)
						return
					}
				}
				offset := 0
				if raw, ok := query["offset"]; ok {
					var err error
					offset, err = strconv.Atoi(raw[0])
					if err != nil || offset < 0 || offset > 1000000 {
						http.Error(w, "invalid offset", 400)
						return
					}
				}
				if len(query.Get("search")) > 128 || len(query.Get("subject")) > 128 {
					http.Error(w, "invalid search", 400)
					return
				}
				limit := 20
				if raw, ok := query["limit"]; ok {
					var err error
					limit, err = strconv.Atoi(raw[0])
					if err != nil || (limit != 5 && limit != 20 && limit != 50) {
						http.Error(w, "invalid limit", 400)
						return
					}
				}
				// The write path stores override subjects trimmed and lowercased;
				// the read must resolve the same spellings or a raw query value
				// silently misses the stored row. An empty subject stays empty
				// and keeps the unfiltered listing behavior.
				rows, more, err := store.UserBudgetOverridesPage(r.Context(), query.Get("search"), strings.ToLower(strings.TrimSpace(query.Get("subject"))), limit, offset)
				if err != nil {
					http.Error(w, "budget query failed", 500)
					return
				}
				policy, err := store.GetQuotaPolicy(r.Context())
				if err != nil {
					http.Error(w, "policy query failed", 500)
					return
				}
				writeJSON(w, map[string]any{"data": rows, "has_more": more, "default_monthly_usd": policy.DefaultMonthlyUSD})
				return
			}
			var body struct {
				Subject    string  `json:"subject"`
				MonthlyUSD float64 `json:"monthly_usd"`
			}
			if r.Method != http.MethodPut && r.Method != http.MethodDelete {
				http.Error(w, "method not allowed", 405)
				return
			}
			if !decodeStandaloneJSON(w, r, &body) {
				return
			}
			subject := strings.ToLower(strings.TrimSpace(body.Subject))
			if subject == "" || len(subject) > 128 {
				http.Error(w, "invalid subject", 400)
				return
			}
			var err error
			if r.Method == http.MethodDelete {
				err = store.DeleteQuotaOverride(r.Context(), actor, "user", subject)
			} else {
				if math.IsNaN(body.MonthlyUSD) || math.IsInf(body.MonthlyUSD, 0) || body.MonthlyUSD < .01 || body.MonthlyUSD > 10000 || math.Abs(body.MonthlyUSD*100-math.Round(body.MonthlyUSD*100)) > 1e-8 {
					http.Error(w, "monthly_usd must be 0.01–10000 in whole cents", 400)
					return
				}
				err = store.UpsertQuotaOverride(r.Context(), actor, "user", subject, body.MonthlyUSD)
			}
			if err != nil {
				http.Error(w, "budget update failed", 500)
				return
			}
			writeJSON(w, map[string]bool{"updated": true})
		case "prices":
			if r.Method == http.MethodGet {
				rows, err := store.GetCurrentPricing(r.Context())
				if err != nil {
					http.Error(w, "price query failed", 500)
					return
				}
				writeJSON(w, rows)
				return
			}
			if r.Method != http.MethodPut {
				http.Error(w, "method not allowed", 405)
				return
			}
			var body storage.ManagedPrice
			if !decodeStandaloneJSON(w, r, &body) {
				return
			}
			if err := store.SetManagedPrice(r.Context(), actor, body); err != nil {
				http.Error(w, "price update rejected", 400)
				return
			}
			writeJSON(w, map[string]bool{"updated": true})
		default:
			http.NotFound(w, r)
		}
	}
}
