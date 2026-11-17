package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

func TestOrgChartsUserFilterNoKeyRoot(t *testing.T) {
	tests := []struct {
		name      string
		root      string
		usernames []string
		want      string
		wantOK    bool
	}{
		{
			name:   "whole org stays unfiltered",
			root:   "",
			want:   "",
			wantOK: true,
		},
		{
			name:      "no-key person must not become whole org",
			root:      "123e4567-e89b-12d3-a456-426614174020",
			usernames: nil,
			want:      "",
			wantOK:    false,
		},
		{
			name:      "no-key person with empty slice must not become whole org",
			root:      "123e4567-e89b-12d3-a456-426614174020",
			usernames: []string{},
			want:      "",
			wantOK:    false,
		},
		{
			name:      "person with a login stays scoped",
			root:      "123e4567-e89b-12d3-a456-426614174020",
			usernames: []string{"alice@example.com"},
			want:      "alice@example.com",
			wantOK:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := orgChartsUserFilter(tt.root, tt.usernames)
			if got != tt.want || ok != tt.wantOK {
				t.Fatalf("orgChartsUserFilter(%q, %v) = (%q, %v), want (%q, %v)",
					tt.root, tt.usernames, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestEmptyOrgChartsResponseIsEmpty(t *testing.T) {
	got := emptyOrgChartsResponse()
	if got.Overview.TotalRequests != 0 ||
		got.Overview.TotalTokens != 0 ||
		got.Overview.ActiveUsers != 0 ||
		got.Overview.TotalCostUSD != 0 ||
		len(got.Models) != 0 ||
		len(got.Users) != 0 ||
		len(got.Timeline) != 0 {
		t.Fatalf("empty org charts response contains data: %+v", got)
	}
}

// The standalone org-usage response must hide blocked-region people from
// managers exactly like the cluster branch, while super-admins keep the full
// directory.
func TestStandaloneOrgUsageHidesBlockedCountries(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "admin", Role: storage.PartnerRoleSuperAdmin}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreatePartnerUser(t.Context(), "test", "21111111-2222-3333-4444-555555555555", map[string]any{
		"email": "blocked@example.com", "first_name": "Blocked", "last_name": "Person", "country": "XX",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddDashboardBlockedCountry(t.Context(), "test", "XX"); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{DeploymentMode: config.DeploymentModeStandalone, UserHeader: "X-User"}
	h := NewPartnerOrgHandler(store, cfg)

	// The blocked person's own view: their row is hidden from a
	// non-super-admin caller.
	r := httptest.NewRequest("GET", "/api/v1/org/usage?range=30d", nil)
	r.Header.Set("X-User", "blocked@example.com")
	w := httptest.NewRecorder()
	h.HandleOrgUsage(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d; blocked-person self view must succeed", w.Code)
	}
	var selfRows []storage.ManagedOrgUsageRow
	if err := json.Unmarshal(w.Body.Bytes(), &selfRows); err != nil {
		t.Fatal(err)
	}
	if len(selfRows) != 0 {
		t.Fatalf("blocked-region row visible to non-super-admin: %+v", selfRows)
	}

	// The super-admin's whole-org view keeps the blocked person visible.
	r = httptest.NewRequest("GET", "/api/v1/org/usage?range=30d", nil)
	r.Header.Set("X-User", "admin")
	w = httptest.NewRecorder()
	h.HandleOrgUsage(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d; super-admin view must succeed", w.Code)
	}
	var adminRows []storage.ManagedOrgUsageRow
	if err := json.Unmarshal(w.Body.Bytes(), &adminRows); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range adminRows {
		if row.Username == "blocked@example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("super-admin must see the blocked person, got %+v", adminRows)
	}
}
