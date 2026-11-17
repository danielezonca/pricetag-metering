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

func TestManagementEntitlementRequiresDirectory(t *testing.T) {
	h := NewEntitlementsHandler(nil, config.Config{DeploymentMode: config.DeploymentModeStandalone, ManagementAPISecret: "test-only"})
	w := httptest.NewRecorder()
	h.HandleEntitlement(w, httptest.NewRequest(http.MethodGet, "/customers/alice/entitlements", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestManagementEntitlementRejectsInactiveAndUnknownUsers(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	inactive := false
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "disabled", Active: &inactive}); err != nil {
		t.Fatal(err)
	}
	h := NewEntitlementsHandler(store, config.Config{DeploymentMode: config.DeploymentModeStandalone, ManagementAPISecret: "test-only"})
	for _, subject := range []string{"disabled", "unknown"} {
		w := httptest.NewRecorder()
		h.HandleEntitlement(w, httptest.NewRequest(http.MethodGet, "/customers/"+subject+"/entitlements?model=free-exception", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("subject=%s status=%d", subject, w.Code)
		}
		var result storage.UsageStats
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.HasAccess || result.ModelAllowed {
			t.Fatal("inactive or unknown account admitted")
		}
	}
}

func TestManagementUserListIncludesSuspendedProfiles(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	inactive := false
	profile, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "suspended", Active: &inactive})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	NewManagementHandler(store, config.Config{})(w, httptest.NewRequest(http.MethodGet, "/api/v1/management/users", nil))
	var page struct {
		Data []struct {
			UserID string   `json:"user_id"`
			Active bool     `json:"active"`
			Logins []string `json:"logins"`
		} `json:"data"`
		HasMore bool `json:"has_more"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	users := page.Data
	if page.HasMore || len(users) != 1 || users[0].UserID != profile.UserID || users[0].Active || len(users[0].Logins) != 1 || users[0].Logins[0] != "suspended" {
		t.Fatal("management list must retain the suspended profile and its login")
	}
}

// TestManagementUserListAcceptsAdvertisedPageSizes pins the listing's
// advertised limit set to what the storage layer actually honors. The
// management route accepts {50,100,250,500} and the standalone admin
// console paginates with limit=500, so every advertised size must
// survive the store query — a mismatch surfaces as HTTP 500, not a
// validation error, and breaks the admin directory at runtime.
func TestManagementUserListAcceptsAdvertisedPageSizes(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "sizecheck"}); err != nil {
		t.Fatal(err)
	}
	h := NewManagementHandler(store, config.Config{})
	for _, limit := range []string{"50", "100", "250", "500"} {
		w := httptest.NewRecorder()
		h(w, httptest.NewRequest(http.MethodGet, "/api/v1/management/users?limit="+limit, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("limit=%s status=%d body=%s", limit, w.Code, w.Body.String())
		}
		var page struct {
			Data []json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatalf("limit=%s decode: %v", limit, err)
		}
		if len(page.Data) != 1 {
			t.Fatalf("limit=%s rows=%d; want 1", limit, len(page.Data))
		}
	}
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, "/api/v1/management/users?limit=501", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("limit=501 status=%d; want 400", w.Code)
	}
}
