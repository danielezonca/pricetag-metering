package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/maasapi"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

func TestManagementCanRevokeInactiveIdentityKeys(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	inactive := false
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "suspended", Active: &inactive}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-MaaS-Username") != "suspended" {
			t.Error("wrong revocation identity")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"revokedCount":2}`))
	}))
	defer upstream.Close()
	cfg := config.Config{UserHeader: "X-User", PartnerUserKeyGroup: "system:authenticated"}
	h := NewManagementKeyRevocationsHandler(store, cfg, maasapi.NewClient(upstream.URL, ""))
	r := httptest.NewRequest("POST", "/api/v1/management/key-revocations", strings.NewReader(`{"subject":"suspended","dry_run":false}`))
	r.Header.Set("X-User", "admin")
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != 200 || calls != 1 {
		t.Fatalf("status=%d calls=%d; suspended users must remain revocable", w.Code, calls)
	}
	if _, err := store.PartnerUserByMaaSUsername(t.Context(), "suspended"); err == nil {
		t.Fatal("authentication unexpectedly accepted suspended account")
	}
}

func TestManagementKeyIssuanceUsesStoredLoginSpelling(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "alice", Name: "Alice"}); err != nil {
		t.Fatal(err)
	}
	var gotSubject string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSubject = r.Header.Get("X-MaaS-Username")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"key-1","name":"onboarding","username":"alice","status":"active","key":"maas-secret-1"}`))
	}))
	defer upstream.Close()
	cfg := config.Config{UserHeader: "X-User", PartnerUserKeyGroup: "system:authenticated"}
	h := NewManagementKeysHandler(store, cfg, maasapi.NewClient(upstream.URL, ""))
	r := httptest.NewRequest("POST", "/api/v1/management/keys", strings.NewReader(`{"subject":"  ALICE ","name":"onboarding","expiresIn":"24h"}`))
	r.Header.Set("X-User", "admin")
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != 200 {
		t.Fatalf("status=%d; issuance must succeed for a padded, case-variant subject", w.Code)
	}
	if gotSubject != "alice" {
		t.Fatalf("upstream subject=%q; the stored login spelling must be used", gotSubject)
	}
	var delivered maasapi.APIKeyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &delivered); err != nil {
		t.Fatal(err)
	}
	if delivered.Key != "maas-secret-1" {
		t.Fatalf("response secret=%q; issuance must deliver the one-time secret", delivered.Key)
	}
}

// A 2xx create that returns an id but no one-time secret must not be
// recorded as a successful issuance: the secret is the deliverable and is
// shown exactly once, at issuance. The unusable key is revoked by id and the
// issuance is refused.
func TestManagementKeyIssuanceMissingSecretIsCompensated(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "alice", Name: "Alice"}); err != nil {
		t.Fatal(err)
	}
	revokes := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodDelete {
			revokes++
			if r.URL.Path != "/v1/api-keys/key-2" {
				t.Errorf("revoke path=%q; the unusable key must be revoked by id", r.URL.Path)
			}
			_, _ = w.Write([]byte(`{"revokedCount":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"key-2","name":"onboarding","username":"alice","status":"active"}`))
	}))
	defer upstream.Close()
	cfg := config.Config{UserHeader: "X-User", PartnerUserKeyGroup: "system:authenticated"}
	h := NewManagementKeysHandler(store, cfg, maasapi.NewClient(upstream.URL, ""))
	r := httptest.NewRequest("POST", "/api/v1/management/keys", strings.NewReader(`{"subject":"alice","name":"onboarding","expiresIn":"24h"}`))
	r.Header.Set("X-User", "admin")
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != 409 {
		t.Fatalf("status=%d; a secret-less create must be compensated and refused, not recorded", w.Code)
	}
	if revokes != 1 {
		t.Fatalf("revokes=%d; the unusable key must be revoked by id", revokes)
	}
	user, err := store.PartnerUserByMaaSUsername(t.Context(), "alice")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := store.ListPartnerUserKeys(t.Context(), user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("recorded keys=%d; a compensated issuance must not be recorded", len(keys))
	}
}

func TestManagementKeyIssuanceDirectoryOutageIs503(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	cfg := config.Config{UserHeader: "X-User", PartnerUserKeyGroup: "system:authenticated"}
	h := NewManagementKeysHandler(store, cfg, maasapi.NewClient(upstream.URL, ""))
	r := httptest.NewRequest("POST", "/api/v1/management/keys", strings.NewReader(`{"subject":"alice","name":"onboarding","expiresIn":"24h"}`))
	r.Header.Set("X-User", "admin")
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != 503 {
		t.Fatalf("status=%d; a directory outage is a retryable availability failure, not a validation 409", w.Code)
	}
	if calls != 0 {
		t.Fatal("the key service must not be reached while the directory is unavailable")
	}
}

func TestManagementKeyRevocationDirectoryOutageIs503(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	cfg := config.Config{UserHeader: "X-User", PartnerUserKeyGroup: "system:authenticated"}
	h := NewManagementKeyRevocationsHandler(store, cfg, maasapi.NewClient(upstream.URL, ""))
	r := httptest.NewRequest("POST", "/api/v1/management/key-revocations", strings.NewReader(`{"subject":"alice","dry_run":false}`))
	r.Header.Set("X-User", "admin")
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != 503 {
		t.Fatalf("status=%d; a directory outage is a retryable availability failure, not a missing user", w.Code)
	}
	if calls != 0 {
		t.Fatal("the key service must not be reached while the directory is unavailable")
	}
}
