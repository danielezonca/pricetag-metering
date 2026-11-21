package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/redhat-et/pricetag-metering/internal/config"
)

func TestClusterLoginAndJSONCompatibility(t *testing.T) {
	auth := NewAuthHandler(config.Config{})
	if got := auth.loginDestination(httptest.NewRequest(http.MethodGet, "/", nil), "alice"); got != "/dashboard" {
		t.Fatalf("cluster login destination = %q, want /dashboard", got)
	}
	if auth.httpClient.CheckRedirect != nil {
		t.Fatal("cluster login client must retain the legacy redirect policy")
	}

	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"alice"} trailing`))
	var value struct{ Name string }
	if !decodeJSON(httptest.NewRecorder(), request, &value) || value.Name != "alice" {
		t.Fatal("cluster JSON decoder changed its legacy trailing-value behavior")
	}
}

func TestClusterModelsCompatibility(t *testing.T) {
	handler := NewAdminHandler(nil, nil, config.Config{})
	recorder := httptest.NewRecorder()
	handler.HandleModels(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/admin/models", nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "[]\n" {
		t.Fatalf("cluster models response changed: status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestClusterAccountHasNoStandaloneControls(t *testing.T) {
	handler := NewAccountHandler(config.Config{})
	recorder := httptest.NewRecorder()
	handler.ServeAccount(recorder, httptest.NewRequest(http.MethodGet, "/account", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("cluster account status = %d", recorder.Code)
	}
	if strings.Contains(recorder.Body.String(), "KeyControls=") {
		t.Fatal("cluster account page injected standalone key controls")
	}
}

// Cluster key-expiry policy must match the pre-standalone behavior exactly:
// the explicit-duration maximum applies, the deployment default is not capped
// by that maximum, the standalone-only day suffix stays rejected, and an
// absurd configured maximum saturates deterministically instead of wrapping
// the conversion negative and silently disabling the cap.
func TestClusterKeyExpiryPolicyUnchanged(t *testing.T) {
	cluster := NewAdminHandler(nil, nil, config.Config{KeyPolicy: config.KeyPolicy{DefaultExpiryHours: 48, MaxExpiryHours: 72}})
	if _, err := cluster.validatedExpiry("24h"); err != nil {
		t.Fatalf("cluster rejected a duration within the maximum: %v", err)
	}
	if _, err := cluster.validatedExpiry("73h"); err == nil {
		t.Fatal("cluster must retain the explicit-duration maximum")
	}
	if _, err := cluster.validatedExpiry(""); err != nil {
		t.Fatalf("cluster rejected the deployment default: %v", err)
	}
	// 48h default vs 24h maximum: the default cap is standalone-only and
	// must not activate for cluster deployments.
	uncapped := NewAdminHandler(nil, nil, config.Config{KeyPolicy: config.KeyPolicy{DefaultExpiryHours: 48, MaxExpiryHours: 24}})
	if got, err := uncapped.validatedExpiry(""); err != nil || got != "48h0m0s" {
		t.Fatalf("cluster default lifetime = %q, %v; want the uncapped deployment default", got, err)
	}
	// Day suffixes are a standalone extension; cluster keeps rejecting them.
	if _, err := cluster.validatedExpiry("3d"); err == nil {
		t.Fatal("cluster accepted the standalone-only day suffix")
	}
	// An absurd configured maximum must remain deterministic in both modes.
	absurd := NewAdminHandler(nil, nil, config.Config{KeyPolicy: config.KeyPolicy{MaxExpiryHours: 1 << 62}})
	if _, err := absurd.validatedExpiry("24h"); err != nil {
		t.Fatalf("saturating maximum rejected a sane duration: %v", err)
	}
}
