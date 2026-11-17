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

func TestSummaryUsesNormalQuotaForPartnerSuperAdmin(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store, testdb := openFreshStoreWithAdmin(t, dsn)
	if _, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "admin", Role: storage.PartnerRoleSuperAdmin}); err != nil {
		t.Fatal(err)
	}
	if _, err := testdb.ExecContext(t.Context(), `
		INSERT INTO quota_policy (id, default_monthly_usd, enforced, allowed_over_limit_models)
		VALUES (true, 123, true, '{}')
		ON CONFLICT (id) DO UPDATE SET default_monthly_usd=123, enforced=true, allowed_over_limit_models='{}'`); err != nil {
		t.Fatal(err)
	}

	handler := NewMeUsageHandler(store, config.Config{
		DeploymentMode: config.DeploymentModeStandalone,
		UserHeader:     "X-User",
	})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/me/usage/summary", nil)
	request.Header.Set("X-User", "admin")
	recorder := httptest.NewRecorder()
	handler.HandleSummary(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Quota storage.QuotaView `json:"quota"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Quota.Exempt {
		t.Fatal("partner super-admin was exempted from the self-service quota")
	}
	if !response.Quota.Enforced || response.Quota.LimitUSD != 123 {
		t.Fatalf("quota=%#v; want the normal enforced policy", response.Quota)
	}
}
