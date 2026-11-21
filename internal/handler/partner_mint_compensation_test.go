package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/maasapi"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

func TestPartnerMintCompensation(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store, db := openFreshStoreWithAdmin(t, dsn)
	caseID := 0
	for _, race := range []string{"rename", "inactive", "record-error", "cancelled"} {
		for _, status := range []int{204, 302, 404, 500, 0} {
			t.Run(fmt.Sprintf("%s/revoke-%d", race, status), func(t *testing.T) {
				caseID++
				login := fmt.Sprintf("old-%d@example.com", caseID)
				keyID := fmt.Sprintf("minted-key-%d", caseID)
				user, err := store.CreatePartnerUser(t.Context(), "test", fmt.Sprintf("123e4567-e89b-12d3-a456-%012d", caseID), map[string]any{"email": login, "first_name": "Test", "last_name": "User"})
				if err != nil {
					t.Fatal(err)
				}
				if race == "record-error" {
					if err := store.RecordPartnerUserKey(t.Context(), "test", user.UserID, keyID, login, "existing"); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				// Hold the row so recording blocks after the upstream mint. This
				// lets cancellation happen after a known successful create.
				if race == "cancelled" {
					tx, err := db.BeginTx(t.Context(), nil)
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback()
					if _, err := tx.ExecContext(t.Context(), `SELECT user_id FROM partner_users WHERE user_id=$1 FOR UPDATE`, user.UserID); err != nil {
						t.Fatal(err)
					}
				}
				var revokes atomic.Int32
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodDelete {
						revokes.Add(1)
						if r.URL.Path != "/v1/api-keys/"+keyID || r.Header.Get("X-MaaS-Username") != login {
							t.Errorf("wrong compensation target: %s %v", r.URL.Path, r.Header)
						}
						if status == 0 {
							conn, _, err := w.(http.Hijacker).Hijack()
							if err != nil {
								t.Error(err)
								return
							}
							_ = conn.Close()
							return
						}
						w.WriteHeader(status)
						return
					}
					var err error
					switch race {
					case "rename":
						_, err = store.UpdatePartnerUser(t.Context(), "test", user.UserID, map[string]any{"email": fmt.Sprintf("new-%d@example.com", caseID), "first_name": "Test", "last_name": "User", "manager_uuid": nil})
					case "inactive":
						_, err = store.BeginPartnerUserDeactivation(t.Context(), "test", user.UserID)
					}
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"id": keyID, "key": "never-return-this-secret"})
				}))
				defer upstream.Close()
				client, err := maasapi.NewClientWithOptions(upstream.URL, "", maasapi.ClientOptions{})
				if err != nil {
					t.Fatal(err)
				}
				h := NewPartnerUsersHandler(store, client, "users")
				r := httptest.NewRequest("POST", "/api/v1/users/"+user.UserID+"/keys", strings.NewReader(`{"name":"test"}`)).WithContext(ctx)
				w := httptest.NewRecorder()
				done := make(chan struct{})
				go func() { defer close(done); h.HandleUsers(w, r) }()
				if race == "cancelled" {
					deadline := time.Now().Add(5 * time.Second)
					for {
						var waiting bool
						if err := db.QueryRowContext(t.Context(), `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT active,key_revocation_pending%')`).Scan(&waiting); err != nil {
							t.Fatal(err)
						}
						if waiting {
							cancel()
							break
						}
						if time.Now().After(deadline) {
							cancel()
							<-done
							t.Fatal("record did not wait for row lock")
						}
						time.Sleep(10 * time.Millisecond)
					}
				}
				<-done
				want := http.StatusServiceUnavailable
				if status == 204 {
					want = http.StatusConflict
					if race == "record-error" || race == "cancelled" {
						want = http.StatusInternalServerError
					}
				}
				if w.Code != want || revokes.Load() == 0 || strings.Contains(w.Body.String(), "never-return-this-secret") {
					t.Fatalf("status=%d want=%d revokes=%d body=%s", w.Code, want, revokes.Load(), w.Body.String())
				}
				if status != 204 && (!strings.Contains(w.Body.String(), "operator reconciliation required") || strings.Contains(w.Body.String(), "was revoked")) {
					t.Fatalf("failed compensation reported incorrectly: %s", w.Body.String())
				}
			})
		}
	}
}

func TestPersonalUsageWithoutPartnerIdentityStaysCallerOnly(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	for _, subject := range []string{"outsider", "other-user"} {
		if err := store.InsertEvent(t.Context(), storage.UsageEvent{EventID: subject, Timestamp: time.Now().UTC(), Username: subject, GroupName: "test", Model: subject, TotalTokens: 10, Source: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	h := NewMeUsageHandler(store, testCfg())
	for _, endpoint := range []struct {
		path    string
		handler http.HandlerFunc
	}{{"summary", h.HandleSummary}, {"models", h.HandleModels}} {
		r := httptest.NewRequest("GET", "/api/v1/me/usage/"+endpoint.path+"?range=mtd&user=other-user", nil)
		r.Header.Set(testCfg().UserHeader, "outsider")
		w := httptest.NewRecorder()
		endpoint.handler(w, r)
		if w.Code != 200 || strings.Contains(w.Body.String(), "other-user") {
			t.Fatalf("%s: status=%d body=%s", endpoint.path, w.Code, w.Body.String())
		}
		if endpoint.path == "summary" {
			var response struct {
				Overview storage.DashboardOverview `json:"overview"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Overview.TotalRequests != 1 || response.Overview.TotalTokens != 10 {
				t.Fatalf("summary not caller-only: %s err=%v", w.Body.String(), err)
			}
		} else if !strings.Contains(w.Body.String(), "outsider") {
			t.Fatalf("own model missing: %s", w.Body.String())
		}
	}
}
