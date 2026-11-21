package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/redhat-et/pricetag-metering/internal/config"
	"github.com/redhat-et/pricetag-metering/internal/maasapi"
	"github.com/redhat-et/pricetag-metering/internal/storage"
)

func TestIncompleteKeyCreateCompensation(t *testing.T) {
	for _, tc := range []struct {
		name, id, secret                    string
		revokeStatus, wantStatus, wantCalls int
	}{
		{"missing id", "", "", 204, 503, 0},
		{"missing secret", "key-id", "", 204, 502, 1},
		{"already gone", "key-id", "", 404, 502, 1},
		{"cleanup failed", "key-id", "", 500, 503, 1},
		{"complete", "key-id", "fixture-secret", 204, 200, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "DELETE" || !strings.HasSuffix(r.URL.Path, "/key-id") {
					t.Errorf("unexpected cleanup: %s %s", r.Method, r.URL.Path)
				}
				w.WriteHeader(tc.revokeStatus)
			}))
			defer upstream.Close()
			client, err := maasapi.NewClientWithOptions(upstream.URL, "", maasapi.ClientOptions{})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			rejected := rejectIncompleteKey(w, httptest.NewRequest("POST", "/", nil), client, &maasapi.APIKeyResponse{ID: tc.id, Key: tc.secret}, "alice", "users")
			if rejected != (tc.wantStatus != 200) || w.Code != tc.wantStatus || calls != tc.wantCalls {
				t.Fatalf("rejected=%v status=%d calls=%d", rejected, w.Code, calls)
			}
		})
	}
}

func TestBulkRevocationRequiresGroupBeforeStorageOrAudit(t *testing.T) {
	w := httptest.NewRecorder()
	NewManagementKeyRevocationsHandler(nil, config.Config{}, nil)(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"subject":"alice"}`)))
	if w.Code != 503 {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestBulkRevocationCoversConcurrentRenameAndBoundsChurn(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	for _, churn := range []bool{false, true} {
		t.Run(fmt.Sprint(churn), func(t *testing.T) {
			store := openFreshStore(t, dsn)
			user, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "old@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			var logins []string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				logins = append(logins, r.Header.Get("X-MaaS-Username"))
				if churn || len(logins) == 1 {
					email := fmt.Sprintf("new%d@example.com", len(logins))
					if _, err := store.UpdatePartnerUser(t.Context(), "test", user.UserID, map[string]any{"email": email, "first_name": "Test", "last_name": "User", "manager_uuid": nil}); err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
				}
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"revokedCount":1}`)
			}))
			defer upstream.Close()
			client, err := maasapi.NewClientWithOptions(upstream.URL, "", maasapi.ClientOptions{})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h := NewManagementKeyRevocationsHandler(store, config.Config{UserHeader: "X-User", PartnerUserKeyGroup: "users"}, client)
			h(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"subject":"old@example.com"}`)))
			if churn {
				if w.Code != 409 || len(logins) != 3 {
					t.Fatalf("unbounded/false success: status=%d logins=%v", w.Code, logins)
				}
			} else if w.Code != 200 || len(logins) != 2 || logins[1] != "new1@example.com" {
				t.Fatalf("missed renamed login: status=%d logins=%v", w.Code, logins)
			}
		})
	}
}
