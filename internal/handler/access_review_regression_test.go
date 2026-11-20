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

func TestTrackedRevocationRejectsRedirects(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	user, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "member"})
	if err != nil {
		t.Fatal(err)
	}
	status := http.StatusFound
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/login")
		w.WriteHeader(status)
	}))
	defer upstream.Close()
	client, err := maasapi.NewClientWithOptions(upstream.URL, "", maasapi.ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h := NewPartnerUsersHandler(store, client, "users")
	for _, code := range []int{200, 204, 301, 302, 307, 404, 500} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			status = code
			id := fmt.Sprint(code)
			if err := store.RecordPartnerUserKey(t.Context(), "test", user.UserID, id, "member", "test"); err != nil {
				t.Fatal(err)
			}
			err := h.revokeTracked(httptest.NewRequest("DELETE", "/", nil), user.UserID, storage.PartnerUserKey{KeyID: id, Username: "member"})
			success := (code >= 200 && code < 300) || code == 404
			if (err == nil) != success {
				t.Fatalf("status %d: err=%v", code, err)
			}
			keys, e := store.ListPartnerUserKeys(t.Context(), user.UserID)
			if e != nil {
				t.Fatal(e)
			}
			for _, key := range keys {
				if key.KeyID == id && (key.RevokedAt != nil) != success {
					t.Fatalf("wrong stored revocation state: %+v", key)
				}
			}
		})
	}
}

func TestManagementProvisionFailsClosedWithoutActorIdentity(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	h := NewManagementHandler(store, config.Config{UserHeader: "X-User"})
	for _, tc := range []struct {
		actor string
		want  int
	}{{"unknown-browser-admin", 503}, {"management-service", 200}} {
		r := httptest.NewRequest("PUT", "/api/v1/management/users", strings.NewReader(`{"subject":"new-user"}`))
		r.Header.Set("X-User", tc.actor)
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != tc.want {
			t.Fatalf("actor %s: status=%d body=%s", tc.actor, w.Code, w.Body.String())
		}
	}
}

func TestManagementMintCompensatesRenameDuringUpstreamCall(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL required")
	}
	store := openFreshStore(t, dsn)
	user, err := store.ProvisionLogin(t.Context(), "test", storage.LoginProvision{Subject: "old@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	revoked := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			revoked = true
			w.WriteHeader(204)
			return
		}
		if _, err := store.UpdatePartnerUser(t.Context(), "test", user.UserID, map[string]any{"email": "new@example.com", "first_name": "Test", "last_name": "User", "manager_uuid": nil}); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"raced-key","key":"fixture-secret","status":"active"}`)
	}))
	defer upstream.Close()
	client, err := maasapi.NewClientWithOptions(upstream.URL, "", maasapi.ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	h := NewManagementKeysHandler(store, config.Config{UserHeader: "X-User", PartnerUserKeyGroup: "users"}, client)
	r := httptest.NewRequest("POST", "/api/v1/management/keys", strings.NewReader(`{"subject":"old@example.com","name":"test","expiresIn":"24h"}`))
	r.Header.Set("X-User", "management-service")
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != 409 || !revoked {
		t.Fatalf("status=%d revoked=%v body=%s", w.Code, revoked, w.Body.String())
	}
	keys, err := store.ListPartnerUserKeys(t.Context(), user.UserID)
	if err != nil || len(keys) != 0 {
		t.Fatalf("recorded keys=%v err=%v", keys, err)
	}
}
