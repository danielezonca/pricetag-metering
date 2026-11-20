package storage

import (
	"errors"
	"testing"
)

func TestProvisionLoginRejectsSuspendedRetainedLogin(t *testing.T) {
	s, ctx := openTestStore(t)
	user, err := s.ProvisionLogin(ctx, "test", LoginProvision{Subject: "old@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpdatePartnerUser(ctx, "test", user.UserID, map[string]any{"email": "new@example.com", "first_name": "Test", "last_name": "User", "manager_uuid": nil}); err != nil {
		t.Fatal(err)
	}
	inactive, active := false, true
	if _, err = s.ProvisionLogin(ctx, "test", LoginProvision{Subject: "new@example.com", Active: &inactive}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ProvisionLogin(ctx, "test", LoginProvision{Subject: "old@example.com", Active: &active}); !errors.Is(err, ErrPartnerLoginRetired) {
		t.Fatalf("retained login reactivation: %v", err)
	}
	if _, err = s.ProvisionLogin(ctx, "test", LoginProvision{Subject: "new@example.com", Active: &active}); err != nil {
		t.Fatalf("current login reactivation: %v", err)
	}
}

func TestRecordPartnerUserKeyRejectsRenamedLogin(t *testing.T) {
	s, ctx := openTestStore(t)
	user, err := s.ProvisionLogin(ctx, "test", LoginProvision{Subject: "old@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpdatePartnerUser(ctx, "test", user.UserID, map[string]any{"email": "new@example.com", "first_name": "Test", "last_name": "User", "manager_uuid": nil}); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordPartnerUserKey(ctx, "test", user.UserID, "old-key", "old@example.com", "test"); !errors.Is(err, ErrPartnerLoginRetired) {
		t.Fatalf("record retired login: %v", err)
	}
	if err = s.RecordPartnerUserKey(ctx, "test", user.UserID, "new-key", "new@example.com", "test"); err != nil {
		t.Fatal(err)
	}
	keys, err := s.ListPartnerUserKeys(ctx, user.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].KeyID != "new-key" {
		t.Fatalf("recorded keys: %+v", keys)
	}
}
