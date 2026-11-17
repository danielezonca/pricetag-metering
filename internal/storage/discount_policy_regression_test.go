package storage

import (
	"encoding/json"

	"github.com/redhat-et/pricetag-metering/internal/pricing"
	"reflect"
	"testing"
)

func TestDiscountPolicySaveRoundTrip(t *testing.T) {
	s, ctx := openTestStore(t)
	policy := pricing.DefaultDiscountPolicy()
	if err := s.UpdatePricingDiscountPolicy(ctx, "test", policy); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPricingDiscountPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, policy) {
		t.Fatal("discount policy changed on round trip")
	}
}

func TestDiscountPolicyDatabaseFailureIsNotDefaultPolicy(t *testing.T) {
	s, ctx := openTestStore(t)
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetPricingDiscountPolicy(ctx); err == nil {
		t.Fatal("database failure silently returned a default discount policy")
	}
}

// The rules column carries a JSON array (its CHECK constraint rejects any
// other shape), and a rules-less policy must persist rules as [] rather
// than JSON null, which both violates that constraint and cannot be
// round-tripped by the reader.
func TestDiscountPolicyStoredFormat(t *testing.T) {
	s, ctx := openTestStore(t)
	if err := s.UpdatePricingDiscountPolicy(ctx, "test", pricing.DiscountPolicy{Version: "empty-v1"}); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := s.db.QueryRowContext(ctx, `SELECT rules FROM pricing_discount_policy WHERE id = true`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var rules []pricing.DiscountRule
	if err := json.Unmarshal(raw, &rules); err != nil {
		t.Fatalf("stored rules are not a JSON array: %v (%s)", err, raw)
	}
	if rules == nil {
		t.Fatalf("stored rules = %s; want [] rather than null", raw)
	}
	var version string
	if err := s.db.QueryRowContext(ctx, `SELECT version FROM pricing_discount_policy WHERE id = true`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != "empty-v1" {
		t.Fatalf("stored version = %q; want the policy version retained", version)
	}
	got, err := s.GetPricingDiscountPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "empty-v1" || len(got.Rules) != 0 {
		t.Fatalf("rules-less policy did not round-trip: %+v", got)
	}
}
