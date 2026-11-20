package storage

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/pricing"
)

func TestConcurrentDefaultRoleCreateRequiresReplacementConsent(t *testing.T) {
	s, ctx := openTestStore(t)
	tenant := createTestTenant(t, s, ctx, "consent", false)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := s.CreateModelAccessRoleWithReplacement(ctx, tenant, "test", fmt.Sprint(i), "", nil, true, 0, 0, fmt.Sprint(i), false)
			results <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrModelAccessDefaultExists) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
	role, err := s.CreateModelAccessRoleWithReplacement(ctx, tenant, "test", "confirmed", "", nil, true, 0, 0, "confirmed", true)
	if err != nil {
		t.Fatal(err)
	}
	current, err := s.GetDefaultModelAccessRole(ctx, tenant)
	if err != nil || current.RoleID != role.RoleID {
		t.Fatalf("replacement failed: %+v %v", current, err)
	}
}

func TestRepriceHashIncludesRatesForLateModels(t *testing.T) {
	s, ctx := openTestStore(t)
	if _, err := s.SeedPricing(ctx, []ModelPrice{{Model: "used", Provider: "fixture", InputCost: 1}, {Model: "late", Provider: "fixture", InputCost: 2}}); err != nil {
		t.Fatal(err)
	}
	from := time.Now().UTC().Truncate(time.Hour)
	if err := s.InsertEvent(ctx, UsageEvent{EventID: "one", Timestamp: from, Username: "alice", Provider: "fixture", Model: "used", PromptTokens: 1000000, TotalTokens: 1000000}); err != nil {
		t.Fatal(err)
	}
	req := HistoricalRepriceRequest{Provider: "fixture", From: from, Until: from.Add(time.Hour), Policy: pricing.DefaultDiscountPolicy().Version}
	preview, err := s.RepriceHistorical(ctx, "test", req)
	if err != nil {
		t.Fatal(err)
	}
	// No late-model event exists yet: its changed rate must still invalidate
	// confirmation, because one could arrive while a chunk is being processed.
	if _, err := s.db.ExecContext(ctx, `UPDATE model_pricing SET input_cost_per_mtok=9 WHERE model='late'`); err != nil {
		t.Fatal(err)
	}
	req.Confirm = true
	req.OperationID = preview.OperationID
	req.PolicyHash = preview.PolicyHash
	if _, err := s.RepriceHistorical(ctx, "test", req); err == nil {
		t.Fatal("unapproved late-model rate accepted")
	}
}
