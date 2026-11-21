package storage

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/pricing"
)

func TestHistoricalRepriceUsesApprovedRatesAndUpdatesMonthSpend(t *testing.T) {
	s, ctx := openTestStore(t)
	s.SetMonthSpendWrites(true)
	model := "snapshot-model"
	if _, err := s.SeedPricing(ctx, []ModelPrice{{Model: model, Provider: "fixture", InputCost: 1}}); err != nil {
		t.Fatal(err)
	}
	from := time.Now().UTC().Truncate(time.Hour).Add(-2 * time.Hour)
	for i := 0; i < 2; i++ {
		if err := s.InsertEvent(ctx, UsageEvent{EventID: fmt.Sprint(i), Timestamp: from.Add(time.Duration(i) * time.Hour), Username: "alice", Model: model, Provider: "fixture", PromptTokens: 1000000, TotalTokens: 1000000}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE model_pricing SET input_cost_per_mtok=2 WHERE model=$1`, model); err != nil {
		t.Fatal(err)
	}
	req := HistoricalRepriceRequest{Model: model, From: from, Until: from.Add(2 * time.Hour), Policy: pricing.DefaultDiscountPolicy().Version}
	preview, err := s.RepriceHistorical(ctx, "test", req)
	if err != nil {
		t.Fatal(err)
	}
	if preview.OldTotal != 2 || preview.NewTotal != 4 {
		t.Fatalf("preview=%+v", preview)
	}
	// Change the live price during the first chunk. Both hours must still use
	// the approved snapshot, even though the second transaction starts later.
	if _, err := s.db.ExecContext(ctx, `CREATE FUNCTION change_rate_during_reprice() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE model_pricing SET input_cost_per_mtok=9 WHERE model=NEW.model; RETURN NEW; END $$;
 CREATE TRIGGER change_rate AFTER UPDATE OF cost_usd ON usage_events FOR EACH ROW EXECUTE FUNCTION change_rate_during_reprice()`); err != nil {
		t.Fatal(err)
	}
	req.Confirm = true
	req.OperationID = preview.OperationID
	req.PolicyHash = preview.PolicyHash
	result, err := s.RepriceHistorical(ctx, "test", req)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied || result.CompletedChunks != 2 {
		t.Fatalf("result=%+v", result)
	}
	var ledger, spend float64
	var tokens, requests int64
	if err := s.db.QueryRowContext(ctx, `SELECT SUM(cost_usd) FROM usage_events`).Scan(&ledger); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT SUM(spent_usd),SUM(tokens),SUM(requests) FROM user_month_spend WHERE username='alice'`).Scan(&spend, &tokens, &requests); err != nil {
		t.Fatal(err)
	}
	if ledger != 4 || spend != 4 || tokens != 2000000 || requests != 2 {
		t.Fatalf("ledger=%v spend=%v tokens=%d requests=%d", ledger, spend, tokens, requests)
	}
	// A confirmation from the earlier rates must not start a fresh operation
	// after the live price changed.
	if _, err = s.RepriceHistorical(ctx, "test", req); err == nil {
		t.Fatal("changed pricing snapshot accepted")
	}
}

func TestRepriceChunkRollbackAndDisabledAccumulator(t *testing.T) {
	s, ctx := openTestStore(t)
	s.SetMonthSpendWrites(true)
	model := "rollback-model"
	if _, err := s.SeedPricing(ctx, []ModelPrice{{Model: model, Provider: "fixture", InputCost: 1}}); err != nil {
		t.Fatal(err)
	}
	from := time.Now().UTC().Truncate(time.Hour)
	if err := s.InsertEvent(ctx, UsageEvent{EventID: "one", Timestamp: from, Username: "alice", Model: model, PromptTokens: 1000000, TotalTokens: 1000000}); err != nil {
		t.Fatal(err)
	}
	rates, _ := json.Marshal([]map[string]any{{"model": model, "input_cost_per_mtok": 3, "output_cost_per_mtok": 0, "cache_read_cost_per_mtok": 0, "cache_write_cost_per_mtok": 0}})
	where, args, err := buildRepriceWhere(HistoricalRepriceRequest{Model: model, From: from, Until: from.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	check := func(wantLedger, wantSpend float64) {
		t.Helper()
		var ledger, spend float64
		if err := s.db.QueryRowContext(ctx, `SELECT cost_usd FROM usage_events WHERE event_id='one'`).Scan(&ledger); err != nil {
			t.Fatal(err)
		}
		if err := s.db.QueryRowContext(ctx, `SELECT spent_usd FROM user_month_spend WHERE username='alice'`).Scan(&spend); err != nil {
			t.Fatal(err)
		}
		if ledger != wantLedger || spend != wantSpend {
			t.Fatalf("ledger=%v spend=%v want=%v,%v", ledger, spend, wantLedger, wantSpend)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = repriceChunk(ctx, tx, where, args, rates, true); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	check(1, 1)
	tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = repriceChunk(ctx, tx, where, args, rates, false); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	check(3, 1)
}
