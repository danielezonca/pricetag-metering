package storage

import (
	"strings"
	"testing"
	"time"
)

func TestManagementLoginPreservesIdentity(t *testing.T) {
	s, ctx := openTestStore(t)
	first, err := s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "alice", Name: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "alice", Name: "Alice Updated"})
	if err != nil {
		t.Fatal(err)
	}
	if first.UserID != second.UserID {
		t.Fatal("repeat setup changed identity")
	}
	if _, err = s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "bad\nsubject"}); err == nil {
		t.Fatal("invalid login accepted")
	}
	if _, err = s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "alice", Role: "unexpected"}); err == nil {
		t.Fatal("invalid role accepted")
	}
}

// Provisioning must materialize the login's policy subject in the same
// transaction: filter-based role and budget grants INSERT..SELECT over
// policy_subjects and silently match nothing while the row is missing.
func TestManagementProvisionCreatesPolicySubject(t *testing.T) {
	s, ctx := openTestStore(t)
	user, err := s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "bob", Name: "Bob"})
	if err != nil {
		t.Fatal(err)
	}
	var status string
	if err = s.db.QueryRowContext(ctx, `
		SELECT status FROM policy_subjects
		WHERE tenant_id = $1 AND principal_type = $2 AND external_id = $3`,
		DefaultTenantID, PrincipalPartnerUser, user.UserID).Scan(&status); err != nil {
		t.Fatalf("provisioned login has no policy subject row: %v", err)
	}
	if status != "active" {
		t.Fatalf("provisioned subject status = %q; want active", status)
	}
	// Re-provisioning keeps the subject id stable, like SyncPartnerUserSubject.
	var subjectID string
	if err = s.db.QueryRowContext(ctx, `
		SELECT subject_id::text FROM policy_subjects
		WHERE tenant_id = $1 AND principal_type = $2 AND external_id = $3`,
		DefaultTenantID, PrincipalPartnerUser, user.UserID).Scan(&subjectID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "bob", Name: "Bob Again"}); err != nil {
		t.Fatal(err)
	}
	var again string
	if err = s.db.QueryRowContext(ctx, `
		SELECT subject_id::text FROM policy_subjects
		WHERE tenant_id = $1 AND principal_type = $2 AND external_id = $3`,
		DefaultTenantID, PrincipalPartnerUser, user.UserID).Scan(&again); err != nil {
		t.Fatal(err)
	}
	if subjectID != again {
		t.Fatalf("re-provisioning changed the subject id: %s vs %s", subjectID, again)
	}
	// A suspended account keeps the row, marked inactive, so grants survive a
	// later reactivation.
	inactive := false
	if _, err = s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "bob", Active: &inactive}); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRowContext(ctx, `
		SELECT status FROM policy_subjects
		WHERE tenant_id = $1 AND principal_type = $2 AND external_id = $3`,
		DefaultTenantID, PrincipalPartnerUser, user.UserID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "inactive" {
		t.Fatalf("suspended account subject status = %q; want inactive", status)
	}
}

// model_pricing rate columns are NUMERIC(10,4): explicit rates are bounded
// and precision-checked in Go so Postgres neither overflows nor silently
// rounds a fifth decimal digit.
func TestSetManagedPriceRejectsRatesBeyondNumericScale(t *testing.T) {
	s, ctx := openTestStore(t)
	over := 1000000.0
	if err := s.SetManagedPrice(ctx, "test-admin", ManagedPrice{Model: "too-big", Provider: "fixture", Input: &over, Output: &over, CacheWrite: &over, CacheRead: &over}); err == nil {
		t.Fatal("rate above the NUMERIC(10,4) range accepted")
	}
	if err := s.SetManagedPrice(ctx, "test-admin", ManagedPrice{Model: "no-provider", Provider: "   "}); err == nil {
		t.Fatal("whitespace-only provider accepted; pricing rows carry display metadata and must not be blanked")
	}
	fifth := 0.00001
	if err := s.SetManagedPrice(ctx, "test-admin", ManagedPrice{Model: "too-precise", Provider: "fixture", Input: &fifth, Output: &fifth, CacheWrite: &fifth, CacheRead: &fifth}); err == nil {
		t.Fatal("rate with a fifth decimal digit accepted")
	}
	tiny := 0.0001
	zero := 0.0
	if err := s.SetManagedPrice(ctx, "test-admin", ManagedPrice{Model: "edge-rates", Provider: "fixture", Input: &tiny, Output: &zero, CacheWrite: &tiny, CacheRead: &zero}); err != nil {
		t.Fatal(err)
	}
	var input float64
	if err := s.db.QueryRowContext(ctx, `SELECT input_cost_per_mtok FROM model_pricing WHERE model='edge-rates'`).Scan(&input); err != nil {
		t.Fatal(err)
	}
	if input != 0.0001 {
		t.Fatalf("stored edge rate = %v; want 0.0001", input)
	}
	max := 999999.9999
	if err := s.SetManagedPrice(ctx, "test-admin", ManagedPrice{Model: "max-rate", Provider: "fixture", Input: &max, Output: &max, CacheWrite: &max, CacheRead: &max}); err != nil {
		t.Fatalf("boundary rate rejected: %v", err)
	}
	var storedMax float64
	if err := s.db.QueryRowContext(ctx, `SELECT input_cost_per_mtok FROM model_pricing WHERE model='max-rate'`).Scan(&storedMax); err != nil {
		t.Fatal(err)
	}
	if storedMax != 999999.9999 {
		t.Fatalf("stored boundary rate = %v; want 999999.9999", storedMax)
	}
}

// Login resolution is case-insensitive everywhere (LOWER(username) =
// LOWER($1)), so provisioning must not be able to mint a second case-variant
// identity for a person whose login already exists: that would make the
// single-row resolvers ambiguous about which account a lookup belongs to.
func TestManagementLoginCaseVariantsResolveToOneAccount(t *testing.T) {
	s, ctx := openTestStore(t)
	first, err := s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "Alice@Example.com", Role: PartnerRoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "  alice@example.com  "})
	if err != nil {
		t.Fatal(err)
	}
	if first.UserID != second.UserID {
		t.Fatalf("case-variant provisioning created two accounts: %s vs %s", first.UserID, second.UserID)
	}
	for _, spelling := range []string{"alice@example.com", "Alice@Example.com", "ALICE@EXAMPLE.COM", " alice@example.com "} {
		id, err := s.PartnerUserIDByLogin(ctx, spelling)
		if err != nil || id != first.UserID {
			t.Fatalf("PartnerUserIDByLogin(%q) = %s, %v; want %s", spelling, id, err, first.UserID)
		}
	}
	var stored string
	if err := s.db.QueryRowContext(ctx, `SELECT username FROM partner_user_logins WHERE user_id=$1 AND is_current`, first.UserID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "alice@example.com" {
		t.Fatalf("stored login spelling = %q; want the canonical lowercase form", stored)
	}
}

func TestManagementPendingRevocationRejectsActivationAtomically(t *testing.T) {
	s, ctx := openTestStore(t)
	user, err := s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "pending-user", Name: "Original"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE partner_users SET active=false,key_revocation_pending=true WHERE user_id=$1`, user.UserID); err != nil {
		t.Fatal(err)
	}
	active := true
	if _, err := s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "pending-user", Name: "Changed", Active: &active}); err == nil {
		t.Fatal("pending revocation reported successful activation")
	}
	var actualActive bool
	var name string
	if err := s.db.QueryRowContext(ctx, `SELECT active,tags->>'first_name' FROM partner_users WHERE user_id=$1`, user.UserID).Scan(&actualActive, &name); err != nil {
		t.Fatal(err)
	}
	if actualActive || name != "Original" {
		t.Fatal("failed activation partially changed the profile")
	}
}

func TestUserBudgetOverridePages(t *testing.T) {
	s, ctx := openTestStore(t)
	for _, name := range []string{"page-alice", "page-bob", "other-user"} {
		if err := s.UpsertQuotaOverride(ctx, "test", "user", name, 7); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertQuotaOverride(ctx, "test", "group", "page-group", 8); err != nil {
		t.Fatal(err)
	}
	rows, more, err := s.UserBudgetOverridesPage(ctx, "page-", "", 1, 0)
	if err != nil || len(rows) != 1 || rows[0].Principal != "page-alice" || !more {
		t.Fatalf("first page: %v %v %v", rows, more, err)
	}
	rows, more, err = s.UserBudgetOverridesPage(ctx, "page-", "", 1, 1)
	if err != nil || len(rows) != 1 || rows[0].Principal != "page-bob" || more {
		t.Fatalf("next page: %v %v %v", rows, more, err)
	}
	rows, _, err = s.UserBudgetOverridesPage(ctx, "", "page-alice", 20, 0)
	if err != nil || len(rows) != 1 || rows[0].MonthlyUSD != 7 {
		t.Fatal("exact subject lookup failed")
	}
	rows, _, err = s.UserBudgetOverridesPage(ctx, "%", "", 20, 0)
	if err != nil || len(rows) != 0 {
		t.Fatal("literal search treated as wildcard")
	}
	if _, _, err = s.UserBudgetOverridesPage(ctx, "", "", 1001, 0); err == nil {
		t.Fatal("unbounded page accepted")
	}
}

func TestManagerBudgetUsesCalendarMonthAndOverride(t *testing.T) {
	s, ctx := openTestStore(t)
	user, err := s.ProvisionLogin(ctx, "test", LoginProvision{Subject: "budget-member", Name: "Member"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertQuotaOverride(ctx, "test", "user", "budget-member", 5); err != nil {
		t.Fatal(err)
	}
	// Several unrelated pricing rows: the monthly spend must join each event
	// to its own model's pricing (e.model = p.model). A tautological join
	// multiplies every event by every pricing row and inflates the spend.
	if _, err := s.SeedPricing(ctx, []ModelPrice{
		{Model: "manager-budget", Provider: "mock", InputCost: 1},
		{Model: "unrelated-a", Provider: "mock", InputCost: 5},
		{Model: "unrelated-b", Provider: "mock", InputCost: 7},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertEvent(ctx, UsageEvent{EventID: "manager-budget-event", Timestamp: time.Now(), Username: "budget-member", Model: "manager-budget", PromptTokens: 1000000, TotalTokens: 1000000}); err != nil {
		t.Fatal(err)
	}
	// A historical chart window must not change the current monthly budget gauge.
	rows, err := s.GetManagedPartnerOrgUsage(ctx, user.UserID, time.Now().AddDate(0, -2, 0), time.Now().AddDate(0, -1, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].QuotaUSD != 5 || rows[0].QuotaSpentUSD != 1 || rows[0].Requests != 0 || rows[0].OverLimit {
		t.Fatalf("incorrect budget summary: %+v", rows)
	}
	if err := s.DeleteQuotaOverride(ctx, "test", "user", "budget-member"); err != nil {
		t.Fatal(err)
	}
	policy, err := s.GetQuotaPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rows, err = s.GetManagedPartnerOrgUsage(ctx, user.UserID, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].QuotaUSD != policy.DefaultMonthlyUSD || rows[0].QuotaSpentUSD != 1 {
		t.Fatal("removing override reset spend or failed inheritance")
	}
}

// A whitespace-only name must behave as unset (never persist as first_name),
// and control characters must be rejected outright.
func TestManagementProvisionRejectsBlankAndControlNames(t *testing.T) {
	s, ctx := openTestStore(t)
	user, err := s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "name-user", Name: " \t "})
	if err != nil {
		t.Fatal(err)
	}
	var name string
	if err := s.db.QueryRowContext(ctx, `SELECT tags->>'first_name' FROM partner_users WHERE user_id=$1`, user.UserID).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "name-user" {
		t.Fatalf("blank name persisted as %q; want the subject fallback", name)
	}
	if _, err := s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "name-user", Name: "bad\x00name"}); err == nil {
		t.Fatal("control-character name accepted")
	}
}

// ManagedUserByLogin must resolve case-variant login rows deterministically,
// exactly like ProvisionLogin and PartnerUserIDByLogin.
func TestManagedUserByLoginResolvesCaseVariantsDeterministically(t *testing.T) {
	s, ctx := openTestStore(t)
	user, err := s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "managed-user", Name: "Managed"})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a pre-normalization database that still carries a stale
	// case-variant row for a different account.
	other, err := s.ProvisionLogin(ctx, "test-admin", LoginProvision{Subject: "managed-other", Name: "Other"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO partner_user_logins(username,user_id,is_current) VALUES('Managed-User',$1,false)`, other.UserID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		resolved, err := s.ManagedUserByLogin(ctx, "managed-user")
		if err != nil {
			t.Fatal(err)
		}
		if resolved.UserID != user.UserID {
			t.Fatalf("ManagedUserByLogin resolved %s; want the current-login account %s", resolved.UserID, user.UserID)
		}
	}
}

// The directory report must resolve a user's override the same way enforcement
// does: a mixed-case SSO login (stored verbatim by CreatePartnerUser) against
// the lowercased override principal the management handler writes.
func TestManagerBudgetOverrideMatchesMixedCaseLogin(t *testing.T) {
	s, ctx := openTestStore(t)
	const login = "Mixed.Case@Example.com"
	userID := "11111111-2222-3333-4444-555555555555"
	if _, err := s.CreatePartnerUser(ctx, "test", userID, map[string]any{
		"email":      login,
		"first_name": "Mixed",
		"last_name":  "Case",
	}); err != nil {
		t.Fatal(err)
	}
	// The management handler stores override principals lowercased.
	if err := s.UpsertQuotaOverride(ctx, "test", "user", "mixed.case@example.com", 5); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SeedPricing(ctx, []ModelPrice{
		{Model: "mixed-case-budget", Provider: "mock", InputCost: 1},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertEvent(ctx, UsageEvent{EventID: "mixed-case-budget-event", Timestamp: time.Now(), Username: login, Model: "mixed-case-budget", PromptTokens: 1000000, TotalTokens: 1000000}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.GetManagedPartnerOrgUsage(ctx, userID, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one org row, got %+v", rows)
	}
	if rows[0].QuotaUSD != 5 || rows[0].QuotaSpentUSD != 1 {
		t.Fatalf("mixed-case override not reflected in directory report: %+v", rows[0])
	}
}

// A retained login (renamed away, is_current=false) must not lend its user
// override to the report: only the current login's override applies, and
// when the current login has none the row falls back to the policy default.
func TestManagedOrgUsageIgnoresRetainedLoginOverride(t *testing.T) {
	s, ctx := openTestStore(t)
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO quota_policy (id, default_monthly_usd, enforced, allowed_over_limit_models)
		VALUES (true, 10, true, '{}')
		ON CONFLICT (id) DO UPDATE SET default_monthly_usd=10, enforced=true, allowed_over_limit_models='{}'`); err != nil {
		t.Fatal(err)
	}
	user, err := s.ProvisionLogin(ctx, "test", LoginProvision{Subject: "before@example.com", Name: "Rename"})
	if err != nil {
		t.Fatal(err)
	}
	// Rename: the old login is retained, the new one is current — the same
	// rows the directory sync writes when a person's email changes.
	if _, err := s.db.ExecContext(ctx, `
		UPDATE partner_user_logins SET is_current=FALSE WHERE user_id=$1 AND is_current`, user.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO partner_user_logins (username,user_id,is_current) VALUES ('after@example.com',$1,TRUE)`, user.UserID); err != nil {
		t.Fatal(err)
	}
	// Override set on the retained login only: with the inner-join lateral
	// this leaked into the row; the current login must see the default.
	if err := s.UpsertQuotaOverride(ctx, "test", "user", "before@example.com", 5); err != nil {
		t.Fatal(err)
	}
	readRow := func() ManagedOrgUsageRow {
		t.Helper()
		rows, err := s.GetManagedPartnerOrgUsage(ctx, user.UserID, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("expected one org row, got %+v", rows)
		}
		return rows[0]
	}
	if row := readRow(); row.QuotaUSD != 10 {
		t.Fatalf("retained login's override leaked into the report: %+v", row)
	}
	// The current login's own override still applies.
	if err := s.UpsertQuotaOverride(ctx, "test", "user", "after@example.com", 7); err != nil {
		t.Fatal(err)
	}
	if row := readRow(); row.QuotaUSD != 7 {
		t.Fatalf("current login's override not applied: %+v", row)
	}
}

// The managed org usage report must compose the quota exactly like
// quotaDecision: a per-user override replaces the role-budget sum, otherwise
// a positive role budget applies, and active unexpired credits are added.
func TestManagedOrgUsageQuotaMatchesEnforcementComposition(t *testing.T) {
	s, ctx := openTestStore(t)
	s.SetMonthSpendEnabled(true)
	tenant, err := s.EnsureDefaultTenant(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The global default sits below the month's spend, the role budget above
	// it: a report that ignores role budgets flags the user over the limit.
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO quota_policy (id, default_monthly_usd, enforced, allowed_over_limit_models)
		VALUES (true, 10, true, '{}')
		ON CONFLICT (id) DO UPDATE SET default_monthly_usd=10, enforced=true, allowed_over_limit_models='{}'`); err != nil {
		t.Fatal(err)
	}
	user, err := s.ProvisionLogin(ctx, "test", LoginProvision{Subject: "compose-member", Name: "Compose"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SyncPartnerUserSubjects(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	subjectID, _, err := s.ResolvePolicySubjectByUsername(ctx, tenant, "compose-member")
	if err != nil {
		t.Fatal(err)
	}
	role, err := s.CreateModelAccessRole(ctx, tenant, "test", "Compose", "", nil, false, 50)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AssignModelAccessRole(ctx, tenant, role.RoleID, subjectID, "test"); err != nil {
		t.Fatal(err)
	}
	// An unexpired credit adds to the limit; the expired one must not count.
	future := time.Now().Add(time.Hour)
	past := time.Now().Add(-time.Hour)
	if _, err := s.AddQuotaCredit(ctx, tenant, subjectID, 20, &future, "test", "admin", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddQuotaCredit(ctx, tenant, subjectID, 999, &past, "test", "admin", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO user_month_spend (username, month, spent_usd, tokens, requests)
		VALUES ('compose-member', date_trunc('month', NOW())::date, 40, 0, 1)
		ON CONFLICT (username, month) DO UPDATE SET spent_usd=EXCLUDED.spent_usd`); err != nil {
		t.Fatal(err)
	}
	readRow := func() ManagedOrgUsageRow {
		t.Helper()
		rows, err := s.GetManagedPartnerOrgUsage(ctx, user.UserID, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("expected one org row, got %+v", rows)
		}
		return rows[0]
	}
	// Role budget (50) replaces the default (10); the active credit (20)
	// adds on top; the expired credit (999) is ignored. Spend 40 sits between
	// the default and the limit, so the user is not over.
	row := readRow()
	if row.QuotaUSD != 70 || row.QuotaSpentUSD != 40 || row.OverLimit {
		t.Fatalf("role budget + credits not composed: %+v", row)
	}
	// A per-user override replaces the role-budget sum but not the credits:
	// 30 + 20 = 50 keeps the spend of 40 under the limit.
	if err := s.UpsertQuotaOverride(ctx, "test", "user", "compose-member", 30); err != nil {
		t.Fatal(err)
	}
	row = readRow()
	if row.QuotaUSD != 50 || row.OverLimit {
		t.Fatalf("override did not replace the role budget: %+v", row)
	}
}

// OverLimit must stay false when the enforced policy carries no USD budget:
// a zero default means "no budget configured", not a zero allowance, so the
// managed usage row must not flag the member over limit.
func TestManagedOrgUsageOverLimitRequiresPositiveBudget(t *testing.T) {
	s, ctx := openTestStore(t)
	s.SetMonthSpendEnabled(true)
	tenant, err := s.EnsureDefaultTenant(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO quota_policy (id, default_monthly_usd, enforced, allowed_over_limit_models)
		VALUES (true, 0, true, '{}')
		ON CONFLICT (id) DO UPDATE SET default_monthly_usd=0, enforced=true, allowed_over_limit_models='{}'`); err != nil {
		t.Fatal(err)
	}
	user, err := s.ProvisionLogin(ctx, "test", LoginProvision{Subject: "no-budget", Name: "NoBudget"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SyncPartnerUserSubjects(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO user_month_spend (username, month, spent_usd, tokens, requests)
		VALUES ('no-budget', date_trunc('month', NOW())::date, 5, 0, 1)
		ON CONFLICT (username, month) DO UPDATE SET spent_usd=EXCLUDED.spent_usd`); err != nil {
		t.Fatal(err)
	}
	rows, err := s.GetManagedPartnerOrgUsage(ctx, user.UserID, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one org row, got %+v", rows)
	}
	if !rows[0].QuotaEnforced || rows[0].QuotaUSD != 0 || rows[0].QuotaSpentUSD != 5 || rows[0].OverLimit {
		t.Fatalf("zero budget with enforced policy must not flag the member over limit: %+v", rows[0])
	}
}

// Identifiers are normalized before every use — advisory lock, backfill,
// upsert, audit, and the source-model lookup must all see the same spelling,
// or a padded request like " model-a " would create a distinct row instead
// of updating model-a. SourceModel gets the same normalization and bounds
// as the destination model.
func TestSetManagedPriceNormalizesIdentifiers(t *testing.T) {
	s, ctx := openTestStore(t)
	rate, zero := 1.5, 0.0
	if err := s.SetManagedPrice(ctx, "test-admin", ManagedPrice{Model: "trim-target", Provider: "fixture", Input: &rate, Output: &zero, CacheWrite: &zero, CacheRead: &zero}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetManagedPrice(ctx, "test-admin", ManagedPrice{Model: "  trim-target  ", Provider: "  fixture  ", Input: &zero, Output: &zero, CacheWrite: &zero, CacheRead: &zero}); err != nil {
		t.Fatalf("padded request rejected: %v", err)
	}
	var rows int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM model_pricing WHERE model LIKE '%trim-target%'`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("padded request produced %d pricing rows; want exactly the trimmed model", rows)
	}
	// A padded source_model resolves the trimmed source row's rates.
	if err := s.SetManagedPrice(ctx, "test-admin", ManagedPrice{Model: "alias", Provider: "fixture", SourceModel: "  trim-target  "}); err != nil {
		t.Fatalf("padded source_model rejected: %v", err)
	}
	var aliased float64
	if err := s.db.QueryRowContext(ctx, `SELECT input_cost_per_mtok FROM model_pricing WHERE model='alias'`).Scan(&aliased); err != nil {
		t.Fatal(err)
	}
	if aliased != 0 {
		t.Fatalf("aliased rate = %v; want the trimmed source row's 0", aliased)
	}
	if err := s.SetManagedPrice(ctx, "test-admin", ManagedPrice{Model: "alias2", Provider: "fixture", SourceModel: strings.Repeat("x", 257)}); err == nil {
		t.Fatal("over-long source_model accepted")
	}
}

// A committed rate change must drop the process-local zero-cost memo and the
// quota decision cache — and only after the commit: resetting earlier would
// let a concurrent reader repopulate both from the still-old committed rates
// and keep serving them after the new rates land.
func TestSetManagedPriceResetsCachesAfterCommit(t *testing.T) {
	s, ctx := openTestStore(t)
	zero := 0.0
	rate := 1.5
	if err := s.SetManagedPrice(ctx, "test-admin", ManagedPrice{Model: "memo-model", Provider: "fixture", Input: &zero, Output: &zero, CacheWrite: &zero, CacheRead: &zero}); err != nil {
		t.Fatal(err)
	}
	// Warm the zero-cost memo so the reset is observable, and plant a
	// non-nil quota cache the same way the decision path does.
	if _, err := s.zeroCostModelList(ctx); err != nil {
		t.Fatal(err)
	}
	s.quotaMu.Lock()
	s.quotaCache = map[string]quotaCacheEntry{}
	s.quotaMu.Unlock()
	s.zeroCostMu.RLock()
	epochBefore := s.zeroCostEpoch
	s.zeroCostMu.RUnlock()
	if err := s.SetManagedPrice(ctx, "test-admin", ManagedPrice{Model: "memo-model", Provider: "fixture", Input: &rate, Output: &rate, CacheWrite: &rate, CacheRead: &rate}); err != nil {
		t.Fatal(err)
	}
	s.zeroCostMu.RLock()
	staleMemo := s.zeroCostModels != nil || !s.zeroCostExpires.IsZero()
	epochAfter := s.zeroCostEpoch
	s.zeroCostMu.RUnlock()
	if staleMemo {
		t.Fatal("zero-cost memo survived a committed rate change")
	}
	if epochAfter != epochBefore+1 {
		t.Fatalf("memo epoch = %d after a committed rate change; want %d", epochAfter, epochBefore+1)
	}
	s.quotaMu.Lock()
	staleCache := s.quotaCache != nil
	s.quotaMu.Unlock()
	if staleCache {
		t.Fatal("quota decision cache survived a committed rate change")
	}
	// The next memo read re-queries and no longer classifies the repriced
	// model as zero-cost.
	models, err := s.zeroCostModelList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range models {
		if m == "memo-model" {
			t.Fatal("repriced model still classified as zero-cost")
		}
	}
}
