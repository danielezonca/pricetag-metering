package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type ManagedOrgUsageRow struct {
	OrgUsageRow
	QuotaExempt   bool `json:"quota_exempt"`
	QuotaEnforced bool `json:"quota_enforced"`
}

func (s *Store) ListPartnerUsersPageByState(ctx context.Context, search, state string, limit, offset int) ([]PartnerUser, int, bool, error) {
	if state != "all" && state != "active" && state != "inactive" {
		return nil, 0, false, errors.New("invalid user state")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	where := `WHERE ($2 = 'all' OR p.active = ($2 = 'active')) AND ($1 = '' OR (
		lower(COALESCE(p.tags->>'email','')) LIKE '%' || lower($1) || '%'
		OR lower(COALESCE(p.tags->>'first_name','')) LIKE '%' || lower($1) || '%'
		OR lower(COALESCE(p.tags->>'last_name','')) LIKE '%' || lower($1) || '%'
		OR lower(TRIM(CONCAT_WS(' ', p.tags->>'first_name', p.tags->>'last_name'))) LIKE '%' || lower($1) || '%'
		OR lower(p.user_id::text) LIKE '%' || lower($1) || '%'
		OR EXISTS (SELECT 1 FROM partner_user_logins l WHERE l.user_id=p.user_id AND lower(l.username) LIKE '%' || lower($1) || '%')
	))`
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM partner_users p `+where, search, state).Scan(&total); err != nil {
		return nil, 0, false, err
	}
	rows, err := s.db.QueryContext(ctx, partnerUserSelect+` `+where+` ORDER BY p.created_at, p.user_id LIMIT $3 OFFSET $4`, search, state, limit+1, offset)
	if err != nil {
		return nil, 0, false, err
	}
	defer rows.Close()
	users := make([]PartnerUser, 0, limit+1)
	for rows.Next() {
		user, err := scanPartnerUser(rows)
		if err != nil {
			return nil, 0, false, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false, err
	}
	hasMore := len(users) > limit
	if hasMore {
		users = users[:limit]
	}
	return users, total, hasMore, nil
}

// CurrentPartnerUserLogin (in partner_users.go) resolves the account's
// current login spelling — the only one new credentials are minted for.

func (s *Store) partnerUserForPolicy(ctx context.Context, username string) (PartnerUser, error) {
	// Deterministic resolution matching ProvisionLogin and
	// PartnerUserIDByLogin: databases can still carry pre-normalization
	// case-variant login rows, and an unordered match could resolve a
	// subject to a different account on each call.
	user, err := scanPartnerUser(s.db.QueryRowContext(ctx, partnerUserSelect+`
		JOIN partner_user_logins l ON l.user_id = p.user_id
		WHERE LOWER(l.username) = LOWER($1)
		ORDER BY l.is_current DESC, l.username
		LIMIT 1`, strings.TrimSpace(username)))
	if errors.Is(err, sql.ErrNoRows) {
		return PartnerUser{}, ErrPartnerUserNotFound
	}
	return user, err
}

func (s *Store) ListPartnerUsernamesBatch(ctx context.Context, userIDs []string) (map[string][]string, error) {
	out := make(map[string][]string, len(userIDs))
	if len(userIDs) == 0 {
		return out, nil
	}
	ids := make([]string, 0, len(userIDs))
	for _, id := range userIDs {
		normalized, err := normalizePartnerUserID(id)
		if err != nil {
			return nil, err
		}
		ids = append(ids, normalized)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT user_id,username FROM partner_user_logins WHERE user_id=ANY($1) ORDER BY user_id,is_current DESC,username`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var userID, username string
		if err := rows.Scan(&userID, &username); err != nil {
			return nil, err
		}
		out[userID] = append(out[userID], username)
	}
	return out, rows.Err()
}

func (s *Store) UserBudgetOverridesPage(ctx context.Context, search, subject string, limit, offset int) ([]QuotaOverride, bool, error) {
	if limit < 1 || limit > 100 || offset < 0 || offset > 1000000 || len(search) > 128 || len(subject) > 128 {
		return nil, false, fmt.Errorf("invalid override page")
	}
	rows, err := s.db.QueryContext(ctx, `SELECT scope,principal,monthly_usd,updated_by,updated_at
 FROM quota_overrides WHERE scope='user' AND ($1='' OR strpos(lower(principal),lower($1))>0)
 AND ($2='' OR principal=$2) ORDER BY principal LIMIT $3 OFFSET $4`, search, subject, limit+1, offset)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []QuotaOverride{}
	for rows.Next() {
		var row QuotaOverride
		if err := rows.Scan(&row.Scope, &row.Principal, &row.MonthlyUSD, &row.UpdatedBy, &row.UpdatedAt); err != nil {
			return nil, false, err
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

func (s *Store) GetManagedPartnerOrgUsage(ctx context.Context, rootUserID string, since, until time.Time) ([]ManagedOrgUsageRow, error) {
	// The role-budget and credit composition needs the tenant-scoped policy
	// subjects; quotaDecision resolves the same default tenant.
	tenantID, err := s.EnsureDefaultTenant(ctx)
	if err != nil {
		return nil, err
	}
	from := `partner_user_logins l ON l.user_id = st.user_id
			JOIN usage_events e ON e.username = l.username
			LEFT JOIN model_pricing p ON e.model = p.model`
	window := `e.timestamp >= $2 AND e.timestamp < $3`
	requests := `COUNT(*)`
	cost := fmt.Sprintf(`COALESCE(ROUND(SUM(%s)::numeric,2),0)`, costUSDExpr)
	lastUsed := `MAX(e.timestamp)`
	if s.rollupsLive() {
		since = ceilToHour(since)
		from = `partner_user_logins l ON l.user_id = st.user_id
			JOIN usage_hourly e ON e.username = l.username`
		window = `e.hour >= $2 AND e.hour < $3`
		requests = `COALESCE(SUM(e.requests),0)`
		cost = `COALESCE(ROUND(SUM(e.cost_usd)::numeric,2),0)`
		lastUsed = `MAX(e.hour)`
	}
	// The join must be e.model = p.model: a self-referential predicate would
	// multiply every event by every pricing row (or drop its cost entirely
	// when no pricing exists), silently corrupting the month-to-date spend
	// that drives QuotaSpentUSD and OverLimit.
	monthly := fmt.Sprintf(`SELECT l.user_id, COALESCE(SUM(%s),0) AS spent
        FROM (SELECT DISTINCT user_id FROM subtree) st
        JOIN partner_user_logins l ON l.user_id=st.user_id
        JOIN usage_events e ON e.username=l.username
        LEFT JOIN model_pricing p ON e.model = p.model
        WHERE e.timestamp>=date_trunc('month',NOW()) GROUP BY l.user_id`, costUSDExpr)
	if s.monthSpendEnabled.Load() {
		monthly = `SELECT l.user_id, COALESCE(SUM(m.spent_usd),0) AS spent
        FROM (SELECT DISTINCT user_id FROM subtree) st JOIN partner_user_logins l ON l.user_id=st.user_id
        JOIN user_month_spend m ON m.username=l.username
        WHERE m.month=date_trunc('month',NOW())::date GROUP BY l.user_id`
	}
	query := fmt.Sprintf(`
		WITH RECURSIVE subtree(user_id, depth, path) AS (
			SELECT p.user_id, 0, ARRAY[p.user_id]
			FROM partner_users p
			WHERE p.active AND ($1 = '' OR p.user_id = $1::uuid)
			UNION ALL
			SELECT p.user_id, st.depth + 1, st.path || p.user_id
			FROM partner_users p JOIN subtree st ON p.manager_user_id = st.user_id
			WHERE $1 <> '' AND p.active AND st.depth < 1000 AND NOT p.user_id = ANY(st.path)
		), u AS (
			SELECT l.user_id, %s AS requests, COALESCE(SUM(e.total_tokens),0) AS total_tokens,
				%s AS cost_usd, %s AS last_used
			FROM (SELECT DISTINCT user_id FROM subtree) st JOIN %s WHERE %s GROUP BY l.user_id
		), managers AS (
			SELECT DISTINCT manager_user_id AS user_id FROM partner_users
			WHERE active AND manager_user_id IS NOT NULL
		), monthly AS (%s),
		%s
		SELECT DISTINCT st.user_id::text, COALESCE(%s, cl.username, ''), COALESCE(cl.username,''),
			COALESCE(pu.manager_user_id::text,''), (m.user_id IS NOT NULL),
			COALESCE(u.requests,0), COALESCE(u.total_tokens,0), COALESCE(u.cost_usd,0),
			to_char(u.last_used, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
			-- Same composition as quotaDecision: a per-user override replaces
			-- the role-budget sum, a positive role budget replaces the
			-- default, and active unexpired credits are added on top.
			(CASE
				WHEN ov.monthly_usd IS NOT NULL THEN ov.monthly_usd
				WHEN COALESCE(rb.usd, 0) > 0 THEN rb.usd
				ELSE pol.default_monthly_usd
			END) + COALESCE(cr.usd, 0), COALESCE(monthly.spent,0),
			COALESCE(pol.enforced,false), pu.role='super_admin', (dbc.country IS NOT NULL)
		FROM (SELECT DISTINCT user_id FROM subtree) st
		JOIN partner_users pu ON pu.user_id = st.user_id
		LEFT JOIN managers m ON m.user_id = st.user_id
		LEFT JOIN LATERAL (
			SELECT username FROM partner_user_logins WHERE user_id = st.user_id
			ORDER BY is_current DESC, username LIMIT 1
		) cl ON true
		LEFT JOIN u ON u.user_id = st.user_id
		LEFT JOIN monthly ON monthly.user_id=st.user_id
		LEFT JOIN (SELECT default_monthly_usd, enforced FROM quota_policy ORDER BY id LIMIT 1) pol ON true
		-- User-scope override principals are stored lowercased (the management
		-- handler normalizes its subjects), so compare against the normalized
		-- login: same rule as the enforcement join in quotaDecision. The LEFT
		-- JOIN keeps the current login selected even when it carries no
		-- override, so an override attached to a retained (renamed-away)
		-- login cannot leak into the row; the CASE above then falls back to
		-- the role budget or the policy default.
		LEFT JOIN LATERAL (
			SELECT ov.monthly_usd FROM partner_user_logins l
			LEFT JOIN quota_overrides ov ON ov.scope='user' AND ov.principal=LOWER(l.username)
			WHERE l.user_id = st.user_id ORDER BY l.is_current DESC, l.username LIMIT 1
		) ov ON true
		LEFT JOIN subjects sb ON sb.user_id = st.user_id
		LEFT JOIN role_budget rb ON rb.subject_id = sb.subject_id
		LEFT JOIN credits cr ON cr.subject_id = sb.subject_id
		-- Dashboard country policy: the row is flagged, not filtered, so
		-- the handler can keep super-admin visibility while hiding the
		-- person from managers (same join as GetPartnerOrgUsage).
		LEFT JOIN dashboard_blocked_countries dbc
			ON dbc.country = UPPER(BTRIM(COALESCE(pu.tags->>'country', '')))
		ORDER BY 8 DESC, 2`, requests, cost, lastUsed, from, window, monthly, roleBudgetCreditsCTE("$4"), partnerFullNameExpr)
	rows, err := s.db.QueryContext(ctx, query, rootUserID, since, until, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ManagedOrgUsageRow
	for rows.Next() {
		var row ManagedOrgUsageRow
		var lastUsed sql.NullString
		if err := rows.Scan(&row.Slug, &row.FullName, &row.Username, &row.ManagerSlug,
			&row.IsManager, &row.Requests, &row.TotalTokens, &row.CostUSD, &lastUsed,
			&row.QuotaUSD, &row.QuotaSpentUSD, &row.QuotaEnforced, &row.QuotaExempt, &row.Blocked); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			row.LastUsed = &lastUsed.String
		}
		row.NoIdentity = row.Username == ""
		// A zero quota means "no USD budget configured", not a zero
		// allowance: without the guard an enforced policy with no default
		// budget would flag every row over limit (spent >= 0).
		row.OverLimit = row.QuotaEnforced && !row.QuotaExempt && row.QuotaUSD > 0 && row.QuotaSpentUSD >= row.QuotaUSD
		out = append(out, row)
	}
	return out, rows.Err()
}
