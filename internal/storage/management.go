package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// LoginProvision is an operator-owned profile contract for non-email identities.
// Partner/SSO profile validation remains unchanged.
type LoginProvision struct {
	Subject string `json:"subject"`
	Name    string `json:"name"`
	Role    string `json:"role,omitempty"`
	Active  *bool  `json:"active,omitempty"`
}

var loginSubjectPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$`)

// ManagedUserByLogin resolves a target for authorized administrative operations,
// including suspended identities and retained logins. Never use this to
// authenticate a caller; PartnerUserByMaaSUsername enforces current + active.
func (s *Store) ManagedUserByLogin(ctx context.Context, username string) (PartnerUser, error) {
	return s.partnerUserForPolicy(ctx, username)
}

// ProvisionLogin preserves an existing login's UUID and all usage records.
// It does not create keys or change budgets. Those are separate API operations.
func (s *Store) ProvisionLogin(ctx context.Context, actor string, p LoginProvision) (PartnerUser, error) {
	// Logins resolve case-insensitively everywhere (LOWER(username) =
	// LOWER($1)); provisioning must not be able to mint a second case-variant
	// identity for a person whose login already exists. Canonicalize the
	// subject first so the advisory lock, the duplicate check, and the stored
	// spelling all use one form.
	p.Subject = strings.ToLower(strings.TrimSpace(p.Subject))
	// Trim the name so a whitespace-only value behaves as unset instead of
	// being persisted as a first_name, and reject control characters that
	// would render as garbage identity labels.
	p.Name = strings.TrimSpace(p.Name)
	if !loginSubjectPattern.MatchString(p.Subject) || len(p.Name) > 256 ||
		strings.IndexFunc(p.Name, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return PartnerUser{}, fmt.Errorf("invalid subject or name")
	}
	if p.Role != "" && p.Role != PartnerRoleUser && p.Role != PartnerRoleAdmin && p.Role != PartnerRoleSuperAdmin {
		return PartnerUser{}, fmt.Errorf("invalid role")
	}
	// Grants (roles, budgets, credits) attach to the default tenant's policy
	// subjects; the subject row is created inside the transaction below so a
	// newly provisioned login is immediately grantable.
	tenantID, err := s.EnsureDefaultTenant(ctx)
	if err != nil {
		return PartnerUser{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return PartnerUser{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('metering-login'),hashtext($1))`, p.Subject); err != nil {
		return PartnerUser{}, err
	}
	var id string
	// Match case-insensitively so a differently spelled provision reuses the
	// existing account instead of creating a case-variant twin. The ORDER BY
	// keeps the pick stable on databases that still carry rows provisioned
	// before this normalization.
	err = tx.QueryRowContext(ctx, `SELECT user_id FROM partner_user_logins WHERE LOWER(username)=$1 ORDER BY is_current DESC, username LIMIT 1`, p.Subject).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		var b [16]byte
		if _, err = rand.Read(b[:]); err != nil {
			return PartnerUser{}, err
		}
		b[6] = (b[6] & 15) | 64
		b[8] = (b[8] & 63) | 128
		id = fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
		name := p.Name
		if name == "" {
			name = p.Subject
		}
		tags, _ := json.Marshal(map[string]string{"first_name": name})
		if _, err = tx.ExecContext(ctx, `INSERT INTO partner_users(user_id,tags,created_by,updated_by) VALUES($1,$2,$3,$3)`, id, string(tags), actor); err != nil {
			return PartnerUser{}, err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO partner_user_logins(username,user_id,is_current) VALUES($1,$2,true)`, p.Subject, id); err != nil {
			return PartnerUser{}, err
		}
	} else if err != nil {
		return PartnerUser{}, err
	}
	// Serialize account-level mutations by stable user id: the advisory lock
	// above is per-login-spelling, so a suspension through the current login
	// and a no-field provision through a retained alias can otherwise race
	// and let the provision's subject upsert write a stale active status
	// back. Lock the row so the subject upsert below reads the committed
	// profile rather than a pre-suspension snapshot.
	if _, err = tx.ExecContext(ctx, `SELECT user_id FROM partner_users WHERE user_id=$1 FOR UPDATE`, id); err != nil {
		return PartnerUser{}, err
	}
	if p.Name != "" {
		if _, err = tx.ExecContext(ctx, `UPDATE partner_users SET tags=tags||jsonb_build_object('first_name',$2::text),updated_by=$3,updated_at=now() WHERE user_id=$1`, id, p.Name, actor); err != nil {
			return PartnerUser{}, err
		}
	}
	if p.Role != "" {
		if _, err = tx.ExecContext(ctx, `UPDATE partner_users SET role=$2,updated_by=$3,updated_at=now() WHERE user_id=$1`, id, p.Role, actor); err != nil {
			return PartnerUser{}, err
		}
	}
	if p.Active != nil {
		result, updateErr := tx.ExecContext(ctx, `UPDATE partner_users SET active=$2,updated_by=$3,updated_at=now() WHERE user_id=$1 AND NOT key_revocation_pending`, id, *p.Active, actor)
		if updateErr != nil {
			return PartnerUser{}, updateErr
		}
		changed, updateErr := result.RowsAffected()
		if updateErr != nil {
			return PartnerUser{}, updateErr
		}
		if changed != 1 {
			return PartnerUser{}, fmt.Errorf("profile activation cannot change while key revocation is pending")
		}
	}
	// Materialize the login's policy subject in the same transaction. The
	// upsert mirrors SyncPartnerUserSubject (stable subject id for an
	// existing row, external_id = the stable user id, never the login
	// spelling), but reads partner_users through the transaction so the
	// subject's status and display name match the profile just written.
	// Without this row, filter-based role and budget grants — an
	// INSERT..SELECT over policy_subjects — silently match nothing until the
	// login's first quota decision or the next startup directory sync
	// creates the subject.
	subject, subjectErr := tx.ExecContext(ctx, `
		INSERT INTO policy_subjects
			(subject_id, tenant_id, principal_type, external_id, display_name, status, source)
		SELECT $1, $2, $3, pu.user_id::text,
			COALESCE(NULLIF(pu.tags->>'preferred_username', ''), NULLIF(pu.tags->>'email', ''), pu.user_id::text),
			CASE WHEN pu.active THEN 'active' ELSE 'inactive' END, 'partner'
		FROM partner_users pu
		WHERE pu.user_id = $4
		ON CONFLICT (tenant_id, principal_type, external_id) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			status = EXCLUDED.status,
			updated_at = NOW()`,
		uuid.NewString(), tenantID, PrincipalPartnerUser, id)
	if subjectErr != nil {
		return PartnerUser{}, fmt.Errorf("provision policy subject: %w", subjectErr)
	}
	changed, subjectErr := subject.RowsAffected()
	if subjectErr != nil {
		return PartnerUser{}, subjectErr
	}
	if changed != 1 {
		return PartnerUser{}, ErrPartnerUserNotFound
	}
	detail, _ := json.Marshal(p)
	if _, err = tx.ExecContext(ctx, `INSERT INTO org_audit(actor,action,target,detail) VALUES($1,'login.provision',$2,$3)`, actor, p.Subject, string(detail)); err != nil {
		return PartnerUser{}, err
	}
	// Read the response row inside the transaction: a failed read rolls the
	// update back instead of reporting an error for a change that already
	// committed.
	user, err := scanPartnerUser(tx.QueryRowContext(ctx, partnerUserSelect+` WHERE p.user_id = $1`, id))
	if err != nil {
		return PartnerUser{}, err
	}
	if err = tx.Commit(); err != nil {
		return PartnerUser{}, err
	}
	s.invalidateQuotaCache()
	return user, nil
}

// ManagedPrice sets a future rate or snapshots a reviewed source under an alias.
// Existing event charges are immutable; historical repricing is a separate API.
type ManagedPrice struct {
	Model       string   `json:"model"`
	Provider    string   `json:"provider"`
	SourceModel string   `json:"source_model,omitempty"`
	Input       *float64 `json:"input_cost_per_mtok,omitempty"`
	Output      *float64 `json:"output_cost_per_mtok,omitempty"`
	CacheWrite  *float64 `json:"cache_write_cost_per_mtok,omitempty"`
	CacheRead   *float64 `json:"cache_read_cost_per_mtok,omitempty"`
}

func (s *Store) SetManagedPrice(ctx context.Context, actor string, p ManagedPrice) error {
	// Normalize before every use — advisory lock, backfill, upsert, audit,
	// and the source-model lookup must all see the same identifier, or a
	// padded request like " model-a " would create a distinct row instead
	// of updating model-a.
	p.Model = strings.TrimSpace(p.Model)
	p.Provider = strings.TrimSpace(p.Provider)
	p.SourceModel = strings.TrimSpace(p.SourceModel)
	if p.Model == "" || len(p.Model) > 256 || p.Provider == "" || len(p.Provider) > 128 || len(p.SourceModel) > 256 {
		return fmt.Errorf("invalid model/provider")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext('model-price'),hashtext($1))`, p.Model); err != nil {
		return err
	}
	var rates [4]float64
	if p.SourceModel != "" {
		if p.Input != nil || p.Output != nil || p.CacheWrite != nil || p.CacheRead != nil {
			return fmt.Errorf("choose source_model or explicit rates")
		}
		if err = tx.QueryRowContext(ctx, `SELECT input_cost_per_mtok,output_cost_per_mtok,cache_write_cost_per_mtok,cache_read_cost_per_mtok FROM model_pricing WHERE model=$1`, p.SourceModel).Scan(&rates[0], &rates[1], &rates[2], &rates[3]); err != nil {
			return err
		}
	} else {
		for i, v := range []*float64{p.Input, p.Output, p.CacheWrite, p.CacheRead} {
			// model_pricing rate columns are NUMERIC(10,4): bound and
			// precision-check here so an over-wide value fails with a clear
			// message instead of a database overflow, and a fifth decimal
			// digit is rejected instead of being silently rounded by
			// Postgres. 0 and 0.0001 stay valid; nothing is rounded.
			if v == nil || math.IsNaN(*v) || math.IsInf(*v, 0) || *v < 0 || *v > 999999.9999 ||
				math.Abs(*v*10000-math.Round(*v*10000)) > 1e-3 {
				return fmt.Errorf("four rates from 0 to 999999.9999 with at most four decimal places are required")
			}
			rates[i] = *v
		}
	}
	// Preserve charges from older, not-yet-backfilled ledger rows before changing rates.
	// The outer WHERE rechecks cost_usd IS NULL: under READ COMMITTED a
	// concurrent repricing can commit a cost for one of these rows after the
	// subquery's snapshot, and this update must not overwrite that value.
	if _, err = tx.ExecContext(ctx, fmt.Sprintf(`UPDATE usage_events u SET cost_usd=q.cost FROM (SELECT e.id,%s AS cost FROM usage_events e LEFT JOIN model_pricing p ON p.model=e.model WHERE e.model=$1 AND e.cost_usd IS NULL) q WHERE u.id=q.id AND u.cost_usd IS NULL`, currentPriceUSDExpr), p.Model); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO model_pricing(model,provider,input_cost_per_mtok,output_cost_per_mtok,cache_write_cost_per_mtok,cache_read_cost_per_mtok,managed_rate) VALUES($1,$2,$3,$4,$5,$6,true) ON CONFLICT(model) DO UPDATE SET provider=EXCLUDED.provider,input_cost_per_mtok=EXCLUDED.input_cost_per_mtok,output_cost_per_mtok=EXCLUDED.output_cost_per_mtok,cache_write_cost_per_mtok=EXCLUDED.cache_write_cost_per_mtok,cache_read_cost_per_mtok=EXCLUDED.cache_read_cost_per_mtok,managed_rate=true`, p.Model, p.Provider, rates[0], rates[1], rates[2], rates[3]); err != nil {
		return err
	}
	detail, _ := json.Marshal(map[string]any{"request": p, "resolved_rates": rates})
	if _, err = tx.ExecContext(ctx, `INSERT INTO org_audit(actor,action,target,detail) VALUES($1,'pricing.rate_set',$2,$3)`, actor, p.Model, string(detail)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	// The rate change is durable now, so drop the process-local zero-cost
	// memo and the quota decision cache — and only now: resetting before
	// the commit would let a concurrent reader repopulate both from the
	// still-old committed rates and keep serving them after this commit
	// lands. A failed commit returns above with both caches untouched.
	// The epoch bump also stops a reader whose query started before this
	// commit from writing its pre-commit answer back into the memo after
	// the reset.
	s.zeroCostMu.Lock()
	s.zeroCostModels = nil
	s.zeroCostExpires = time.Time{}
	s.zeroCostEpoch++
	s.zeroCostMu.Unlock()
	s.invalidateQuotaCache()
	return nil
}

// PartnerUserIDByLogin resolves any login spelling, current or retained, to
// its stable user ID with the exact resolution ProvisionLogin applies. The
// management self-protection guard uses it to compare stable identities:
// login spellings change when an account is renamed, and a retained login
// still resolves to the renamed account.
func (s *Store) PartnerUserIDByLogin(ctx context.Context, username string) (string, error) {
	var id string
	// The exact resolution ProvisionLogin applies — normalized and
	// case-insensitive over every spelling, current or retained — so the
	// management self-guard cannot be bypassed with a case or whitespace
	// variant of a login. The ORDER BY keeps the pick stable on databases
	// that still carry pre-normalization case variants.
	username = strings.ToLower(strings.TrimSpace(username))
	err := s.db.QueryRowContext(ctx, `SELECT user_id FROM partner_user_logins WHERE LOWER(username)=$1 ORDER BY is_current DESC, username LIMIT 1`, username).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrPartnerUserNotFound
	}
	return id, err
}
