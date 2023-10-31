// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.19.1
// source: profiles.sql

package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

const countProfilesByEntityType = `-- name: CountProfilesByEntityType :many
SELECT COUNT(p.id) AS num_profiles, ep.entity AS profile_entity
FROM profiles AS p
         JOIN entity_profiles AS ep ON p.id = ep.profile_id
GROUP BY ep.entity
`

type CountProfilesByEntityTypeRow struct {
	NumProfiles   int64    `json:"num_profiles"`
	ProfileEntity Entities `json:"profile_entity"`
}

func (q *Queries) CountProfilesByEntityType(ctx context.Context) ([]CountProfilesByEntityTypeRow, error) {
	rows, err := q.db.QueryContext(ctx, countProfilesByEntityType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []CountProfilesByEntityTypeRow{}
	for rows.Next() {
		var i CountProfilesByEntityTypeRow
		if err := rows.Scan(&i.NumProfiles, &i.ProfileEntity); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const createProfile = `-- name: CreateProfile :one
INSERT INTO profiles (  
    provider,
    project_id,
    remediate,
    alert,
    name) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, provider, project_id, remediate, alert, created_at, updated_at
`

type CreateProfileParams struct {
	Provider  string         `json:"provider"`
	ProjectID uuid.UUID      `json:"project_id"`
	Remediate NullActionType `json:"remediate"`
	Alert     NullActionType `json:"alert"`
	Name      string         `json:"name"`
}

func (q *Queries) CreateProfile(ctx context.Context, arg CreateProfileParams) (Profile, error) {
	row := q.db.QueryRowContext(ctx, createProfile,
		arg.Provider,
		arg.ProjectID,
		arg.Remediate,
		arg.Alert,
		arg.Name,
	)
	var i Profile
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Provider,
		&i.ProjectID,
		&i.Remediate,
		&i.Alert,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const createProfileForEntity = `-- name: CreateProfileForEntity :one
INSERT INTO entity_profiles (
    entity,
    profile_id,
    contextual_rules) VALUES ($1, $2, $3::jsonb) RETURNING id, entity, profile_id, contextual_rules, created_at, updated_at
`

type CreateProfileForEntityParams struct {
	Entity          Entities        `json:"entity"`
	ProfileID       uuid.UUID       `json:"profile_id"`
	ContextualRules json.RawMessage `json:"contextual_rules"`
}

func (q *Queries) CreateProfileForEntity(ctx context.Context, arg CreateProfileForEntityParams) (EntityProfile, error) {
	row := q.db.QueryRowContext(ctx, createProfileForEntity, arg.Entity, arg.ProfileID, arg.ContextualRules)
	var i EntityProfile
	err := row.Scan(
		&i.ID,
		&i.Entity,
		&i.ProfileID,
		&i.ContextualRules,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const deleteProfile = `-- name: DeleteProfile :exec
DELETE FROM profiles
WHERE id = $1
`

func (q *Queries) DeleteProfile(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, deleteProfile, id)
	return err
}

const getProfileByID = `-- name: GetProfileByID :one
SELECT id, name, provider, project_id, remediate, alert, created_at, updated_at FROM profiles WHERE id = $1
`

func (q *Queries) GetProfileByID(ctx context.Context, id uuid.UUID) (Profile, error) {
	row := q.db.QueryRowContext(ctx, getProfileByID, id)
	var i Profile
	err := row.Scan(
		&i.ID,
		&i.Name,
		&i.Provider,
		&i.ProjectID,
		&i.Remediate,
		&i.Alert,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getProfileByProjectAndID = `-- name: GetProfileByProjectAndID :many
SELECT profiles.id, name, provider, project_id, remediate, alert, profiles.created_at, profiles.updated_at, entity_profiles.id, entity, profile_id, contextual_rules, entity_profiles.created_at, entity_profiles.updated_at FROM profiles JOIN entity_profiles ON profiles.id = entity_profiles.profile_id
WHERE profiles.project_id = $1 AND profiles.id = $2
`

type GetProfileByProjectAndIDParams struct {
	ProjectID uuid.UUID `json:"project_id"`
	ID        uuid.UUID `json:"id"`
}

type GetProfileByProjectAndIDRow struct {
	ID              uuid.UUID       `json:"id"`
	Name            string          `json:"name"`
	Provider        string          `json:"provider"`
	ProjectID       uuid.UUID       `json:"project_id"`
	Remediate       NullActionType  `json:"remediate"`
	Alert           NullActionType  `json:"alert"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	ID_2            uuid.UUID       `json:"id_2"`
	Entity          Entities        `json:"entity"`
	ProfileID       uuid.UUID       `json:"profile_id"`
	ContextualRules json.RawMessage `json:"contextual_rules"`
	CreatedAt_2     time.Time       `json:"created_at_2"`
	UpdatedAt_2     time.Time       `json:"updated_at_2"`
}

func (q *Queries) GetProfileByProjectAndID(ctx context.Context, arg GetProfileByProjectAndIDParams) ([]GetProfileByProjectAndIDRow, error) {
	rows, err := q.db.QueryContext(ctx, getProfileByProjectAndID, arg.ProjectID, arg.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetProfileByProjectAndIDRow{}
	for rows.Next() {
		var i GetProfileByProjectAndIDRow
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Provider,
			&i.ProjectID,
			&i.Remediate,
			&i.Alert,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.ID_2,
			&i.Entity,
			&i.ProfileID,
			&i.ContextualRules,
			&i.CreatedAt_2,
			&i.UpdatedAt_2,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const getProfileByProjectAndName = `-- name: GetProfileByProjectAndName :many
SELECT profiles.id, name, provider, project_id, remediate, alert, profiles.created_at, profiles.updated_at, entity_profiles.id, entity, profile_id, contextual_rules, entity_profiles.created_at, entity_profiles.updated_at FROM profiles JOIN entity_profiles ON profiles.id = entity_profiles.profile_id
WHERE profiles.project_id = $1 AND profiles.name = $2
`

type GetProfileByProjectAndNameParams struct {
	ProjectID uuid.UUID `json:"project_id"`
	Name      string    `json:"name"`
}

type GetProfileByProjectAndNameRow struct {
	ID              uuid.UUID       `json:"id"`
	Name            string          `json:"name"`
	Provider        string          `json:"provider"`
	ProjectID       uuid.UUID       `json:"project_id"`
	Remediate       NullActionType  `json:"remediate"`
	Alert           NullActionType  `json:"alert"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	ID_2            uuid.UUID       `json:"id_2"`
	Entity          Entities        `json:"entity"`
	ProfileID       uuid.UUID       `json:"profile_id"`
	ContextualRules json.RawMessage `json:"contextual_rules"`
	CreatedAt_2     time.Time       `json:"created_at_2"`
	UpdatedAt_2     time.Time       `json:"updated_at_2"`
}

func (q *Queries) GetProfileByProjectAndName(ctx context.Context, arg GetProfileByProjectAndNameParams) ([]GetProfileByProjectAndNameRow, error) {
	rows, err := q.db.QueryContext(ctx, getProfileByProjectAndName, arg.ProjectID, arg.Name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetProfileByProjectAndNameRow{}
	for rows.Next() {
		var i GetProfileByProjectAndNameRow
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Provider,
			&i.ProjectID,
			&i.Remediate,
			&i.Alert,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.ID_2,
			&i.Entity,
			&i.ProfileID,
			&i.ContextualRules,
			&i.CreatedAt_2,
			&i.UpdatedAt_2,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const listProfilesByProjectID = `-- name: ListProfilesByProjectID :many
SELECT profiles.id, name, provider, project_id, remediate, alert, profiles.created_at, profiles.updated_at, entity_profiles.id, entity, profile_id, contextual_rules, entity_profiles.created_at, entity_profiles.updated_at FROM profiles JOIN entity_profiles ON profiles.id = entity_profiles.profile_id
WHERE profiles.project_id = $1
`

type ListProfilesByProjectIDRow struct {
	ID              uuid.UUID       `json:"id"`
	Name            string          `json:"name"`
	Provider        string          `json:"provider"`
	ProjectID       uuid.UUID       `json:"project_id"`
	Remediate       NullActionType  `json:"remediate"`
	Alert           NullActionType  `json:"alert"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	ID_2            uuid.UUID       `json:"id_2"`
	Entity          Entities        `json:"entity"`
	ProfileID       uuid.UUID       `json:"profile_id"`
	ContextualRules json.RawMessage `json:"contextual_rules"`
	CreatedAt_2     time.Time       `json:"created_at_2"`
	UpdatedAt_2     time.Time       `json:"updated_at_2"`
}

func (q *Queries) ListProfilesByProjectID(ctx context.Context, projectID uuid.UUID) ([]ListProfilesByProjectIDRow, error) {
	rows, err := q.db.QueryContext(ctx, listProfilesByProjectID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ListProfilesByProjectIDRow{}
	for rows.Next() {
		var i ListProfilesByProjectIDRow
		if err := rows.Scan(
			&i.ID,
			&i.Name,
			&i.Provider,
			&i.ProjectID,
			&i.Remediate,
			&i.Alert,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.ID_2,
			&i.Entity,
			&i.ProfileID,
			&i.ContextualRules,
			&i.CreatedAt_2,
			&i.UpdatedAt_2,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const listProfilesInstantiatingRuleType = `-- name: ListProfilesInstantiatingRuleType :many
SELECT profiles.id, profiles.name, profiles.created_at FROM profiles
JOIN entity_profiles ON profiles.id = entity_profiles.profile_id 
JOIN entity_profile_rules ON entity_profiles.id = entity_profile_rules.entity_profile_id
WHERE entity_profile_rules.rule_type_id = $1
GROUP BY profiles.id
`

type ListProfilesInstantiatingRuleTypeRow struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// get profile information that instantiate a rule. This is done by joining the profiles with entity_profiles, then correlating those
// with entity_profile_rules. The rule_type_id is used to filter the results. Note that we only really care about the overal profile,
// so we only return the profile information. We also should group the profiles so that we don't get duplicates.
func (q *Queries) ListProfilesInstantiatingRuleType(ctx context.Context, ruleTypeID uuid.UUID) ([]ListProfilesInstantiatingRuleTypeRow, error) {
	rows, err := q.db.QueryContext(ctx, listProfilesInstantiatingRuleType, ruleTypeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ListProfilesInstantiatingRuleTypeRow{}
	for rows.Next() {
		var i ListProfilesInstantiatingRuleTypeRow
		if err := rows.Scan(&i.ID, &i.Name, &i.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const upsertRuleInstantiation = `-- name: UpsertRuleInstantiation :one
INSERT INTO entity_profile_rules (entity_profile_id, rule_type_id)
VALUES ($1, $2)
ON CONFLICT (entity_profile_id, rule_type_id) DO NOTHING RETURNING id, entity_profile_id, rule_type_id, created_at
`

type UpsertRuleInstantiationParams struct {
	EntityProfileID uuid.UUID `json:"entity_profile_id"`
	RuleTypeID      uuid.UUID `json:"rule_type_id"`
}

func (q *Queries) UpsertRuleInstantiation(ctx context.Context, arg UpsertRuleInstantiationParams) (EntityProfileRule, error) {
	row := q.db.QueryRowContext(ctx, upsertRuleInstantiation, arg.EntityProfileID, arg.RuleTypeID)
	var i EntityProfileRule
	err := row.Scan(
		&i.ID,
		&i.EntityProfileID,
		&i.RuleTypeID,
		&i.CreatedAt,
	)
	return i, err
}
