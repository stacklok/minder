// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0
// source: profiles.sql

package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

const countProfilesByEntityType = `-- name: CountProfilesByEntityType :many
SELECT COUNT(DISTINCT(p.id)) AS num_profiles, r.entity_type AS profile_entity
FROM profiles AS p
JOIN rule_instances AS r ON p.id = r.profile_id
GROUP BY r.entity_type
`

type CountProfilesByEntityTypeRow struct {
	NumProfiles   int64    `json:"num_profiles"`
	ProfileEntity Entities `json:"profile_entity"`
}

// SELECT COUNT(p.id) AS num_profiles, ep.entity AS profile_entity
// FROM profiles AS p
// JOIN entity_profiles AS ep ON p.id = ep.profile_id
// GROUP BY ep.entity;
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

const countProfilesByName = `-- name: CountProfilesByName :one
SELECT COUNT(*) AS num_named_profiles FROM profiles WHERE lower(name) = lower($1)
`

func (q *Queries) CountProfilesByName(ctx context.Context, name string) (int64, error) {
	row := q.db.QueryRowContext(ctx, countProfilesByName, name)
	var num_named_profiles int64
	err := row.Scan(&num_named_profiles)
	return num_named_profiles, err
}

const createProfile = `-- name: CreateProfile :one
INSERT INTO profiles (  
    project_id,
    remediate,
    alert,
    name,
    subscription_id,
    display_name,
    labels
) VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7::text[], '{}'::text[])) RETURNING id, name, provider, project_id, remediate, alert, created_at, updated_at, provider_id, subscription_id, display_name, labels
`

type CreateProfileParams struct {
	ProjectID      uuid.UUID      `json:"project_id"`
	Remediate      NullActionType `json:"remediate"`
	Alert          NullActionType `json:"alert"`
	Name           string         `json:"name"`
	SubscriptionID uuid.NullUUID  `json:"subscription_id"`
	DisplayName    string         `json:"display_name"`
	Labels         []string       `json:"labels"`
}

func (q *Queries) CreateProfile(ctx context.Context, arg CreateProfileParams) (Profile, error) {
	row := q.db.QueryRowContext(ctx, createProfile,
		arg.ProjectID,
		arg.Remediate,
		arg.Alert,
		arg.Name,
		arg.SubscriptionID,
		arg.DisplayName,
		pq.Array(arg.Labels),
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
		&i.ProviderID,
		&i.SubscriptionID,
		&i.DisplayName,
		pq.Array(&i.Labels),
	)
	return i, err
}

const createProfileForEntity = `-- name: CreateProfileForEntity :one
INSERT INTO entity_profiles (
    entity,
    profile_id,
    contextual_rules,
    migrated
) VALUES (
    $1,
    $2,
    $3::jsonb,
    TRUE
) RETURNING id, entity, profile_id, contextual_rules, created_at, updated_at, migrated
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
		&i.Migrated,
	)
	return i, err
}

const deleteProfile = `-- name: DeleteProfile :exec
DELETE FROM profiles
WHERE id = $1 AND project_id = $2
`

type DeleteProfileParams struct {
	ID        uuid.UUID `json:"id"`
	ProjectID uuid.UUID `json:"project_id"`
}

func (q *Queries) DeleteProfile(ctx context.Context, arg DeleteProfileParams) error {
	_, err := q.db.ExecContext(ctx, deleteProfile, arg.ID, arg.ProjectID)
	return err
}

const deleteProfileForEntity = `-- name: DeleteProfileForEntity :exec
DELETE FROM entity_profiles WHERE profile_id = $1 AND entity = $2
`

type DeleteProfileForEntityParams struct {
	ProfileID uuid.UUID `json:"profile_id"`
	Entity    Entities  `json:"entity"`
}

func (q *Queries) DeleteProfileForEntity(ctx context.Context, arg DeleteProfileForEntityParams) error {
	_, err := q.db.ExecContext(ctx, deleteProfileForEntity, arg.ProfileID, arg.Entity)
	return err
}

const deleteRuleInstantiation = `-- name: DeleteRuleInstantiation :exec
DELETE FROM entity_profile_rules WHERE entity_profile_id = $1 AND rule_type_id = $2
`

type DeleteRuleInstantiationParams struct {
	EntityProfileID uuid.UUID `json:"entity_profile_id"`
	RuleTypeID      uuid.UUID `json:"rule_type_id"`
}

func (q *Queries) DeleteRuleInstantiation(ctx context.Context, arg DeleteRuleInstantiationParams) error {
	_, err := q.db.ExecContext(ctx, deleteRuleInstantiation, arg.EntityProfileID, arg.RuleTypeID)
	return err
}

const getProfileByID = `-- name: GetProfileByID :one
SELECT id, name, provider, project_id, remediate, alert, created_at, updated_at, provider_id, subscription_id, display_name, labels FROM profiles WHERE id = $1 AND project_id = $2
`

type GetProfileByIDParams struct {
	ID        uuid.UUID `json:"id"`
	ProjectID uuid.UUID `json:"project_id"`
}

func (q *Queries) GetProfileByID(ctx context.Context, arg GetProfileByIDParams) (Profile, error) {
	row := q.db.QueryRowContext(ctx, getProfileByID, arg.ID, arg.ProjectID)
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
		&i.ProviderID,
		&i.SubscriptionID,
		&i.DisplayName,
		pq.Array(&i.Labels),
	)
	return i, err
}

const getProfileByIDAndLock = `-- name: GetProfileByIDAndLock :one
SELECT id, name, provider, project_id, remediate, alert, created_at, updated_at, provider_id, subscription_id, display_name, labels FROM profiles WHERE id = $1 AND project_id = $2 FOR UPDATE
`

type GetProfileByIDAndLockParams struct {
	ID        uuid.UUID `json:"id"`
	ProjectID uuid.UUID `json:"project_id"`
}

func (q *Queries) GetProfileByIDAndLock(ctx context.Context, arg GetProfileByIDAndLockParams) (Profile, error) {
	row := q.db.QueryRowContext(ctx, getProfileByIDAndLock, arg.ID, arg.ProjectID)
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
		&i.ProviderID,
		&i.SubscriptionID,
		&i.DisplayName,
		pq.Array(&i.Labels),
	)
	return i, err
}

const getProfileByNameAndLock = `-- name: GetProfileByNameAndLock :one
SELECT id, name, provider, project_id, remediate, alert, created_at, updated_at, provider_id, subscription_id, display_name, labels FROM profiles WHERE lower(name) = lower($2) AND project_id = $1 FOR UPDATE
`

type GetProfileByNameAndLockParams struct {
	ProjectID uuid.UUID `json:"project_id"`
	Name      string    `json:"name"`
}

func (q *Queries) GetProfileByNameAndLock(ctx context.Context, arg GetProfileByNameAndLockParams) (Profile, error) {
	row := q.db.QueryRowContext(ctx, getProfileByNameAndLock, arg.ProjectID, arg.Name)
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
		&i.ProviderID,
		&i.SubscriptionID,
		&i.DisplayName,
		pq.Array(&i.Labels),
	)
	return i, err
}

const getProfileByProjectAndID = `-- name: GetProfileByProjectAndID :many
WITH helper AS(
    SELECT pr.id as profid,
           ARRAY_AGG(ROW(ps.id, ps.profile_id, ps.entity, ps.selector, ps.comment)::profile_selector) AS selectors
    FROM profiles pr
             JOIN profile_selectors ps
                  ON pr.id = ps.profile_id
    WHERE pr.project_id = $1
    GROUP BY pr.id
)
SELECT
    profiles.id, profiles.name, profiles.provider, profiles.project_id, profiles.remediate, profiles.alert, profiles.created_at, profiles.updated_at, profiles.provider_id, profiles.subscription_id, profiles.display_name, profiles.labels,
    profiles_with_entity_profiles.id, profiles_with_entity_profiles.entity, profiles_with_entity_profiles.profile_id, profiles_with_entity_profiles.contextual_rules, profiles_with_entity_profiles.created_at, profiles_with_entity_profiles.updated_at, profiles_with_entity_profiles.profid,
    helper.selectors::profile_selector[] AS profiles_with_selectors
FROM profiles
JOIN profiles_with_entity_profiles ON profiles.id = profiles_with_entity_profiles.profid
LEFT JOIN helper ON profiles.id = helper.profid
WHERE profiles.project_id = $1 AND profiles.id = $2
`

type GetProfileByProjectAndIDParams struct {
	ProjectID uuid.UUID `json:"project_id"`
	ID        uuid.UUID `json:"id"`
}

type GetProfileByProjectAndIDRow struct {
	Profile                   Profile                   `json:"profile"`
	ProfilesWithEntityProfile ProfilesWithEntityProfile `json:"profiles_with_entity_profile"`
	ProfilesWithSelectors     []ProfileSelector         `json:"profiles_with_selectors"`
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
			&i.Profile.ID,
			&i.Profile.Name,
			&i.Profile.Provider,
			&i.Profile.ProjectID,
			&i.Profile.Remediate,
			&i.Profile.Alert,
			&i.Profile.CreatedAt,
			&i.Profile.UpdatedAt,
			&i.Profile.ProviderID,
			&i.Profile.SubscriptionID,
			&i.Profile.DisplayName,
			pq.Array(&i.Profile.Labels),
			&i.ProfilesWithEntityProfile.ID,
			&i.ProfilesWithEntityProfile.Entity,
			&i.ProfilesWithEntityProfile.ProfileID,
			&i.ProfilesWithEntityProfile.ContextualRules,
			&i.ProfilesWithEntityProfile.CreatedAt,
			&i.ProfilesWithEntityProfile.UpdatedAt,
			&i.ProfilesWithEntityProfile.Profid,
			pq.Array(&i.ProfilesWithSelectors),
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

const getProfileForEntity = `-- name: GetProfileForEntity :one
SELECT id, entity, profile_id, contextual_rules, created_at, updated_at, migrated FROM entity_profiles WHERE profile_id = $1 AND entity = $2
`

type GetProfileForEntityParams struct {
	ProfileID uuid.UUID `json:"profile_id"`
	Entity    Entities  `json:"entity"`
}

func (q *Queries) GetProfileForEntity(ctx context.Context, arg GetProfileForEntityParams) (EntityProfile, error) {
	row := q.db.QueryRowContext(ctx, getProfileForEntity, arg.ProfileID, arg.Entity)
	var i EntityProfile
	err := row.Scan(
		&i.ID,
		&i.Entity,
		&i.ProfileID,
		&i.ContextualRules,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Migrated,
	)
	return i, err
}

const listProfilesByProjectID = `-- name: ListProfilesByProjectID :many
WITH helper AS(
     SELECT pr.id as profid,
            ARRAY_AGG(ROW(ps.id, ps.profile_id, ps.entity, ps.selector, ps.comment)::profile_selector) AS selectors
       FROM profiles pr
       JOIN profile_selectors ps
         ON pr.id = ps.profile_id
      WHERE pr.project_id = $1
      GROUP BY pr.id
)
SELECT
    profiles.id, profiles.name, profiles.provider, profiles.project_id, profiles.remediate, profiles.alert, profiles.created_at, profiles.updated_at, profiles.provider_id, profiles.subscription_id, profiles.display_name, profiles.labels,
    profiles_with_entity_profiles.id, profiles_with_entity_profiles.entity, profiles_with_entity_profiles.profile_id, profiles_with_entity_profiles.contextual_rules, profiles_with_entity_profiles.created_at, profiles_with_entity_profiles.updated_at, profiles_with_entity_profiles.profid,
    helper.selectors::profile_selector[] AS profiles_with_selectors
FROM profiles
JOIN profiles_with_entity_profiles ON profiles.id = profiles_with_entity_profiles.profid
LEFT JOIN helper ON profiles.id = helper.profid
WHERE profiles.project_id = $1
`

type ListProfilesByProjectIDRow struct {
	Profile                   Profile                   `json:"profile"`
	ProfilesWithEntityProfile ProfilesWithEntityProfile `json:"profiles_with_entity_profile"`
	ProfilesWithSelectors     []ProfileSelector         `json:"profiles_with_selectors"`
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
			&i.Profile.ID,
			&i.Profile.Name,
			&i.Profile.Provider,
			&i.Profile.ProjectID,
			&i.Profile.Remediate,
			&i.Profile.Alert,
			&i.Profile.CreatedAt,
			&i.Profile.UpdatedAt,
			&i.Profile.ProviderID,
			&i.Profile.SubscriptionID,
			&i.Profile.DisplayName,
			pq.Array(&i.Profile.Labels),
			&i.ProfilesWithEntityProfile.ID,
			&i.ProfilesWithEntityProfile.Entity,
			&i.ProfilesWithEntityProfile.ProfileID,
			&i.ProfilesWithEntityProfile.ContextualRules,
			&i.ProfilesWithEntityProfile.CreatedAt,
			&i.ProfilesWithEntityProfile.UpdatedAt,
			&i.ProfilesWithEntityProfile.Profid,
			pq.Array(&i.ProfilesWithSelectors),
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

const listProfilesByProjectIDAndLabel = `-- name: ListProfilesByProjectIDAndLabel :many
WITH helper AS(
     SELECT pr.id as profid,
     ARRAY_AGG(ROW(ps.id, ps.profile_id, ps.entity, ps.selector, ps.comment)::profile_selector) AS selectors
       FROM profiles pr
       JOIN profile_selectors ps
         ON pr.id = ps.profile_id
      WHERE pr.project_id = $1
      GROUP BY pr.id
)
SELECT profiles.id, profiles.name, profiles.provider, profiles.project_id, profiles.remediate, profiles.alert, profiles.created_at, profiles.updated_at, profiles.provider_id, profiles.subscription_id, profiles.display_name, profiles.labels,
       profiles_with_entity_profiles.id, profiles_with_entity_profiles.entity, profiles_with_entity_profiles.profile_id, profiles_with_entity_profiles.contextual_rules, profiles_with_entity_profiles.created_at, profiles_with_entity_profiles.updated_at, profiles_with_entity_profiles.profid,
       helper.selectors::profile_selector[] AS profiles_with_selectors
FROM profiles
JOIN profiles_with_entity_profiles ON profiles.id = profiles_with_entity_profiles.profid
LEFT JOIN helper ON profiles.id = helper.profid
WHERE profiles.project_id = $1
AND (
    -- the most common case first, if the include_labels is empty, we list profiles with no labels
    -- we use coalesce to handle the case where the include_labels is null
    (COALESCE(cardinality($2::TEXT[]), 0) = 0 AND profiles.labels = ARRAY[]::TEXT[]) OR
    -- if the include_labels arg is equal to '*', we list all profiles
    $2::TEXT[] = ARRAY['*'] OR
    -- if the include_labels arg is not empty and not a wildcard, we list profiles whose labels are a subset of include_labels
    (COALESCE(cardinality($2::TEXT[]), 0) > 0 AND profiles.labels @> $2::TEXT[])
) AND (
    -- if the exclude_labels arg is empty, we list all profiles
    COALESCE(cardinality($3::TEXT[]), 0) = 0 OR
    -- if the exclude_labels arg is not empty, we exclude profiles containing any of the exclude_labels
    NOT profiles.labels::TEXT[] && $3::TEXT[]
)
`

type ListProfilesByProjectIDAndLabelParams struct {
	ProjectID     uuid.UUID `json:"project_id"`
	IncludeLabels []string  `json:"include_labels"`
	ExcludeLabels []string  `json:"exclude_labels"`
}

type ListProfilesByProjectIDAndLabelRow struct {
	Profile                   Profile                   `json:"profile"`
	ProfilesWithEntityProfile ProfilesWithEntityProfile `json:"profiles_with_entity_profile"`
	ProfilesWithSelectors     []ProfileSelector         `json:"profiles_with_selectors"`
}

func (q *Queries) ListProfilesByProjectIDAndLabel(ctx context.Context, arg ListProfilesByProjectIDAndLabelParams) ([]ListProfilesByProjectIDAndLabelRow, error) {
	rows, err := q.db.QueryContext(ctx, listProfilesByProjectIDAndLabel, arg.ProjectID, pq.Array(arg.IncludeLabels), pq.Array(arg.ExcludeLabels))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ListProfilesByProjectIDAndLabelRow{}
	for rows.Next() {
		var i ListProfilesByProjectIDAndLabelRow
		if err := rows.Scan(
			&i.Profile.ID,
			&i.Profile.Name,
			&i.Profile.Provider,
			&i.Profile.ProjectID,
			&i.Profile.Remediate,
			&i.Profile.Alert,
			&i.Profile.CreatedAt,
			&i.Profile.UpdatedAt,
			&i.Profile.ProviderID,
			&i.Profile.SubscriptionID,
			&i.Profile.DisplayName,
			pq.Array(&i.Profile.Labels),
			&i.ProfilesWithEntityProfile.ID,
			&i.ProfilesWithEntityProfile.Entity,
			&i.ProfilesWithEntityProfile.ProfileID,
			&i.ProfilesWithEntityProfile.ContextualRules,
			&i.ProfilesWithEntityProfile.CreatedAt,
			&i.ProfilesWithEntityProfile.UpdatedAt,
			&i.ProfilesWithEntityProfile.Profid,
			pq.Array(&i.ProfilesWithSelectors),
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

const updateProfile = `-- name: UpdateProfile :one
UPDATE profiles SET
    remediate = $3,
    alert = $4,
    updated_at = NOW(),
    display_name = $5,
    labels = COALESCE($6::TEXT[], '{}'::TEXT[])
WHERE id = $1 AND project_id = $2 RETURNING id, name, provider, project_id, remediate, alert, created_at, updated_at, provider_id, subscription_id, display_name, labels
`

type UpdateProfileParams struct {
	ID          uuid.UUID      `json:"id"`
	ProjectID   uuid.UUID      `json:"project_id"`
	Remediate   NullActionType `json:"remediate"`
	Alert       NullActionType `json:"alert"`
	DisplayName string         `json:"display_name"`
	Labels      []string       `json:"labels"`
}

func (q *Queries) UpdateProfile(ctx context.Context, arg UpdateProfileParams) (Profile, error) {
	row := q.db.QueryRowContext(ctx, updateProfile,
		arg.ID,
		arg.ProjectID,
		arg.Remediate,
		arg.Alert,
		arg.DisplayName,
		pq.Array(arg.Labels),
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
		&i.ProviderID,
		&i.SubscriptionID,
		&i.DisplayName,
		pq.Array(&i.Labels),
	)
	return i, err
}

const upsertProfileForEntity = `-- name: UpsertProfileForEntity :one
INSERT INTO entity_profiles (
    entity,
    profile_id,
    contextual_rules,
    migrated
) VALUES ($1, $2, $3::jsonb, false)
ON CONFLICT (entity, profile_id) DO UPDATE SET
    contextual_rules = $3::jsonb,
    migrated = TRUE
RETURNING id, entity, profile_id, contextual_rules, created_at, updated_at, migrated
`

type UpsertProfileForEntityParams struct {
	Entity          Entities        `json:"entity"`
	ProfileID       uuid.UUID       `json:"profile_id"`
	ContextualRules json.RawMessage `json:"contextual_rules"`
}

func (q *Queries) UpsertProfileForEntity(ctx context.Context, arg UpsertProfileForEntityParams) (EntityProfile, error) {
	row := q.db.QueryRowContext(ctx, upsertProfileForEntity, arg.Entity, arg.ProfileID, arg.ContextualRules)
	var i EntityProfile
	err := row.Scan(
		&i.ID,
		&i.Entity,
		&i.ProfileID,
		&i.ContextualRules,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Migrated,
	)
	return i, err
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
