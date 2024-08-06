// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: selectors.sql

package db

import (
	"context"

	"github.com/google/uuid"
)

const createSelector = `-- name: CreateSelector :one
INSERT INTO profile_selectors (profile_id, entity, selector, comment)
VALUES ($1, $2, $3, $4)
RETURNING id, profile_id, entity, selector, comment
`

type CreateSelectorParams struct {
	ProfileID uuid.UUID    `json:"profile_id"`
	Entity    NullEntities `json:"entity"`
	Selector  string       `json:"selector"`
	Comment   string       `json:"comment"`
}

func (q *Queries) CreateSelector(ctx context.Context, arg CreateSelectorParams) (ProfileSelector, error) {
	row := q.db.QueryRowContext(ctx, createSelector,
		arg.ProfileID,
		arg.Entity,
		arg.Selector,
		arg.Comment,
	)
	var i ProfileSelector
	err := row.Scan(
		&i.ID,
		&i.ProfileID,
		&i.Entity,
		&i.Selector,
		&i.Comment,
	)
	return i, err
}

const deleteSelector = `-- name: DeleteSelector :exec
DELETE FROM profile_selectors
WHERE id = $1
`

func (q *Queries) DeleteSelector(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, deleteSelector, id)
	return err
}

const deleteSelectorsByProfileID = `-- name: DeleteSelectorsByProfileID :exec
DELETE FROM profile_selectors
WHERE profile_id = $1
`

func (q *Queries) DeleteSelectorsByProfileID(ctx context.Context, profileID uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, deleteSelectorsByProfileID, profileID)
	return err
}

const getSelectorByID = `-- name: GetSelectorByID :one
SELECT id, profile_id, entity, selector, comment
FROM profile_selectors
WHERE id = $1
`

func (q *Queries) GetSelectorByID(ctx context.Context, id uuid.UUID) (ProfileSelector, error) {
	row := q.db.QueryRowContext(ctx, getSelectorByID, id)
	var i ProfileSelector
	err := row.Scan(
		&i.ID,
		&i.ProfileID,
		&i.Entity,
		&i.Selector,
		&i.Comment,
	)
	return i, err
}

const getSelectorsByProfileID = `-- name: GetSelectorsByProfileID :many
SELECT id, profile_id, entity, selector, comment
FROM profile_selectors
WHERE profile_id = $1
`

func (q *Queries) GetSelectorsByProfileID(ctx context.Context, profileID uuid.UUID) ([]ProfileSelector, error) {
	rows, err := q.db.QueryContext(ctx, getSelectorsByProfileID, profileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ProfileSelector{}
	for rows.Next() {
		var i ProfileSelector
		if err := rows.Scan(
			&i.ID,
			&i.ProfileID,
			&i.Entity,
			&i.Selector,
			&i.Comment,
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

const updateSelector = `-- name: UpdateSelector :one
UPDATE profile_selectors
SET entity = $2, selector = $3, comment = $4
WHERE id = $1
RETURNING id, profile_id, entity, selector, comment
`

type UpdateSelectorParams struct {
	ID       uuid.UUID    `json:"id"`
	Entity   NullEntities `json:"entity"`
	Selector string       `json:"selector"`
	Comment  string       `json:"comment"`
}

func (q *Queries) UpdateSelector(ctx context.Context, arg UpdateSelectorParams) (ProfileSelector, error) {
	row := q.db.QueryRowContext(ctx, updateSelector,
		arg.ID,
		arg.Entity,
		arg.Selector,
		arg.Comment,
	)
	var i ProfileSelector
	err := row.Scan(
		&i.ID,
		&i.ProfileID,
		&i.Entity,
		&i.Selector,
		&i.Comment,
	)
	return i, err
}
