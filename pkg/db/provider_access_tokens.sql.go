// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.18.0
// source: provider_access_tokens.sql

package db

import (
	"context"
	"time"
)

const createAccessToken = `-- name: CreateAccessToken :one
INSERT INTO provider_access_tokens (group_id, provider, encrypted_token, expiration_time) VALUES ($1, $2, $3, $4) RETURNING id, provider, group_id, encrypted_token, expiration_time, created_at, updated_at
`

type CreateAccessTokenParams struct {
	GroupID        int32     `json:"group_id"`
	Provider       string    `json:"provider"`
	EncryptedToken string    `json:"encrypted_token"`
	ExpirationTime time.Time `json:"expiration_time"`
}

func (q *Queries) CreateAccessToken(ctx context.Context, arg CreateAccessTokenParams) (ProviderAccessToken, error) {
	row := q.db.QueryRowContext(ctx, createAccessToken,
		arg.GroupID,
		arg.Provider,
		arg.EncryptedToken,
		arg.ExpirationTime,
	)
	var i ProviderAccessToken
	err := row.Scan(
		&i.ID,
		&i.Provider,
		&i.GroupID,
		&i.EncryptedToken,
		&i.ExpirationTime,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const deleteAccessToken = `-- name: DeleteAccessToken :exec
DELETE FROM provider_access_tokens WHERE provider = $1 AND group_id = $2
`

type DeleteAccessTokenParams struct {
	Provider string `json:"provider"`
	GroupID  int32  `json:"group_id"`
}

func (q *Queries) DeleteAccessToken(ctx context.Context, arg DeleteAccessTokenParams) error {
	_, err := q.db.ExecContext(ctx, deleteAccessToken, arg.Provider, arg.GroupID)
	return err
}

const getAccessTokenByGroupID = `-- name: GetAccessTokenByGroupID :one
SELECT id, provider, group_id, encrypted_token, expiration_time, created_at, updated_at FROM provider_access_tokens WHERE provider = $1 AND group_id = $2
`

type GetAccessTokenByGroupIDParams struct {
	Provider string `json:"provider"`
	GroupID  int32  `json:"group_id"`
}

func (q *Queries) GetAccessTokenByGroupID(ctx context.Context, arg GetAccessTokenByGroupIDParams) (ProviderAccessToken, error) {
	row := q.db.QueryRowContext(ctx, getAccessTokenByGroupID, arg.Provider, arg.GroupID)
	var i ProviderAccessToken
	err := row.Scan(
		&i.ID,
		&i.Provider,
		&i.GroupID,
		&i.EncryptedToken,
		&i.ExpirationTime,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getAccessTokenByProvider = `-- name: GetAccessTokenByProvider :many
SELECT id, provider, group_id, encrypted_token, expiration_time, created_at, updated_at FROM provider_access_tokens WHERE provider = $1
`

func (q *Queries) GetAccessTokenByProvider(ctx context.Context, provider string) ([]ProviderAccessToken, error) {
	rows, err := q.db.QueryContext(ctx, getAccessTokenByProvider, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []ProviderAccessToken{}
	for rows.Next() {
		var i ProviderAccessToken
		if err := rows.Scan(
			&i.ID,
			&i.Provider,
			&i.GroupID,
			&i.EncryptedToken,
			&i.ExpirationTime,
			&i.CreatedAt,
			&i.UpdatedAt,
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

const updateAccessToken = `-- name: UpdateAccessToken :one
UPDATE provider_access_tokens SET provider = $2, encrypted_token = $3, expiration_time = $4, updated_at = NOW() WHERE provider = $1 AND group_id = $2 RETURNING id, provider, group_id, encrypted_token, expiration_time, created_at, updated_at
`

type UpdateAccessTokenParams struct {
	Provider       string    `json:"provider"`
	Provider_2     string    `json:"provider_2"`
	EncryptedToken string    `json:"encrypted_token"`
	ExpirationTime time.Time `json:"expiration_time"`
}

func (q *Queries) UpdateAccessToken(ctx context.Context, arg UpdateAccessTokenParams) (ProviderAccessToken, error) {
	row := q.db.QueryRowContext(ctx, updateAccessToken,
		arg.Provider,
		arg.Provider_2,
		arg.EncryptedToken,
		arg.ExpirationTime,
	)
	var i ProviderAccessToken
	err := row.Scan(
		&i.ID,
		&i.Provider,
		&i.GroupID,
		&i.EncryptedToken,
		&i.ExpirationTime,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}
