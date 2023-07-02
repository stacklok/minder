// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.18.0
// source: repositories.sql

package db

import (
	"context"
	"database/sql"
)

const createRepository = `-- name: CreateRepository :one
INSERT INTO repositories (
    group_id,
    repo_owner, 
    repo_name,
    repo_id,
    is_private,
    is_fork,
    webhook_id,
    webhook_url,
    deploy_url) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, repo_owner, repo_name, repo_id, is_private, is_fork, group_id, webhook_id, webhook_url, deploy_url, created_at, updated_at
`

type CreateRepositoryParams struct {
	GroupID    int32         `json:"group_id"`
	RepoOwner  string        `json:"repo_owner"`
	RepoName   string        `json:"repo_name"`
	RepoID     int32         `json:"repo_id"`
	IsPrivate  bool          `json:"is_private"`
	IsFork     bool          `json:"is_fork"`
	WebhookID  sql.NullInt32 `json:"webhook_id"`
	WebhookUrl string        `json:"webhook_url"`
	DeployUrl  string        `json:"deploy_url"`
}

func (q *Queries) CreateRepository(ctx context.Context, arg CreateRepositoryParams) (Repository, error) {
	row := q.db.QueryRowContext(ctx, createRepository,
		arg.GroupID,
		arg.RepoOwner,
		arg.RepoName,
		arg.RepoID,
		arg.IsPrivate,
		arg.IsFork,
		arg.WebhookID,
		arg.WebhookUrl,
		arg.DeployUrl,
	)
	var i Repository
	err := row.Scan(
		&i.ID,
		&i.RepoOwner,
		&i.RepoName,
		&i.RepoID,
		&i.IsPrivate,
		&i.IsFork,
		&i.GroupID,
		&i.WebhookID,
		&i.WebhookUrl,
		&i.DeployUrl,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const deleteRepository = `-- name: DeleteRepository :exec
DELETE FROM repositories
WHERE id = $1
`

func (q *Queries) DeleteRepository(ctx context.Context, id int32) error {
	_, err := q.db.ExecContext(ctx, deleteRepository, id)
	return err
}

const getRepositoryByID = `-- name: GetRepositoryByID :one
SELECT id, repo_owner, repo_name, repo_id, is_private, is_fork, group_id, webhook_id, webhook_url, deploy_url, created_at, updated_at FROM repositories WHERE id = $1
`

func (q *Queries) GetRepositoryByID(ctx context.Context, id int32) (Repository, error) {
	row := q.db.QueryRowContext(ctx, getRepositoryByID, id)
	var i Repository
	err := row.Scan(
		&i.ID,
		&i.RepoOwner,
		&i.RepoName,
		&i.RepoID,
		&i.IsPrivate,
		&i.IsFork,
		&i.GroupID,
		&i.WebhookID,
		&i.WebhookUrl,
		&i.DeployUrl,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getRepositoryByRepoID = `-- name: GetRepositoryByRepoID :one
SELECT id, repo_owner, repo_name, repo_id, is_private, is_fork, group_id, webhook_id, webhook_url, deploy_url, created_at, updated_at FROM repositories WHERE repo_id = $1
`

func (q *Queries) GetRepositoryByRepoID(ctx context.Context, repoID int32) (Repository, error) {
	row := q.db.QueryRowContext(ctx, getRepositoryByRepoID, repoID)
	var i Repository
	err := row.Scan(
		&i.ID,
		&i.RepoOwner,
		&i.RepoName,
		&i.RepoID,
		&i.IsPrivate,
		&i.IsFork,
		&i.GroupID,
		&i.WebhookID,
		&i.WebhookUrl,
		&i.DeployUrl,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const getRepositoryByRepoName = `-- name: GetRepositoryByRepoName :one
SELECT id, repo_owner, repo_name, repo_id, is_private, is_fork, group_id, webhook_id, webhook_url, deploy_url, created_at, updated_at FROM repositories WHERE repo_name = $1
`

func (q *Queries) GetRepositoryByRepoName(ctx context.Context, repoName string) (Repository, error) {
	row := q.db.QueryRowContext(ctx, getRepositoryByRepoName, repoName)
	var i Repository
	err := row.Scan(
		&i.ID,
		&i.RepoOwner,
		&i.RepoName,
		&i.RepoID,
		&i.IsPrivate,
		&i.IsFork,
		&i.GroupID,
		&i.WebhookID,
		&i.WebhookUrl,
		&i.DeployUrl,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const listAllRepositories = `-- name: ListAllRepositories :many
SELECT id, repo_owner, repo_name, repo_id, is_private, is_fork, group_id, webhook_id, webhook_url, deploy_url, created_at, updated_at FROM repositories
ORDER BY id
`

func (q *Queries) ListAllRepositories(ctx context.Context) ([]Repository, error) {
	rows, err := q.db.QueryContext(ctx, listAllRepositories)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Repository{}
	for rows.Next() {
		var i Repository
		if err := rows.Scan(
			&i.ID,
			&i.RepoOwner,
			&i.RepoName,
			&i.RepoID,
			&i.IsPrivate,
			&i.IsFork,
			&i.GroupID,
			&i.WebhookID,
			&i.WebhookUrl,
			&i.DeployUrl,
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

const listRepositoriesByGroupID = `-- name: ListRepositoriesByGroupID :many
SELECT id, repo_owner, repo_name, repo_id, is_private, is_fork, group_id, webhook_id, webhook_url, deploy_url, created_at, updated_at FROM repositories
WHERE group_id = $1
ORDER BY id
LIMIT $2
OFFSET $3
`

type ListRepositoriesByGroupIDParams struct {
	GroupID int32 `json:"group_id"`
	Limit   int32 `json:"limit"`
	Offset  int32 `json:"offset"`
}

func (q *Queries) ListRepositoriesByGroupID(ctx context.Context, arg ListRepositoriesByGroupIDParams) ([]Repository, error) {
	rows, err := q.db.QueryContext(ctx, listRepositoriesByGroupID, arg.GroupID, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Repository{}
	for rows.Next() {
		var i Repository
		if err := rows.Scan(
			&i.ID,
			&i.RepoOwner,
			&i.RepoName,
			&i.RepoID,
			&i.IsPrivate,
			&i.IsFork,
			&i.GroupID,
			&i.WebhookID,
			&i.WebhookUrl,
			&i.DeployUrl,
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

const listRepositoriesByOwner = `-- name: ListRepositoriesByOwner :many
SELECT id, repo_owner, repo_name, repo_id, is_private, is_fork, group_id, webhook_id, webhook_url, deploy_url, created_at, updated_at FROM repositories
WHERE repo_owner = $1
ORDER BY id
LIMIT $2
OFFSET $3
`

type ListRepositoriesByOwnerParams struct {
	RepoOwner string `json:"repo_owner"`
	Limit     int32  `json:"limit"`
	Offset    int32  `json:"offset"`
}

func (q *Queries) ListRepositoriesByOwner(ctx context.Context, arg ListRepositoriesByOwnerParams) ([]Repository, error) {
	rows, err := q.db.QueryContext(ctx, listRepositoriesByOwner, arg.RepoOwner, arg.Limit, arg.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Repository{}
	for rows.Next() {
		var i Repository
		if err := rows.Scan(
			&i.ID,
			&i.RepoOwner,
			&i.RepoName,
			&i.RepoID,
			&i.IsPrivate,
			&i.IsFork,
			&i.GroupID,
			&i.WebhookID,
			&i.WebhookUrl,
			&i.DeployUrl,
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

const updateRepository = `-- name: UpdateRepository :one
UPDATE repositories 
SET group_id = $2,
repo_owner = $3,
repo_name = $4,
repo_id = $5,
is_private = $6,
is_fork = $7,
webhook_id = $8,
webhook_url = $9,
deploy_url = $10, 
updated_at = NOW() 
WHERE id = $1 RETURNING id, repo_owner, repo_name, repo_id, is_private, is_fork, group_id, webhook_id, webhook_url, deploy_url, created_at, updated_at
`

type UpdateRepositoryParams struct {
	ID         int32         `json:"id"`
	GroupID    int32         `json:"group_id"`
	RepoOwner  string        `json:"repo_owner"`
	RepoName   string        `json:"repo_name"`
	RepoID     int32         `json:"repo_id"`
	IsPrivate  bool          `json:"is_private"`
	IsFork     bool          `json:"is_fork"`
	WebhookID  sql.NullInt32 `json:"webhook_id"`
	WebhookUrl string        `json:"webhook_url"`
	DeployUrl  string        `json:"deploy_url"`
}

func (q *Queries) UpdateRepository(ctx context.Context, arg UpdateRepositoryParams) (Repository, error) {
	row := q.db.QueryRowContext(ctx, updateRepository,
		arg.ID,
		arg.GroupID,
		arg.RepoOwner,
		arg.RepoName,
		arg.RepoID,
		arg.IsPrivate,
		arg.IsFork,
		arg.WebhookID,
		arg.WebhookUrl,
		arg.DeployUrl,
	)
	var i Repository
	err := row.Scan(
		&i.ID,
		&i.RepoOwner,
		&i.RepoName,
		&i.RepoID,
		&i.IsPrivate,
		&i.IsFork,
		&i.GroupID,
		&i.WebhookID,
		&i.WebhookUrl,
		&i.DeployUrl,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const updateRepositoryByID = `-- name: UpdateRepositoryByID :one
UPDATE repositories 
SET group_id = $2,
repo_owner = $3,
repo_name = $4,
is_private = $5,
is_fork = $6,
webhook_id = $7,
webhook_url = $8,
deploy_url = $9, 
updated_at = NOW() 
WHERE repo_id = $1 RETURNING id, repo_owner, repo_name, repo_id, is_private, is_fork, group_id, webhook_id, webhook_url, deploy_url, created_at, updated_at
`

type UpdateRepositoryByIDParams struct {
	RepoID     int32         `json:"repo_id"`
	GroupID    int32         `json:"group_id"`
	RepoOwner  string        `json:"repo_owner"`
	RepoName   string        `json:"repo_name"`
	IsPrivate  bool          `json:"is_private"`
	IsFork     bool          `json:"is_fork"`
	WebhookID  sql.NullInt32 `json:"webhook_id"`
	WebhookUrl string        `json:"webhook_url"`
	DeployUrl  string        `json:"deploy_url"`
}

func (q *Queries) UpdateRepositoryByID(ctx context.Context, arg UpdateRepositoryByIDParams) (Repository, error) {
	row := q.db.QueryRowContext(ctx, updateRepositoryByID,
		arg.RepoID,
		arg.GroupID,
		arg.RepoOwner,
		arg.RepoName,
		arg.IsPrivate,
		arg.IsFork,
		arg.WebhookID,
		arg.WebhookUrl,
		arg.DeployUrl,
	)
	var i Repository
	err := row.Scan(
		&i.ID,
		&i.RepoOwner,
		&i.RepoName,
		&i.RepoID,
		&i.IsPrivate,
		&i.IsFork,
		&i.GroupID,
		&i.WebhookID,
		&i.WebhookUrl,
		&i.DeployUrl,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}
