// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0
// source: repositories.sql

package db

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

const countRepositories = `-- name: CountRepositories :one
SELECT COUNT(*) FROM repositories
`

func (q *Queries) CountRepositories(ctx context.Context) (int64, error) {
	row := q.db.QueryRowContext(ctx, countRepositories)
	var count int64
	err := row.Scan(&count)
	return count, err
}

const createRepository = `-- name: CreateRepository :one
INSERT INTO repositories (
    provider,
    project_id,
    repo_owner, 
    repo_name,
    repo_id,
    is_private,
    is_fork,
    webhook_id,
    webhook_url,
    deploy_url,
    clone_url,
    default_branch,
    license,
    provider_id
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id, provider, project_id, repo_owner, repo_name, repo_id, is_private, is_fork, webhook_id, webhook_url, deploy_url, clone_url, created_at, updated_at, default_branch, license, provider_id
`

type CreateRepositoryParams struct {
	Provider      string         `json:"provider"`
	ProjectID     uuid.UUID      `json:"project_id"`
	RepoOwner     string         `json:"repo_owner"`
	RepoName      string         `json:"repo_name"`
	RepoID        int64          `json:"repo_id"`
	IsPrivate     bool           `json:"is_private"`
	IsFork        bool           `json:"is_fork"`
	WebhookID     sql.NullInt64  `json:"webhook_id"`
	WebhookUrl    string         `json:"webhook_url"`
	DeployUrl     string         `json:"deploy_url"`
	CloneUrl      string         `json:"clone_url"`
	DefaultBranch sql.NullString `json:"default_branch"`
	License       sql.NullString `json:"license"`
	ProviderID    uuid.UUID      `json:"provider_id"`
}

func (q *Queries) CreateRepository(ctx context.Context, arg CreateRepositoryParams) (Repository, error) {
	row := q.db.QueryRowContext(ctx, createRepository,
		arg.Provider,
		arg.ProjectID,
		arg.RepoOwner,
		arg.RepoName,
		arg.RepoID,
		arg.IsPrivate,
		arg.IsFork,
		arg.WebhookID,
		arg.WebhookUrl,
		arg.DeployUrl,
		arg.CloneUrl,
		arg.DefaultBranch,
		arg.License,
		arg.ProviderID,
	)
	var i Repository
	err := row.Scan(
		&i.ID,
		&i.Provider,
		&i.ProjectID,
		&i.RepoOwner,
		&i.RepoName,
		&i.RepoID,
		&i.IsPrivate,
		&i.IsFork,
		&i.WebhookID,
		&i.WebhookUrl,
		&i.DeployUrl,
		&i.CloneUrl,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DefaultBranch,
		&i.License,
		&i.ProviderID,
	)
	return i, err
}

const deleteRepository = `-- name: DeleteRepository :exec
DELETE FROM repositories
WHERE id = $1
`

func (q *Queries) DeleteRepository(ctx context.Context, id uuid.UUID) error {
	_, err := q.db.ExecContext(ctx, deleteRepository, id)
	return err
}

const getRepositoryByID = `-- name: GetRepositoryByID :one
SELECT id, provider, project_id, repo_owner, repo_name, repo_id, is_private, is_fork, webhook_id, webhook_url, deploy_url, clone_url, created_at, updated_at, default_branch, license, provider_id FROM repositories WHERE id = $1
`

func (q *Queries) GetRepositoryByID(ctx context.Context, id uuid.UUID) (Repository, error) {
	row := q.db.QueryRowContext(ctx, getRepositoryByID, id)
	var i Repository
	err := row.Scan(
		&i.ID,
		&i.Provider,
		&i.ProjectID,
		&i.RepoOwner,
		&i.RepoName,
		&i.RepoID,
		&i.IsPrivate,
		&i.IsFork,
		&i.WebhookID,
		&i.WebhookUrl,
		&i.DeployUrl,
		&i.CloneUrl,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DefaultBranch,
		&i.License,
		&i.ProviderID,
	)
	return i, err
}

const getRepositoryByIDAndProject = `-- name: GetRepositoryByIDAndProject :one
SELECT id, provider, project_id, repo_owner, repo_name, repo_id, is_private, is_fork, webhook_id, webhook_url, deploy_url, clone_url, created_at, updated_at, default_branch, license, provider_id FROM repositories WHERE provider = $1 AND id = $2 AND project_id = $3
`

type GetRepositoryByIDAndProjectParams struct {
	Provider  string    `json:"provider"`
	ID        uuid.UUID `json:"id"`
	ProjectID uuid.UUID `json:"project_id"`
}

func (q *Queries) GetRepositoryByIDAndProject(ctx context.Context, arg GetRepositoryByIDAndProjectParams) (Repository, error) {
	row := q.db.QueryRowContext(ctx, getRepositoryByIDAndProject, arg.Provider, arg.ID, arg.ProjectID)
	var i Repository
	err := row.Scan(
		&i.ID,
		&i.Provider,
		&i.ProjectID,
		&i.RepoOwner,
		&i.RepoName,
		&i.RepoID,
		&i.IsPrivate,
		&i.IsFork,
		&i.WebhookID,
		&i.WebhookUrl,
		&i.DeployUrl,
		&i.CloneUrl,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DefaultBranch,
		&i.License,
		&i.ProviderID,
	)
	return i, err
}

const getRepositoryByRepoID = `-- name: GetRepositoryByRepoID :one
SELECT id, provider, project_id, repo_owner, repo_name, repo_id, is_private, is_fork, webhook_id, webhook_url, deploy_url, clone_url, created_at, updated_at, default_branch, license, provider_id FROM repositories WHERE repo_id = $1
`

func (q *Queries) GetRepositoryByRepoID(ctx context.Context, repoID int64) (Repository, error) {
	row := q.db.QueryRowContext(ctx, getRepositoryByRepoID, repoID)
	var i Repository
	err := row.Scan(
		&i.ID,
		&i.Provider,
		&i.ProjectID,
		&i.RepoOwner,
		&i.RepoName,
		&i.RepoID,
		&i.IsPrivate,
		&i.IsFork,
		&i.WebhookID,
		&i.WebhookUrl,
		&i.DeployUrl,
		&i.CloneUrl,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DefaultBranch,
		&i.License,
		&i.ProviderID,
	)
	return i, err
}

const getRepositoryByRepoName = `-- name: GetRepositoryByRepoName :one
SELECT id, provider, project_id, repo_owner, repo_name, repo_id, is_private, is_fork, webhook_id, webhook_url, deploy_url, clone_url, created_at, updated_at, default_branch, license, provider_id FROM repositories WHERE provider = $1 AND repo_owner = $2 AND repo_name = $3 AND project_id = $4
`

type GetRepositoryByRepoNameParams struct {
	Provider  string    `json:"provider"`
	RepoOwner string    `json:"repo_owner"`
	RepoName  string    `json:"repo_name"`
	ProjectID uuid.UUID `json:"project_id"`
}

func (q *Queries) GetRepositoryByRepoName(ctx context.Context, arg GetRepositoryByRepoNameParams) (Repository, error) {
	row := q.db.QueryRowContext(ctx, getRepositoryByRepoName,
		arg.Provider,
		arg.RepoOwner,
		arg.RepoName,
		arg.ProjectID,
	)
	var i Repository
	err := row.Scan(
		&i.ID,
		&i.Provider,
		&i.ProjectID,
		&i.RepoOwner,
		&i.RepoName,
		&i.RepoID,
		&i.IsPrivate,
		&i.IsFork,
		&i.WebhookID,
		&i.WebhookUrl,
		&i.DeployUrl,
		&i.CloneUrl,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.DefaultBranch,
		&i.License,
		&i.ProviderID,
	)
	return i, err
}

const listRegisteredRepositoriesByProjectIDAndProvider = `-- name: ListRegisteredRepositoriesByProjectIDAndProvider :many
SELECT id, provider, project_id, repo_owner, repo_name, repo_id, is_private, is_fork, webhook_id, webhook_url, deploy_url, clone_url, created_at, updated_at, default_branch, license, provider_id FROM repositories
WHERE provider = $1 AND project_id = $2 AND webhook_id IS NOT NULL
ORDER BY repo_name
`

type ListRegisteredRepositoriesByProjectIDAndProviderParams struct {
	Provider  string    `json:"provider"`
	ProjectID uuid.UUID `json:"project_id"`
}

func (q *Queries) ListRegisteredRepositoriesByProjectIDAndProvider(ctx context.Context, arg ListRegisteredRepositoriesByProjectIDAndProviderParams) ([]Repository, error) {
	rows, err := q.db.QueryContext(ctx, listRegisteredRepositoriesByProjectIDAndProvider, arg.Provider, arg.ProjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Repository{}
	for rows.Next() {
		var i Repository
		if err := rows.Scan(
			&i.ID,
			&i.Provider,
			&i.ProjectID,
			&i.RepoOwner,
			&i.RepoName,
			&i.RepoID,
			&i.IsPrivate,
			&i.IsFork,
			&i.WebhookID,
			&i.WebhookUrl,
			&i.DeployUrl,
			&i.CloneUrl,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.DefaultBranch,
			&i.License,
			&i.ProviderID,
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

const listRepositoriesByProjectID = `-- name: ListRepositoriesByProjectID :many
SELECT id, provider, project_id, repo_owner, repo_name, repo_id, is_private, is_fork, webhook_id, webhook_url, deploy_url, clone_url, created_at, updated_at, default_branch, license, provider_id FROM repositories
WHERE provider = $1 AND project_id = $2
  AND (repo_id >= $3 OR $3 IS NULL)
ORDER BY project_id, provider, repo_id
LIMIT $4::bigint
`

type ListRepositoriesByProjectIDParams struct {
	Provider  string        `json:"provider"`
	ProjectID uuid.UUID     `json:"project_id"`
	RepoID    sql.NullInt64 `json:"repo_id"`
	Limit     sql.NullInt64 `json:"limit"`
}

func (q *Queries) ListRepositoriesByProjectID(ctx context.Context, arg ListRepositoriesByProjectIDParams) ([]Repository, error) {
	rows, err := q.db.QueryContext(ctx, listRepositoriesByProjectID,
		arg.Provider,
		arg.ProjectID,
		arg.RepoID,
		arg.Limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Repository{}
	for rows.Next() {
		var i Repository
		if err := rows.Scan(
			&i.ID,
			&i.Provider,
			&i.ProjectID,
			&i.RepoOwner,
			&i.RepoName,
			&i.RepoID,
			&i.IsPrivate,
			&i.IsFork,
			&i.WebhookID,
			&i.WebhookUrl,
			&i.DeployUrl,
			&i.CloneUrl,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.DefaultBranch,
			&i.License,
			&i.ProviderID,
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
