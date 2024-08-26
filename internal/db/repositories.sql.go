// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
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

const getProviderWebhooks = `-- name: GetProviderWebhooks :many
SELECT repo_owner, repo_name, webhook_id FROM repositories
WHERE webhook_id IS NOT NULL AND provider_id = $1
`

type GetProviderWebhooksRow struct {
	RepoOwner string `json:"repo_owner"`
	RepoName  string `json:"repo_name"`
	WebhookID int64  `json:"webhook_id"`
}

// get a list of repos with webhooks belonging to a provider
// is used for webhook cleanup during provider deletion
func (q *Queries) GetProviderWebhooks(ctx context.Context, providerID uuid.UUID) ([]GetProviderWebhooksRow, error) {
	rows, err := q.db.QueryContext(ctx, getProviderWebhooks, providerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetProviderWebhooksRow{}
	for rows.Next() {
		var i GetProviderWebhooksRow
		if err := rows.Scan(&i.RepoOwner, &i.RepoName, &i.WebhookID); err != nil {
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

const getRepoPathFromArtifactID = `-- name: GetRepoPathFromArtifactID :one
SELECT r.repo_owner AS owner , r.repo_name AS name FROM repositories AS r
JOIN artifacts AS a ON a.repository_id = r.id
WHERE a.id = $1
`

type GetRepoPathFromArtifactIDRow struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

func (q *Queries) GetRepoPathFromArtifactID(ctx context.Context, id uuid.UUID) (GetRepoPathFromArtifactIDRow, error) {
	row := q.db.QueryRowContext(ctx, getRepoPathFromArtifactID, id)
	var i GetRepoPathFromArtifactIDRow
	err := row.Scan(&i.Owner, &i.Name)
	return i, err
}

const getRepoPathFromPullRequestID = `-- name: GetRepoPathFromPullRequestID :one
SELECT r.repo_owner AS owner , r.repo_name AS name FROM repositories AS r
JOIN pull_requests AS p ON p.repository_id = r.id
WHERE p.id = $1
`

type GetRepoPathFromPullRequestIDRow struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

func (q *Queries) GetRepoPathFromPullRequestID(ctx context.Context, id uuid.UUID) (GetRepoPathFromPullRequestIDRow, error) {
	row := q.db.QueryRowContext(ctx, getRepoPathFromPullRequestID, id)
	var i GetRepoPathFromPullRequestIDRow
	err := row.Scan(&i.Owner, &i.Name)
	return i, err
}

const getRepositoryByID = `-- name: GetRepositoryByID :one
SELECT id, project_id, provider, provider_id, repo_owner, repo_name, repo_id, is_private, is_fork, webhook_id, webhook_url, deploy_url, clone_url, default_branch, license, created_at FROM repositories WHERE id = $1
`

// avoid using this, where possible use GetRepositoryByIDAndProject instead
func (q *Queries) GetRepositoryByID(ctx context.Context, id uuid.UUID) (Repository, error) {
	row := q.db.QueryRowContext(ctx, getRepositoryByID, id)
	var i Repository
	err := row.Scan(
		&i.ID,
		&i.ProjectID,
		&i.Provider,
		&i.ProviderID,
		&i.RepoOwner,
		&i.RepoName,
		&i.RepoID,
		&i.IsPrivate,
		&i.IsFork,
		&i.WebhookID,
		&i.WebhookUrl,
		&i.DeployUrl,
		&i.CloneUrl,
		&i.DefaultBranch,
		&i.License,
		&i.CreatedAt,
	)
	return i, err
}

const getRepositoryByIDAndProject = `-- name: GetRepositoryByIDAndProject :one
SELECT id, project_id, provider, provider_id, repo_owner, repo_name, repo_id, is_private, is_fork, webhook_id, webhook_url, deploy_url, clone_url, default_branch, license, created_at FROM repositories WHERE id = $1 AND project_id = $2
`

type GetRepositoryByIDAndProjectParams struct {
	ID        uuid.UUID `json:"id"`
	ProjectID uuid.UUID `json:"project_id"`
}

func (q *Queries) GetRepositoryByIDAndProject(ctx context.Context, arg GetRepositoryByIDAndProjectParams) (Repository, error) {
	row := q.db.QueryRowContext(ctx, getRepositoryByIDAndProject, arg.ID, arg.ProjectID)
	var i Repository
	err := row.Scan(
		&i.ID,
		&i.ProjectID,
		&i.Provider,
		&i.ProviderID,
		&i.RepoOwner,
		&i.RepoName,
		&i.RepoID,
		&i.IsPrivate,
		&i.IsFork,
		&i.WebhookID,
		&i.WebhookUrl,
		&i.DeployUrl,
		&i.CloneUrl,
		&i.DefaultBranch,
		&i.License,
		&i.CreatedAt,
	)
	return i, err
}

const getRepositoryByRepoID = `-- name: GetRepositoryByRepoID :one
SELECT id, project_id, provider, provider_id, repo_owner, repo_name, repo_id, is_private, is_fork, webhook_id, webhook_url, deploy_url, clone_url, default_branch, license, created_at FROM repositories WHERE repo_id = $1
`

func (q *Queries) GetRepositoryByRepoID(ctx context.Context, repoID int64) (Repository, error) {
	row := q.db.QueryRowContext(ctx, getRepositoryByRepoID, repoID)
	var i Repository
	err := row.Scan(
		&i.ID,
		&i.ProjectID,
		&i.Provider,
		&i.ProviderID,
		&i.RepoOwner,
		&i.RepoName,
		&i.RepoID,
		&i.IsPrivate,
		&i.IsFork,
		&i.WebhookID,
		&i.WebhookUrl,
		&i.DeployUrl,
		&i.CloneUrl,
		&i.DefaultBranch,
		&i.License,
		&i.CreatedAt,
	)
	return i, err
}

const getRepositoryByRepoName = `-- name: GetRepositoryByRepoName :one
SELECT id, project_id, provider, provider_id, repo_owner, repo_name, repo_id, is_private, is_fork, webhook_id, webhook_url, deploy_url, clone_url, default_branch, license, created_at FROM repositories
    WHERE repo_owner = $1 AND repo_name = $2 AND project_id = $3
    AND (lower(provider) = lower($4::text) OR $4::text IS NULL)
`

type GetRepositoryByRepoNameParams struct {
	RepoOwner string         `json:"repo_owner"`
	RepoName  string         `json:"repo_name"`
	ProjectID uuid.UUID      `json:"project_id"`
	Provider  sql.NullString `json:"provider"`
}

func (q *Queries) GetRepositoryByRepoName(ctx context.Context, arg GetRepositoryByRepoNameParams) (Repository, error) {
	row := q.db.QueryRowContext(ctx, getRepositoryByRepoName,
		arg.RepoOwner,
		arg.RepoName,
		arg.ProjectID,
		arg.Provider,
	)
	var i Repository
	err := row.Scan(
		&i.ID,
		&i.ProjectID,
		&i.Provider,
		&i.ProviderID,
		&i.RepoOwner,
		&i.RepoName,
		&i.RepoID,
		&i.IsPrivate,
		&i.IsFork,
		&i.WebhookID,
		&i.WebhookUrl,
		&i.DeployUrl,
		&i.CloneUrl,
		&i.DefaultBranch,
		&i.License,
		&i.CreatedAt,
	)
	return i, err
}

const listRegisteredRepositoriesByProjectIDAndProvider = `-- name: ListRegisteredRepositoriesByProjectIDAndProvider :many
SELECT id, project_id, provider, provider_id, repo_owner, repo_name, repo_id, is_private, is_fork, webhook_id, webhook_url, deploy_url, clone_url, default_branch, license, created_at FROM repositories
WHERE project_id = $1 AND webhook_id IS NOT NULL
    AND (lower(provider) = lower($2::text) OR $2::text IS NULL)
ORDER BY repo_name
`

type ListRegisteredRepositoriesByProjectIDAndProviderParams struct {
	ProjectID uuid.UUID      `json:"project_id"`
	Provider  sql.NullString `json:"provider"`
}

func (q *Queries) ListRegisteredRepositoriesByProjectIDAndProvider(ctx context.Context, arg ListRegisteredRepositoriesByProjectIDAndProviderParams) ([]Repository, error) {
	rows, err := q.db.QueryContext(ctx, listRegisteredRepositoriesByProjectIDAndProvider, arg.ProjectID, arg.Provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Repository{}
	for rows.Next() {
		var i Repository
		if err := rows.Scan(
			&i.ID,
			&i.ProjectID,
			&i.Provider,
			&i.ProviderID,
			&i.RepoOwner,
			&i.RepoName,
			&i.RepoID,
			&i.IsPrivate,
			&i.IsFork,
			&i.WebhookID,
			&i.WebhookUrl,
			&i.DeployUrl,
			&i.CloneUrl,
			&i.DefaultBranch,
			&i.License,
			&i.CreatedAt,
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

const listRepositoriesAfterID = `-- name: ListRepositoriesAfterID :many
SELECT id, project_id, provider, provider_id, repo_owner, repo_name, repo_id, is_private, is_fork, webhook_id, webhook_url, deploy_url, clone_url, default_branch, license, created_at
FROM repositories
WHERE id > $1
ORDER BY id
LIMIT $2::bigint
`

type ListRepositoriesAfterIDParams struct {
	ID    uuid.UUID `json:"id"`
	Limit int64     `json:"limit"`
}

func (q *Queries) ListRepositoriesAfterID(ctx context.Context, arg ListRepositoriesAfterIDParams) ([]Repository, error) {
	rows, err := q.db.QueryContext(ctx, listRepositoriesAfterID, arg.ID, arg.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Repository{}
	for rows.Next() {
		var i Repository
		if err := rows.Scan(
			&i.ID,
			&i.ProjectID,
			&i.Provider,
			&i.ProviderID,
			&i.RepoOwner,
			&i.RepoName,
			&i.RepoID,
			&i.IsPrivate,
			&i.IsFork,
			&i.WebhookID,
			&i.WebhookUrl,
			&i.DeployUrl,
			&i.CloneUrl,
			&i.DefaultBranch,
			&i.License,
			&i.CreatedAt,
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
SELECT id, project_id, provider, provider_id, repo_owner, repo_name, repo_id, is_private, is_fork, webhook_id, webhook_url, deploy_url, clone_url, default_branch, license, created_at FROM repositories
WHERE project_id = $1
  AND (repo_id >= $2 OR $2 IS NULL)
  AND lower(provider) = lower(COALESCE($3, provider)::text)
ORDER BY project_id, provider, repo_id
LIMIT $4::bigint
`

type ListRepositoriesByProjectIDParams struct {
	ProjectID uuid.UUID      `json:"project_id"`
	RepoID    sql.NullInt64  `json:"repo_id"`
	Provider  sql.NullString `json:"provider"`
	Limit     sql.NullInt64  `json:"limit"`
}

func (q *Queries) ListRepositoriesByProjectID(ctx context.Context, arg ListRepositoriesByProjectIDParams) ([]Repository, error) {
	rows, err := q.db.QueryContext(ctx, listRepositoriesByProjectID,
		arg.ProjectID,
		arg.RepoID,
		arg.Provider,
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
			&i.ProjectID,
			&i.Provider,
			&i.ProviderID,
			&i.RepoOwner,
			&i.RepoName,
			&i.RepoID,
			&i.IsPrivate,
			&i.IsFork,
			&i.WebhookID,
			&i.WebhookUrl,
			&i.DeployUrl,
			&i.CloneUrl,
			&i.DefaultBranch,
			&i.License,
			&i.CreatedAt,
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

const repositoryExistsAfterID = `-- name: RepositoryExistsAfterID :one
SELECT EXISTS (
  SELECT 1
  FROM repositories
  WHERE id > $1)
AS exists
`

func (q *Queries) RepositoryExistsAfterID(ctx context.Context, id uuid.UUID) (bool, error) {
	row := q.db.QueryRowContext(ctx, repositoryExistsAfterID, id)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}
