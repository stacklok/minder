-- name: GetRepositoryByRepoID :one
SELECT * FROM repositories WHERE repo_id = $1;

-- name: GetRepositoryByRepoName :one
SELECT * FROM repositories
    WHERE repo_owner = $1 AND repo_name = $2 AND project_id = $3
    AND (lower(provider) = lower(sqlc.narg('provider')::text) OR sqlc.narg('provider')::text IS NULL);

-- avoid using this, where possible use GetRepositoryByIDAndProject instead
-- name: GetRepositoryByID :one
SELECT * FROM repositories WHERE id = $1;

-- name: GetRepositoryByIDAndProject :one
SELECT * FROM repositories WHERE id = $1 AND project_id = $2;

-- name: ListRepositoriesByProjectID :many
SELECT * FROM repositories
WHERE project_id = $1
  AND (repo_id >= sqlc.narg('repo_id') OR sqlc.narg('repo_id') IS NULL)
  AND lower(provider) = lower(COALESCE(sqlc.narg('provider'), provider)::text)
ORDER BY project_id, provider, repo_id
LIMIT sqlc.narg('limit')::bigint;

-- name: ListRegisteredRepositoriesByProjectIDAndProvider :many
SELECT * FROM repositories
WHERE project_id = $1 AND webhook_id IS NOT NULL
    AND (lower(provider) = lower(sqlc.narg('provider')::text) OR sqlc.narg('provider')::text IS NULL)
ORDER BY repo_name;

-- name: ListRepositoriesAfterID :many
SELECT *
FROM repositories
WHERE id > $1
ORDER BY id
LIMIT sqlc.arg('limit')::bigint;

-- name: RepositoryExistsAfterID :one
SELECT EXISTS (
  SELECT 1
  FROM repositories
  WHERE id > $1)
AS exists;

-- name: CountRepositories :one
SELECT COUNT(*) FROM repositories;

-- get a list of repos with webhooks belonging to a provider
-- is used for webhook cleanup during provider deletion
-- name: GetProviderWebhooks :many
SELECT repo_owner, repo_name, webhook_id FROM repositories
WHERE webhook_id IS NOT NULL AND provider_id = $1;

-- name: GetRepoPathFromArtifactID :one
SELECT r.repo_owner AS owner , r.repo_name AS name FROM repositories AS r
JOIN artifacts AS a ON a.repository_id = r.id
WHERE a.id = $1;

-- name: GetRepoPathFromPullRequestID :one
SELECT r.repo_owner AS owner , r.repo_name AS name FROM repositories AS r
JOIN pull_requests AS p ON p.repository_id = r.id
WHERE p.id = $1;