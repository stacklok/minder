// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.18.0
// source: policy_status.sql

package db

import (
	"context"
	"time"
)

const getPolicyStatus = `-- name: GetPolicyStatus :many
SELECT pt.policy_type, r.id as repo_id, r.repo_owner, r.repo_name,
ps.policy_status, ps.last_updated FROM policy_status ps
INNER JOIN policies p ON p.id = ps.policy_id
INNER JOIN repositories r ON r.id = ps.repository_id
INNER JOIN policy_types pt ON pt.id = p.policy_type
WHERE p.id = $1
`

type GetPolicyStatusRow struct {
	PolicyType   string            `json:"policy_type"`
	RepoID       int32             `json:"repo_id"`
	RepoOwner    string            `json:"repo_owner"`
	RepoName     string            `json:"repo_name"`
	PolicyStatus PolicyStatusTypes `json:"policy_status"`
	LastUpdated  time.Time         `json:"last_updated"`
}

func (q *Queries) GetPolicyStatus(ctx context.Context, id int32) ([]GetPolicyStatusRow, error) {
	rows, err := q.db.QueryContext(ctx, getPolicyStatus, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetPolicyStatusRow{}
	for rows.Next() {
		var i GetPolicyStatusRow
		if err := rows.Scan(
			&i.PolicyType,
			&i.RepoID,
			&i.RepoOwner,
			&i.RepoName,
			&i.PolicyStatus,
			&i.LastUpdated,
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

const updatePolicyStatus = `-- name: UpdatePolicyStatus :exec
INSERT INTO policy_status (repository_id, policy_id, policy_status, last_updated) VALUES ($1, $2, $3, NOW())
ON CONFLICT (repository_id, policy_id) DO UPDATE SET policy_status = $3, last_updated = NOW()
`

type UpdatePolicyStatusParams struct {
	RepositoryID int32             `json:"repository_id"`
	PolicyID     int32             `json:"policy_id"`
	PolicyStatus PolicyStatusTypes `json:"policy_status"`
}

func (q *Queries) UpdatePolicyStatus(ctx context.Context, arg UpdatePolicyStatusParams) error {
	_, err := q.db.ExecContext(ctx, updatePolicyStatus, arg.RepositoryID, arg.PolicyID, arg.PolicyStatus)
	return err
}
