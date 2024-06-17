// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0
// source: eval_history.sql

package db

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

const getLatestEvalStateForRuleEntity = `-- name: GetLatestEvalStateForRuleEntity :one

SELECT eh.id, eh.rule_entity_id, eh.status, eh.details, eh.evaluation_times, eh.most_recent_evaluation FROM evaluation_rule_entities AS re
JOIN latest_evaluation_statuses AS les ON les.rule_entity_id = re.id
JOIN evaluation_statuses AS eh ON les.evaluation_history_id = eh.id
WHERE re.rule_id = $1
AND (
    re.repository_id = $2
    OR re.pull_request_id = $3
    OR re.artifact_id = $4
)
FOR UPDATE
`

type GetLatestEvalStateForRuleEntityParams struct {
	RuleID        uuid.UUID     `json:"rule_id"`
	RepositoryID  uuid.NullUUID `json:"repository_id"`
	PullRequestID uuid.NullUUID `json:"pull_request_id"`
	ArtifactID    uuid.NullUUID `json:"artifact_id"`
}

// Copyright 2024 Stacklok, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
func (q *Queries) GetLatestEvalStateForRuleEntity(ctx context.Context, arg GetLatestEvalStateForRuleEntityParams) (EvaluationStatus, error) {
	row := q.db.QueryRowContext(ctx, getLatestEvalStateForRuleEntity,
		arg.RuleID,
		arg.RepositoryID,
		arg.PullRequestID,
		arg.ArtifactID,
	)
	var i EvaluationStatus
	err := row.Scan(
		&i.ID,
		&i.RuleEntityID,
		&i.Status,
		&i.Details,
		pq.Array(&i.EvaluationTimes),
		&i.MostRecentEvaluation,
	)
	return i, err
}

const insertEvaluationRuleEntity = `-- name: InsertEvaluationRuleEntity :one
INSERT INTO evaluation_rule_entities(
    rule_id,
    repository_id,
    pull_request_id,
    artifact_id
) VALUES (
    $1,
    $2,
    $3,
    $4
)
RETURNING id
`

type InsertEvaluationRuleEntityParams struct {
	RuleID        uuid.UUID     `json:"rule_id"`
	RepositoryID  uuid.NullUUID `json:"repository_id"`
	PullRequestID uuid.NullUUID `json:"pull_request_id"`
	ArtifactID    uuid.NullUUID `json:"artifact_id"`
}

func (q *Queries) InsertEvaluationRuleEntity(ctx context.Context, arg InsertEvaluationRuleEntityParams) (uuid.UUID, error) {
	row := q.db.QueryRowContext(ctx, insertEvaluationRuleEntity,
		arg.RuleID,
		arg.RepositoryID,
		arg.PullRequestID,
		arg.ArtifactID,
	)
	var id uuid.UUID
	err := row.Scan(&id)
	return id, err
}

const insertEvaluationStatus = `-- name: InsertEvaluationStatus :one
INSERT INTO evaluation_statuses(
    rule_entity_id,
    status,
    details
) VALUES (
    $1,
    $2,
    $3
)
RETURNING id
`

type InsertEvaluationStatusParams struct {
	RuleEntityID uuid.UUID       `json:"rule_entity_id"`
	Status       EvalStatusTypes `json:"status"`
	Details      string          `json:"details"`
}

func (q *Queries) InsertEvaluationStatus(ctx context.Context, arg InsertEvaluationStatusParams) (uuid.UUID, error) {
	row := q.db.QueryRowContext(ctx, insertEvaluationStatus, arg.RuleEntityID, arg.Status, arg.Details)
	var id uuid.UUID
	err := row.Scan(&id)
	return id, err
}

const updateEvaluationTimes = `-- name: UpdateEvaluationTimes :exec
UPDATE evaluation_statuses
SET evaluation_times = $1
WHERE id = $2
`

type UpdateEvaluationTimesParams struct {
	EvaluationTimes []time.Time `json:"evaluation_times"`
	ID              uuid.UUID   `json:"id"`
}

func (q *Queries) UpdateEvaluationTimes(ctx context.Context, arg UpdateEvaluationTimesParams) error {
	_, err := q.db.ExecContext(ctx, updateEvaluationTimes, pq.Array(arg.EvaluationTimes), arg.ID)
	return err
}

const upsertLatestEvaluationStatus = `-- name: UpsertLatestEvaluationStatus :exec
INSERT INTO latest_evaluation_statuses(
    rule_entity_id,
    evaluation_history_id
) VALUES (
    $1,
    $2
)
ON CONFLICT (rule_entity_id, evaluation_history_id) DO UPDATE
SET evaluation_history_id = $2
`

type UpsertLatestEvaluationStatusParams struct {
	RuleEntityID        uuid.UUID `json:"rule_entity_id"`
	EvaluationHistoryID uuid.UUID `json:"evaluation_history_id"`
}

func (q *Queries) UpsertLatestEvaluationStatus(ctx context.Context, arg UpsertLatestEvaluationStatusParams) error {
	_, err := q.db.ExecContext(ctx, upsertLatestEvaluationStatus, arg.RuleEntityID, arg.EvaluationHistoryID)
	return err
}
