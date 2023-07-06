// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.17.2
// source: user_groups.sql

package db

import (
	"context"
	"database/sql"
	"time"
)

const addUserGroup = `-- name: AddUserGroup :one
INSERT INTO user_groups (
  user_id,
  group_id
    ) VALUES (
        $1, $2
) RETURNING id, user_id, group_id
`

type AddUserGroupParams struct {
	UserID  int32 `json:"user_id"`
	GroupID int32 `json:"group_id"`
}

func (q *Queries) AddUserGroup(ctx context.Context, arg AddUserGroupParams) (UserGroup, error) {
	row := q.db.QueryRowContext(ctx, addUserGroup, arg.UserID, arg.GroupID)
	var i UserGroup
	err := row.Scan(&i.ID, &i.UserID, &i.GroupID)
	return i, err
}

const getUserGroups = `-- name: GetUserGroups :many
SELECT groups.id, organization_id, name, description, is_protected, created_at, updated_at, user_groups.id, user_id, group_id FROM groups INNER JOIN user_groups ON groups.id = user_groups.group_id WHERE user_groups.user_id = $1
`

type GetUserGroupsRow struct {
	ID             int32          `json:"id"`
	OrganizationID int32          `json:"organization_id"`
	Name           string         `json:"name"`
	Description    sql.NullString `json:"description"`
	IsProtected    bool           `json:"is_protected"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	ID_2           int32          `json:"id_2"`
	UserID         int32          `json:"user_id"`
	GroupID        int32          `json:"group_id"`
}

func (q *Queries) GetUserGroups(ctx context.Context, userID int32) ([]GetUserGroupsRow, error) {
	rows, err := q.db.QueryContext(ctx, getUserGroups, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []GetUserGroupsRow{}
	for rows.Next() {
		var i GetUserGroupsRow
		if err := rows.Scan(
			&i.ID,
			&i.OrganizationID,
			&i.Name,
			&i.Description,
			&i.IsProtected,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.ID_2,
			&i.UserID,
			&i.GroupID,
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
