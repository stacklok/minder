// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0

package db

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type ActionType string

const (
	ActionTypeOn     ActionType = "on"
	ActionTypeOff    ActionType = "off"
	ActionTypeDryRun ActionType = "dry_run"
)

func (e *ActionType) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = ActionType(s)
	case string:
		*e = ActionType(s)
	default:
		return fmt.Errorf("unsupported scan type for ActionType: %T", src)
	}
	return nil
}

type NullActionType struct {
	ActionType ActionType `json:"action_type"`
	Valid      bool       `json:"valid"` // Valid is true if ActionType is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullActionType) Scan(value interface{}) error {
	if value == nil {
		ns.ActionType, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.ActionType.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullActionType) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.ActionType), nil
}

type AlertStatusTypes string

const (
	AlertStatusTypesOn           AlertStatusTypes = "on"
	AlertStatusTypesOff          AlertStatusTypes = "off"
	AlertStatusTypesError        AlertStatusTypes = "error"
	AlertStatusTypesSkipped      AlertStatusTypes = "skipped"
	AlertStatusTypesNotAvailable AlertStatusTypes = "not_available"
)

func (e *AlertStatusTypes) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = AlertStatusTypes(s)
	case string:
		*e = AlertStatusTypes(s)
	default:
		return fmt.Errorf("unsupported scan type for AlertStatusTypes: %T", src)
	}
	return nil
}

type NullAlertStatusTypes struct {
	AlertStatusTypes AlertStatusTypes `json:"alert_status_types"`
	Valid            bool             `json:"valid"` // Valid is true if AlertStatusTypes is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullAlertStatusTypes) Scan(value interface{}) error {
	if value == nil {
		ns.AlertStatusTypes, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.AlertStatusTypes.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullAlertStatusTypes) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.AlertStatusTypes), nil
}

type Entities string

const (
	EntitiesRepository       Entities = "repository"
	EntitiesBuildEnvironment Entities = "build_environment"
	EntitiesArtifact         Entities = "artifact"
	EntitiesPullRequest      Entities = "pull_request"
)

func (e *Entities) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = Entities(s)
	case string:
		*e = Entities(s)
	default:
		return fmt.Errorf("unsupported scan type for Entities: %T", src)
	}
	return nil
}

type NullEntities struct {
	Entities Entities `json:"entities"`
	Valid    bool     `json:"valid"` // Valid is true if Entities is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullEntities) Scan(value interface{}) error {
	if value == nil {
		ns.Entities, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.Entities.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullEntities) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.Entities), nil
}

type EvalStatusTypes string

const (
	EvalStatusTypesSuccess EvalStatusTypes = "success"
	EvalStatusTypesFailure EvalStatusTypes = "failure"
	EvalStatusTypesError   EvalStatusTypes = "error"
	EvalStatusTypesSkipped EvalStatusTypes = "skipped"
	EvalStatusTypesPending EvalStatusTypes = "pending"
)

func (e *EvalStatusTypes) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = EvalStatusTypes(s)
	case string:
		*e = EvalStatusTypes(s)
	default:
		return fmt.Errorf("unsupported scan type for EvalStatusTypes: %T", src)
	}
	return nil
}

type NullEvalStatusTypes struct {
	EvalStatusTypes EvalStatusTypes `json:"eval_status_types"`
	Valid           bool            `json:"valid"` // Valid is true if EvalStatusTypes is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullEvalStatusTypes) Scan(value interface{}) error {
	if value == nil {
		ns.EvalStatusTypes, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.EvalStatusTypes.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullEvalStatusTypes) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.EvalStatusTypes), nil
}

type ProviderType string

const (
	ProviderTypeGithub     ProviderType = "github"
	ProviderTypeRest       ProviderType = "rest"
	ProviderTypeGit        ProviderType = "git"
	ProviderTypeOci        ProviderType = "oci"
	ProviderTypeRepoLister ProviderType = "repo-lister"
)

func (e *ProviderType) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = ProviderType(s)
	case string:
		*e = ProviderType(s)
	default:
		return fmt.Errorf("unsupported scan type for ProviderType: %T", src)
	}
	return nil
}

type NullProviderType struct {
	ProviderType ProviderType `json:"provider_type"`
	Valid        bool         `json:"valid"` // Valid is true if ProviderType is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullProviderType) Scan(value interface{}) error {
	if value == nil {
		ns.ProviderType, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.ProviderType.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullProviderType) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.ProviderType), nil
}

type RemediationStatusTypes string

const (
	RemediationStatusTypesSuccess      RemediationStatusTypes = "success"
	RemediationStatusTypesFailure      RemediationStatusTypes = "failure"
	RemediationStatusTypesError        RemediationStatusTypes = "error"
	RemediationStatusTypesSkipped      RemediationStatusTypes = "skipped"
	RemediationStatusTypesNotAvailable RemediationStatusTypes = "not_available"
)

func (e *RemediationStatusTypes) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = RemediationStatusTypes(s)
	case string:
		*e = RemediationStatusTypes(s)
	default:
		return fmt.Errorf("unsupported scan type for RemediationStatusTypes: %T", src)
	}
	return nil
}

type NullRemediationStatusTypes struct {
	RemediationStatusTypes RemediationStatusTypes `json:"remediation_status_types"`
	Valid                  bool                   `json:"valid"` // Valid is true if RemediationStatusTypes is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullRemediationStatusTypes) Scan(value interface{}) error {
	if value == nil {
		ns.RemediationStatusTypes, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.RemediationStatusTypes.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullRemediationStatusTypes) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.RemediationStatusTypes), nil
}

type Severity string

const (
	SeverityUnknown  Severity = "unknown"
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (e *Severity) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = Severity(s)
	case string:
		*e = Severity(s)
	default:
		return fmt.Errorf("unsupported scan type for Severity: %T", src)
	}
	return nil
}

type NullSeverity struct {
	Severity Severity `json:"severity"`
	Valid    bool     `json:"valid"` // Valid is true if Severity is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullSeverity) Scan(value interface{}) error {
	if value == nil {
		ns.Severity, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.Severity.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullSeverity) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.Severity), nil
}

type Artifact struct {
	ID                 uuid.UUID `json:"id"`
	RepositoryID       uuid.UUID `json:"repository_id"`
	ArtifactName       string    `json:"artifact_name"`
	ArtifactType       string    `json:"artifact_type"`
	ArtifactVisibility string    `json:"artifact_visibility"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type Entitlement struct {
	ID        uuid.UUID `json:"id"`
	Feature   string    `json:"feature"`
	ProjectID uuid.UUID `json:"project_id"`
	CreatedAt time.Time `json:"created_at"`
}

type EntityExecutionLock struct {
	ID            uuid.UUID     `json:"id"`
	Entity        Entities      `json:"entity"`
	LockedBy      uuid.UUID     `json:"locked_by"`
	LastLockTime  time.Time     `json:"last_lock_time"`
	RepositoryID  uuid.UUID     `json:"repository_id"`
	ArtifactID    uuid.NullUUID `json:"artifact_id"`
	PullRequestID uuid.NullUUID `json:"pull_request_id"`
}

type EntityProfile struct {
	ID              uuid.UUID       `json:"id"`
	Entity          Entities        `json:"entity"`
	ProfileID       uuid.UUID       `json:"profile_id"`
	ContextualRules json.RawMessage `json:"contextual_rules"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

type EntityProfileRule struct {
	ID              uuid.UUID `json:"id"`
	EntityProfileID uuid.UUID `json:"entity_profile_id"`
	RuleTypeID      uuid.UUID `json:"rule_type_id"`
	CreatedAt       time.Time `json:"created_at"`
}

type Feature struct {
	Name      string          `json:"name"`
	Settings  json.RawMessage `json:"settings"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type FlushCache struct {
	ID            uuid.UUID     `json:"id"`
	Entity        Entities      `json:"entity"`
	RepositoryID  uuid.UUID     `json:"repository_id"`
	ArtifactID    uuid.NullUUID `json:"artifact_id"`
	PullRequestID uuid.NullUUID `json:"pull_request_id"`
	QueuedAt      time.Time     `json:"queued_at"`
}

type MigrationProfileBackfillLog struct {
	ProfileID uuid.UUID `json:"profile_id"`
}

type Profile struct {
	ID        uuid.UUID      `json:"id"`
	Name      string         `json:"name"`
	Provider  string         `json:"provider"`
	ProjectID uuid.UUID      `json:"project_id"`
	Remediate NullActionType `json:"remediate"`
	Alert     NullActionType `json:"alert"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

type ProfileStatus struct {
	ID            uuid.UUID       `json:"id"`
	ProfileID     uuid.UUID       `json:"profile_id"`
	ProfileStatus EvalStatusTypes `json:"profile_status"`
	LastUpdated   time.Time       `json:"last_updated"`
}

type Project struct {
	ID             uuid.UUID       `json:"id"`
	Name           string          `json:"name"`
	IsOrganization bool            `json:"is_organization"`
	Metadata       json.RawMessage `json:"metadata"`
	ParentID       uuid.NullUUID   `json:"parent_id"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

type Provider struct {
	ID         uuid.UUID       `json:"id"`
	Name       string          `json:"name"`
	Version    string          `json:"version"`
	ProjectID  uuid.UUID       `json:"project_id"`
	Implements []ProviderType  `json:"implements"`
	Definition json.RawMessage `json:"definition"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

type ProviderAccessToken struct {
	ID             int32          `json:"id"`
	Provider       string         `json:"provider"`
	ProjectID      uuid.UUID      `json:"project_id"`
	OwnerFilter    sql.NullString `json:"owner_filter"`
	EncryptedToken string         `json:"encrypted_token"`
	ExpirationTime time.Time      `json:"expiration_time"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type PullRequest struct {
	ID           uuid.UUID `json:"id"`
	RepositoryID uuid.UUID `json:"repository_id"`
	PrNumber     int64     `json:"pr_number"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Repository struct {
	ID            uuid.UUID      `json:"id"`
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
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DefaultBranch sql.NullString `json:"default_branch"`
}

type RuleDetailsAlert struct {
	ID          uuid.UUID        `json:"id"`
	RuleEvalID  uuid.UUID        `json:"rule_eval_id"`
	Status      AlertStatusTypes `json:"status"`
	Details     string           `json:"details"`
	Metadata    json.RawMessage  `json:"metadata"`
	LastUpdated time.Time        `json:"last_updated"`
}

type RuleDetailsEval struct {
	ID          uuid.UUID       `json:"id"`
	RuleEvalID  uuid.UUID       `json:"rule_eval_id"`
	Status      EvalStatusTypes `json:"status"`
	Details     string          `json:"details"`
	LastUpdated time.Time       `json:"last_updated"`
}

type RuleDetailsRemediate struct {
	ID          uuid.UUID              `json:"id"`
	RuleEvalID  uuid.UUID              `json:"rule_eval_id"`
	Status      RemediationStatusTypes `json:"status"`
	Details     string                 `json:"details"`
	LastUpdated time.Time              `json:"last_updated"`
}

type RuleEvaluation struct {
	ID            uuid.UUID     `json:"id"`
	Entity        Entities      `json:"entity"`
	ProfileID     uuid.UUID     `json:"profile_id"`
	RuleTypeID    uuid.UUID     `json:"rule_type_id"`
	RepositoryID  uuid.NullUUID `json:"repository_id"`
	ArtifactID    uuid.NullUUID `json:"artifact_id"`
	PullRequestID uuid.NullUUID `json:"pull_request_id"`
	RuleName      string        `json:"rule_name"`
}

type RuleType struct {
	ID            uuid.UUID       `json:"id"`
	Name          string          `json:"name"`
	Provider      string          `json:"provider"`
	ProjectID     uuid.UUID       `json:"project_id"`
	Description   string          `json:"description"`
	Guidance      string          `json:"guidance"`
	Definition    json.RawMessage `json:"definition"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	SeverityValue Severity        `json:"severity_value"`
}

type SessionStore struct {
	ID           int32          `json:"id"`
	Provider     string         `json:"provider"`
	ProjectID    uuid.UUID      `json:"project_id"`
	Port         sql.NullInt32  `json:"port"`
	OwnerFilter  sql.NullString `json:"owner_filter"`
	SessionState string         `json:"session_state"`
	CreatedAt    time.Time      `json:"created_at"`
	RedirectUrl  sql.NullString `json:"redirect_url"`
}

type User struct {
	ID              int32     `json:"id"`
	IdentitySubject string    `json:"identity_subject"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}
