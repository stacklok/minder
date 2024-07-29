// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0

package db

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"
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

type AuthorizationFlow string

const (
	AuthorizationFlowUserInput                   AuthorizationFlow = "user_input"
	AuthorizationFlowOauth2AuthorizationCodeFlow AuthorizationFlow = "oauth2_authorization_code_flow"
	AuthorizationFlowGithubAppFlow               AuthorizationFlow = "github_app_flow"
	AuthorizationFlowNone                        AuthorizationFlow = "none"
)

func (e *AuthorizationFlow) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = AuthorizationFlow(s)
	case string:
		*e = AuthorizationFlow(s)
	default:
		return fmt.Errorf("unsupported scan type for AuthorizationFlow: %T", src)
	}
	return nil
}

type NullAuthorizationFlow struct {
	AuthorizationFlow AuthorizationFlow `json:"authorization_flow"`
	Valid             bool              `json:"valid"` // Valid is true if AuthorizationFlow is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullAuthorizationFlow) Scan(value interface{}) error {
	if value == nil {
		ns.AuthorizationFlow, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.AuthorizationFlow.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullAuthorizationFlow) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.AuthorizationFlow), nil
}

type Entities string

const (
	EntitiesRepository       Entities = "repository"
	EntitiesBuildEnvironment Entities = "build_environment"
	EntitiesArtifact         Entities = "artifact"
	EntitiesPullRequest      Entities = "pull_request"
	EntitiesRelease          Entities = "release"
	EntitiesPipelineRun      Entities = "pipeline_run"
	EntitiesTaskRun          Entities = "task_run"
	EntitiesBuild            Entities = "build"
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

type ProviderClass string

const (
	ProviderClassGithub    ProviderClass = "github"
	ProviderClassGithubApp ProviderClass = "github-app"
	ProviderClassGhcr      ProviderClass = "ghcr"
	ProviderClassDockerhub ProviderClass = "dockerhub"
)

func (e *ProviderClass) Scan(src interface{}) error {
	switch s := src.(type) {
	case []byte:
		*e = ProviderClass(s)
	case string:
		*e = ProviderClass(s)
	default:
		return fmt.Errorf("unsupported scan type for ProviderClass: %T", src)
	}
	return nil
}

type NullProviderClass struct {
	ProviderClass ProviderClass `json:"provider_class"`
	Valid         bool          `json:"valid"` // Valid is true if ProviderClass is not NULL
}

// Scan implements the Scanner interface.
func (ns *NullProviderClass) Scan(value interface{}) error {
	if value == nil {
		ns.ProviderClass, ns.Valid = "", false
		return nil
	}
	ns.Valid = true
	return ns.ProviderClass.Scan(value)
}

// Value implements the driver Valuer interface.
func (ns NullProviderClass) Value() (driver.Value, error) {
	if !ns.Valid {
		return nil, nil
	}
	return string(ns.ProviderClass), nil
}

type ProviderType string

const (
	ProviderTypeGithub      ProviderType = "github"
	ProviderTypeRest        ProviderType = "rest"
	ProviderTypeGit         ProviderType = "git"
	ProviderTypeOci         ProviderType = "oci"
	ProviderTypeRepoLister  ProviderType = "repo-lister"
	ProviderTypeImageLister ProviderType = "image-lister"
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
	RemediationStatusTypesPending      RemediationStatusTypes = "pending"
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

type AlertEvent struct {
	ID           uuid.UUID        `json:"id"`
	EvaluationID uuid.UUID        `json:"evaluation_id"`
	Status       AlertStatusTypes `json:"status"`
	Details      string           `json:"details"`
	Metadata     json.RawMessage  `json:"metadata"`
	CreatedAt    time.Time        `json:"created_at"`
}

type Artifact struct {
	ID                 uuid.UUID     `json:"id"`
	RepositoryID       uuid.NullUUID `json:"repository_id"`
	ArtifactName       string        `json:"artifact_name"`
	ArtifactType       string        `json:"artifact_type"`
	ArtifactVisibility string        `json:"artifact_visibility"`
	CreatedAt          time.Time     `json:"created_at"`
	UpdatedAt          time.Time     `json:"updated_at"`
	ProjectID          uuid.UUID     `json:"project_id"`
	ProviderID         uuid.UUID     `json:"provider_id"`
	ProviderName       string        `json:"provider_name"`
}

type Bundle struct {
	ID        uuid.UUID `json:"id"`
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
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
	RepositoryID  uuid.NullUUID `json:"repository_id"`
	ArtifactID    uuid.NullUUID `json:"artifact_id"`
	PullRequestID uuid.NullUUID `json:"pull_request_id"`
	ProjectID     uuid.NullUUID `json:"project_id"`
}

type EntityProfile struct {
	ID              uuid.UUID       `json:"id"`
	Entity          Entities        `json:"entity"`
	ProfileID       uuid.UUID       `json:"profile_id"`
	ContextualRules json.RawMessage `json:"contextual_rules"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
	Migrated        bool            `json:"migrated"`
}

type EvaluationRuleEntity struct {
	ID            uuid.UUID     `json:"id"`
	RuleID        uuid.UUID     `json:"rule_id"`
	RepositoryID  uuid.NullUUID `json:"repository_id"`
	PullRequestID uuid.NullUUID `json:"pull_request_id"`
	ArtifactID    uuid.NullUUID `json:"artifact_id"`
	EntityType    Entities      `json:"entity_type"`
}

type EvaluationStatus struct {
	ID             uuid.UUID       `json:"id"`
	RuleEntityID   uuid.UUID       `json:"rule_entity_id"`
	Status         EvalStatusTypes `json:"status"`
	Details        string          `json:"details"`
	EvaluationTime time.Time       `json:"evaluation_time"`
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
	RepositoryID  uuid.NullUUID `json:"repository_id"`
	ArtifactID    uuid.NullUUID `json:"artifact_id"`
	PullRequestID uuid.NullUUID `json:"pull_request_id"`
	QueuedAt      time.Time     `json:"queued_at"`
	ProjectID     uuid.NullUUID `json:"project_id"`
}

type LatestEvaluationStatus struct {
	RuleEntityID        uuid.UUID     `json:"rule_entity_id"`
	EvaluationHistoryID uuid.UUID     `json:"evaluation_history_id"`
	ProfileID           uuid.NullUUID `json:"profile_id"`
}

type Profile struct {
	ID             uuid.UUID      `json:"id"`
	Name           string         `json:"name"`
	Provider       sql.NullString `json:"provider"`
	ProjectID      uuid.UUID      `json:"project_id"`
	Remediate      NullActionType `json:"remediate"`
	Alert          NullActionType `json:"alert"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	ProviderID     uuid.NullUUID  `json:"provider_id"`
	SubscriptionID uuid.NullUUID  `json:"subscription_id"`
	DisplayName    string         `json:"display_name"`
	Labels         []string       `json:"labels"`
}

type ProfileSelector struct {
	ID        uuid.UUID    `json:"id"`
	ProfileID uuid.UUID    `json:"profile_id"`
	Entity    NullEntities `json:"entity"`
	Selector  string       `json:"selector"`
	Comment   string       `json:"comment"`
}

type ProfileStatus struct {
	ID            uuid.UUID       `json:"id"`
	ProfileID     uuid.UUID       `json:"profile_id"`
	ProfileStatus EvalStatusTypes `json:"profile_status"`
	LastUpdated   time.Time       `json:"last_updated"`
}

type ProfilesWithEntityProfile struct {
	ID              uuid.NullUUID         `json:"id"`
	Entity          NullEntities          `json:"entity"`
	ProfileID       uuid.NullUUID         `json:"profile_id"`
	ContextualRules pqtype.NullRawMessage `json:"contextual_rules"`
	CreatedAt       sql.NullTime          `json:"created_at"`
	UpdatedAt       sql.NullTime          `json:"updated_at"`
	Profid          uuid.UUID             `json:"profid"`
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
	ID         uuid.UUID           `json:"id"`
	Name       string              `json:"name"`
	Version    string              `json:"version"`
	ProjectID  uuid.UUID           `json:"project_id"`
	Implements []ProviderType      `json:"implements"`
	Definition json.RawMessage     `json:"definition"`
	CreatedAt  time.Time           `json:"created_at"`
	UpdatedAt  time.Time           `json:"updated_at"`
	AuthFlows  []AuthorizationFlow `json:"auth_flows"`
	Class      ProviderClass       `json:"class"`
}

type ProviderAccessToken struct {
	ID                   int32                 `json:"id"`
	Provider             string                `json:"provider"`
	ProjectID            uuid.UUID             `json:"project_id"`
	OwnerFilter          sql.NullString        `json:"owner_filter"`
	EncryptedToken       sql.NullString        `json:"encrypted_token"`
	ExpirationTime       time.Time             `json:"expiration_time"`
	CreatedAt            time.Time             `json:"created_at"`
	UpdatedAt            time.Time             `json:"updated_at"`
	EnrollmentNonce      sql.NullString        `json:"enrollment_nonce"`
	EncryptedAccessToken pqtype.NullRawMessage `json:"encrypted_access_token"`
}

type ProviderGithubAppInstallation struct {
	AppInstallationID int64          `json:"app_installation_id"`
	ProviderID        uuid.NullUUID  `json:"provider_id"`
	OrganizationID    int64          `json:"organization_id"`
	EnrollingUserID   sql.NullString `json:"enrolling_user_id"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	EnrollmentNonce   sql.NullString `json:"enrollment_nonce"`
	ProjectID         uuid.NullUUID  `json:"project_id"`
	IsOrg             bool           `json:"is_org"`
}

type PullRequest struct {
	ID           uuid.UUID `json:"id"`
	RepositoryID uuid.UUID `json:"repository_id"`
	PrNumber     int64     `json:"pr_number"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type RemediationEvent struct {
	ID           uuid.UUID              `json:"id"`
	EvaluationID uuid.UUID              `json:"evaluation_id"`
	Status       RemediationStatusTypes `json:"status"`
	Details      string                 `json:"details"`
	Metadata     json.RawMessage        `json:"metadata"`
	CreatedAt    time.Time              `json:"created_at"`
}

type Repository struct {
	ID               uuid.UUID      `json:"id"`
	Provider         string         `json:"provider"`
	ProjectID        uuid.UUID      `json:"project_id"`
	RepoOwner        string         `json:"repo_owner"`
	RepoName         string         `json:"repo_name"`
	RepoID           int64          `json:"repo_id"`
	IsPrivate        bool           `json:"is_private"`
	IsFork           bool           `json:"is_fork"`
	WebhookID        sql.NullInt64  `json:"webhook_id"`
	WebhookUrl       string         `json:"webhook_url"`
	DeployUrl        string         `json:"deploy_url"`
	CloneUrl         string         `json:"clone_url"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	DefaultBranch    sql.NullString `json:"default_branch"`
	License          sql.NullString `json:"license"`
	ProviderID       uuid.UUID      `json:"provider_id"`
	ReminderLastSent sql.NullTime   `json:"reminder_last_sent"`
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
	Metadata    json.RawMessage        `json:"metadata"`
}

type RuleEvaluation struct {
	ID             uuid.UUID     `json:"id"`
	Entity         Entities      `json:"entity"`
	ProfileID      uuid.UUID     `json:"profile_id"`
	RuleTypeID     uuid.UUID     `json:"rule_type_id"`
	RepositoryID   uuid.NullUUID `json:"repository_id"`
	ArtifactID     uuid.NullUUID `json:"artifact_id"`
	PullRequestID  uuid.NullUUID `json:"pull_request_id"`
	RuleName       string        `json:"rule_name"`
	RuleEntityID   uuid.NullUUID `json:"rule_entity_id"`
	RuleInstanceID uuid.NullUUID `json:"rule_instance_id"`
}

type RuleInstance struct {
	ID         uuid.UUID       `json:"id"`
	ProfileID  uuid.UUID       `json:"profile_id"`
	RuleTypeID uuid.UUID       `json:"rule_type_id"`
	Name       string          `json:"name"`
	EntityType Entities        `json:"entity_type"`
	Def        json.RawMessage `json:"def"`
	Params     json.RawMessage `json:"params"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
	ProjectID  uuid.UUID       `json:"project_id"`
}

type RuleType struct {
	ID             uuid.UUID       `json:"id"`
	Name           string          `json:"name"`
	Provider       sql.NullString  `json:"provider"`
	ProjectID      uuid.UUID       `json:"project_id"`
	Description    string          `json:"description"`
	Guidance       string          `json:"guidance"`
	Definition     json.RawMessage `json:"definition"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
	SeverityValue  Severity        `json:"severity_value"`
	ProviderID     uuid.NullUUID   `json:"provider_id"`
	SubscriptionID uuid.NullUUID   `json:"subscription_id"`
	DisplayName    string          `json:"display_name"`
}

type SessionStore struct {
	ID                int32                 `json:"id"`
	Provider          string                `json:"provider"`
	ProjectID         uuid.UUID             `json:"project_id"`
	Port              sql.NullInt32         `json:"port"`
	OwnerFilter       sql.NullString        `json:"owner_filter"`
	SessionState      string                `json:"session_state"`
	CreatedAt         time.Time             `json:"created_at"`
	RedirectUrl       sql.NullString        `json:"redirect_url"`
	RemoteUser        sql.NullString        `json:"remote_user"`
	EncryptedRedirect pqtype.NullRawMessage `json:"encrypted_redirect"`
	ProviderConfig    []byte                `json:"provider_config"`
}

type Subscription struct {
	ID             uuid.UUID `json:"id"`
	ProjectID      uuid.UUID `json:"project_id"`
	BundleID       uuid.UUID `json:"bundle_id"`
	CurrentVersion string    `json:"current_version"`
}

type User struct {
	ID              int32     `json:"id"`
	IdentitySubject string    `json:"identity_subject"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type UserInvite struct {
	Code      string    `json:"code"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Project   uuid.UUID `json:"project"`
	Sponsor   int32     `json:"sponsor"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
