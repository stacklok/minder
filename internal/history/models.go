package history

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrMalformedCursor represents errors in the cursor payload.
	ErrMalformedCursor = errors.New("malformed cursor")
	// ErrAlreadySet is returned when a field is set multiple
	// times.
	ErrAlreadySet = errors.New("field already set")
	// ErrInvalidTimeRange is returned the time range from-to is
	// either missing one end or from is greater than to.
	ErrInvalidTimeRange = errors.New("invalid time range")
	// ErrInvalidIdentifier is returned when an identifier
	// (e.g. entity name) is empty or malformed.
	ErrInvalidIdentifier = errors.New("invalid identifier")
)

// Direction enumerates the direction of the Cursor.
type Direction string

const (
	// Next represents the next page.
	Next = "next"
	// Prev represents the prev page.
	Prev = "prev"
)

// ListEvaluationCursor is a struct representing a cursor in the
// dataset of historical evaluations.
type ListEvaluationCursor struct {
	ID        uuid.UUID
	Timestamp time.Time
	Direction Direction
}

var (
	// DefaultCursor is a cursor starting from the beginning of
	// the data set.
	DefaultCursor = ListEvaluationCursor{
		ID:        uuid.Nil,
		Timestamp: time.UnixMilli(0),
		Direction: Next,
	}
)

// ParseListEvaluationCursor interprets an opaque payload and returns
// a ListEvaluationCursor. The opaque paylaod is expected to be of one
// of the following forms
//
//   - `"+00000000-0000-0000-0000-000000000000"` meaning the next page
//     of data starting from the given UUID excluded
//
//   - `"-00000000-0000-0000-0000-000000000000"` meaning the previous
//     page of data starting from the given UUID excluded
//
//   - `"00000000-0000-0000-0000-000000000000"` meaning the next page
//     of data (default) starting from the given UUID excluded
func ParseListEvaluationCursor(payload string) (*ListEvaluationCursor, error) {
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrMalformedCursor, err)
	}

	switch {
	case string(decoded) == "":
		return &DefaultCursor, nil
	case strings.HasPrefix(string(decoded), "+"):
		// +00000000-0000-0000-0000-000000000000
		id, err := uuid.ParseBytes(decoded[1:])
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrMalformedCursor, err)
		}
		return &ListEvaluationCursor{
			ID:        id,
			Timestamp: time.UnixMilli(0),
			Direction: Next,
		}, nil
	case strings.HasPrefix(string(decoded), "-"):
		// -00000000-0000-0000-0000-000000000000
		id, err := uuid.ParseBytes(decoded[1:])
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrMalformedCursor, err)
		}
		return &ListEvaluationCursor{
			ID:        id,
			Timestamp: time.UnixMilli(0),
			Direction: Prev,
		}, nil
	default:
		// 00000000-0000-0000-0000-000000000000
		id, err := uuid.ParseBytes(decoded)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrMalformedCursor, err)
		}
		return &ListEvaluationCursor{
			ID:        id,
			Timestamp: time.UnixMilli(0),
			Direction: Next,
		}, nil
	}
}

// Filter is an empty interface to be implemented by structs
// representing filters. Its main purpose is to allow a generic
// definition of options functions.
type Filter interface{}

// FilterOpt is the option type used to configure filters.
type FilterOpt func(Filter) error

// EntityTypeFilter interface should be implemented by types
// implementing a filter on entity types.
type EntityTypeFilter interface {
	// AddEntityType adds an entity type for inclusion/exclusion
	// in the filter.
	AddEntityType(string) error
	// IncludedEntityTypes returns the list of included entity
	// types.
	IncludedEntityTypes() []string
	// ExcludedEntityTypes returns the list of excluded entity
	// types.
	ExcludedEntityTypes() []string
}

// EntityNameFilter interface should be implemented by types
// implementing a filter on entity names.
type EntityNameFilter interface {
	// AddEntityName adds an entity name for inclusion/exclution
	// in the filter.
	AddEntityName(string) error
	// IncludedEntityNames returns the list of included entity
	// names.
	IncludedEntityNames() []string
	// ExcludedEntityNames returns the list of excluded entity
	// names.
	ExcludedEntityNames() []string
}

// ProfileNameFilter interface should be implemented by types
// implementing a filter on profile names.
type ProfileNameFilter interface {
	// AddProfileName adds a profile name for inclusion/exclusion
	// in the filter.
	AddProfileName(string) error
	// IncludedProfileNames returns the list of included profile
	// names.
	IncludedProfileNames() []string
	// ExcludedProfileNames returns the list of excluded profile
	// names.
	ExcludedProfileNames() []string
}

// StatusFilter interface should be implemented by types implementing
// a filter on statuses.
type StatusFilter interface {
	// AddStatus adds a status for inclusion/exclusion in the
	// filter.
	AddStatus(string) error
	// IncludedStatus returns the list of included statuses.
	IncludedStatus() []string
	// ExcludedStatus returns the list of excluded statuses.
	ExcludedStatus() []string
}

// RemediationFilter interface should be implemented by types
// implementing a filter on remediation statuses.
type RemediationFilter interface {
	// AddRemediation adds a remediation for inclusion/exclusion
	// in the filter.
	AddRemediation(string) error
	// IncludedRemediation returns the list of included
	// remediations.
	IncludedRemediation() []string
	// ExcludedRemediation returns the list of excluded
	// remediations.
	ExcludedRemediation() []string
}

// AlertFilter interface should be implemented by types implementing a
// filter on alert settings.
type AlertFilter interface {
	// AddAlert adds an alert setting for inclusion/exclusion in
	// the filter.
	AddAlert(string) error
	// IncludedAlert returns the list of included alert settings.
	IncludedAlert() []string
	// IncludedAlert returns the list of excluded alert settings.
	ExcludedAlert() []string
}

// TimeRangeFilter interface should be implemented by types
// implementing a filter based on time range.
type TimeRangeFilter interface {
	// SetFrom sets the start of the time range.
	SetFrom(time.Time) error
	// SetTo sets the end of the time range.
	SetTo(time.Time) error
	// GetFrom retrieves the start of the time range.
	GetFrom() *time.Time
	// GetTo retrieves the end of the time range.
	GetTo() *time.Time
}

// ListEvaluationFilter is a filter to be used when listing historical
// evaluations.
type ListEvaluationFilter interface {
	EntityTypeFilter
	EntityNameFilter
	ProfileNameFilter
	StatusFilter
	RemediationFilter
	AlertFilter
	TimeRangeFilter
}

type listEvaluationFilter struct {
	// List of entity types to include in the selection
	includedEntityTypes []string
	// List of entity types to exclude from the selection
	excludedEntityTypes []string
	// List of entity names to include in the selection
	includedEntityNames []string
	// List of entity names to exclude from the selection
	excludedEntityNames []string
	// List of profile names to include in the selection
	includedProfileNames []string
	// List of profile names to exclude from the selection
	excludedProfileNames []string
	// List of statuses to include in the selection
	includedStatuses []string
	// List of statuses to exclude from the selection
	excludedStatuses []string
	// List of remediations to include in the selection
	includedRemediation []string
	// List of remediations to exclude from the selection
	excludedRemediation []string
	// List of alerts to include in the selection
	includedAlerts []string
	// List of alerts to exclude from the selection
	excludedAlerts []string
	// Lower bound of the time range, inclusive
	from *time.Time
	// Upper bound of the time range, exclusive
	to *time.Time
}

func (filter *listEvaluationFilter) AddEntityType(entityType string) error {
	if strings.HasPrefix(entityType, "!") {
		entityType = strings.Split(entityType, "!")[1] // guaranteed to exist
		filter.excludedEntityTypes = append(filter.excludedEntityTypes, entityType)
	} else {
		filter.includedEntityTypes = append(filter.includedEntityTypes, entityType)
	}
	return nil
}
func (filter *listEvaluationFilter) IncludedEntityTypes() []string {
	return filter.includedEntityTypes
}
func (filter *listEvaluationFilter) ExcludedEntityTypes() []string {
	return filter.excludedEntityTypes
}

func (filter *listEvaluationFilter) AddEntityName(entityName string) error {
	if strings.HasPrefix(entityName, "!") {
		entityName = strings.Split(entityName, "!")[1] // guaranteed to exist
		filter.excludedEntityNames = append(filter.excludedEntityNames, entityName)
	} else {
		filter.includedEntityNames = append(filter.includedEntityNames, entityName)
	}
	return nil
}
func (filter *listEvaluationFilter) IncludedEntityNames() []string {
	return filter.includedEntityNames
}
func (filter *listEvaluationFilter) ExcludedEntityNames() []string {
	return filter.excludedEntityNames
}

func (filter *listEvaluationFilter) AddProfileName(profileName string) error {
	if strings.HasPrefix(profileName, "!") {
		profileName = strings.Split(profileName, "!")[1] // guaranteed to exist
		filter.excludedProfileNames = append(filter.excludedProfileNames, profileName)
	} else {
		filter.includedProfileNames = append(filter.includedProfileNames, profileName)
	}
	return nil
}
func (filter *listEvaluationFilter) IncludedProfileNames() []string {
	return filter.includedProfileNames
}
func (filter *listEvaluationFilter) ExcludedProfileNames() []string {
	return filter.excludedProfileNames
}

func (filter *listEvaluationFilter) AddStatus(status string) error {
	if strings.HasPrefix(status, "!") {
		status = strings.Split(status, "!")[1] // guaranteed to exist
		filter.excludedStatuses = append(filter.excludedStatuses, status)
	} else {
		filter.includedStatuses = append(filter.includedStatuses, status)
	}
	return nil
}
func (filter *listEvaluationFilter) IncludedStatus() []string {
	return filter.includedStatuses
}
func (filter *listEvaluationFilter) ExcludedStatus() []string {
	return filter.excludedStatuses
}

func (filter *listEvaluationFilter) AddRemediation(remediation string) error {
	if strings.HasPrefix(remediation, "!") {
		remediation = strings.Split(remediation, "!")[1] // guaranteed to exist
		filter.excludedRemediation = append(filter.excludedRemediation, remediation)
	} else {
		filter.includedRemediation = append(filter.includedRemediation, remediation)
	}
	return nil
}
func (filter *listEvaluationFilter) IncludedRemediation() []string {
	return filter.includedRemediation
}
func (filter *listEvaluationFilter) ExcludedRemediation() []string {
	return filter.excludedRemediation
}

func (filter *listEvaluationFilter) AddAlert(alert string) error {
	if strings.HasPrefix(alert, "!") {
		alert = strings.Split(alert, "!")[1] // guaranteed to exist
		filter.excludedAlerts = append(filter.excludedAlerts, alert)
	} else {
		filter.includedAlerts = append(filter.includedAlerts, alert)
	}
	return nil
}
func (filter *listEvaluationFilter) IncludedAlert() []string {
	return filter.includedAlerts
}
func (filter *listEvaluationFilter) ExcludedAlert() []string {
	return filter.excludedAlerts
}

func (filter *listEvaluationFilter) SetFrom(from time.Time) error {
	if filter.from != nil {
		return fmt.Errorf("%w: from", ErrAlreadySet)
	}
	filter.from = &from
	return nil
}
func (filter *listEvaluationFilter) SetTo(to time.Time) error {
	if filter.to != nil {
		return fmt.Errorf("%w: to", ErrAlreadySet)
	}
	filter.to = &to
	return nil
}
func (filter *listEvaluationFilter) GetFrom() *time.Time {
	return filter.from
}
func (filter *listEvaluationFilter) GetTo() *time.Time {
	return filter.to
}

var _ Filter = (*listEvaluationFilter)(nil)
var _ ListEvaluationFilter = (*listEvaluationFilter)(nil)

// WithEntityType adds an entity type string to the filter. The entity
// type is added for inclusion unless it starts with a `!` characters,
// in which case it is added for exclusion.
func WithEntityType(entityType string) FilterOpt {
	return func(filter Filter) error {
		if entityType == "" || entityType == "!" {
			return fmt.Errorf("%w: entity type", ErrInvalidIdentifier)
		}
		inner, ok := filter.(EntityTypeFilter)
		if !ok {
			return fmt.Errorf("%w: wrong filter type", ErrInvalidIdentifier)
		}
		// TODO add validation on enumerated types
		return inner.AddEntityType(entityType)
	}
}

// WithEntityName adds an entity name string to the filter. The entity
// name is added for inclusion unless it starts with a `!` characters,
// in which case it is added for exclusion.
func WithEntityName(entityName string) FilterOpt {
	return func(filter Filter) error {
		if entityName == "" || entityName == "!" {
			return fmt.Errorf("%w: entity name", ErrInvalidIdentifier)
		}
		inner, ok := filter.(EntityNameFilter)
		if !ok {
			return fmt.Errorf("%w: wrong filter type", ErrInvalidIdentifier)
		}
		return inner.AddEntityName(entityName)
	}
}

// WithProfileName adds an profile name string to the filter. The
// profile name is added for inclusion unless it starts with a `!`
// characters, in which case it is added for exclusion.
func WithProfileName(profileName string) FilterOpt {
	return func(filter Filter) error {
		if profileName == "" || profileName == "!" {
			return fmt.Errorf("%w: profile name", ErrInvalidIdentifier)
		}
		inner, ok := filter.(ProfileNameFilter)
		if !ok {
			return fmt.Errorf("%w: wrong filter type", ErrInvalidIdentifier)
		}
		return inner.AddProfileName(profileName)
	}
}

// WithStatus adds a status string to the filter. The status is added
// for inclusion unless it starts with a `!` characters, in which case
// it is added for exclusion.
func WithStatus(status string) FilterOpt {
	return func(filter Filter) error {
		if status == "" || status == "!" {
			return fmt.Errorf("%w: status", ErrInvalidIdentifier)
		}
		inner, ok := filter.(StatusFilter)
		if !ok {
			return fmt.Errorf("%w: wrong filter type", ErrInvalidIdentifier)
		}
		// TODO add validation on enumerated types
		return inner.AddStatus(status)
	}
}

// WithRemediation adds a remediation string to the filter. The
// remediation is added for inclusion unless it starts with a `!`
// characters, in which case it is added for exclusion.
func WithRemediation(remediation string) FilterOpt {
	return func(filter Filter) error {
		if remediation == "" || remediation == "!" {
			return fmt.Errorf("%w: remediation", ErrInvalidIdentifier)
		}
		inner, ok := filter.(RemediationFilter)
		if !ok {
			return fmt.Errorf("%w: wrong filter type", ErrInvalidIdentifier)
		}
		// TODO add validation on enumerated types
		return inner.AddRemediation(remediation)
	}
}

// WithAlert adds an alert string to the filter. The alert is added
// for inclusion unless it starts with a `!` characters, in which case
// it is added for exclusion.
func WithAlert(alert string) FilterOpt {
	return func(filter Filter) error {
		if alert == "" || alert == "!" {
			return fmt.Errorf("%w: alert", ErrInvalidIdentifier)
		}
		inner, ok := filter.(AlertFilter)
		if !ok {
			return fmt.Errorf("%w: wrong filter type", ErrInvalidIdentifier)
		}
		// TODO add validation on enumerated types
		return inner.AddAlert(alert)
	}
}

// WithFrom sets the start of the time range, inclusive.
func WithFrom(from time.Time) FilterOpt {
	return func(filter Filter) error {
		inner, ok := filter.(TimeRangeFilter)
		if !ok {
			return fmt.Errorf("%w: wrong filter type", ErrInvalidIdentifier)
		}
		return inner.SetFrom(from)
	}
}

// WithTo sets the end of the time range, exclusive.
func WithTo(to time.Time) FilterOpt {
	return func(filter Filter) error {
		inner, ok := filter.(TimeRangeFilter)
		if !ok {
			return fmt.Errorf("%w: wrong filter type", ErrInvalidIdentifier)
		}
		return inner.SetTo(to)
	}
}

// NewListEvaluationFilter is a constructor routine for
// ListEvaluationFilter objects.
//
// It accepts a list of ListEvaluationFilterOpt options and performs
// validation on them, allowing only logically sound filters.
func NewListEvaluationFilter(opts ...FilterOpt) (ListEvaluationFilter, error) {
	filter := &listEvaluationFilter{}
	for _, opt := range opts {
		if err := opt(filter); err != nil {
			return nil, err
		}
	}

	if filter.to != nil && filter.from == nil {
		return nil, fmt.Errorf("%w: from is missing", ErrInvalidTimeRange)
	}
	if filter.from != nil && filter.to == nil {
		return nil, fmt.Errorf("%w: to is missing", ErrInvalidTimeRange)
	}
	if filter.from != nil && filter.to != nil && filter.from.After(*filter.to) {
		return nil, fmt.Errorf("%w: from is greated than to", ErrInvalidTimeRange)
	}

	return filter, nil
}