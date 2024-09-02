// Copyright 2023 Stacklok, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/stacklok/minder/internal/db"
	"github.com/stacklok/minder/internal/engine/engcontext"
	"github.com/stacklok/minder/internal/engine/entities"
	entmodels "github.com/stacklok/minder/internal/entities/models"
	"github.com/stacklok/minder/internal/logger"
	prof "github.com/stacklok/minder/internal/profiles"
	ghprop "github.com/stacklok/minder/internal/providers/github/properties"
	"github.com/stacklok/minder/internal/ruletypes"
	"github.com/stacklok/minder/internal/util"
	minderv1 "github.com/stacklok/minder/pkg/api/protobuf/go/minder/v1"
	provifv1 "github.com/stacklok/minder/pkg/providers/v1"
)

// CreateProfile creates a profile for a project
func (s *Server) CreateProfile(ctx context.Context,
	cpr *minderv1.CreateProfileRequest) (*minderv1.CreateProfileResponse, error) {
	in := cpr.GetProfile()
	if err := in.Validate(); err != nil {
		if errors.Is(err, minderv1.ErrValidationFailed) {
			return nil, util.UserVisibleError(codes.InvalidArgument, "Couldn't create profile: %s", err)
		}
		return nil, status.Errorf(codes.InvalidArgument, "invalid profile: %v", err)
	}

	entityCtx := engcontext.EntityFromContext(ctx)

	// validate that project is valid and exist in the db
	err := entityCtx.ValidateProject(ctx, s.store)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error in entity context: %v", err)
	}

	newProfile, err := db.WithTransaction(s.store, func(qtx db.ExtendQuerier) (*minderv1.Profile, error) {
		return s.profiles.CreateProfile(ctx, entityCtx.Project.ID, uuid.Nil, in, qtx)
	})
	if err != nil {
		// assumption: service layer is setting meaningful errors
		return nil, err
	}

	resp := &minderv1.CreateProfileResponse{
		Profile: newProfile,
	}

	return resp, nil
}

// DeleteProfile is a method to delete a profile
func (s *Server) DeleteProfile(ctx context.Context,
	in *minderv1.DeleteProfileRequest) (*minderv1.DeleteProfileResponse, error) {
	entityCtx := engcontext.EntityFromContext(ctx)

	err := entityCtx.ValidateProject(ctx, s.store)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error in entity context: %v", err)
	}

	parsedProfileID, err := uuid.Parse(in.Id)
	if err != nil {
		return nil, util.UserVisibleError(codes.InvalidArgument, "invalid profile ID")
	}

	profile, err := s.store.GetProfileByID(ctx, db.GetProfileByIDParams{
		ProjectID: entityCtx.Project.ID,
		ID:        parsedProfileID,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "profile not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to get profile: %s", err)
	}

	// TEMPORARY HACK: Since we do not need to support the deletion of bundle
	// profile yet, reject deletion requests in the API
	// TODO: Move this deletion logic to ProfileService
	if profile.SubscriptionID.Valid {
		return nil, status.Errorf(codes.InvalidArgument, "cannot delete profile from bundle")
	}

	err = s.store.DeleteProfile(ctx, db.DeleteProfileParams{
		ID:        profile.ID,
		ProjectID: entityCtx.Project.ID,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete profile: %s", err)
	}

	// Telemetry logging
	logger.BusinessRecord(ctx).Project = profile.ProjectID
	logger.BusinessRecord(ctx).Profile = logger.Profile{Name: profile.Name, ID: profile.ID}

	return &minderv1.DeleteProfileResponse{}, nil
}

// ListProfiles is a method to get all profiles for a project
func (s *Server) ListProfiles(ctx context.Context,
	req *minderv1.ListProfilesRequest) (*minderv1.ListProfilesResponse, error) {
	entityCtx := engcontext.EntityFromContext(ctx)

	err := entityCtx.ValidateProject(ctx, s.store)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error in entity context: %v", err)
	}

	listParams := db.ListProfilesByProjectIDAndLabelParams{
		ProjectID: entityCtx.Project.ID,
	}
	listParams.LabelsFromFilter(req.GetLabelFilter())

	zerolog.Ctx(ctx).Debug().Interface("listParams", listParams).Msg("profile list parameters")

	profiles, err := s.store.ListProfilesByProjectIDAndLabel(ctx, listParams)
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "failed to get profiles: %s", err)
	}

	var resp minderv1.ListProfilesResponse
	resp.Profiles = make([]*minderv1.Profile, 0, len(profiles))
	profileMap := prof.MergeDatabaseListIntoProfiles(profiles)

	// Sort the profiles by name to get a consistent order. This is important for UI.
	profileNames := make([]string, 0, len(profileMap))
	for prfName := range profileMap {
		profileNames = append(profileNames, prfName)
	}
	sort.Strings(profileNames)

	for _, prfName := range profileNames {
		profile := profileMap[prfName]
		resp.Profiles = append(resp.Profiles, profile)
	}

	// Telemetry logging
	logger.BusinessRecord(ctx).Project = entityCtx.Project.ID

	return &resp, nil
}

// GetProfileById is a method to get a profile by id
func (s *Server) GetProfileById(ctx context.Context,
	in *minderv1.GetProfileByIdRequest) (*minderv1.GetProfileByIdResponse, error) {

	entityCtx := engcontext.EntityFromContext(ctx)

	err := entityCtx.ValidateProject(ctx, s.store)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error in entity context: %v", err)
	}

	parsedProfileID, err := uuid.Parse(in.Id)
	if err != nil {
		return nil, util.UserVisibleError(codes.InvalidArgument, "invalid profile ID")
	}

	profile, err := getProfilePBFromDB(ctx, parsedProfileID, entityCtx, s.store)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || strings.Contains(err.Error(), "not found") {
			return nil, util.UserVisibleError(codes.NotFound, "profile not found")
		}

		return nil, status.Errorf(codes.Internal, "failed to get profile: %s", err)
	}

	// Telemetry logging
	logger.BusinessRecord(ctx).Project = entityCtx.Project.ID
	logger.BusinessRecord(ctx).Profile = logger.Profile{Name: profile.Name, ID: parsedProfileID}

	return &minderv1.GetProfileByIdResponse{
		Profile: profile,
	}, nil
}

// GetProfileByName implements the RPC method for getting a profile by name
func (s *Server) GetProfileByName(ctx context.Context,
	in *minderv1.GetProfileByNameRequest) (*minderv1.GetProfileByNameResponse, error) {
	entityCtx := engcontext.EntityFromContext(ctx)

	err := entityCtx.ValidateProject(ctx, s.store)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error in entity context: %v", err)
	}

	if in.Name == "" {
		return nil, util.UserVisibleError(codes.InvalidArgument, "profile name must be specified")
	}

	profiles, err := s.store.GetProfileByProjectAndName(ctx, db.GetProfileByProjectAndNameParams{
		ProjectID: entityCtx.Project.ID,
		Name:      in.Name,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, util.UserVisibleError(codes.NotFound, "profile %q not found", in.Name)
		}
		return nil, err
	}

	pols := prof.MergeDatabaseGetByNameIntoProfiles(profiles)

	// Telemetry logging
	logger.BusinessRecord(ctx).Project = entityCtx.Project.ID

	if len(pols) == 0 {
		return nil, util.UserVisibleError(codes.NotFound, "profile %q not found", in.Name)
	} else if len(pols) > 1 {
		return nil, fmt.Errorf("expected only one profile, got %d", len(pols))
	}

	// This should be only one profile
	for _, profile := range pols {
		return &minderv1.GetProfileByNameResponse{
			Profile: profile,
		}, nil
	}

	return nil, util.UserVisibleError(codes.NotFound, "profile %q not found", in.Name)
}

func getProfilePBFromDB(
	ctx context.Context,
	id uuid.UUID,
	entityCtx engcontext.EntityContext,
	querier db.ExtendQuerier,
) (*minderv1.Profile, error) {
	profiles, err := querier.GetProfileByProjectAndID(ctx, db.GetProfileByProjectAndIDParams{
		ProjectID: entityCtx.Project.ID,
		ID:        id,
	})
	if err != nil {
		return nil, err
	}

	pols := prof.MergeDatabaseGetIntoProfiles(profiles)
	if len(pols) == 0 {
		return nil, fmt.Errorf("profile not found")
	} else if len(pols) > 1 {
		return nil, fmt.Errorf("expected only one profile, got %d", len(pols))
	}

	// This should be only one profile
	for _, profile := range pols {
		return profile, nil
	}

	return nil, fmt.Errorf("profile not found")
}

// TODO: We need to replace this with a more generic method that can be used for all entities
// probably coming from the properties.
func getRuleEvalEntityInfo(
	rs db.ListRuleEvaluationsByProfileIdRow,
	efp *entmodels.EntityForProperties,
) map[string]string {
	entityInfo := map[string]string{}

	if owner := efp.Properties.GetProperty(ghprop.RepoPropertyOwner); owner != nil {
		entityInfo["repo_owner"] = owner.GetString()
	}
	if name := efp.Properties.GetProperty(ghprop.RepoPropertyName); name != nil {
		entityInfo["repo_name"] = name.GetString()
	}

	if artName := efp.Properties.GetProperty(ghprop.ArtifactPropertyName); artName != nil {
		entityInfo["artifact_name"] = artName.GetString()
	}

	if artType := efp.Properties.GetProperty(ghprop.ArtifactPropertyType); artType != nil {
		entityInfo["artifact_type"] = artType.GetString()
	}

	entityInfo["provider"] = rs.Provider
	entityInfo["entity_type"] = efp.Entity.Type.ToString()
	entityInfo["entity_id"] = rs.EntityID.String()

	// temporary: These will be replaced by entity_id
	if rs.EntityType == db.EntitiesRepository {
		entityInfo["repository_id"] = efp.Entity.ID.String()
	} else if rs.EntityType == db.EntitiesArtifact {
		entityInfo["artifact_id"] = efp.Entity.ID.String()
	}

	return entityInfo
}

// GetProfileStatusByName is a method to get profile status
// nolint:gocyclo // TODO: Refactor this to be more readable
func (s *Server) GetProfileStatusByName(ctx context.Context,
	in *minderv1.GetProfileStatusByNameRequest) (*minderv1.GetProfileStatusByNameResponse, error) {

	entityCtx := engcontext.EntityFromContext(ctx)

	err := entityCtx.ValidateProject(ctx, s.store)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error in entity context: %v", err)
	}

	dbProfileStatus, err := s.store.GetProfileStatusByNameAndProject(ctx, db.GetProfileStatusByNameAndProjectParams{
		ProjectID: entityCtx.Project.ID,
		Name:      in.Name,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, util.UserVisibleError(codes.NotFound, "profile %q status not found", in.Name)
		}
		return nil, status.Errorf(codes.Unknown, "failed to get profile: %s", err)
	}

	var ruleEvaluationStatuses []*minderv1.RuleEvaluationStatus
	var selector *uuid.NullUUID
	var ruleType *sql.NullString
	var ruleName *sql.NullString

	if in.GetAll() {
		selector = &uuid.NullUUID{}
	} else if e := in.GetEntity(); e != nil {
		if !e.GetType().IsValid() {
			return nil, util.UserVisibleError(codes.InvalidArgument,
				"invalid entity type %s, please use one of %s",
				e.GetType(), entities.KnownTypesCSV())
		}
		selector = &uuid.NullUUID{}
		if err := selector.Scan(e.GetId()); err != nil {
			return nil, util.UserVisibleError(codes.InvalidArgument, "invalid entity ID in selector")
		}
	}

	ruleType = &sql.NullString{
		String: in.GetRuleType(),
		Valid:  in.GetRuleType() != "",
	}

	// TODO: Remove deprecated 'rule' field from proto
	if !ruleType.Valid {
		//nolint:staticcheck // ignore SA1019: Deprecated field supported for backward compatibility
		ruleType = &sql.NullString{
			String: in.GetRule(),
			Valid:  in.GetRule() != "",
		}
	}

	ruleName = &sql.NullString{
		String: in.GetRuleName(),
		Valid:  in.GetRuleName() != "",
	}

	// TODO: Handle retrieving status for other types of entities
	if selector != nil {
		dbRuleEvaluationStatuses, err := s.store.ListRuleEvaluationsByProfileId(ctx, db.ListRuleEvaluationsByProfileIdParams{
			ProfileID:    dbProfileStatus.ID,
			EntityID:     *selector,
			RuleTypeName: *ruleType,
			RuleName:     *ruleName,
		})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, status.Errorf(codes.Unknown, "failed to list rule evaluation status: %s", err)
		}

		ruleEvaluationStatuses = s.getRuleEvaluationStatuses(
			ctx, dbRuleEvaluationStatuses, dbProfileStatus.ID.String(),
		)
		// TODO: Add other entities once we have database entries for them
	}

	// Telemetry logging
	logger.BusinessRecord(ctx).Project = entityCtx.Project.ID
	logger.BusinessRecord(ctx).Profile = logger.Profile{Name: dbProfileStatus.Name, ID: dbProfileStatus.ID}

	return &minderv1.GetProfileStatusByNameResponse{
		ProfileStatus: &minderv1.ProfileStatus{
			ProfileId:     dbProfileStatus.ID.String(),
			ProfileName:   dbProfileStatus.Name,
			ProfileStatus: string(dbProfileStatus.ProfileStatus),
			LastUpdated:   timestamppb.New(dbProfileStatus.LastUpdated),
		},
		RuleEvaluationStatus: ruleEvaluationStatuses,
	}, nil
}

func (s *Server) getRuleEvaluationStatuses(
	ctx context.Context,
	dbRuleEvaluationStatuses []db.ListRuleEvaluationsByProfileIdRow,
	profileId string,
) []*minderv1.RuleEvaluationStatus {
	ruleEvaluationStatuses := make(
		[]*minderv1.RuleEvaluationStatus, 0, len(dbRuleEvaluationStatuses),
	)
	// Loop through the rule evaluation statuses and convert them to protobuf
	for _, dbRuleEvalStat := range dbRuleEvaluationStatuses {
		// Get the rule evaluation status
		st, err := s.getRuleEvalStatus(ctx, profileId, dbRuleEvalStat)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) || errors.Is(err, provifv1.ErrEntityNotFound) {
				zerolog.Ctx(ctx).Error().
					Str("profile_id", profileId).
					Str("rule_id", dbRuleEvalStat.RuleTypeID.String()).
					Str("entity_id", dbRuleEvalStat.EntityID.String()).
					Err(err).Msg("entity not found. error getting rule evaluation status")
				continue
			}

			zerolog.Ctx(ctx).Error().
				Str("profile_id", profileId).
				Str("rule_id", dbRuleEvalStat.RuleTypeID.String()).
				Str("entity_id", dbRuleEvalStat.EntityID.String()).
				Err(err).Msg("error getting rule evaluation status")
			continue
		}
		// Append the rule evaluation status to the list
		ruleEvaluationStatuses = append(ruleEvaluationStatuses, st)
	}
	return ruleEvaluationStatuses
}

// getRuleEvalStatus is a helper function to get rule evaluation status from a db row
//
//nolint:gocyclo
func (s *Server) getRuleEvalStatus(
	ctx context.Context,
	profileID string,
	dbRuleEvalStat db.ListRuleEvaluationsByProfileIdRow,
) (*minderv1.RuleEvaluationStatus, error) {
	l := zerolog.Ctx(ctx)
	var guidance string
	var err error

	efp, err := s.props.EntityForProperties(
		ctx, dbRuleEvalStat.EntityID, dbRuleEvalStat.ProjectID, s.providerManager, nil)
	if err != nil {
		return nil, fmt.Errorf("error fetching entity for properties: %w", err)
	}

	err = s.props.RetrieveAllPropertiesForEntity(ctx, efp)
	if err != nil {
		return nil, fmt.Errorf("error fetching properties for entity: %w", err)
	}

	if dbRuleEvalStat.EvalStatus == db.EvalStatusTypesFailure ||
		dbRuleEvalStat.EvalStatus == db.EvalStatusTypesError {
		ruleTypeInfo, err := s.store.GetRuleTypeByID(ctx, dbRuleEvalStat.RuleTypeID)
		if err != nil {
			l.Err(err).Msg("error getting rule type info from db")
		} else {
			guidance = ruleTypeInfo.Guidance
		}
	}
	remediationURL := ""
	if dbRuleEvalStat.EntityType == db.EntitiesRepository {
		remediationURL, err = getRemediationURLFromMetadata(
			dbRuleEvalStat.RemMetadata,
			efp.Entity.Name,
		)
		if err != nil {
			// A failure parsing the alert metadata points to a corrupt record. Log but don't err.
			zerolog.Ctx(ctx).Error().Err(err).Msg("error parsing remediation pull request data")
		}
	}

	releasePhase, err := ruletypes.GetPBReleasePhaseFromDBReleaseStatus(&dbRuleEvalStat.RuleTypeReleasePhase)
	if err != nil {
		l.Err(err).Msg("error getting release phase")
	}

	st := &minderv1.RuleEvaluationStatus{
		ProfileId:           profileID,
		RuleId:              dbRuleEvalStat.RuleTypeID.String(),
		RuleName:            dbRuleEvalStat.RuleTypeName,
		RuleTypeName:        dbRuleEvalStat.RuleTypeName,
		RuleDescriptionName: dbRuleEvalStat.RuleName,
		RuleDisplayName:     dbRuleEvalStat.RuleTypeDisplayName,
		Entity:              string(dbRuleEvalStat.EntityType),
		Status:              string(dbRuleEvalStat.EvalStatus),
		Details:             dbRuleEvalStat.EvalDetails,
		EntityInfo:          getRuleEvalEntityInfo(dbRuleEvalStat, efp),
		Guidance:            guidance,
		LastUpdated:         timestamppb.New(dbRuleEvalStat.EvalLastUpdated),
		RemediationStatus:   string(dbRuleEvalStat.RemStatus),
		RemediationDetails:  dbRuleEvalStat.RemDetails,
		RemediationUrl:      remediationURL,
		Alert: &minderv1.EvalResultAlert{
			Status:      string(dbRuleEvalStat.AlertStatus),
			Details:     dbRuleEvalStat.AlertDetails,
			LastUpdated: timestamppb.New(dbRuleEvalStat.AlertLastUpdated),
		},
		RemediationLastUpdated: timestamppb.New(dbRuleEvalStat.RemLastUpdated),
		ReleasePhase:           releasePhase,
	}

	// If the alert is on and its metadata is valid, parse it and set the URL
	if st.Alert.Status == string(db.AlertStatusTypesOn) {
		// Due to the fact that this code was written around the old history tables
		// There was an assumption that repository information was always included
		// details about the repository. For other types of entity, we now need to
		// explicitly pull information about the repository.
		// TODO: Change all this logic to store the alert URL in the alert metadata
		// This logic should not be in the presentation layer of Minder.
		var repoPath string
		if dbRuleEvalStat.EntityType == db.EntitiesRepository {
			repoPath = fmt.Sprintf("%s/%s", st.EntityInfo["repo_owner"], st.EntityInfo["repo_name"])
		} else if dbRuleEvalStat.EntityType == db.EntitiesArtifact {
			artRepoOwner := efp.Properties.GetProperty(ghprop.ArtifactPropertyRepoOwner).GetString()
			artRepoName := efp.Properties.GetProperty(ghprop.ArtifactPropertyRepoName).GetString()
			if artRepoOwner != "" && artRepoName != "" {
				repoPath = fmt.Sprintf("%s/%s", artRepoOwner, artRepoName)
			}
		} else if dbRuleEvalStat.EntityType == db.EntitiesPullRequest {
			prRepoOwner := efp.Properties.GetProperty(ghprop.PullPropertyRepoOwner).GetString()
			prRepoName := efp.Properties.GetProperty(ghprop.PullPropertyRepoName).GetString()
			if prRepoOwner != "" && prRepoName != "" {
				repoPath = fmt.Sprintf("%s/%s", prRepoOwner, prRepoName)
			}
		}
		alertURL, err := getAlertURLFromMetadata(
			dbRuleEvalStat.AlertMetadata,
			repoPath,
		)
		if err != nil {
			l.Err(err).Msg("error getting alert URL from metadata")
		} else {
			st.Alert.Url = alertURL
		}
	}
	return st, nil
}

// GetProfileStatusByProject is a method to get profile status for a project
func (s *Server) GetProfileStatusByProject(ctx context.Context,
	_ *minderv1.GetProfileStatusByProjectRequest) (*minderv1.GetProfileStatusByProjectResponse, error) {

	entityCtx := engcontext.EntityFromContext(ctx)

	err := entityCtx.ValidateProject(ctx, s.store)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error in entity context: %v", err)
	}

	// read profile status
	dbstats, err := s.store.GetProfileStatusByProject(ctx, entityCtx.Project.ID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, status.Errorf(codes.NotFound, "profile statuses not found for project")
		}
		return nil, status.Errorf(codes.Unknown, "failed to get profile status: %s", err)
	}

	res := &minderv1.GetProfileStatusByProjectResponse{
		ProfileStatus: make([]*minderv1.ProfileStatus, 0, len(dbstats)),
	}

	for _, dbstat := range dbstats {
		res.ProfileStatus = append(res.ProfileStatus, &minderv1.ProfileStatus{
			ProfileId:     dbstat.ID.String(),
			ProfileName:   dbstat.Name,
			ProfileStatus: string(dbstat.ProfileStatus),
		})
	}

	// Telemetry logging
	logger.BusinessRecord(ctx).Project = entityCtx.Project.ID

	return res, nil
}

// PatchProfile updates a profile for a project with a partial request
func (s *Server) PatchProfile(ctx context.Context, ppr *minderv1.PatchProfileRequest) (*minderv1.PatchProfileResponse, error) {
	patch := ppr.GetPatch()
	entityCtx := engcontext.EntityFromContext(ctx)

	err := entityCtx.ValidateProject(ctx, s.store)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error in entity context: %v", err)
	}

	if ppr.GetId() == "" {
		return nil, util.UserVisibleError(codes.InvalidArgument, "profile ID must be specified")
	}

	profileID, err := uuid.Parse(ppr.GetId())
	if err != nil {
		return nil, util.UserVisibleError(codes.InvalidArgument, "Malformed UUID")
	}

	patchedProfile, err := db.WithTransaction(s.store, func(qtx db.ExtendQuerier) (*minderv1.Profile, error) {
		return s.profiles.PatchProfile(ctx, entityCtx.Project.ID, profileID, patch, ppr.GetUpdateMask(), qtx)
	})
	if err != nil {
		// assumption: service layer sets sensible errors
		return nil, err
	}

	return &minderv1.PatchProfileResponse{
		Profile: patchedProfile,
	}, nil
}

// UpdateProfile updates a profile for a project
func (s *Server) UpdateProfile(ctx context.Context,
	cpr *minderv1.UpdateProfileRequest) (*minderv1.UpdateProfileResponse, error) {
	in := cpr.GetProfile()

	entityCtx := engcontext.EntityFromContext(ctx)

	err := entityCtx.ValidateProject(ctx, s.store)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "error in entity context: %v", err)
	}

	updatedProfile, err := db.WithTransaction(s.store, func(qtx db.ExtendQuerier) (*minderv1.Profile, error) {
		return s.profiles.UpdateProfile(ctx, entityCtx.Project.ID, uuid.Nil, in, qtx)
	})

	if err != nil {
		// assumption: service layer sets sensible errors
		return nil, err
	}

	return &minderv1.UpdateProfileResponse{
		Profile: updatedProfile,
	}, nil
}
