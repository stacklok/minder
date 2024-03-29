//
// Copyright 2024 Stacklok, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package projects

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/stacklok/minder/internal/authz"
	"github.com/stacklok/minder/internal/config/server"
	"github.com/stacklok/minder/internal/db"
	"github.com/stacklok/minder/internal/marketplaces"
	"github.com/stacklok/minder/internal/marketplaces/types"
	github "github.com/stacklok/minder/internal/providers/github/oauth"
	pb "github.com/stacklok/minder/pkg/api/protobuf/go/minder/v1"
	"github.com/stacklok/minder/pkg/mindpak"
)

var (
	// ErrProjectAlreadyExists is returned when a project with the same name already exists
	ErrProjectAlreadyExists = errors.New("project already exists")
)

// ProvisionSelfEnrolledProject creates the default records, such as projects, roles and provider for the organization
func ProvisionSelfEnrolledProject(
	ctx context.Context,
	authzClient authz.Client,
	qtx db.Querier,
	projectName string,
	userSub string,
	// Passing these as arguments to minimize code changes. In future, it may
	// make sense to hang these project create/delete methods off a struct or
	// interface to reduce the amount of dependencies which need to be passed
	// to individual methods.
	marketplace marketplaces.Marketplace,
	profilesCfg server.DefaultProfilesConfig,
) (outproj *pb.Project, projerr error) {
	projectmeta := NewSelfEnrolledMetadata(projectName)

	jsonmeta, err := json.Marshal(&projectmeta)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal meta: %w", err)
	}

	projectID := uuid.New()

	// Create authorization tuple
	// NOTE: This is only creating a tuple for the project, not the organization
	//       We currently have no use for the organization and it might be
	//       removed in the future.
	if err := authzClient.Write(ctx, userSub, authz.AuthzRoleAdmin, projectID); err != nil {
		return nil, fmt.Errorf("failed to create authorization tuple: %w", err)
	}
	defer func() {
		if outproj == nil && projerr != nil {
			if err := authzClient.Delete(ctx, userSub, authz.AuthzRoleAdmin, projectID); err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("failed to delete authorization tuple")
			}
		}
	}()

	// we need to create the default records for the organization
	project, err := qtx.CreateProjectWithID(ctx, db.CreateProjectWithIDParams{
		ID:       projectID,
		Name:     projectName,
		Metadata: jsonmeta,
	})
	if err != nil {
		// Check if `project_name_lower_idx` unique constraint was violated
		if db.ErrIsUniqueViolation(err) {
			return nil, ErrProjectAlreadyExists
		}
		return nil, fmt.Errorf("failed to create default project: %v", err)
	}

	prj := pb.Project{
		ProjectId:   project.ID.String(),
		Name:        project.Name,
		Description: projectmeta.Public.Description,
		DisplayName: projectmeta.Public.DisplayName,
		CreatedAt:   timestamppb.New(project.CreatedAt),
		UpdatedAt:   timestamppb.New(project.UpdatedAt),
	}

	// Create GitHub provider
	dbProvider, err := qtx.CreateProvider(ctx, db.CreateProviderParams{
		Name:       github.Github,
		ProjectID:  project.ID,
		Class:      db.NullProviderClass{ProviderClass: db.ProviderClassGithub, Valid: true},
		Implements: github.Implements,
		Definition: json.RawMessage(`{"github": {}}`),
		AuthFlows:  github.AuthorizationFlows,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %v", err)
	}

	// Enable any default profiles and rule types in the project.
	// For now, we subscribe to a single bundle and a single profile.
	// Both are specified in the service config.
	projectContext := types.NewProjectContext(project.ID, &dbProvider)
	bundleID := mindpak.ID(profilesCfg.Bundle.Namespace, profilesCfg.Bundle.Name)
	if err := marketplace.Subscribe(ctx, projectContext, bundleID, qtx); err != nil {
		return nil, fmt.Errorf("unable to subscribe to bundle: %w", err)
	}
	for _, profileName := range profilesCfg.GetProfiles() {
		if err := marketplace.AddProfile(ctx, projectContext, bundleID, profileName, qtx); err != nil {
			return nil, fmt.Errorf("unable to enable bundle profile: %w", err)
		}
	}

	return &prj, nil
}
