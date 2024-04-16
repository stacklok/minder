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

package reconcilers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/stacklok/minder/internal/db"
	"github.com/stacklok/minder/internal/engine"
	"github.com/stacklok/minder/internal/engine/entities"
	"github.com/stacklok/minder/internal/util"
)

// ProfileInitEvent is an event that is sent to the reconciler topic
// when a new profile is created. It is used to initialize the profile
// by iterating over all registered entities for the relevant project
// and sending a profile evaluation event for each one.
type ProfileInitEvent struct {
	// Project is the project that the event is relevant to
	Project uuid.UUID `json:"project"`
}

// NewProfileInitMessage creates a new repos init event
func NewProfileInitMessage(projectID uuid.UUID) (*message.Message, error) {
	evt := &ProfileInitEvent{
		Project: projectID,
	}

	evtStr, err := json.Marshal(evt)
	if err != nil {
		return nil, fmt.Errorf("error marshalling init event: %w", err)
	}

	msg := message.NewMessage(uuid.New().String(), evtStr)
	return msg, nil
}

// handleProfileInitEvent handles a profile init event.
// It is responsible for iterating over all registered repositories
// for the project and sending a profile evaluation event for each one.
func (r *Reconciler) handleProfileInitEvent(msg *message.Message) error {
	ctx := msg.Context()

	var evt ProfileInitEvent
	if err := json.Unmarshal(msg.Payload, &evt); err != nil {
		return fmt.Errorf("error unmarshalling payload: %w", err)
	}

	// validate event
	validate := validator.New()
	if err := validate.Struct(evt); err != nil {
		// We don't return the event since there's no use
		// retrying it if it's invalid.
		zerolog.Ctx(ctx).Error().Err(err).Msg("error validating event")
		log.Printf("error validating event: %v", err)
		return nil
	}

	ectx := &engine.EntityContext{
		Project: engine.Project{
			ID: evt.Project,
		},
	}

	zerolog.Ctx(ctx).Debug().Msg("handling profile init event")
	if err := r.publishProfileInitEvents(ctx, ectx); err != nil {
		// We don't return an error since watermill will retry
		// the message.
		zerolog.Ctx(ctx).Error().Msg("error publishing profile events")
		return nil
	}

	return nil
}

func (r *Reconciler) publishProfileInitEvents(
	ctx context.Context,
	ectx *engine.EntityContext,
) error {
	dbrepos, err := r.store.ListRegisteredRepositoriesByProjectIDAndProvider(ctx,
		db.ListRegisteredRepositoriesByProjectIDAndProviderParams{
			Provider: sql.NullString{
				String: ectx.Provider.Name,
				Valid:  ectx.Provider.Name != "",
			},
			ProjectID: ectx.Project.ID,
		})
	if err != nil {
		return fmt.Errorf("publishProfileInitEvents: error getting registered repos: %v", err)
	}

	for _, dbrepo := range dbrepos {
		// protobufs are our API, so we always execute on these instead of the DB directly.
		repo := util.PBRepositoryFromDB(dbrepo)
		err := entities.NewEntityInfoWrapper().
			WithProvider(dbrepo.Provider).
			WithProjectID(ectx.Project.ID).
			WithRepository(repo).
			WithRepositoryID(dbrepo.ID).
			Publish(r.evt)

		// This is a non-fatal error, so we'll just log it
		// and continue
		if err != nil {
			return fmt.Errorf("error publishing init event for repo %s: %v", dbrepo.ID, err)
		}
	}

	// after we've initialized repository profiles, let's initialize artifacts
	// TODO(jakub): this should be done in an iterator of sorts
	for i := range dbrepos {
		pdb := &dbrepos[i]
		err := r.publishArtifactProfileInitEvents(ctx, ectx, pdb)
		if err != nil {
			return fmt.Errorf("publishProfileInitEvents: error publishing artifact events: %v", err)
		}
	}

	return nil
}

func (r *Reconciler) publishArtifactProfileInitEvents(
	ctx context.Context,
	ectx *engine.EntityContext,
	dbrepo *db.Repository,
) error {
	dbArtifacts, err := r.store.ListArtifactsByRepoID(ctx, uuid.NullUUID{
		UUID:  dbrepo.ID,
		Valid: true,
	})
	if err != nil {
		return fmt.Errorf("error getting artifacts: %w", err)
	}
	if len(dbArtifacts) == 0 {
		zerolog.Ctx(ctx).Debug().Str("repository", dbrepo.ID.String()).Msgf("no artifacts found, skipping")
		return nil
	}
	for _, dbA := range dbArtifacts {
		// Get the artifact with all its versions as a protobuf
		pbArtifact, err := util.GetArtifact(ctx, r.store, dbrepo.ProjectID, dbA.ID)
		if err != nil {
			return fmt.Errorf("error getting artifact versions: %w", err)
		}

		err = entities.NewEntityInfoWrapper().
			WithProvider(dbrepo.Provider).
			WithProjectID(ectx.Project.ID).
			WithArtifact(pbArtifact).
			WithRepositoryID(dbrepo.ID).
			WithArtifactID(dbA.ID).
			Publish(r.evt)

		// This is a non-fatal error, so we'll just log it
		// and continue
		if err != nil {
			log.Printf("error publishing init event for repo %s: %v", dbrepo.ID, err)
			continue
		}
	}
	return nil
}