//
// Copyright 2023 Stacklok, Inc.
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

// Package mock provides a no-op implementation of the minder the authorization client
package mock

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/stacklok/minder/internal/authz"
)

// NoopClient is a no-op implementation of the authz.Client interface, which always returns
// the same authorization result.
type NoopClient struct {
	// If Authorized is true, all Check calls will return nil
	Authorized bool
}

var _ authz.Client = &NoopClient{}

// Check implements authz.Client
func (n *NoopClient) Check(_ context.Context, action string, project uuid.UUID) error {
	fmt.Printf("noop authz check (%t): %s %s\n", n.Authorized, action, project)
	if n.Authorized {
		return nil
	}
	return authz.ErrNotAuthorized
}

// Write_ implements authz.Client
func (_ *NoopClient) Write(_ context.Context, _ string, _ authz.Role, _ uuid.UUID) error {
	return nil
}

// Delete implements authz.Client
func (_ *NoopClient) Delete(_ context.Context, _ string, _ authz.Role, _ uuid.UUID) error {
	return nil
}
