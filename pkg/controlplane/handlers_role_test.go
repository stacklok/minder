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
	"testing"
	"time"

	pb "github.com/stacklok/mediator/pkg/generated/protobuf/go/mediator/v1"
	"github.com/stacklok/mediator/pkg/util"
)

func TestRoleCreate(t *testing.T) {
	seed := time.Now().UnixNano()
	server := CreateTestServer()
	if server == nil {
		t.Fatalf("Failed to create server")
	}

	// create organization and group first
	org, err := server.CreateOrganisation(context.Background(), &pb.CreateOrganisationRequest{
		Name:    util.RandomString(10, seed),
		Company: util.RandomString(10, seed),
	})

	if err != nil {
		t.Fatalf("Failed to create organisation: %v", err)
	}

	group, err := server.CreateGroup(context.Background(), &pb.CreateGroupRequest{
		OrganisationId: org.GetId(),
		Name:           util.RandomString(10, seed),
	})

	role, err := server.CreateRole(context.Background(), &pb.CreateRoleRequest{
		OrganisationId: org.Id,
		GroupId:        group.GetGroupId(),
		Name:           util.RandomString(10, seed),
	})

	if err != nil {
		t.Fatalf("Failed to create role: %v", err)
	}

	t.Logf("Created role: %v", role)
}
