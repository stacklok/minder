// Copyright 2023 Stacklok, Inc.
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

// Package git provides the git rule data ingest engine
package git

// IngesterConfig is the profile-provided configuration for the git ingester
// This allows for users to pass in configuration to the ingester
// in different calls as opposed to having to set it in the rule type.
type IngesterConfig struct {
	Branch   string `json:"branch" yaml:"branch" mapstructure:"branch"`
	CloneURL string `json:"clone_url" yaml:"clone_url" mapstructure:"clone_url"`
}
