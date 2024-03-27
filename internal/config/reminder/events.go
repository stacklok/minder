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

package reminder

import (
	"fmt"

	"github.com/stacklok/minder/internal/config"
)

// EventConfig is the configuration for reminder's eventing system.
type EventConfig struct {
	// Connection is the configuration for the SQL event driver
	Connection config.DatabaseConfig `mapstructure:"sql_connection" default:"{}"`
}

// Validate checks that the event config is valid.
func (e EventConfig) Validate() error {
	if e == (EventConfig{}) {
		return fmt.Errorf("event config is empty, required for sending events to minder server")
	}
	return nil
}
