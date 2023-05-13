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

package main

import (
	"github.com/stacklok/mediator/cmd/cli/app"

	// Add each subcommand here
	_ "github.com/stacklok/mediator/cmd/cli/app/auth"
	_ "github.com/stacklok/mediator/cmd/cli/app/create"
	_ "github.com/stacklok/mediator/cmd/cli/app/delete"
	_ "github.com/stacklok/mediator/cmd/cli/app/list"
)

func main() {
	app.Execute()
}
