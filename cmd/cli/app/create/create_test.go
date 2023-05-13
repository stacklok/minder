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

package create

import (
	"os"
	"testing"

	"github.com/stacklok/mediator/cmd/cli/app"
)

type testWriter struct {
	output string
}

func (tw *testWriter) Write(p []byte) (n int, err error) {
	tw.output += string(p)
	return len(p), nil
}

func setupConfigFile() string {
	configFile := "config.yaml"
	config := []byte(`logging: "info"`)
	err := os.WriteFile(configFile, config, 0o644)
	if err != nil {
		panic(err)
	}
	return configFile
}

func removeConfigFile(filename string) {
	os.Remove(filename)
}

func TestCobraMain(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectedOutput string
	}{
		{
			name:           "create command",
			args:           []string{"create", "--help"},
			expectedOutput: "create called\n",
		},
		{
			name:           "create group command",
			args:           []string{"create", "group", "--help"},
			expectedOutput: "create group called\n",
		},
		{
			name:           "create org command",
			args:           []string{"create", "org", "--help"},
			expectedOutput: "create org called\n",
		},
		{
			name:           "create role command",
			args:           []string{"create", "role", "--help"},
			expectedOutput: "create role called\n",
		},
		{
			name:           "create user command",
			args:           []string{"create", "user", "--help"},
			expectedOutput: "create user called\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configFile := setupConfigFile()
			defer removeConfigFile(configFile)

			os.Setenv("CONFIG_FILE", configFile)

			tw := &testWriter{}
			app.RootCmd.SetOut(tw) // stub to capture eventual output
			app.RootCmd.SetArgs(test.args)

			if err := app.RootCmd.Execute(); err != nil {
				t.Errorf("Error executing command: %v", err)
			}

			// stub to capture eventual output and compare
			// or specfic tests according to the output of the command
			// if got := strings.TrimSpace(tw.output); got != test.expectedOutput {
			// 	t.Errorf("Expected output: %v, got: %v", test.expectedOutput, got)
			// }
		})
	}
}
