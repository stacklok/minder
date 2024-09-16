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

// Package main provides the entrypoint for the minder server
package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"

	"github.com/stacklok/minder/cmd/server/app"
)

func main() {
	f, err := os.Create("output.prof")
	if err != nil {
		fmt.Println(err)
		return
	}
	runtime.SetCPUProfileRate(1000)
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()

	app.Execute()
}
