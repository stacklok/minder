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

package telemetry

import (
	"net/http"

	"github.com/mindersec/minder/internal/db"
)

type noop struct{}

var _ ProviderMetrics = (*noop)(nil)

// NewNoopMetrics returns a new noop httpClientMetrics provider
func NewNoopMetrics() *noop {
	return &noop{}
}

func (_ *noop) NewDurationRoundTripper(wrapped http.RoundTripper, _ db.ProviderType) (http.RoundTripper, error) {
	return wrapped, nil
}
