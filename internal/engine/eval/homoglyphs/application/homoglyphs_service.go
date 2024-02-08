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

package application

import (
	"fmt"

	"github.com/stacklok/minder/internal/engine/interfaces"
	"github.com/stacklok/minder/internal/providers"
	pb "github.com/stacklok/minder/pkg/api/protobuf/go/minder/v1"
)

const (
	HomoglyphsEvalType = "homoglyphs"

	invisibleCharacters = "invisible_characters"
	mixedScript         = "mixed_scripts"
)

func NewHomoglyphsEvaluator(reh *pb.RuleType_Definition_Eval_Homoglyphs, pbuild *providers.ProviderBuilder) (interfaces.Evaluator, error) {
	if pbuild == nil {
		return nil, fmt.Errorf("provider builder is nil")
	}
	if reh == nil {
		return nil, fmt.Errorf("homoglyphs configuration is nil")
	}

	switch reh.Type {
	case invisibleCharacters:
		return NewInvisibleCharactersEvaluator(pbuild)
	case mixedScript:
		return NewMixedScriptEvaluator(pbuild)
	default:
		return nil, fmt.Errorf("unsupported homoglyphs type: %s", reh.Type)
	}
}
