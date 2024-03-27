// Copyright 2024 Stacklok, Inc
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

// Package reminder contains configuration options for the reminder service.
package reminder

import (
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/stacklok/minder/internal/config"
)

// Config contains the configuration for the reminder service
type Config struct {
	Database         config.DatabaseConfig `mapstructure:"database"`
	RecurrenceConfig RecurrenceConfig      `mapstructure:"recurrence"`
	EventConfig      EventConfig           `mapstructure:"events"`
	CursorFile       string                `mapstructure:"cursor_file" default:"/tmp/reminder_cursor"`
	LoggingLevel     string                `mapstructure:"logging_level" default:"info"`
}

// ValidateConfig validates the configuration
func ValidateConfig(cfgFileData interface{}) error {
	cfg := &Config{}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeDurationHookFunc(),
		Result:     cfg,
	})
	if err != nil {
		return err
	}

	err = decoder.Decode(cfgFileData)
	if err != nil {
		return err
	}

	err = cfg.RecurrenceConfig.Validate()
	if err != nil {
		return err
	}

	err = cfg.EventConfig.Validate()
	if err != nil {
		return err
	}

	return nil
}

// SetViperDefaults sets the default values for the configuration to be picked up by viper
func SetViperDefaults(v *viper.Viper) {
	v.SetEnvPrefix("reminder")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	config.SetViperStructDefaults(v, "", Config{})
}

// RegisterReminderFlags registers the flags for the minder cli
func RegisterReminderFlags(v *viper.Viper, flags *pflag.FlagSet) error {
	viperPath := "cursor_file"
	if err := config.BindConfigFlag(v, flags, viperPath, "cursor-file",
		v.GetString(viperPath), "DB Cursor file path for reminder", flags.String); err != nil {
		return err
	}

	viperPath = "logging_level"
	if err := config.BindConfigFlag(v, flags, viperPath, "logging-level",
		v.GetString(viperPath), "Logging level for reminder", flags.String); err != nil {
		return err
	}

	if err := config.RegisterDatabaseFlags(v, flags); err != nil {
		return err
	}

	return registerRecurrenceFlags(v, flags)
}
