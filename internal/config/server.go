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

package config

import (
	"fmt"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// HTTPServerConfig is the configuration for the HTTP server
type HTTPServerConfig struct {
	// Host is the host to bind to
	Host string `mapstructure:"host" default:"127.0.0.1"`
	// Port is the port to bind to
	Port int `mapstructure:"port" default:"8080"`
}

// GetAddress returns the address to bind to
func (s *HTTPServerConfig) GetAddress() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// MetricServerConfig is the configuration for the metric server
type MetricServerConfig struct {
	// Host is the host to bind to
	Host string `mapstructure:"host" default:"127.0.0.1"`
	// Port is the port to bind to
	Port int `mapstructure:"port" default:"9090"`
}

// GetAddress returns the address to bind to
func (s *MetricServerConfig) GetAddress() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// GRPCServerConfig is the configuration for the gRPC server
type GRPCServerConfig struct {
	// Host is the host to bind to
	Host string `mapstructure:"host" default:"127.0.0.1"`
	// Port is the port to bind to
	Port int `mapstructure:"port" default:"8090"`
}

// GetAddress returns the address to bind to
func (s *GRPCServerConfig) GetAddress() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// RegisterServerFlags registers the flags for the Minder server
func RegisterServerFlags(v *viper.Viper, flags *pflag.FlagSet) error {
	// Register the flags for the HTTP server
	if err := registerHTTPServerFlags(v, flags); err != nil {
		return err
	}

	// Register the flags for the gRPC server
	if err := registerGRPCServerFlags(v, flags); err != nil {
		return err
	}

	// Register the flags for the metric server
	return registerMetricServerFlags(v, flags)
}

// registerHTTPServerFlags registers the flags for the HTTP server
func registerHTTPServerFlags(v *viper.Viper, flags *pflag.FlagSet) error {
	err := BindConfigFlag(v, flags, "http_server.host", "http-host", "",
		"The host to bind to for the HTTP server", flags.String)
	if err != nil {
		return err
	}

	return BindConfigFlag(v, flags, "http_server.port", "http-port", 8080,
		"The port to bind to for the HTTP server", flags.Int)
}

// registerGRPCServerFlags registers the flags for the gRPC server
func registerGRPCServerFlags(v *viper.Viper, flags *pflag.FlagSet) error {
	err := BindConfigFlag(v, flags, "grpc_server.host", "grpc-host", "",
		"The host to bind to for the gRPC server", flags.String)
	if err != nil {
		return err
	}

	return BindConfigFlag(v, flags, "grpc_server.port", "grpc-port", 8090,
		"The port to bind to for the gRPC server", flags.Int)
}

// registerMetricServerFlags registers the flags for the metric server
func registerMetricServerFlags(v *viper.Viper, flags *pflag.FlagSet) error {
	err := BindConfigFlag(v, flags, "metric_server.host", "metric-host", "",
		"The host to bind to for the metric server", flags.String)
	if err != nil {
		return err
	}

	return BindConfigFlag(v, flags, "metric_server.port", "metric-port", 9090,
		"The port to bind to for the metric server", flags.Int)
}
