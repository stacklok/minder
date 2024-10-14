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

// Package offline_token provides the auth offline_token command for the minder CLI.
package offline_token

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/mindersec/minder/internal/config"
	clientconfig "github.com/mindersec/minder/internal/config/client"
	"github.com/mindersec/minder/internal/util"
	"github.com/mindersec/minder/internal/util/cli"
)

// offlineTokenUseCmd represents the offline-token use command
var offlineTokenUseCmd = &cobra.Command{
	Use:   "use",
	Short: "Use an offline token",
	Long: `The minder auth offline-token use command project lets you install and use an offline token
for the minder control plane.

Offline tokens are used to authenticate to the minder control plane without
requiring the user's presence. This is useful for long-running processes
that need to authenticate to the control plane.`,
	RunE: cli.GRPCClientWrapRunE(offlineUseCommand),
}

// offlineUseCommand is the offline-token use subcommand
func offlineUseCommand(_ context.Context, cmd *cobra.Command, _ []string, _ *grpc.ClientConn) error {
	clientConfig, err := config.ReadConfigFromViper[clientconfig.Config](viper.GetViper())
	if err != nil {
		return fmt.Errorf("error reading config: %w", err)
	}

	f := viper.GetString("file")
	tok := viper.GetString("token")
	if tok == "" {
		fpath := filepath.Clean(f)
		tokbytes, err := os.ReadFile(fpath)
		if err != nil {
			return fmt.Errorf("error reading file: %w", err)
		}

		tok = string(tokbytes)
	}

	// No longer print usage on returned error, since we've parsed our inputs
	// See https://github.com/spf13/cobra/issues/340#issuecomment-374617413
	cmd.SilenceUsage = true

	issuerUrlStr := clientConfig.Identity.CLI.IssuerUrl
	clientID := clientConfig.Identity.CLI.ClientId

	creds, err := util.RefreshCredentials(tok, issuerUrlStr, clientID)
	if err != nil {
		return fmt.Errorf("couldn't fetch credentials: %v", err)
	}

	// save credentials
	filePath, err := util.SaveCredentials(util.OpenIdCredentials{
		AccessToken:          creds.AccessToken,
		RefreshToken:         creds.RefreshToken,
		AccessTokenExpiresAt: creds.AccessTokenExpiresAt,
	})
	if err != nil {
		cmd.PrintErrf("couldn't save credentials: %s\n", err)
	}

	cmd.Printf("Your access credentials have been saved to %s\n", filePath)

	return nil
}

func init() {
	offlineTokenCmd.AddCommand(offlineTokenUseCmd)

	offlineTokenUseCmd.Flags().StringP("file", "f", "offline.token", "The file that contains the offline token")
	offlineTokenUseCmd.Flags().StringP("token", "t", "",
		"The offline token to use. Also settable through the MINDER_OFFLINE_TOKEN environment variable.")

	offlineTokenUseCmd.MarkFlagsMutuallyExclusive("file", "token")

	if err := viper.BindPFlag("file", offlineTokenUseCmd.Flag("file")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("token", offlineTokenUseCmd.Flag("token")); err != nil {
		panic(err)
	}

	if err := viper.BindEnv("token", "MINDER_OFFLINE_TOKEN"); err != nil {
		panic(err)
	}
}
