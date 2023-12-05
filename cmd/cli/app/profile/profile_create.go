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

package profile

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/stacklok/minder/internal/util"
	pb "github.com/stacklok/minder/pkg/api/protobuf/go/minder/v1"
)

// Profile_createCmd represents the profile create command
var Profile_createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a profile within a minder control plane",
	Long: `The minder profile create subcommand lets you create new profiles for a project
within a minder control plane.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			fmt.Fprintf(os.Stderr, "Error binding flags: %s\n", err)
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		f := util.GetConfigValue(viper.GetViper(), "file", "file", cmd, "").(string)
		proj := viper.GetString("project")

		conn, err := util.GrpcForCommand(cmd, viper.GetViper())
		util.ExitNicelyOnError(err, "Error getting grpc connection")
		defer conn.Close()

		client := pb.NewProfileServiceClient(conn)
		ctx, cancel := util.GetAppContext()
		defer cancel()

		table := InitializeTable(cmd)

		createFunc := func(f string, p *pb.Profile) (*pb.Profile, error) {
			// create a profile
			resp, err := client.CreateProfile(ctx, &pb.CreateProfileRequest{
				Profile: p,
			})
			if err != nil {
				return nil, err
			}

			return resp.GetProfile(), nil
		}

		if err := execOnOneProfile(table, f, cmd.InOrStdin(), proj, createFunc); err != nil {
			return err
		}

		table.Render()
		return nil
	},
}

func init() {
	ProfileCmd.AddCommand(Profile_createCmd)
	Profile_createCmd.Flags().StringP("file", "f", "", "Path to the YAML defining the profile (or - for stdin)")
	if err := Profile_createCmd.MarkFlagRequired("file"); err != nil {
		fmt.Fprintf(os.Stderr, "Error marking flag required: %s\n", err)
		os.Exit(1)
	}
	Profile_createCmd.Flags().StringP("project", "p", "", "Project to create the profile in")
}
