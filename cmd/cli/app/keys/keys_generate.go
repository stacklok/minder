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

// NOTE: This file is for stubbing out client code for proof of concept
// purposes. It will / should be removed in the future.
// Until then, it is not covered by unit tests and should not be used
// It does make a good example of how to use the generated client code
// for others to use as a reference.

package keys

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	pb "github.com/stacklok/mediator/pkg/generated/protobuf/go/mediator/v1"
	"github.com/stacklok/mediator/pkg/util"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var genKeys_listCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate keys within a mediator control plane",
	Long: `The medic keys generate  subcommand lets you create keys within a
mediator control plane for an specific group.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			fmt.Fprintf(os.Stderr, "Error binding flags: %s\n", err)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {
		pass, err := util.GetPassFromTerm(true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting password: %s\n", err)
			os.Exit(1)
		}
		fmt.Println()

		grpc_host := util.GetConfigValue("grpc_server.host", "grpc-host", cmd, "").(string)
		grpc_port := util.GetConfigValue("grpc_server.port", "grpc-port", cmd, 0).(int)
		group_id := util.GetConfigValue("group-id", "group-id", cmd, int32(0))
		out := util.GetConfigValue("output", "output", cmd, "").(string)

		conn, err := util.GetGrpcConnection(grpc_host, grpc_port)
		util.ExitNicelyOnError(err, "Error getting grpc connection")
		defer conn.Close()

		client := pb.NewKeyServiceClient(conn)
		ctx, cancel := util.GetAppContext()
		defer cancel()

		keyResp, err := client.CreateKeyPair(ctx, &pb.CreateKeyPairRequest{
			Passphrase: base64.RawStdEncoding.EncodeToString(pass),
			GroupId:    group_id.(int32),
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error calling create keys: %s\n", err)
			os.Exit(1)
		}

		decodedPublicKey, err := base64.RawStdEncoding.DecodeString(keyResp.PublicKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error decoding public key: %s\n", err)
			os.Exit(1)
		}

		if out != "" {
			err = util.WriteToFile(out, decodedPublicKey, 0644)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error writing public key to file: %s\n", err)
				os.Exit(1)
			}
		}

		// write to tablewriter for output

		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"Status", "Key Indentifier"})
		table.Append([]string{"Success", keyResp.KeyIdentifier})
		table.Render()

	},
}

func init() {
	KeysCmd.AddCommand(genKeys_listCmd)
	genKeys_listCmd.Flags().Int32P("group-id", "g", 0, "group id to list roles for")
	genKeys_listCmd.Flags().StringP("output", "o", "", "Output public key to file")
}
