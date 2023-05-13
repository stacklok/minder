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
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var org_createCmd = &cobra.Command{
	Use:   "org",
	Short: "medctl org commands",
	Long: `The medctl org subcommand group lets you create new organizations
within the mediator controlplane.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("create org called")
	},
}

func init() {
	CreateCmd.AddCommand(org_createCmd)
	if err := viper.BindPFlags(org_createCmd.PersistentFlags()); err != nil {
		log.Fatal(err)
	}
}
