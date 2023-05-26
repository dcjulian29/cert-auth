/*
Copyright © 2023 Julian Easterling <julian@julianscorner.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var removeCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove subordinate authority files.",
	Long:  "Remove subordinate authority files.",
	PreRun: func(cmd *cobra.Command, args []string) {
		if len(settings.Name) == 0 {
			cobra.CheckErr(fmt.Errorf("'%s' is not a certificate authority", folderPath))
		}

		if settings.Type != "root" {
			cobra.CheckErr(fmt.Errorf("'%s' is not a root certificate authority", folderPath))
		}

		ensureAuthorityDirectory()
	},
	PostRun: func(cmd *cobra.Command, args []string) {
		ensureWorkingDirectoryAndExit()
	},
	Run: func(cmd *cobra.Command, args []string) {
		name, _ := cmd.Flags().GetString("name")

		for _, s := range settings.Subordinates {
			if s.Name == name {
				if s.Id == "~REVOKED~" {
					remove_authority(s.Name)

					return
				}

				cobra.CheckErr(fmt.Errorf("'%s' authority has not been revoked", s.Name))

				return
			}
		}

		cobra.CheckErr(fmt.Errorf("'%s' is not a subordinate of this authority", name))
	},
}

func init() {
	rootCmd.AddCommand(removeCmd)

	removeCmd.Flags().StringP("name", "n", "", "name of subordinate authority")

	removeCmd.MarkFlagRequired("name")
}

func remove_authority(name string) {
	if !dirExists(name) {
		cobra.CheckErr(fmt.Errorf("'%s' authority has already been removed", name))
	}

	os.RemoveAll(name)
}
