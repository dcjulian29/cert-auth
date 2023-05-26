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
	"path"

	"github.com/spf13/cobra"
)

var revokeReason RevokeType = unspecified

var revokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke a certificate or subordinate authority.",
	Long:  "Revoke a certificate or subordinate authority.",
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
					cobra.CheckErr(fmt.Errorf("'%s' authority has already been revoked", s.Name))
				}

				pass := askPassword("private/ca.key")
				revoke_authority(s, revokeReason, pass)

				settings.Subordinates = addSubordinate(settings, s.Name, "~REVOKED~")

				save_authority("ca.yml", settings)

				return
			}
		}

		cobra.CheckErr(fmt.Errorf("'%s' is not a subordinate of this authority", name))
	},
}

func init() {
	rootCmd.AddCommand(revokeCmd)

	revokeCmd.Flags().VarP(&revokeReason, "reason", "r", "reason for revocation")
	revokeCmd.Flags().StringP("name", "n", "", "name of subordinate authority")

	revokeCmd.MarkFlagRequired("name")
}

func revoke_authority(subordinate Subordinate, reason RevokeType, pass string) {
	if len(subordinate.Id) > 0 {
		cert := path.Join("certs", fmt.Sprintf("%s.pem", subordinate.Id))
		if fileExists(cert) {
			executeExternalProgram("openssl", []string{
				"ca",
				"-config ca.cnf",
				fmt.Sprintf("-revoke %s", cert),
				fmt.Sprintf("-crl_reason %s", reason),
				fmt.Sprintf("-passin pass:%s", pass),
			}...)

			os.Rename(cert, fmt.Sprintf("%s.revoked", cert))
		} else {
			cobra.CheckErr(fmt.Errorf("'%s' certificate file not found", subordinate.Id))
		}
	}
}
