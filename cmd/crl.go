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

	"github.com/spf13/cobra"
)

var crlCmd = &cobra.Command{
	Use:   "crl",
	Short: "Manage Certificate Revocation List within this authority.",
	Long:  "Manage Certificate Revocation List within this authority.",
	PreRun: func(cmd *cobra.Command, args []string) {
		if len(settings.Name) == 0 {
			cobra.CheckErr(fmt.Errorf("'%s' is not a certificate authority", folderPath))
		}

		ensureAuthorityDirectory()
	},
	PostRun: func(cmd *cobra.Command, args []string) {
		ensureWorkingDirectoryAndExit()
	},
	Run: func(cmd *cobra.Command, args []string) {
		if u, _ := cmd.Flags().GetBool("update"); u {
			crl_update("", settings)
		}

		if fileExists("ca.crl") {
			executeExternalProgram("openssl", []string{
				"crl",
				fmt.Sprintf("-in %s", "ca.crl"),
				"-noout",
				"-text",
			}...)
		}
	},
}

func init() {
	rootCmd.AddCommand(crlCmd)

	crlCmd.Flags().BoolP("update", "u", false, "update the Certificate Revocation List")
}

func crl_update(password string, authority CertAuth) {
	if len(password) == 0 {
		password = askPassword("private/ca.key")
	}

	info("Updating the certificate revocation list...")

	executeExternalProgram("openssl", []string{
		"ca",
		"-config ca.cnf",
		"-gencrl",
		"-out ca.crl",
		fmt.Sprintf("-passin pass:%s", password),
	}...)
}
