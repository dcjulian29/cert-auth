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

var ocspCmd = &cobra.Command{
	Use:   "ocsp",
	Short: "Manage OCSP within this authority.",
	Long:  "Manage OCSP within this authority.",
	PreRun: func(cmd *cobra.Command, args []string) {
		if len(settings.Name) == 0 {
			cobra.CheckErr(fmt.Errorf("'%s' is not a certificate authority", folderPath))
		}
	},
	PostRun: func(cmd *cobra.Command, args []string) {
		ensureWorkingDirectoryAndExit()
	},
	Run: func(cmd *cobra.Command, args []string) {
		if settings.OCSP {
			if u, _ := cmd.Flags().GetBool("update"); u {
				ocsp_update("")
			}

			if r, _ := cmd.Flags().GetBool("reset"); r {
				ocsp_reset()
				ocsp_update("")
			}

			// TODO: Show OCSP certificate info
		}
	},
}

func init() {
	rootCmd.AddCommand(ocspCmd)

	ocspCmd.Flags().BoolP("update", "u", false, "update the OCSP certificate")
	ocspCmd.Flags().BoolP("reset", "r", false, "reset the OCSP certificate")

	ocspCmd.MarkFlagsMutuallyExclusive("update", "reset")
}

func ocsp_reset() {
	info("Generating the OCSP private key for this authority...")

	executeExternalProgram("openssl", []string{
		"genrsa",
		"-out private/ocsp.key",
		"-verbose",
		"2048",
	}...)
}

func ocsp_update(password string) {
	if len(password) == 0 {
		password = askPassword("private/ca.key")
	}

	// TODO: revoke existing OCSP certificates

	info("Generating the OCSP certificate for this authority...")

	executeExternalProgram("openssl", []string{
		"ca",
		"-batch",
		"-config ca.cnf",
		"-out certs/ocsp.pem",
		"-extensions ocsp_ext",
		"-days 90",
		fmt.Sprintf("-passin pass:%s", password),
		"-infiles csr/ocsp.csr",
	}...)
}
