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

var timestampCmd = &cobra.Command{
	Use:   "timestamp",
	Short: "Manage Timestamp certificate within this authority.",
	Long:  "Manage Timestamp certificate within this authority.",
	Run: func(cmd *cobra.Command, args []string) {
		if settings.TimeStamp {
			if u, _ := cmd.Flags().GetBool("update"); u {
				timestamp_update("")
			}

			if r, _ := cmd.Flags().GetBool("reset"); r {
				timestamp_reset()
				timestamp_update("")
			}

			// TODO: Show timestamp certificate info
		}
	},
}

func init() {
	rootCmd.AddCommand(timestampCmd)

	timestampCmd.Flags().BoolP("update", "u", false, "update the Timestamp certificate")
	timestampCmd.Flags().BoolP("reset", "r", false, "reset the Timestamp certificate")

	timestampCmd.MarkFlagsMutuallyExclusive("update", "reset")
}

func timestamp_reset() {
	info("Generating the timestamp private key for this authority...")

	executeExternalProgram("openssl", []string{
		"genrsa",
		"-out private/timestamp.key",
		"-verbose",
		"2048",
	}...)
}

func timestamp_update(password string) {
	if len(password) == 0 {
		password = askPassword("private/ca.key")
	}

	// TODO: revoke existing Timestamp certificates

	info("Generating the timestamp certificate for this authority...")

	executeExternalProgram("openssl", []string{
		"ca",
		"-batch",
		"-config ca.cnf",
		"-out certs/timestamp.pem",
		"-extensions timestamp_ext",
		"-days 90",
		fmt.Sprintf("-passin pass:%s", password),
		"-infiles csr/timestamp.csr",
	}...)
}
