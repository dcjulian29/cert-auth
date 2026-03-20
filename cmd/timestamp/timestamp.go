/*
Copyright © 2026 Julian Easterling

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

// Package timestamp provides the CLI command for managing the Timestamp
// Authority (TSA) certificate within a certificate authority.
package timestamp

import (
	"errors"

	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/spf13/cobra"
)

// NewCommand returns a cobra.Command that manages the Timestamp Authority (TSA)
// certificate within the current root certificate authority. The command
// verifies that the current directory is a root certificate authority before
// running. If timestamping is enabled in the authority settings, it displays
// the current timestamp certificate via ShowCertificate. If the --replace flag
// is provided, the existing timestamp certificate is replaced with a new one
// via ReplaceTimestamp before displaying it. Returns an error if the settings
// cannot be loaded or timestamping is not enabled.
//
// Flags:
//
//	--replace    replace the Timestamp certificate with a new one
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "timestamp",
		Short: "Manage Timestamp certificate within this authority.",
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return shared.IsRootCertificateAuthority()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			settings, err := shared.GetSettings()
			if err != nil {
				return err
			}

			if settings.TimeStamp {
				if r, _ := cmd.Flags().GetBool("replace"); r {
					if err := shared.ReplaceTimestamp(); err != nil {
						return err
					}
				}

				return shared.ShowCertificate("timestamp", false)
			}

			return errors.New("timestamping is not enabled in this certificate authority")
		},
	}

	cmd.Flags().Bool("replace", false, "replace the Timestamp certificate with a new one")

	return cmd
}
