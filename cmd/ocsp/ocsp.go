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

// Package ocsp provides CLI commands for managing the OCSP responder and OCSP
// certificate within a certificate authority.
package ocsp

import (
	"errors"

	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/spf13/cobra"
)

// revokeReason is the package-level revocation reason used when replacing the
// OCSP certificate, defaulting to Unspecified.
var revokeReason shared.RevokeType = shared.Unspecified

// NewCommand returns a cobra.Command that manages the OCSP certificate and
// responder for the current root certificate authority. The command verifies
// that the current directory is a root certificate authority before running.
// If OCSP is enabled in the authority settings, it displays the current OCSP
// certificate via ShowCertificate. If the --replace flag is provided, the
// existing OCSP certificate is replaced with a new one via ReplaceOCSP using
// the specified revocation reason before displaying it. The server subcommand
// is registered for managing the OCSP responder process. Returns an error if
// the settings cannot be loaded or OCSP is not enabled.
//
// Flags:
//
//	    --replace    replace the OCSP certificate with a new one
//	-r, --reason     reason for replacement (default: unspecified)
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ocsp",
		Short: "Manage OCSP within this authority.",
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return shared.IsRootCertificateAuthority()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			settings, err := shared.GetSettings()
			if err != nil {
				return err
			}

			if settings.OCSP {
				if r, _ := cmd.Flags().GetBool("replace"); r {
					if err := shared.ReplaceOCSP(revokeReason); err != nil {
						return err
					}
				}

				return shared.ShowCertificate("ocsp", false)
			}

			return errors.New("OCSP is not enabled in this certificate authority")
		},
	}

	cmd.Flags().Bool("replace", false, "replace the OCSP certificate with a new one")
	cmd.Flags().VarP(&revokeReason, "reason", "r", "reason for replacement")

	cmd.AddCommand(serverCmd())

	return cmd
}
