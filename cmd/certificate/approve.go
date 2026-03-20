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

package certificate

import (
	"errors"

	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/spf13/cobra"
)

// approveCmd returns a cobra.Command that approves an imported certificate
// request by its ID, provided as a positional argument. The command verifies
// that the current directory is a certificate authority before running. The
// --server flag approves the request as a server certificate and --client
// approves it as a client certificate; these flags are mutually exclusive. If
// neither flag is provided, the help text is displayed. Returns an error if
// the authority check fails, the request ID is missing, or the approval fails.
//
// Flags:
//
//	--server    approve a server certificate request
//	--client    approve a client certificate request
//	--days      days for the certificate to be valid (default: 365)
func approveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approve",
		Short: "Approve a certificate request",
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return shared.IsCertificateAuthority()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			days, _ := cmd.Flags().GetInt("days")

			if f, _ := cmd.Flags().GetBool("server"); f {
				if len(args) > 0 {
					return shared.ApproveCertificate(args[0], shared.CertificateTypeServer, days)
				}

				return errors.New("ID of the imported request missing")
			}

			if f, _ := cmd.Flags().GetBool("client"); f {
				if len(args) > 0 {
					return shared.ApproveCertificate(args[0], shared.CertificateTypeClient, days)
				}

				return errors.New("ID of the imported request missing")
			}

			return cmd.Help()
		},
	}

	cmd.Flags().Bool("client", false, "Approve a client certificate request")
	cmd.Flags().Bool("server", false, "Approve a server certificate request")
	cmd.Flags().Int("days", 365, "days for the certificate to be valid")

	cmd.MarkFlagsMutuallyExclusive("client", "server")

	return cmd
}
