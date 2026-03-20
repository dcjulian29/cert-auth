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

// Package certificate provides CLI commands for managing certificates within
// a certificate authority, including issuance, requests, revocation, and
// validation.
package certificate

import (
	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/spf13/cobra"
)

// certificateKeyType is the cryptographic algorithm used when generating a new
// certificate's private key.
var certificateKeyType shared.KeyType

// NewCommand returns a cobra.Command that manages certificates within the
// current certificate authority. The command accepts an optional certificate ID
// argument and verifies that the current directory is a certificate authority
// before running. With no flag, the help text is displayed. The --issued flag
// displays issued certificates, --requests displays pending certificate
// requests, and --revoked displays revoked certificates; these three flags are
// mutually exclusive. The following subcommands are registered:
//
//   - approve    approve a pending certificate request
//   - new        create a new certificate
//   - request    create a new certificate request
//   - revoke     revoke an issued certificate
//   - validate   validate a certificate
//
// Flags:
//
//	--issued      show issued certificate(s)
//	--requests    show certificate request(s)
//	--revoked     show revoked certificate(s)
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "certificate [id]",
		Aliases: []string{"cert"},
		Short:   "Manage certificates within this authority",
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return shared.IsCertificateAuthority()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			id := ""

			if len(args) > 0 {
				id = args[0]
			}

			if f, _ := cmd.Flags().GetBool("issued"); f {
				return shared.ShowCertificate(id, false)
			}

			if f, _ := cmd.Flags().GetBool("requests"); f {
				return shared.ShowRequest(id)
			}

			if f, _ := cmd.Flags().GetBool("revoked"); f {
				return shared.ShowCertificate(id, true)
			}

			return cmd.Help()
		},
	}

	cmd.AddCommand(approveCmd())
	cmd.AddCommand(newCmd())
	cmd.AddCommand(requestCmd())
	cmd.AddCommand(revokeCmd())
	cmd.AddCommand(validateCmd())

	cmd.Flags().Bool("issued", false, "Show issued certificate(s)")
	cmd.Flags().Bool("requests", false, "Show certificate request(s)")
	cmd.Flags().Bool("revoked", false, "Show revoked certificate(s)")

	cmd.MarkFlagsMutuallyExclusive("issued", "requests", "revoked")

	return cmd
}
