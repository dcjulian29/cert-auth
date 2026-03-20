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
	"fmt"
	"path/filepath"

	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/spf13/cobra"
)

// certificateRevokeReason is the package-level revocation reason used by the
// revoke command, defaulting to Unspecified.
var certificateRevokeReason shared.RevokeType = shared.Unspecified

// revokeCmd returns a cobra.Command that revokes an issued certificate by its
// serial number. The serial number must be provided as a positional argument.
// The certificate file is resolved as "certs/<serial>.pem" and revoked via
// RevokeCertificate using the specified revocation reason. Returns an error if
// the current directory is not a certificate authority, no serial number is
// provided, or the revocation fails.
//
// Flags:
//
//	-r, --reason    reason for revocation (default: unspecified)
func revokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke <serial>",
		Short: "Revoke a issued certificate",
		PreRunE: func(_ *cobra.Command, args []string) error {
			if err := shared.IsCertificateAuthority(); err != nil {
				return err
			}

			if len(args) == 0 {
				return errors.New("serial number of certificate was not provided")
			}

			return nil
		},
		RunE: func(_ *cobra.Command, args []string) error {
			filePath := filepath.Join("certs", fmt.Sprintf("%s.pem", args[0]))

			return shared.RevokeCertificate(filePath, certificateRevokeReason)
		},
	}

	cmd.Flags().VarP(&certificateRevokeReason, "reason", "r", "reason for revocation")

	return cmd
}
