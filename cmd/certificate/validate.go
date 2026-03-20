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

// validateCmd returns a cobra.Command that validates the signature of a
// certificate file against the current authority's CA chain. The command
// verifies that the current directory is a certificate authority before
// running. The path to the certificate file must be provided as a positional
// argument. If the --bundle flag is provided, Mozilla's root CA bundle is
// downloaded and used as the trust store instead of the local CA chain. Returns
// an error if no file path is provided, the certificate cannot be validated, or
// the CA bundle download fails.
//
// Flags:
//
//	--bundle    use Mozilla CA certificate store to validate
func validateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate <filePath>",
		Short: "Validate the signature of a certificate",
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return shared.IsCertificateAuthority()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("path to certificate file was not provided")
			}

			if f, _ := cmd.Flags().GetBool("bundle"); f {
				if err := shared.ValidateCertificate(args[0], true); err != nil {
					return err
				}
			} else {
				if err := shared.ValidateCertificate(args[0], false); err != nil {
					return err
				}
			}

			return nil
		},
	}

	cmd.Flags().Bool("bundle", false, "use Mozilla CA certificate store to validate")

	return cmd
}
