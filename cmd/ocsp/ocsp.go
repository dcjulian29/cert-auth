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
package ocsp

import (
	"errors"

	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/spf13/cobra"
)

var revokeReason shared.RevokeType = shared.Unspecified

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ocsp",
		Short: "Manage OCSP within this authority.",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return shared.IsRootCertificateAuthority()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
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
			} else {
				return errors.New("OCSP is not enabled in this certificate authority")
			}
		},
	}

	cmd.Flags().Bool("replace", false, "replace the OCSP certificate with a new one")
	cmd.Flags().VarP(&revokeReason, "reason", "r", "reason for replacement")

	cmd.AddCommand(serverCmd())

	return cmd
}
