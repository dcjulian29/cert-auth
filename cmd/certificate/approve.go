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

func approveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approve",
		Short: "Approve a certificate request",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return shared.IsCertificateAuthority()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			days, _ := cmd.Flags().GetInt("days")

			if f, _ := cmd.Flags().GetBool("server"); f {
				if len(args) > 0 {
					return shared.ApproveCertificate(args[0], shared.CertificateTypeServer, days)
				} else {
					return errors.New("ID of the imported request missing")
				}
			}

			if f, _ := cmd.Flags().GetBool("client"); f {
				if len(args) > 0 {
					return shared.ApproveCertificate(args[0], shared.CertificateTypeClient, days)
				} else {
					return errors.New("ID of the imported request missing")
				}
			}

			return cmd.Help()
		},
	}

	cmd.Flags().String("client", "", "Approve a client certificate request")
	cmd.Flags().String("server", "", "Approve a server certificate request")
	cmd.Flags().Int("days", 365, "days for the certificate to be valid")

	cmd.MarkFlagsMutuallyExclusive("client", "server")

	return cmd
}
