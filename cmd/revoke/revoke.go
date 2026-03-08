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
package revoke

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/dcjulian29/go-toolbox/execute"
	"github.com/dcjulian29/go-toolbox/filesystem"
	"github.com/spf13/cobra"
)

var revokeReason shared.RevokeType = shared.Unspecified

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke subordinate authority.",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := shared.IsCertificateAuthority(); err != nil {
				return err
			}

			return shared.IsRootCertificateAuthority()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			settings, err := shared.GetSettings()
			if err != nil {
				return err
			}

			for _, s := range settings.Subordinates {
				if s.Name == name {
					if s.Id == "~REVOKED~" {
						return fmt.Errorf("'%s' authority has already been revoked", s.Name)
					}

					pass, err := shared.AskPrivateKeyPassword()
					if err != nil {
						return err
					}

					cert := filepath.Join("certs", fmt.Sprintf("%s.pem", s.Id))
					if filesystem.FileExists(cert) {
						if err := execute.ExternalProgram("openssl", []string{
							"ca",
							"-config ca.cnf",
							fmt.Sprintf("-revoke %s", cert),
							fmt.Sprintf("-crl_reason %s", revokeReason),
							fmt.Sprintf("-passin pass:%s", pass),
						}...); err != nil {
							return nil
						}

						if err := os.Rename(cert, fmt.Sprintf("%s.revoked", cert)); err != nil {
							return nil
						}
					} else {
						return fmt.Errorf("'%s' certificate file not found", s.Id)
					}

					s.Id = "~REVOKED~"

					shared.SaveSettings(&settings)

					return nil
				}
			}

			return fmt.Errorf("'%s' is not a subordinate of this authority", name)
		},
	}

	cmd.Flags().VarP(&revokeReason, "reason", "r", "reason for revocation")
	cmd.Flags().StringP("name", "n", "", "name of subordinate authority")

	cmd.MarkFlagRequired("name")

	return cmd
}
