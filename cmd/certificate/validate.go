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

func validateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate <filePath>",
		Short: "Validate the signature of a certificate",
		PreRunE: func(cmd *cobra.Command, args []string) error {
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
