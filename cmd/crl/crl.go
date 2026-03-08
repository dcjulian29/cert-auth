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
package crl

import (
	"errors"
	"fmt"

	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/dcjulian29/go-toolbox/execute"
	"github.com/dcjulian29/go-toolbox/filesystem"
	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "crl",
		Short: "Manage Certificate Revocation List within this authority.",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return shared.IsCertificateAuthority()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if u, _ := cmd.Flags().GetBool("update"); u {
				if err := shared.UpdateCRL(""); err != nil {
					return err
				}
			}

			if filesystem.FileExists("ca.crl") {
				if err := execute.ExternalProgram("openssl", []string{
					"crl",
					fmt.Sprintf("-in %s", "ca.crl"),
					"-noout",
					"-text",
				}...); err != nil {
					return err
				}
			} else {
				return errors.New("the CRL file does not exist")
			}

			return nil
		},
	}

	cmd.Flags().BoolP("update", "u", false, "update the certificate revocation list")

	return cmd
}
