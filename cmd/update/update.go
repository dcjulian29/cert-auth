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

// Package update provides the CLI command for updating the certificate
// authority database files.
package update

import (
	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/spf13/cobra"
)

// NewCommand returns a cobra.Command that updates the certificate authority
// database files by invoking UpdateAuthority. The command verifies that the
// current directory is a certificate authority before running. The CA private
// key password is collected interactively at runtime.
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update the certificate authority database files.",
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return shared.IsCertificateAuthority()
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return shared.UpdateAuthority("")
		},
	}

	return cmd
}
