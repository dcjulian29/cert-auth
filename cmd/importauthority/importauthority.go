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
package importauthority

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/dcjulian29/go-toolbox/filesystem"
	"github.com/dcjulian29/go-toolbox/textformat"
	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import and sign a subordinate authority.",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := shared.IsCertificateAuthority(); err != nil {
				return err
			}

			settings, err := shared.GetSettings()
			if err != nil {
				return err
			}

			if settings.Type != "root" {
				pwd, _ := os.Getwd()

				return fmt.Errorf("'%s' is not a root certificate authority", pwd)
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			file, _ := cmd.Flags().GetString("request")
			name, _ := cmd.Flags().GetString("name")

			if len(file) == 0 {
				file = filepath.Join("csr", fmt.Sprintf("%s.csr", name))
			}

			if !filesystem.FileExists(file) {
				return fmt.Errorf("'%s' does not exist", file)
			}

			request, _ := shared.LoadRequest(file)

			id, serial, err := shared.ImportSubordinate(file, "")
			if err != nil {
				return err
			}

			authority := shared.Authority{
				Type:         "imported",
				Public:       false,
				Name:         name,
				Domain:       "Unknown",
				Country:      "Unknown",
				Organization: "Unknown",
				CommonName:   request.Name,
				OCSP:         false,
				TimeStamp:    false,
				Serial:       serial,
				Subordinates: []shared.Subordinate{},
			}

			if err := filesystem.EnsureDirectoryExist(name); err != nil {
				return err
			}

			if err := shared.SaveSubordinateSettings(id, authority); err != nil {
				return err
			}

			if err := filesystem.EnsureDirectoryExist(filepath.Join(name, "csr")); err != nil {
				return err
			}

			if err := filesystem.CopyFile(filepath.Join(".", "csr", fmt.Sprintf("%s.csr", id)),
				filepath.Join(".", name, "csr", "ca.csr")); err != nil {
				return err
			}

			if err := filesystem.EnsureDirectoryExist(filepath.Join(name, "certs")); err != nil {
				return err
			}

			if err := filesystem.CopyFile(filepath.Join(".", "certs", fmt.Sprintf("%s.pem", id)),
				filepath.Join(".", name, "certs", "ca.pem")); err != nil {
				return err
			}

			fmt.Println(textformat.Info("Writing subordinate authority chain certificate..."))

			root, err := os.ReadFile("./certs/ca.pem")
			if err != nil {
				return err
			}

			sub, err := os.ReadFile(filepath.Join(".", name, "certs", "ca.pem"))
			if err != nil {
				return err
			}

			chain := fmt.Sprintf("%s\n%s\n", string(root), string(sub))

			return filesystem.EnsureFileExist(filepath.Join(".", name, "certs", "ca-chain.pem"), []byte(chain))
		},
	}

	cmd.Flags().StringP("name", "n", "", "name for subordinate authority")
	cmd.Flags().StringP("request", "r", "", "request file for subordinate authority")

	_ = cmd.MarkFlagRequired("name")

	return cmd
}
