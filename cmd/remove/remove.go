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
package remove

import (
	"errors"
	"fmt"
	"os"


	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/dcjulian29/go-toolbox/filesystem"
	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove subordinate authority files.",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := shared.IsCertificateAuthority(); err != nil {
				return err
			}

			settings, err := shared.GetSettings()
			if err != nil {
				return err
			}

			if settings.Type != "root" {
				return errors.New("this is not a root certificate authority")
			}

			return nil
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
						if !filesystem.DirectoryExists(name) {
							return fmt.Errorf("'%s' authority has already been removed", name)
						}

						return os.RemoveAll(s.Name)
					}

					return fmt.Errorf("'%s' authority has not been revoked", s.Name)
				}
			}

			return fmt.Errorf("'%s' is not a subordinate of this authority", name)
		},
	}

	cmd.Flags().StringP("name", "n", "", "name of subordinate authority")

	cmd.MarkFlagRequired("name")

	return cmd
}
