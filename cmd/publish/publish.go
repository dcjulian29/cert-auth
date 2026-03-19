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
package publish

import (
	"errors"
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
		Use:   "publish",
		Short: "Publish the certificate authority files suitable for deployment to web",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return shared.IsRootCertificateAuthority()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			dest, _ := cmd.Flags().GetString("destination")

			if filesystem.DirectoryExists(dest) {
				files, err := os.ReadDir(dest)
				if err != nil {
					return err
				}

				if len(files) > 0 {
					if f, _ := cmd.Flags().GetBool("force"); f {
						if err := os.RemoveAll(dest); err != nil {
							return err
						}
					} else {
						return errors.New("files present in the publish path and Force was not supplied")
					}
				}
			}

			if err := filesystem.EnsureDirectoryExist(dest); err != nil {
				return err
			}

			if err := mime_types(filepath.Join(dest, "mime.types")); err != nil {
				return err
			}

			settings, err := shared.GetSettings()
			if err != nil {
				return err
			}

			if err := publish_files(settings, dest); err != nil {
				return err
			}

			for _, s := range settings.Subordinates {
				if err := shared.ValidateSubordinate(s.Id, s.Name); err != nil {
					return err
				}

				authority, err := shared.LoadSubordinate(s.Name)
				if err != nil {
					return err
				}
				if err := publish_files(authority, filepath.Join("..", dest)); err != nil {
					return err
				}
			}

			fmt.Println(textformat.Warn(fmt.Sprintf("~~~~~~\nThis certificate authority has been published to '%s'.", dest)))

			return nil
		},
	}

	cmd.Flags().String("destination", ".publish", "directory to publish to")
	cmd.Flags().BoolP("force", "f", false, "overwrite existing published files")

	return cmd
}
