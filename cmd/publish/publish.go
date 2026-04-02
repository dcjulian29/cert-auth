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

// Package publish provides the CLI command for publishing certificate authority
// files in a format suitable for deployment to a web server.
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

// NewCommand returns a cobra.Command that publishes the current root
// certificate authority's files to a destination directory suitable for web
// deployment. The command verifies that the current directory is a root
// certificate authority before running. The destination is resolved to an
// absolute path; if it already contains files, the --force flag must be
// provided to remove them before publishing. A mime.types file is written to
// the destination, followed by the root authority's files and the files for
// each registered subordinate authority. Each subordinate is validated via
// ValidateSubordinate before its files are published. Returns an error if the
// destination path cannot be resolved, the directory cannot be created or
// cleared, any file publishing step fails, or a subordinate cannot be
// validated or loaded.
//
// Flags:
//
//	    --destination    directory to publish to (default: .publish)
//	-f, --force          overwrite existing published files
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "publish",
		Short: "Publish the certificate authority files suitable for deployment to web",
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return shared.IsRootCertificateAuthority()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			relativePath, _ := cmd.Flags().GetString("destination")

			dest, err := filepath.Abs(relativePath)
			if err != nil {
				return fmt.Errorf("error getting absolute destination path: %v", err)
			}

			if filesystem.DirectoryExist(dest) {
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

			if err := mimeTypes(filepath.Join(dest, "mime.types")); err != nil {
				return err
			}

			settings, err := shared.GetSettings()
			if err != nil {
				return err
			}

			if err := publishFiles(settings, dest); err != nil {
				return err
			}

			for _, s := range settings.Subordinates {
				if err := shared.ValidateSubordinate(s.ID, s.Name); err != nil {
					return err
				}

				authority, err := shared.LoadSubordinate(s.Name)
				if err != nil {
					return err
				}
				if err := publishFiles(*authority, dest); err != nil {
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
