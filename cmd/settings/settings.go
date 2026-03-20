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

// Package settings provides the CLI command for displaying the configuration
// settings of a certificate authority.
package settings

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/spf13/cobra"
)

// NewCommand returns a cobra.Command that displays the settings of the current
// certificate authority. The command verifies that the current directory is a
// certificate authority before running and accepts an optional key argument.
// If no key is provided, all settings are printed to stdout as indented JSON.
// If a key is provided, the value of the matching field is printed using
// reflection; the key must exactly match the exported field name of the
// Authority settings struct. Returns an error if the current directory is not
// a certificate authority, the settings cannot be loaded, or the provided key
// does not match any settings field.
//
// Usage:
//
//	settings [<key>]
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "settings [<key>]",
		Args:  cobra.MaximumNArgs(1),
		Short: "Show setting(s) of the certificate authority",
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return shared.IsCertificateAuthority()
		},
		RunE: func(_ *cobra.Command, args []string) error {
			key := ""

			if len(args) > 0 {
				key = args[0]
			}

			settings, err := shared.GetSettings()
			if err != nil {
				return err
			}

			if len(key) == 0 {
				if json, err := json.MarshalIndent(settings, "", "  "); err == nil {
					fmt.Printf("%s\n", string(json))
				}
			} else {
				val := reflect.ValueOf(settings).FieldByName(key)

				if val.IsValid() {
					fmt.Printf("%v\n", val)
				} else {
					return fmt.Errorf("'%s' is not a valid setting", key)
				}
			}

			return nil
		},
	}

	return cmd
}
