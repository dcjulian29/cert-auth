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
package settings

import (
	"encoding/json"
	"fmt"
	"reflect"


	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/spf13/cobra"
)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "settings [<key>]",
		Args:  cobra.MaximumNArgs(1),
		Short: "Show setting(s) of the certificate authority",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return shared.IsCertificateAuthority()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
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
