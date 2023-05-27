/*
Copyright © 2023 Julian Easterling <julian@julianscorner.com>

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
package cmd

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/spf13/cobra"
)

var settingsCmd = &cobra.Command{
	Use:   "settings [<key>]",
	Args:  cobra.MaximumNArgs(1),
	Short: "Show setting(s) of the certificate authority",
	Long:  "Show setting(s) of the certificate authority",
	Run: func(cmd *cobra.Command, args []string) {
		key := ""

		if len(args) > 0 {
			key = args[0]
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
				cobra.CheckErr(fmt.Errorf("'%s' is not a valid setting", key))
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(settingsCmd)
}
