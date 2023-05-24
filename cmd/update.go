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
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update the certificate authority database files.",
	Long:  "Update the certificate authority database files.",
	PreRun: func(cmd *cobra.Command, args []string) {
		if len(settings.Name) == 0 {
			cobra.CheckErr(fmt.Errorf("'%s' is not a certificate authority", folderPath))
		}
	},
	PostRun: func(cmd *cobra.Command, args []string) {
		ensureWorkingDirectoryAndExit()
	},
	Run: func(cmd *cobra.Command, args []string) {
		update_authority("")
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
}

func update_authority(password string) {
	if len(password) == 0 {
		fmt.Printf("\033[1;35mEnter pass phrase for %s:\033[0m ", "private/ca.key")

		p, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		cobra.CheckErr(err)

		password = string(p)
	}

	executeExternalProgram("openssl", []string{
		"ca",
		fmt.Sprintf("-config %s", "ca.cnf"),
		"-updatedb",
		fmt.Sprintf("-passin pass:%s", password),
	}...)
}
