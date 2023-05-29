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
	"path"

	"github.com/spf13/cobra"
)

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import and sign a subordinate authority.",
	Long:  "Import and sign a subordinate authority.",
	PreRun: func(cmd *cobra.Command, args []string) {
		if len(settings.Name) == 0 {
			cobra.CheckErr(fmt.Errorf("'%s' is not a certificate authority", folderPath))
		}

		if settings.Type != "root" {
			cobra.CheckErr(fmt.Errorf("'%s' is not a root certificate authority", folderPath))
		}

		ensureAuthorityDirectory()
	},
	PostRun: func(cmd *cobra.Command, args []string) {
		ensureWorkingDirectoryAndExit()
	},
	Run: func(cmd *cobra.Command, args []string) {
		file, _ := cmd.Flags().GetString("request")
		name, _ := cmd.Flags().GetString("name")

		if len(file) == 0 {
			file = path.Join("csr", fmt.Sprintf("%s.csr", name))
		}

		if !fileExists(file) {
			cobra.CheckErr(fmt.Errorf("'%s' is not accessable", file))
		}

		request := load_request(file)
		id, serial := import_authority(file, "")

		authority := CertAuth{
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
			Subordinates: []Subordinate{},
		}

		ensureDir(name)
		save_authority(path.Join(name, "ca.yml"), authority)

		ensureDir(path.Join(name, "csr"))
		copyFile(path.Join(".", "csr", fmt.Sprintf("%s.csr", id)), path.Join(".", name, "csr", "ca.csr"))

		ensureDir(path.Join(name, "certs"))
		copyFile(path.Join(".", "certs", fmt.Sprintf("%s.pem", id)), path.Join(".", name, "certs", "ca.pem"))

		settings.Subordinates = addSubordinate(settings, name, serial)

		save_authority("ca.yml", settings) // root CA configuration

		info("Writing subordinate authority chain certificate...")

		root, err := os.ReadFile("./certs/ca.pem")
		cobra.CheckErr(err)

		sub, err := os.ReadFile(path.Join(".", name, "certs", "ca.pem"))
		cobra.CheckErr(err)

		chain := fmt.Sprintf("%s\n%s\n", string(root), string(sub))

		touchFile(path.Join(".", name, "certs", "ca-chain.pem"), []byte(chain))
	},
}

func init() {
	rootCmd.AddCommand(importCmd)

	importCmd.Flags().StringP("name", "n", "", "name for subordinate authority")
	importCmd.Flags().StringP("request", "r", "", "request file for subordinate authority")

	importCmd.MarkFlagRequired("name")
}
