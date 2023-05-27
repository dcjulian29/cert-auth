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
	"strings"

	"github.com/spf13/cobra"
)

var ocspCmd = &cobra.Command{
	Use:   "ocsp",
	Short: "Manage OCSP within this authority.",
	Long:  "Manage OCSP within this authority.",
	PreRun: func(cmd *cobra.Command, args []string) {
		if len(settings.Name) == 0 {
			cobra.CheckErr(fmt.Errorf("'%s' is not a certificate authority", folderPath))
		}
	},
	PostRun: func(cmd *cobra.Command, args []string) {
		ensureWorkingDirectoryAndExit()
	},
	Run: func(cmd *cobra.Command, args []string) {
		if settings.OCSP {
			if u, _ := cmd.Flags().GetBool("update"); u {
				ocsp_update("")
			}

			if r, _ := cmd.Flags().GetBool("reset"); r {
				ocsp_reset()
				ocsp_update("")
			}

			// TODO: Show OCSP certificate info
		}
	},
}

var ocspServerCmd = &cobra.Command{
	Use:   "server",
	Short: "Manage OCSP Responder suitable for low-volume traffic.",
	Long:  "Manage OCSP Responder suitable for low-volume traffic.",
	PreRun: func(cmd *cobra.Command, args []string) {
		if len(settings.Name) == 0 {
			cobra.CheckErr(fmt.Errorf("'%s' is not a certificate authority", folderPath))
		}

		ensureAuthorityDirectory()
	},
	PostRun: func(cmd *cobra.Command, args []string) {
		ensureWorkingDirectoryAndExit()
	},
	Run: func(cmd *cobra.Command, args []string) {
		if settings.OCSP {
			if t, _ := cmd.Flags().GetBool("start"); t {
				port, _ := cmd.Flags().GetInt("port")
				background, _ := cmd.Flags().GetBool("background")

				ocsp_start(port, background)
			}

			if p, _ := cmd.Flags().GetBool("stop"); p {
				ocsp_stop()
			}
		} else {
			cobra.CheckErr(fmt.Errorf("OCSP is not enabled in the '%s' certificate authority", folderPath))
		}
	},
}

func init() {
	rootCmd.AddCommand(ocspCmd)

	ocspCmd.Flags().BoolP("update", "u", false, "update the OCSP certificate")
	ocspCmd.Flags().BoolP("reset", "r", false, "reset the OCSP certificate")

	ocspCmd.MarkFlagsMutuallyExclusive("update", "reset")

	ocspCmd.AddCommand(ocspServerCmd)

	ocspServerCmd.Flags().Bool("start", false, "start the OCSP responder")
	ocspServerCmd.Flags().Bool("stop", false, "stop the OCSP responder")
	ocspServerCmd.Flags().IntP("port", "p", 8080, "port for OCSP responder to listen on")
	ocspServerCmd.Flags().BoolP("background", "b", false, "run the OCSP responder in the background")

	ocspServerCmd.MarkFlagsMutuallyExclusive("start", "stop")
}

func ocsp_reset() {
	info("Generating the OCSP private key for this authority...")

	executeExternalProgram("openssl", []string{
		"genrsa",
		"-out private/ocsp.key",
		"-verbose",
		"2048",
	}...)
}

func ocsp_running(name string) bool {
	r := executeExternalProgramCapture("docker", []string{
		"ps",
		"--format", "{{.Names}}", "--filter",
		fmt.Sprintf("name=%s", name),
	}...)

	return len(r) != 0
}

func ocsp_start(port int, background bool) {
	name := fmt.Sprintf("ocsp_%s", settings.Name)

	if ocsp_running(name) {
		cobra.CheckErr(fmt.Errorf("'%s' OCSP responder is already running", settings.Name))
	}

	pwd, _ := os.Getwd()
	detach := "-it"

	if background {
		detach = "--detach"
	}

	executeExternalProgram("docker", []string{
		"run",
		"--rm",
		detach,
		"--name",
		name,
		"-p",
		fmt.Sprintf("%d:8080/tcp", port),
		"-v",
		fmt.Sprintf("%s:/data", strings.ReplaceAll(pwd, "\\", "/")),
		"dcjulian29/openssl:latest",
		"ocsp",
		"-port", "8080",
		"-index", "db/index",
		"-rsigner", "certs/ocsp.pem",
		"-rkey", "private/ocsp.key",
		"-CA", "certs/ca.pem",
		"-text",
	}...)

}

func ocsp_stop() {
	name := fmt.Sprintf("ocsp_%s", settings.Name)

	if ocsp_running(name) {
		executeExternalProgram("docker", []string{
			"rm",
			"--force",
			name,
		}...)
	} else {
		cobra.CheckErr(fmt.Errorf("'%s' OCSP responder is not running", settings.Name))
	}
}

func ocsp_update(password string) {
	if len(password) == 0 {
		password = askPassword("private/ca.key")
	}

	// TODO: revoke existing OCSP certificates

	info("Generating the OCSP certificate for this authority...")

	executeExternalProgram("openssl", []string{
		"ca",
		"-batch",
		"-config ca.cnf",
		"-out certs/ocsp.pem",
		"-extensions ocsp_ext",
		"-days 90",
		fmt.Sprintf("-passin pass:%s", password),
		"-infiles csr/ocsp.csr",
	}...)
}
