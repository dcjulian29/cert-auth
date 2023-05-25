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
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/spf13/cobra"
)

var publishCmd = &cobra.Command{
	Use:   "publish",
	Short: "Publish the certificate authority files suitable for deployment to web",
	Long:  "Publish the certificate authority files suitable for deployment to web",
	PreRun: func(cmd *cobra.Command, args []string) {
		if len(settings.Name) == 0 {
			cobra.CheckErr(fmt.Errorf("'%s' is not a certificate authority", folderPath))
		}

		if settings.Type != "root" {
			cobra.CheckErr(errors.New("authorities can only be published from the root authority"))
		}

		ensureAuthorityDirectory()
	},
	PostRun: func(cmd *cobra.Command, args []string) {
		ensureWorkingDirectoryAndExit()
	},
	Run: func(cmd *cobra.Command, args []string) {
		dest, _ := cmd.Flags().GetString("destination")

		if dirExists(dest) {
			files, err := os.ReadDir(dest)
			cobra.CheckErr(err)

			if len(files) > 0 {
				if f, _ := cmd.Flags().GetBool("force"); f {
					os.RemoveAll(dest)
				} else {
					cobra.CheckErr(errors.New("files present in the publish path and Force was not supplied"))
				}
			}
		}

		ensureDir(dest)

		mime_types(path.Join(dest, "mime.types"))

		publish_files(settings, dest)

		for _, s := range settings.Subordinates {
			if is_mounted(s.Id, s.Name) {
				publish_files(load_authority(path.Join(s.Name, "ca.yml")), path.Join("..", dest))
			}
		}

		info(fmt.Sprintf("~~~~~~\nThis certificate authority has been published to '%s'.", dest))
	},
}

func init() {
	rootCmd.AddCommand(publishCmd)

	publishCmd.Flags().String("destination", ".publish", "directory to publish to")
	publishCmd.Flags().BoolP("force", "f", false, "overwrite existing published files")
}

func mime_types(filePath string) {
	var contents bytes.Buffer

	contents.WriteString("application/pkcs7-mime              .p7c\n")
	contents.WriteString("application/pkcs8                   .p8  .key\n")
	contents.WriteString("application/pkcs10                  .p10 .csr\n")
	contents.WriteString("application/pkix-cert               .cer\n")
	contents.WriteString("application/pkix-crl                .crl\n")
	contents.WriteString("application/x-pem-file              .pem\n")
	contents.WriteString("application/x-pkcs7-certificates    .p7b .spc\n")
	contents.WriteString("application/x-pkcs7-certreqresp     .p7r\n")
	contents.WriteString("application/x-pkcs7-crl             .crl\n")
	contents.WriteString("application/x-pkcs12                .p12 .pfx\n")
	contents.WriteString("application/x-x509-ca-cert          .crt .der\n")
	contents.WriteString("application/x-x509-user-cert        .crt\n")

	touchFile(filePath, contents.Bytes())
}

func is_mounted(id string, name string) bool {
	if dirExists(name) {
		s := load_authority(path.Join(name, "ca.yml"))

		return s.Serial == id
	} else {
		return false
	}
}

func publish_files(authority CertAuth, dest string) {
	info(fmt.Sprintf("Authority '%s' is mounted. Proceeding to publish...", authority.Name))

	if authority.Type != "root" {
		err := os.Chdir(authority.Name)
		cobra.CheckErr(err)
	}

	info(fmt.Sprintf(">>>---------------- '%s' Certificate Authority", authority.Name))

	if authority.Type == "imported" {
		fmt.Printf("\033[1;36mThis is an imported authority.\033[0m\n")
	} else {
		pass := askPassword("private/ca.key")

		fmt.Println("Updating the certificate authority database...")
		update_authority(pass)

		if authority.OCSP {
			ocsp_update(pass)
		}

		if authority.TimeStamp {
			timestamp_update(pass)
		}

		crl_update(pass, authority)
	}

	if fileExists(path.Join("certs", "ca.pem")) {
		executeExternalProgram("openssl", []string{
			"x509",
			"-outform der",
			"-in certs/ca.pem",
			fmt.Sprintf("-out %s/%s.crt", dest, authority.Name),
		}...)
	}

	if fileExists("ca.crl") {
		executeExternalProgram("openssl", []string{
			"crl",
			"-in ca.crl",
			fmt.Sprintf("-out %s/%s.crl", dest, authority.CommonName),
			"-outform der",
		}...)
	}

	if fileExists(path.Join("certs", "ocsp.pem")) {
		executeExternalProgram("openssl", []string{
			"x509",
			"-outform der",
			"-in certs/ocsp.pem",
			fmt.Sprintf("-out %s/%s-ocsp.crt", dest, authority.CommonName),
		}...)
	}

	if fileExists(path.Join("certs", "timestamp.pem")) {
		executeExternalProgram("openssl", []string{
			"x509",
			"-outform der",
			"-in certs/ocsp.pem",
			fmt.Sprintf("-out %s/%s-timestamp.crt", dest, authority.CommonName),
		}...)
	}

	if authority.Type != "root" {
		err := os.Chdir("../")
		cobra.CheckErr(err)
	}
}
