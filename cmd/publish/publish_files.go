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
	"fmt"
	"os"
	"path/filepath"

	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/dcjulian29/go-toolbox/execute"
	"github.com/dcjulian29/go-toolbox/filesystem"
	"github.com/dcjulian29/go-toolbox/textformat"
)

func publish_files(authority shared.Authority, dest string) error {
	fmt.Println(textformat.Info(fmt.Sprintf("Authority '%s' is valid. Proceeding to publish...", authority.Name)))

	if authority.Type != "root" {
		if err := os.Chdir(authority.Name); err != nil {
			return err
		}
	}

	fmt.Println(textformat.Info(fmt.Sprintf(">>>---------------- '%s' Certificate Authority", authority.Name)))

	if authority.Type == "imported" {
		fmt.Printf("\033[1;36mThis is an imported authority.\033[0m\n")
	} else {
		pass, err := shared.AskPrivateKeyPassword()
		if err != nil {
			return err
		}

		fmt.Println("Updating the certificate authority database...")
		if err := shared.UpdateAuthority(pass); err != nil {
			return err
		}

		if err := shared.UpdateCRL(pass); err != nil {
			return err
		}
	}

	if filesystem.FileExists(filepath.Join("certs", "ca.pem")) {
		if err := execute.ExternalProgram("openssl", []string{
			"x509",
			"-outform der",
			"-in certs/ca.pem",
			fmt.Sprintf("-out %s.crt", filepath.Join(dest, authority.Name)),
		}...); err != nil {
			return err
		}
	}

	if filesystem.FileExists("ca.crl") {
		if err := execute.ExternalProgram("openssl", []string{
			"crl",
			"-in ca.crl",
			fmt.Sprintf("-out %s.crl", filepath.Join(dest, authority.Name)),
			"-outform der",
		}...); err != nil {
			return err
		}
	}

	if filesystem.FileExists(filepath.Join("certs", "ocsp.pem")) {
		if err := execute.ExternalProgram("openssl", []string{
			"x509",
			"-outform der",
			"-in certs/ocsp.pem",
			fmt.Sprintf("-out %s-ocsp.crt", filepath.Join(dest, authority.CommonName)),
		}...); err != nil {
			return err
		}
	}

	if filesystem.FileExists(filepath.Join("certs", "timestamp.pem")) {
		if err := execute.ExternalProgram("openssl", []string{
			"x509",
			"-outform der",
			"-in certs/ocsp.pem",
			fmt.Sprintf("-out %s-timestamp.crt", filepath.Join(dest, authority.CommonName)),
		}...); err != nil {
			return err
		}
	}

	if authority.Type != "root" {
		if err := os.Chdir("../"); err != nil {
			return err
		}
	}

	return nil
}
