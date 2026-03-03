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
package cmd

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/dcjulian29/cert-auth/internal/certauth"
	"github.com/dcjulian29/go-toolbox/execute"
	"github.com/dcjulian29/go-toolbox/filesystem"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

func import_authority(filePath, pass string) (string, string) {
	id := import_request(filePath)

	info("Using root authority to sign the certificate for this authority...")

	sign_request(id, pass, 1825)

	serial, _ := execute.ExternalProgramCapture("openssl", []string{
		"x509",
		"-noout",
		fmt.Sprintf("-in ./certs/%s.pem", id),
		"-serial",
	}...)

	serial = strings.TrimRight(strings.Replace(serial, "serial=", "", 1), "\r\n")

	return id, serial
}

func initialize_authority() {
	if cfgFile != "" {
		folderPath, cfgFile = filepath.Split(cfgFile)
	} else {
		cfgFile = "ca.yml"
	}

	file := path.Join(folderPath, cfgFile)
	if filesystem.FileExists(file) {
		fmt.Fprintf(os.Stderr, "\033[1;36mUsing config file: %s\033[0m\n", file)
		settings = load_authority(file)
	}
}

func load_authority(filePath string) certauth.Authority {
	var authority_settings certauth.Authority

	file, err := os.ReadFile(filePath)
	cobra.CheckErr(err)

	err = yaml.Unmarshal(file, &authority_settings)
	cobra.CheckErr(err)

	if authority_settings.Type != "root" {
		authority_settings.Subordinates = []certauth.Subordinate{}
	}

	return authority_settings
}

func save_authority(filePath string, authority certauth.Authority) {
	yaml, err := yaml.Marshal(&authority)
	cobra.CheckErr(err)

	if filesystem.FileExists(filePath) {
		os.Remove(filePath)
	}

	destination, err := os.Create(filePath)
	cobra.CheckErr(err)

	defer destination.Close()

	err = os.WriteFile(filePath, yaml, 0640)
	cobra.CheckErr(err)
}
