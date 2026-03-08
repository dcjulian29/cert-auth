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
package shared

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dcjulian29/go-toolbox/color"
	"github.com/dcjulian29/go-toolbox/execute"
	"github.com/dcjulian29/go-toolbox/filesystem"
)

func EnableTimestamp(password string) error {
	if filesystem.FileExists("timestamp.cnf") {
		return errors.New("OCSP is already enabled in this authority")
	}

	settings, err := GetSettings()
	if err != nil {
		return err
	}

	if len(password) == 0 {
		pass, err := AskPrivateKeyPassword()
		if err != nil {
			return err
		}

		password = pass
	}

	var contents bytes.Buffer

	fmt.Println(color.Info("Initializing timestamp configuration for this authority..."))

	contents.WriteString("[req]\n")
	contents.WriteString("encrypt_key             = no\n")
	contents.WriteString("utf8                    = yes\n")
	contents.WriteString("string_mask             = utf8only\n")
	contents.WriteString("prompt                  = no\n")
	contents.WriteString("distinguished_name      = req_subj\n\n")
	contents.WriteString("[req_subj]\n")

	fmt.Fprintf(&contents, "countryName             = %s\n", settings.Country)
	fmt.Fprintf(&contents, "organizationName        = %s\n", settings.Organization)
	fmt.Fprintf(&contents, "commonName              = %s Timestamp Authority\n", settings.CommonName)

	if err := filesystem.EnsureFileExist("timestamp.cnf", contents.Bytes()); err != nil {
		return err
	}

	if err := newTimestampKey(); err != nil {
		return err
	}

	if err := newTimestampRequest(); err != nil {
		return err
	}

	return newTimestampCert(password)
}

func ReplaceTimestamp() error {
	settings, err := GetSettings()
	if err != nil {
		return err
	}

	if !settings.TimeStamp {
		return errors.New("timestamp is not enabled in this authority")
	}

	filePath := filepath.Join("cert", "timestamp.pem")
	keyPath := filepath.Join("private", "timestamp.key")

	if !filesystem.FileExists(filePath) {
		return errors.New("the Timestamp certificate does not exist")
	}

	password, err := AskPrivateKeyPassword()
	if err != nil {
		return err
	}

	fmt.Println(color.Warn("Removing the current Timestamp certificate and key..."))

	if filesystem.FileExists(filePath) {
		if err := os.Remove(filePath); err != nil {
			return err
		}
	}

	if filesystem.FileExists(keyPath) {
		if err := os.Remove(keyPath); err != nil {
			return err
		}
	}

	if err := newTimestampKey(); err != nil {
		return err
	}

	if err := newTimestampRequest(); err != nil {
		return err
	}

	return newTimestampCert(password)
}

func newTimestampCert(password string) error {
	fmt.Println(color.Info("Generating the Timestamp certificate..."))

	return execute.ExternalProgram("openssl", []string{
		"ca",
		"-batch",
		"-config ca.cnf",
		"-out certs/timestamp.pem",
		"-extensions timestamp_ext",
		"-days 3645",
		fmt.Sprintf("-passin pass:%s", password),
		"-infiles csr/timestamp.csr",
	}...)
}

func newTimestampKey() error {
	fmt.Println(color.Info("Generating the Timestamp private key..."))

	return execute.ExternalProgram("openssl", []string{
		"ecparam",
		"-name secp384r1",
		"-genkey",
		"-noout",
		fmt.Sprintf("-out %s", "private/timestamp.key"),
	}...)
}

func newTimestampRequest() error {
	fmt.Println(color.Info("Generating the Timestamp certificate request..."))

	return execute.ExternalProgram("openssl", []string{
		"req",
		"-new",
		"-config timestamp.cnf",
		"-out csr/timestamp.csr",
		"-key private/timestamp.key",
		"-sha384",
	}...)
}
