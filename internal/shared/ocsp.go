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

	"github.com/dcjulian29/go-toolbox/execute"
	"github.com/dcjulian29/go-toolbox/filesystem"
	"github.com/dcjulian29/go-toolbox/textformat"
)

// EnableOCSP initializes OCSP support for the current certificate authority.
// It generates an ocsp.cnf configuration file populated with the authority's
// country, organization, and common name, then creates a new OCSP private key,
// certificate signing request, and OCSP certificate signed by the CA. If
// password is empty, the user is prompted interactively for the CA private key
// password. Returns an error if OCSP is already enabled (ocsp.cnf exists), the
// settings cannot be loaded, the password prompt fails, the configuration file
// cannot be written, or any key/certificate generation step fails.
func EnableOCSP(password string) error {
	if filesystem.FileExist("ocsp.cnf") {
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

	fmt.Println(textformat.Info("Initializing OCSP configuration for this authority..."))

	contents.WriteString("[req]\n")
	contents.WriteString("encrypt_key             = no\n")
	contents.WriteString("utf8                    = yes\n")
	contents.WriteString("string_mask             = utf8only\n")
	contents.WriteString("prompt                  = no\n")
	contents.WriteString("distinguished_name      = req_subj\n\n")
	contents.WriteString("[req_subj]\n")

	fmt.Fprintf(&contents, "countryName             = %s\n", settings.Country)
	fmt.Fprintf(&contents, "organizationName        = %s\n", settings.Organization)
	fmt.Fprintf(&contents, "commonName              = %s OCSP Responder\n", settings.CommonName)

	if err := filesystem.EnsureFileExist("ocsp.cnf", contents.Bytes()); err != nil {
		return err
	}

	if err := newOcspKey(); err != nil {
		return err
	}

	if err := newOcspRequest(); err != nil {
		return err
	}

	return newOcspCert(password)
}

// ReplaceOCSP revokes the existing OCSP responder certificate and issues a new
// one. The revocation reason must be either Superseded or KeyCompromise; any
// other reason is rejected. The current OCSP certificate ("cert/ocsp.pem") and
// private key ("private/ocsp.key") are removed after revocation, the CRL is
// updated, and a new OCSP key, CSR, and certificate are generated. Returns an
// error if OCSP is not enabled in the authority settings, the reason is not
// permitted, the OCSP certificate is missing, the CA private key password
// prompt fails, or any revocation, removal, CRL update, or generation step
// fails.
func ReplaceOCSP(reason RevokeType) error {
	settings, err := GetSettings()
	if err != nil {
		return err
	}

	if !settings.OCSP {
		return errors.New("OCSP is not enabled in this authority")
	}

	if !(reason == Superseded || reason == KeyCompromise) { //nolint
		return errors.New("the reason provided is not allowed (only 'superseded' or 'keycompromise' allowed)")
	}

	filePath := filepath.Join("cert", "ocsp.pem")
	keyPath := filepath.Join("private", "ocsp.key")

	if !filesystem.FileExist(filePath) {
		return errors.New("the OCSP certificate does not exist")
	}

	password, err := AskPrivateKeyPassword()
	if err != nil {
		return err
	}

	fmt.Println(textformat.Warn("Revoking the current OCSP certificate..."))

	if err := execute.ExternalProgram("openssl", []string{
		"ca",
		fmt.Sprintf("-config %s", "ca.cnf"),
		fmt.Sprintf("-revoke %s", filePath),
		fmt.Sprintf("-crl_reason %s", reason),
		fmt.Sprintf("-passin pass:%s", password),
	}...); err != nil {
		return err
	}

	fmt.Println(textformat.Warn("Removing the current OCSP certificate and key..."))

	if filesystem.FileExist(filePath) {
		if err := os.Remove(filePath); err != nil {
			return err
		}
	}

	if filesystem.FileExist(keyPath) {
		if err := os.Remove(keyPath); err != nil {
			return err
		}
	}

	if err := UpdateCRL(password); err != nil {
		return err
	}

	if err := newOcspKey(); err != nil {
		return err
	}

	if err := newOcspRequest(); err != nil {
		return err
	}

	return newOcspCert(password)

}

func newOcspCert(password string) error {
	fmt.Println(textformat.Info("Generating the OCSP certificate..."))

	return execute.ExternalProgram("openssl", []string{
		"ca",
		"-batch",
		"-config ca.cnf",
		"-out certs/ocsp.pem",
		"-extensions ocsp_ext",
		"-days 35",
		fmt.Sprintf("-passin pass:%s", password),
		"-infiles csr/ocsp.csr",
	}...)
}

func newOcspKey() error {
	fmt.Println(textformat.Info("Generating the OCSP private key..."))

	return execute.ExternalProgram("openssl", []string{
		"ecparam",
		"-name prime256v1",
		"-genkey",
		"-noout",
		fmt.Sprintf("-out %s", "private/ocsp.key"),
	}...)
}

func newOcspRequest() error {
	fmt.Println(textformat.Info("Generating the OCSP certificate request..."))

	return execute.ExternalProgram("openssl", []string{
		"req",
		"-new",
		"-config ocsp.cnf",
		"-sha256",
		"-out csr/ocsp.csr",
		"-key private/ocsp.key",
	}...)
}
