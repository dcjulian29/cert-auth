package shared

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

import (
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	"github.com/dcjulian29/go-toolbox/execute"
	"github.com/dcjulian29/go-toolbox/filesystem"
	"github.com/dcjulian29/go-toolbox/textformat"
)

// ValidateCertificate verifies a certificate at the given path against a CA
// chain file using OpenSSL. The certificate file must exist. If bundle is
// false, the CA file used is "certs/ca-chain.pem" if it exists, falling back
// to "certs/ca.pem". If bundle is true, Mozilla's root CA bundle is downloaded
// from https://curl.se/ca/cacert.pem, saved to "certs/ca-bundle.pem", and used
// as the CA file. Returns an error if the certificate file does not exist, the
// CA bundle download or write fails, or the OpenSSL verify command fails.
func ValidateCertificate(path string, bundle bool) error {
	if !filesystem.FileExists(path) {
		return fmt.Errorf("'%s' does not exists or is not accessable", path)
	}

	ca := filepath.Join("certs", "ca-chain.pem")

	if !filesystem.FileExists(ca) {
		ca = filepath.Join("certs", "ca.pem")
	}

	if bundle {
		ca = filepath.Join("certs", "ca-bundle.pem")

		fmt.Println(textformat.Warn("Downloading Mozilla's ca-bundle.pem..."))

		resp, err := http.Get("https://curl.se/ca/cacert.pem")
		if err != nil {
			return err
		}

		defer resp.Body.Close() //nolint

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		if err := filesystem.EnsureFileExist(ca, body); err != nil {
			return err
		}
	}

	return execute.ExternalProgram("openssl", []string{
		"verify",
		fmt.Sprintf("-CAfile %s", ca),
		path,
	}...)
}
