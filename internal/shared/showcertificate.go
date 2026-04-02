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
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/dcjulian29/go-toolbox/execute"
	"github.com/dcjulian29/go-toolbox/filesystem"
)

// ShowCertificate displays certificate information from the current authority.
// If id is non-empty, the corresponding PEM file is located at
// "certs/<id>.pem" (or "certs/<id>.pem.revoked" if revoked is true) and its
// full text representation is printed to stdout via OpenSSL. If id is empty,
// the certificate database is loaded via LoadCertificateDB and printed to
// stdout as indented JSON. Returns an error if the certificate file does not
// exist, the OpenSSL command fails, the database cannot be loaded, or the JSON
// marshalling fails.
func ShowCertificate(id string, revoked bool) error {
	if len(id) > 0 {
		pemFile := filepath.Join("certs", fmt.Sprintf("%s.pem", id))

		if revoked {
			pemFile = fmt.Sprintf("%s.revoked", pemFile)
		}

		if !filesystem.FileExist(pemFile) {
			return fmt.Errorf("certificate '%s' was not found", id)
		}

		if err := execute.ExternalProgram("openssl", []string{
			"x509",
			"-text",
			"-noout",
			fmt.Sprintf("-in %s", pemFile),
		}...); err != nil {
			return err
		}
	} else {
		certs, err := LoadCertificateDB(revoked)
		if err != nil {
			return err
		}

		json, err := json.MarshalIndent(certs, "", "  ")
		if err != nil {
			return err
		}

		fmt.Printf("%s\n", string(json))
	}

	return nil
}
