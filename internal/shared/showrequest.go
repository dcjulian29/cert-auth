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

// ShowRequest displays certificate signing request (CSR) information from the
// current authority. If id is non-empty, the corresponding CSR file is located
// at "csr/<id>.csr" and its full text representation is printed to stdout via
// OpenSSL, including signature verification. Returns an error if the CSR file
// does not exist, the OpenSSL command fails, any individual request cannot
// be loaded, or the JSON marshalling fails.
func ShowRequest(id string) error {
	if len(id) > 0 {
		csrFile := filepath.Join("csr", fmt.Sprintf("%s.csr", id))

		if !filesystem.FileExists(csrFile) {
			return fmt.Errorf("request '%s' was not found", id)
		}

		if err := execute.ExternalProgram("openssl", []string{
			"req",
			"-text",
			"-noout",
			"-verify",
			fmt.Sprintf("-in %s", csrFile),
		}...); err != nil {
			return err
		}
	} else {
		var requests []CertificateRequest

		files, _ := filesystem.FindFilesByExtension("csr", ".csr")

		for _, file := range files {
			request, err := LoadRequest(file)
			if err != nil {
				return err
			}

			requests = append(requests, request)
		}

		json, err := json.MarshalIndent(requests, "", "  ")
		if err != nil {
			return err
		}

		fmt.Printf("%s\n", string(json))
	}

	return nil
}
