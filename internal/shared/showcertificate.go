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

func ShowCertificate(id string, revoked bool) error {
	if len(id) > 0 {
		pemFile := filepath.Join("certs", fmt.Sprintf("%s.pem", id))

		if revoked {
			pemFile = fmt.Sprintf("%s.revoked", pemFile)
		}

		if !filesystem.FileExists(pemFile) {
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
