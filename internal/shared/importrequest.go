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
	"fmt"
	"path/filepath"

	"github.com/dcjulian29/go-toolbox/filesystem"
)

// ImportRequest validates and imports a certificate signing request (CSR) from
// the given filePath into the authority's csr/ directory. The file must exist
// and contain a CSR with a valid self-signature. On success, the CSR is copied
// into the csr/ directory with a randomly generated 15-character ID as its
// filename (e.g. "csr/a3f9c2d1b8e2f4a.csr") and that ID is returned. Returns
// an error if the file does not exist, cannot be parsed, has an invalid
// signature, or cannot be copied.
func ImportRequest(filePath string) (string, error) {
	if !filesystem.FileExists(filePath) {
		return "", fmt.Errorf("'%s' doesn't exist or is not accessable", filePath)
	}

	request, err := LoadRequest(filePath)
	if err != nil {
		return "", err
	}

	if !request.SignatureValid {
		return "", fmt.Errorf("'%s' is not a valid certificate request", filePath)
	}

	id, _ := RandomID(15)
	csrName := filepath.Join("csr", fmt.Sprintf("%s.csr", id))

	if err := filesystem.CopyFile(filePath, csrName); err != nil {
		return "", err
	}

	return id, nil
}
