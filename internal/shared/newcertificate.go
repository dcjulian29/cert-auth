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
)

// NewCertificate creates a new certificate end-to-end by generating a private
// key, a certificate signing request (CSR), and a signed certificate, all
// identified by a randomly generated 15-character ID. The process is:
//
//  1. Generate a 15-character random ID.
//  2. Prompt the user for a pass phrase for the new private key (stored at
//     "private/<id>.key").
//  3. Generate a new private key of DefaultKeyType at the key path.
//  4. Generate a CSR at "csr/<id>.csr" using the key and the provided
//     RequestData.
//  5. Sign the CSR via ApproveCertificate using the certificate type from
//     RequestData and the given validity period in days.
//
// Returns the generated ID on success, or an error if any step fails.
func NewCertificate(data RequestData, days int) (string, error) {
	id, err := RandomID(15)
	if err != nil {
		return "", err
	}

	keyPath := filepath.Join("private", fmt.Sprintf("%s.key", id))
	csrPath := filepath.Join("csr", fmt.Sprintf("%s.csr", id))
	pass, err := AskPassword(keyPath)
	if err != nil {
		return "", err
	}

	if err := NewPrivateKey(keyPath, DefaultKeyType, pass); err != nil {
		return "", err
	}

	if err := NewRequest(csrPath, keyPath, pass, data); err != nil {
		return "", err
	}

	if err = ApproveCertificate(id, data.RequestType, days); err != nil {
		return "", err
	}

	return id, nil
}
