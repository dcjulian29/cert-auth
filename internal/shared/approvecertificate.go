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
	"path/filepath"

	"github.com/dcjulian29/go-toolbox/execute"
)

// ApproveCertificate signs a pending certificate signing request (CSR)
// using the local certificate authority configuration. It locates the
// CSR file at csr/<id>.csr, prompts the operator for the CA private key
// password, and invokes OpenSSL in batch mode with the appropriate
// extensions for the given certType ("server" or "client") and the
// requested validity period in days.
//
// The CA configuration is read from ca.cnf in the current working
// directory. The corresponding OpenSSL extension section used is
// "<certType>_ext".
func ApproveCertificate(id string, certType CertificateType, days int) error {
	csrName := filepath.Join("csr", fmt.Sprintf("%s.csr", id))
	pass, err := AskPrivateKeyPassword()
	if err != nil {
		return err
	}

	return execute.ExternalProgram("openssl", []string{
		"ca",
		"-batch",
		fmt.Sprintf("-config %s", "ca.cnf"),
		fmt.Sprintf("-extensions %s_ext", certType),
		fmt.Sprintf("-days %d", days),
		fmt.Sprintf("-passin pass:%s", pass),
		fmt.Sprintf("-infiles %s", csrName),
	}...)
}
