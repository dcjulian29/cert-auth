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

	"github.com/dcjulian29/go-toolbox/execute"
	"github.com/dcjulian29/go-toolbox/textformat"
)

// SignRequest signs the CSR identified by id using the CA configured in
// ca.cnf and writes the resulting certificate to "certs/<id>.pem". The CSR is
// read from "csr/<id>.csr". The subca_ext extensions are applied and the
// certificate is valid for the given number of days. If pass is empty, the
// user is prompted interactively for the CA private key password. The OpenSSL
// ca command is run in batch (non-interactive) mode. Returns an error if the
// password prompt fails or the OpenSSL command fails.
func SignRequest(id, pass string, days int) error {
	if len(pass) == 0 {
		pass, _ = AskPrivateKeyPassword()
	}

	fmt.Println(textformat.Info("Signing request and generating a certificate..."))

	return execute.ExternalProgram("openssl", []string{
		"ca",
		"-batch",
		"-config ca.cnf",
		"-extensions subca_ext",
		fmt.Sprintf("-days %d", days),
		fmt.Sprintf("-passin pass:%s", pass),
		fmt.Sprintf("-out ./certs/%s.pem", id),
		fmt.Sprintf("-in ./csr/%s.csr", id),
	}...)
}
