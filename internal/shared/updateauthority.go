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

// UpdateAuthority updates the certificate authority database by running the
// OpenSSL ca -updatedb command using the ca.cnf configuration. This marks any
// expired certificates in the database as expired. If password is empty, the
// user is prompted interactively for the CA private key password. Returns an
// error if the password prompt fails or the OpenSSL command fails.
func UpdateAuthority(password string) error {
	if len(password) == 0 {
		pass, err := AskPrivateKeyPassword()
		if err != nil {
			return err
		}

		password = pass
	}

	textformat.Info("Updating the certificate authority database...")

	return execute.ExternalProgram("openssl", []string{
		"ca",
		fmt.Sprintf("-config %s", "ca.cnf"),
		"-updatedb",
		fmt.Sprintf("-passin pass:%s", password),
	}...)
}
