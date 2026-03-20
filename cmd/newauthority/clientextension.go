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

package newauthority

import (
	"bytes"
)

func clientExtension() []byte {
	var contents bytes.Buffer

	contents.WriteString("\n[client_ext]\n")
	contents.WriteString("authorityInfoAccess     = @issuer_info\n")
	contents.WriteString("authorityKeyIdentifier  = keyid:always, issuer:always\n")
	contents.WriteString("basicConstraints        = critical,CA:false\n")
	contents.WriteString("crlDistributionPoints   = @crl_info\n")
	contents.WriteString("extendedKeyUsage        = clientAuth,codeSigning,emailProtection\n")
	contents.WriteString("keyUsage                = critical,digitalSignature\n")

	if !settings.Public {
		contents.WriteString("nameConstraints         = @name_constraints\n")
	}

	contents.WriteString("subjectAltName          = email:move\n")
	contents.WriteString("subjectKeyIdentifier    = hash\n")

	return contents.Bytes()
}
