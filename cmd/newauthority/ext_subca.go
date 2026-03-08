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

func ext_subca() []byte {
	var contents bytes.Buffer

	contents.WriteString("\n[subca_ext]\n")
	contents.WriteString("authorityInfoAccess     = @issuer_info\n")
	contents.WriteString("authorityKeyIdentifier  = keyid:always\n")
	contents.WriteString("basicConstraints        = critical,CA:true,pathlen:0\n")
	contents.WriteString("crlDistributionPoints   = @crl_info\n")
	contents.WriteString("extendedKeyUsage        = clientAuth,serverAuth\n")
	contents.WriteString("keyUsage                = critical,keyCertSign,cRLSign\n")
	contents.WriteString("subjectKeyIdentifier    = hash\n")

	if !settings.Public {
		contents.WriteString("nameConstraints         = @name_constraints\n")
	}

	return contents.Bytes()
}
