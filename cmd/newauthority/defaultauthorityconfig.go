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

func defaultAuthorityConfig() []byte {
	var contents bytes.Buffer

	contents.WriteString("\n[ca_default]\n")
	contents.WriteString("home                    = .\n")
	contents.WriteString("database                = $home/db/index\n")
	contents.WriteString("serial                  = $home/db/serial\n")
	contents.WriteString("crlnumber               = $home/db/crlnumber\n")
	contents.WriteString("certificate             = $home/certs/ca.pem\n")
	contents.WriteString("private_key             = $home/private/ca.key\n")
	contents.WriteString("RANDFILE                = $home/private/random\n")
	contents.WriteString("new_certs_dir           = $home/certs\n")
	contents.WriteString("unique_subject          = no\n")
	contents.WriteString("default_md              = sha256\n")

	return contents.Bytes()
}
