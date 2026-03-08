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

func ext_ca() []byte {
	var contents bytes.Buffer

	contents.WriteString("\n[ca_ext]\n")
	contents.WriteString("basicConstraints        = critical,CA:true\n")
	contents.WriteString("keyUsage                = critical,keyCertSign,cRLSign\n")
	contents.WriteString("subjectKeyIdentifier    = hash\n")

	return contents.Bytes()
}
