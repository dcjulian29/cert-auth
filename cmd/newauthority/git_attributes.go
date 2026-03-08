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

	"github.com/dcjulian29/go-toolbox/filesystem"
)

func git_attributes() error {
	var contents bytes.Buffer

	contents.WriteString("*       text eol=lf\n")
	contents.WriteString("*.cer   binary\n")
	contents.WriteString("*.csr   text\n")
	contents.WriteString("*.crl   text\n")
	contents.WriteString("*.crt   binary\n")
	contents.WriteString("*.der   binary\n")
	contents.WriteString("*.pem   text\n")
	contents.WriteString("*.p12   binary\n")
	contents.WriteString("*.pfx   binary\n")
	contents.WriteString("*.key   text\n")

	return filesystem.EnsureFileExist(".gitattributes", contents.Bytes())
}
