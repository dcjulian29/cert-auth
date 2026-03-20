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

func editorConfig() error {
	var contents bytes.Buffer

	contents.WriteString("root = true\n\n")
	contents.WriteString("[*]\n")
	contents.WriteString("end_of_line = lf\n")
	contents.WriteString("indent_style = space\n")
	contents.WriteString("indent_size = 2\n")
	contents.WriteString("trim_trailing_whitespace = true\n")
	contents.WriteString("insert_final_newline = true\n\n")
	contents.WriteString("[{*.pem,*.crl,*.csr,*.key}]\n")
	contents.WriteString("insert_final_newline = false\n")

	return filesystem.EnsureFileExist(".editorconfig", contents.Bytes())
}
