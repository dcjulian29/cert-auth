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
	"bytes"
	"fmt"
	"strings"

	"github.com/dcjulian29/go-toolbox/execute"
	"github.com/dcjulian29/go-toolbox/filesystem"
)

func NewRequest(requestFile, keyFile, pass string, data RequestData) error {
	settings, err := GetSettings()
	if err != nil {
		return err
	}

	if len(data.Country) == 0 {
		data.Country = settings.Country
	}

	if len(data.Organization) == 0 {
		data.Organization = settings.Organization
	}

	if data.RequestType == CertificateTypeClient {
		if !strings.Contains(data.Name, "@") {
			data.Name = fmt.Sprintf("%s@%s", data.Name, settings.Domain)
		}
	}

	configFile := fmt.Sprintf("%s.cnf", requestFile)

	var contents bytes.Buffer

	contents.WriteString("[req]\n")
	contents.WriteString("default_md = sha256\n")
	contents.WriteString("utf8 = yes\n")
	contents.WriteString("string_mask = utf8only\n")
	contents.WriteString("prompt = no\n")
	contents.WriteString("distinguished_name = req_subj\n")

	if data.RequestType == CertificateTypeServer {
		contents.WriteString("req_extensions = server_req\n\n")

		contents.Write(cnf_san(data.Name, data.AdditionalNames))
	}

	if data.RequestType == CertificateTypeClient {
		contents.WriteString("req_extensions = client_req\n\n")
		contents.WriteString("[ client_req ]\n")
		contents.WriteString("keyUsage = nonRepudiation, digitalSignature, keyEncipherment\n")
		fmt.Fprintf(&contents, "subjectAltName = email:%s\n", data.Name)
	}

	contents.Write(RequestSubject(data))

	if err := filesystem.EnsureFileExist(configFile, contents.Bytes()); err != nil {
		return err
	}

	if len(pass) == 0 {
		pass, err = AskPassword(keyFile)
		if err != nil {
			return err
		}
	}

	return execute.ExternalProgram("openssl", []string{
		"req",
		fmt.Sprintf("-config %s", configFile),
		"-new",
		fmt.Sprintf("-key %s", keyFile),
		fmt.Sprintf("-out %s", requestFile),
		fmt.Sprintf("-passin pass:%s", pass),
	}...)
}
