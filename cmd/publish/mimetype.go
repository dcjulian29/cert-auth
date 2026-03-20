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

package publish

import (
	"bytes"

	"github.com/dcjulian29/go-toolbox/filesystem"
)

func mimeTypes(filePath string) error {
	var contents bytes.Buffer

	contents.WriteString("application/pkcs7-mime              .p7c\n")
	contents.WriteString("application/pkcs8                   .p8  .key\n")
	contents.WriteString("application/pkcs10                  .p10 .csr\n")
	contents.WriteString("application/pkix-cert               .cer\n")
	contents.WriteString("application/pkix-crl                .crl\n")
	contents.WriteString("application/x-pem-file              .pem\n")
	contents.WriteString("application/x-pkcs7-certificates    .p7b .spc\n")
	contents.WriteString("application/x-pkcs7-certreqresp     .p7r\n")
	contents.WriteString("application/x-pkcs7-crl             .crl\n")
	contents.WriteString("application/x-pkcs12                .p12 .pfx\n")
	contents.WriteString("application/x-x509-ca-cert          .crt .der\n")
	contents.WriteString("application/x-x509-user-cert        .crt\n")

	return filesystem.EnsureFileExist(filePath, contents.Bytes())
}
