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
	"fmt"

	"github.com/dcjulian29/go-toolbox/filesystem"
)

func authorityConfig() error {
	var contents bytes.Buffer

	contents.WriteString("[default]\n")
	fmt.Fprintf(&contents, "name                    = %s\n", settings.Name)
	fmt.Fprintf(&contents, "domain_suffix           = %s\n", settings.Domain)

	contents.Write(defaultConfig())

	contents.WriteString("\n[ca_dn]\n")
	fmt.Fprintf(&contents, "countryName             = %s\n", settings.Country)
	fmt.Fprintf(&contents, "organizationName        = %s\n", settings.Organization)
	fmt.Fprintf(&contents, "commonName              = %s\n", settings.CommonName)

	contents.Write(defaultAuthorityConfig())

	if settings.Type == "subordinate" {
		contents.WriteString("copy_extensions         = copy\n")
		contents.WriteString("default_days            = 365\n")
		contents.WriteString("default_crl_days        = 30\n")
	} else {
		contents.WriteString("copy_extensions         = none\n")
		contents.WriteString("default_days            = 3650\n")
		contents.WriteString("default_crl_days        = 365\n")
	}

	if !settings.Public {
		contents.Write(policyConfig())
	}

	contents.Write(crlInfoConfig())

	if settings.OCSP {
		contents.Write(ocspInfoConfig())
	} else {
		contents.Write(issuerInfoConfig())
	}

	if !settings.Public {
		contents.Write(nameConstraintsConfig())
	}

	contents.WriteString("\n[req]\n")
	contents.WriteString("encrypt_key             = yes\n")
	contents.WriteString("default_md              = sha256\n")
	contents.WriteString("utf8                    = yes\n")
	contents.WriteString("string_mask             = utf8only\n")
	contents.WriteString("prompt                  = no\n")
	contents.WriteString("distinguished_name      = ca_dn\n")
	contents.WriteString("req_extensions          = ca_ext\n")

	contents.Write(authorityExtension())

	if settings.OCSP {
		contents.Write(ocspExtension())
	}

	if settings.TimeStamp {
		contents.Write(timestampExtension())
	}

	if settings.Type == "subordinate" {
		contents.Write(serverExtension())
		contents.Write(clientExtension())
	} else {
		contents.Write(subordinateExtension())
	}

	return filesystem.EnsureFileExist("ca.cnf", contents.Bytes())
}
