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

func cnf_ca() error {
	var contents bytes.Buffer

	contents.WriteString("[default]\n")
	fmt.Fprintf(&contents, "name                    = %s\n", settings.Name)
	fmt.Fprintf(&contents, "domain_suffix           = %s\n", settings.Domain)

	contents.Write(cnf_default())

	contents.WriteString("\n[ca_dn]\n")
	fmt.Fprintf(&contents, "countryName             = %s\n", settings.Country)
	fmt.Fprintf(&contents, "organizationName        = %s\n", settings.Organization)
	fmt.Fprintf(&contents, "commonName              = %s\n", settings.CommonName)

	contents.Write(cnf_default_ca())

	if settings.Type == "subordinate" {
		contents.WriteString("copy_extensions         = copy\n")
		contents.WriteString("default_days            = 370\n")
		contents.WriteString("default_crl_days        = 30\n")
	} else {
		contents.WriteString("copy_extensions         = none\n")
		contents.WriteString("default_days            = 3655\n")
		contents.WriteString("default_crl_days        = 365\n")
	}

	if !settings.Public {
		contents.Write(cnf_policy())
	}

	contents.Write(cnf_crl_info())

	if settings.OCSP {
		contents.Write(cnf_ocsp_info())
	} else {
		contents.Write(cnf_issuer_info())
	}

	if !settings.Public {
		contents.Write(cnf_name_constraints())
	}

	contents.WriteString("\n[req]\n")
	contents.WriteString("encrypt_key             = yes\n")
	contents.WriteString("default_md              = sha256\n")
	contents.WriteString("utf8                    = yes\n")
	contents.WriteString("string_mask             = utf8only\n")
	contents.WriteString("prompt                  = no\n")
	contents.WriteString("distinguished_name      = ca_dn\n")
	contents.WriteString("req_extensions          = ca_ext\n")

	contents.Write(ext_ca())

	if settings.OCSP {
		contents.Write(ext_ocsp())
	}

	if settings.TimeStamp {
		contents.Write(ext_timestamp())
	}

	if settings.Type == "subordinate" {
		contents.Write(ext_server())
		contents.Write(ext_client())
	} else {
		contents.Write(ext_subca())
	}

	return filesystem.EnsureFileExist("ca.cnf", contents.Bytes())
}
