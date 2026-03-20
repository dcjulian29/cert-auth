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

func defaultConfig() []byte {
	var contents bytes.Buffer

	contents.WriteString("aia_url                 = http://pki.$domain_suffix/$name.crt\n")
	contents.WriteString("crl_url                 = http://pki.$domain_suffix/$name.crl\n")

	if settings.OCSP {
		contents.WriteString("ocsp_url                =  http://ocsp-$name.$domain_suffix\n")
	}

	contents.WriteString("default_ca              = ca_default\n")
	contents.WriteString("name_opt                = utf8,esc_ctrl,multiline,lname,align\n")

	return contents.Bytes()
}
