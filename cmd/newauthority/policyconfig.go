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
)

func policyConfig() []byte {
	var contents bytes.Buffer
	var policy string

	if strictPolicy {
		policy = "policy_c_o_match"
	} else {
		policy = "policy_o_match"
	}

	fmt.Fprintf(&contents, "policy                  = %s\n", policy)
	contents.WriteString("\n[policy_c_o_match]\n")
	contents.WriteString("countryName             = match\n")
	contents.WriteString("stateOrProvinceName     = optional\n")
	contents.WriteString("organizationName        = match\n")
	contents.WriteString("organizationalUnitName  = optional\n")
	contents.WriteString("commonName              = supplied\n")
	contents.WriteString("emailAddress            = optional\n")
	contents.WriteString("\n[policy_o_match]\n")
	contents.WriteString("countryName             = optional\n")
	contents.WriteString("stateOrProvinceName     = optional\n")
	contents.WriteString("organizationName        = match\n")
	contents.WriteString("organizationalUnitName  = optional\n")
	contents.WriteString("commonName              = supplied\n")
	contents.WriteString("emailAddress            = optional\n")

	return contents.Bytes()
}
