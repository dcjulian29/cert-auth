package shared

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

import (
	"bytes"
	"fmt"
)

// RequestSubject builds the [req_subj] section of an OpenSSL configuration
// file from the given RequestData and returns it as a byte slice. The country
// and organization are always included. State, locality, and organizational
// unit are only written when their respective fields are non-empty. The common
// name is always written last using the Name field.
func RequestSubject(data RequestData) []byte {
	var contents bytes.Buffer

	fmt.Fprintf(&contents, "[req_subj]\ncountryName = %s\n", data.Country)

	if len(data.State) > 0 {
		fmt.Fprintf(&contents, "stateOrProvinceName = %s\n", data.State)
	}

	if len(data.Locality) > 0 {
		fmt.Fprintf(&contents, "localityName = %s\n", data.Locality)
	}

	fmt.Fprintf(&contents, "organizationName = %s\n", data.Organization)

	if len(data.OrganizationalUnit) > 0 {
		fmt.Fprintf(&contents, "organizationUnitName = %s\n", data.OrganizationalUnit)
	}

	fmt.Fprintf(&contents, "commonName = %s\n", data.Name)

	return contents.Bytes()
}
