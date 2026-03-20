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

// SubordinateExists reports whether a subordinate CA with the given name is
// registered with the current root certificate authority. It first verifies
// that the current directory is a certificate authority and specifically a root
// authority, then searches the authority's Subordinates list for a matching
// name. Returns false and an error if the current directory is not a
// certificate authority, is not a root authority, or the settings cannot be
// loaded. Returns true and nil if a matching subordinate is found, or false
// and nil if it is not.
func SubordinateExists(name string) (bool, error) {
	if err := IsCertificateAuthority(); err != nil {
		return false, err
	}

	if err := IsRootCertificateAuthority(); err != nil {
		return false, err
	}

	settings, err := GetSettings()
	if err != nil {
		return false, err
	}

	for _, s := range settings.Subordinates {
		if s.Name == name {
			return true, nil
		}
	}

	return false, nil
}
