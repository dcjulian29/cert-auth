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
	"fmt"
)

// AddSubordinate appends a new Subordinate with the given name and serial
// to the authority's Subordinates list. If a subordinate with the same name
// already exists, it returns nil and an error. Returns the updated slice of
// Subordinates on success.
func AddSubordinate(authority Authority, name, serial string) ([]Subordinate, error) {
	subordinate := Subordinate{Name: name, ID: serial}
	n := []Subordinate{}
	found := false

	for _, s := range authority.Subordinates {
		if s.Name == subordinate.Name {
			found = true
		} else {
			n = append(n, s)
		}
	}

	if !found {
		n = append(n, subordinate)

		return n, nil
	}

	return nil, fmt.Errorf("subordinate '%s' already exist in root authority", name)
}
