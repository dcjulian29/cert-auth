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

	"github.com/dcjulian29/go-toolbox/filesystem"
)

// ValidateSubordinate verifies that the subordinate CA identified by name has
// a serial number matching the given id. It loads the subordinate's Authority
// configuration from its subdirectory via LoadSubordinate and compares the
// stored serial against id. Returns nil if they match, or an error if the
// subordinate's directory does not exist, the configuration cannot be loaded,
// or the serial number does not match.
func ValidateSubordinate(id string, name string) error {
	if filesystem.DirectoryExist(name) {
		s, err := LoadSubordinate(name)
		if err != nil {
			return err
		}

		if s.Serial == id {
			return nil
		}

		return fmt.Errorf("serial '%s' from the subordinate '%s' does not match '%s'", s.Serial, name, id)
	}

	return fmt.Errorf("the directory for subordinate '%s' does not exist", name)
}
