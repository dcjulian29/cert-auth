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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dcjulian29/go-toolbox/filesystem"
	"gopkg.in/yaml.v2"
)

// LoadSubordinate loads and returns the Authority configuration for the named
// subordinate CA. It first verifies that the named subordinate is registered
// with the current authority via SubordinateExists, then reads and unmarshals
// the ca.yml file from the subordinate's subdirectory. Returns an error if the
// subordinate is not registered, its directory does not exist, the ca.yml file
// is missing or unreadable, or the YAML cannot be unmarshalled.
func LoadSubordinate(name string) (*Authority, error) {
	cfg := &Authority{}

	exist, err := SubordinateExists(name)
	if err != nil {
		return cfg, err
	}

	if !exist {
		return cfg, fmt.Errorf("'%s' is not a subordinate of this authority", name)
	}

	if filesystem.DirectoryExists(name) {
		pwd, _ := os.Getwd()
		filePath := filepath.Join(pwd, name, "ca.yml")

		if !filesystem.FileExists(filePath) {
			return cfg, errors.New("certification authority configuration not found")
		}

		file, err := os.ReadFile(filePath)
		if err != nil {
			return cfg, fmt.Errorf("could not read certification authority configuration: %w", err)
		}

		err = yaml.Unmarshal(file, &cfg)
		if err != nil {
			return cfg, fmt.Errorf("unable to load certification authority configuration: %w", err)
		}

		return cfg, nil
	}

	return cfg, fmt.Errorf("the directory for subordinate '%s' does not exist", name)
}
