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
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dcjulian29/go-toolbox/filesystem"
	"gopkg.in/yaml.v2"
)

func LoadSubordinate(name string) (Authority, error) {
	exist, err := SubordinateExists(name)
	if err != nil {
		return Authority{}, err
	} else {
		if !exist {
			return Authority{}, fmt.Errorf("'%s' is not a subordinate of this authority", name)
		}
	}

	if filesystem.DirectoryExists(name) {
		pwd, _ := os.Getwd()
		filePath := filepath.Join(pwd, name, "ca.yml")

		if !filesystem.FileExists(filePath) {
			return Authority{}, errors.New("certification authority configuration not found")
		}

		var cfg Authority

		file, err := os.ReadFile(filePath)
		if err != nil {
			return Authority{}, fmt.Errorf("could not read certification authority configuration: %w", err)
		}

		err = yaml.Unmarshal(file, cfg)
		if err != nil {
			return Authority{}, fmt.Errorf("unable to load certification authority configuration: %w", err)
		}

		return cfg, nil
	}

	return Authority{}, fmt.Errorf("the directory for subordinate '%s' does not exist", name)
}
