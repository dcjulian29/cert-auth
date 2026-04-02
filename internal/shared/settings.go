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
	"sync"

	"github.com/dcjulian29/go-toolbox/filesystem"
	"gopkg.in/yaml.v2"
)

var (
	instance *Authority
	loadErr  error
	mutex    sync.RWMutex
	once     sync.Once
)

// GetSettings loads and returns the Authority configuration from the ca.yml file
// in the current working directory. The settings are loaded once and cached for
// subsequent calls. Returns an error if the file cannot be read or parsed.
func GetSettings() (Authority, error) {
	once.Do(func() {
		instance, loadErr = load()
	})

	mutex.RLock()
	defer mutex.RUnlock()

	if instance == nil {
		return Authority{}, loadErr
	}

	return *instance, loadErr
}

// SaveSettings persists the provided Authority configuration to the ca.yml file
// in the current working directory and updates the cached instance. Returns an
// error if authority is nil or if the file cannot be written.
func SaveSettings(authority *Authority) error {
	if authority == nil {
		return errors.New("can not save settings with an uninitialized authority")
	}

	mutex.Lock()
	defer mutex.Unlock()

	if err := save(authority); err != nil {
		return err
	}

	instance = authority

	return nil
}

// SaveSubordinateSettings writes the given subordinate Authority configuration
// as a ca.yml file under a subdirectory named after the subordinate. If the
// subordinate name matches the current directory name, it writes ca.yml directly
// into the current directory. Returns an error if the file already exists or
// if marshalling the YAML fails.
func SaveSubordinateSettings(subordinate Authority) error {
	yaml, err := yaml.Marshal(subordinate)
	if err != nil {
		return err
	}

	var filePath string

	pwd, _ := os.Getwd()

	if filesystem.IsCurrentDirectoryName(subordinate.Name) {
		filePath = filepath.Join(pwd, "ca.yml")
	} else {
		filePath = filepath.Join(pwd, subordinate.Name, "ca.yml")
	}

	if filesystem.FileExist(filePath) {
		return errors.New("subordinate configuration file already exists")
	}

	return filesystem.EnsureFileExist(filePath, yaml)
}

func load() (*Authority, error) {
	pwd, _ := os.Getwd()
	filePath := filepath.Join(pwd, "ca.yml")

	cfg := &Authority{}

	if !filesystem.FileExist(filePath) {
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

func save(authority *Authority) error {
	yaml, err := yaml.Marshal(authority)
	if err != nil {
		return err
	}

	pwd, _ := os.Getwd()
	filePath := filepath.Join(pwd, "ca.yml")

	if filesystem.FileExist(filePath) {
		if err := os.Remove(filePath); err != nil {
			return err
		}
	}

	return filesystem.EnsureFileExist(filePath, yaml)
}
