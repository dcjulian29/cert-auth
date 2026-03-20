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

	"github.com/dcjulian29/go-toolbox/filesystem"
)

// IsCertificateAuthority checks whether the current working directory contains
// a certificate authority by verifying the presence of a ca.yml configuration
// file. Returns an error if the file does not exist.
func IsCertificateAuthority() error {
	if !filesystem.FileExists("ca.yml") {
		return errors.New("this is not a certificate authority")
	}

	return nil
}
