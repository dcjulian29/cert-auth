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
	"io"
	"net/http"
	"path/filepath"

	"github.com/dcjulian29/go-toolbox/color"
	"github.com/dcjulian29/go-toolbox/execute"
	"github.com/dcjulian29/go-toolbox/filesystem"
)

func ValidateCertificate(path string, bundle bool) error {
	if !filesystem.FileExists(path) {
		return fmt.Errorf("'%s' does not exists or is not accessable", path)
	}

	ca := filepath.Join("certs", "ca-chain.pem")

	if !filesystem.FileExists(ca) {
		ca = filepath.Join("certs", "ca.pem")
	}

	if bundle {
		ca = filepath.Join("certs", "ca-bundle.pem")

		fmt.Println(color.Warn("Downloading Mozilla's ca-bundle.pem..."))

		resp, err := http.Get("https://curl.se/ca/cacert.pem")
		if err != nil {
			return err
		}

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		filesystem.EnsureFileExist(ca, body)
	}

	execute.ExternalProgram("openssl", []string{
		"verify",
		fmt.Sprintf("-CAfile %s", ca),
		path,
	}...)

	return nil
}
