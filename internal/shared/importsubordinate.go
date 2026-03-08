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
	"strings"

	"github.com/dcjulian29/go-toolbox/execute"
)

func ImportSubordinate(filePath, pass string) (string, string, error) {
	id, err := ImportRequest(filePath)
	if err != nil {
		return "", "", err
	}

	SignRequest(id, pass, 1825)

	serial, _ := execute.ExternalProgramCapture("openssl", []string{
		"x509",
		"-noout",
		fmt.Sprintf("-in ./certs/%s.pem", id),
		"-serial",
	}...)

	serial = strings.TrimRight(strings.Replace(serial, "serial=", "", 1), "\r\n")

	return id, serial, nil
}
