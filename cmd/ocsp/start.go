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

package ocsp

import (
	"fmt"
	"os"
	"strings"

	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/dcjulian29/go-toolbox/docker"
)

func start(port int, background bool) error {
	settings, err := shared.GetSettings()
	if err != nil {
		return err
	}

	name := fmt.Sprintf("ocsp_%s", settings.Name)

	if running(name) {
		return fmt.Errorf("'%s' OCSP responder is already running", settings.Name)
	}

	pwd, err := os.Getwd()
	if err != nil {
		return err
	}

	opts := docker.ContainerOptions{
		AdditionalArgs: []string{
			"-port", "8080",
			"-index", "db/index",
			"-rsigner", "certs/ocsp.pem",
			"-rkey", "private/ocsp.key",
			"-CA", "certs/ca.pem",
			"-text",
		},
		Command:     "ocsp",
		Image:       "dcjulian29/openssl",
		Interactive: !background,
		Name:        name,
		Ports:       []string{fmt.Sprintf("%d:8080/tcp", port)},
		Tag:         "latest",
		Volumes:     []string{fmt.Sprintf("%s:/data", strings.ReplaceAll(pwd, "\\", "/"))},
	}

	_, err = docker.Run(opts)

	return err
}
