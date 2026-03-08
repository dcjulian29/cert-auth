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

	"github.com/dcjulian29/go-toolbox/execute"
)

func NewPrivateKey(filePath string, keyType KeyType, pass string) error {
	var (
		keyPass string
		err     error
	)

	if len(pass) == 0 {
		keyPass, err = AskPassword(filePath)
		if err != nil {
			return err
		}
	} else {
		keyPass = pass
	}

	switch keyType {
	case Edwards:
		if err := execute.ExternalProgram("openssl", []string{
			"genpkey",
			"-algorithm ed25519",
			fmt.Sprintf("-out %s", filePath),
			"-aes-256-cfb",
			fmt.Sprintf("-pass pass:%s", keyPass),
		}...); err != nil {
			return err
		}

	case Elliptic:
		if err := execute.ExternalProgram("openssl", []string{
			"ecparam",
			"-name secp521r1",
			"-genkey",
			"-noout",
			fmt.Sprintf("-out %s", filePath),
		}...); err != nil {
			return err
		}

		if err := execute.ExternalProgram("openssl", []string{
			"ec",
			"-aes-256-cfb",
			fmt.Sprintf("-in %s", filePath),
			fmt.Sprintf("-out %s.tmp", filePath),
			fmt.Sprintf("-passout pass:%s", keyPass),
		}...); err != nil {
			return err
		}

		if err := os.Remove(filePath); err != nil {
			return err
		}

		if err := os.Rename(fmt.Sprintf("%s.tmp", filePath), filePath); err != nil {
			return err
		}

	case RSA:
		param := []string{
			"genrsa",
			fmt.Sprintf("-out %s", filePath),
			"-verbose",
			"-aes-256-cfb",
			fmt.Sprintf("-passout pass:%s", keyPass),
		}

		_, err := GetSettings()
		if err != nil {
			param = append(param, "4096")
		} else {
			param = append(param, "2048")
		}

		if err = execute.ExternalProgram("openssl", param...); err != nil {
			return err
		}

	default:
		return errors.New("unknown key type")
	}

	return nil
}
