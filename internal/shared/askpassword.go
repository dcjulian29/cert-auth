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
	"os"
	"path/filepath"

	"golang.org/x/term"
)

func AskPassword(filePath string) (string, error) {
	pwd, _ := os.Getwd()
	filePath = filepath.Join(pwd, filePath)

	fmt.Printf("\033[1;35mEnter pass phrase for %s:\033[0m ", filePath)

	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	if err != nil {
		return "", nil
	}

	return string(p), nil
}
