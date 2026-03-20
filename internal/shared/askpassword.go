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

// AskPassword prompts the user to enter a pass phrase for the file at the given
// filePath, resolved relative to the current working directory. Input is read
// securely without echo using the terminal raw mode. Returns the entered
// password as a string, or an error if reading fails.
func AskPassword(filePath string) (string, error) {
	pwd, _ := os.Getwd()
	filePath = filepath.Join(pwd, filePath)

	fmt.Printf("\033[1;35mEnter pass phrase for %s:\033[0m ", filePath)

	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	if err != nil {
		return "", err
	}

	return string(p), nil
}
