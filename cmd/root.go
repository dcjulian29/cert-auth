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
package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/dcjulian29/cert-auth/internal/certauth"
	"github.com/dcjulian29/go-toolbox/color"
	"github.com/spf13/cobra"
	"go.szostok.io/version/extension"
	"golang.org/x/term"
)

var (
	cfgFile    string
	folderPath string
	settings   certauth.Authority

	rootCmd = &cobra.Command{
		Use:   "cert-auth",
		Short: "cert-auth provides the commands to run a certificate authority",
		Long:  `cert-auth provides the commands to run a certificate authority`,
	}
)

func Execute() {
	rootCmd.AddCommand(
		extension.NewVersionCobraCmd(
			extension.WithUpgradeNotice("dcjulian29", "cert-auth"),
		),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "\n"+color.Fatal(err.Error()))
		os.Exit(1)
	}
}

func init() {
	pwd, _ := os.Getwd()

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "specify authority configuration file")
	rootCmd.PersistentFlags().StringVar(&folderPath, "path", pwd, "path to certificate authority folder")

	cobra.OnInitialize(initialize_authority)
}

func askPassword(filePath string) string {
	fmt.Printf("\033[1;35mEnter pass phrase for %s:\033[0m ", filePath)

	p, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	cobra.CheckErr(err)

	return string(p)
}

func ensureAuthorityDirectory() {
	if err := os.Chdir(folderPath); err != nil {
		cobra.CheckErr(err)
	}
}

func executeExternalProgram(program string, params ...string) error {
	cmd := exec.Command(program, params...)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout

	return cmd.Run()
}

func executeExternalProgramCapture(program string, params ...string) string {
	cmd := exec.Command(program, params...)
	cmd.Stdin = os.Stdin
	out, err := cmd.CombinedOutput()
	cobra.CheckErr(err)

	return string(out)
}

func findFiles(dirPath, extension string) []string {
	var files []string

	filepath.WalkDir(dirPath, func(f string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}

		if filepath.Ext(d.Name()) == extension {
			files = append(files, f)
		}

		return nil
	})

	return files
}

func getRandomId(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	cobra.CheckErr(err)

	return hex.EncodeToString(bytes)
}

func info(message string) {
	fmt.Printf("\n\033[1;36m%s\033[0m\n", message)
}
