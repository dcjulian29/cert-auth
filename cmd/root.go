/*
Copyright © 2023 Julian Easterling julian@julianscorner.com

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
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
	"go.szostok.io/version/extension"
	"golang.org/x/term"
)

var (
	cfgFile          string
	folderPath       string
	workingDirectory string
	settings         CertAuth

	rootCmd = &cobra.Command{
		Use:   "cert-auth",
		Short: "cert-auth provides the commands to run a certificate authority",
		Long:  `cert-auth provides the commands to run a certificate authority`,
	}
)

func Execute() {
	workingDirectory, _ = os.Getwd()

	rootCmd.AddCommand(
		extension.NewVersionCobraCmd(
			extension.WithUpgradeNotice("dcjulian29", "cert-auth"),
		),
	)

	if err := rootCmd.Execute(); err != nil {
		cobra.CheckErr(err)
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

func copyFile(src, dst string) {
	if fileExists(src) {
		if fileExists(dst) {
			err := os.Remove(dst)
			cobra.CheckErr(err)
		}

		source, err := os.Open(src)
		cobra.CheckErr(err)

		defer source.Close()

		destination, err := os.Create(dst)
		cobra.CheckErr(err)

		defer destination.Close()

		_, err = io.Copy(destination, source)
		cobra.CheckErr(err)
	}
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}

	return info.IsDir()
}

func ensureAuthorityDirectory() {
	if workingDirectory != folderPath {
		if err := os.Chdir(folderPath); err != nil {
			cobra.CheckErr(err)
		}
	}
}

func ensureDir(dirPath string) error {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return err
		}
	}

	return nil
}

func ensureWorkingDirectoryAndExit() {
	if workingDirectory != folderPath {
		if err := os.Chdir(workingDirectory); err != nil {
			cobra.CheckErr(err)
		}
	}

	os.Exit(0)
}

func executeExternalProgram(program string, params ...string) {
	cmd := exec.Command(program, params...)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout

	if err := cmd.Run(); err != nil {
		ensureWorkingDirectoryAndExit()
	}
}

func executeExternalProgramCapture(program string, params ...string) string {
	cmd := exec.Command(program, params...)
	cmd.Stdin = os.Stdin
	out, err := cmd.CombinedOutput()
	cobra.CheckErr(err)

	return string(out)
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}

	return !info.IsDir()
}

func info(message string) {
	fmt.Printf("\n\033[1;36m%s\033[0m\n", message)
}
