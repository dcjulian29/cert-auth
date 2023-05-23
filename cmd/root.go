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
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.szostok.io/version/extension"
)

type CertAuth struct {
	Type         string        `mapstructure:"type"`
	Public       bool          `mapstructure:"public"`
	Name         string        `mapstructure:"authority_name"`
	Domain       string        `mapstructure:"domain"`
	Country      string        `mapstructure:"country"`
	Organization string        `mapstructure:"organization"`
	CommonName   string        `mapstructure:"common_name"`
	OCSP         bool          `mapstructure:"ocsp"`
	TimeStamp    bool          `mapstructure:"timestamp"`
	Serial       string        `mapstructure:"serial"`
	Subordinates []Subordinate `mapstructure:"subordinates"`
}

type Subordinate struct {
	Id   string `mapstructure:"id"`
	Name string `mapstructure:"name"`
}

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

	cobra.OnInitialize(initConfig)
}

func initConfig() {
	if cfgFile != "" {
		folderPath = filepath.Dir(cfgFile)
	}

	viper.AddConfigPath(folderPath)
	viper.SetConfigType("yml")
	viper.SetConfigName("ca")

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintf(os.Stderr, "\033[1;36mUsing config file: %s\033[0m\n", viper.ConfigFileUsed())
	}

	err := viper.Unmarshal(&settings)
	cobra.CheckErr(err)

	if settings.Type != "root" {
		settings.Subordinates = []Subordinate{}
	}
}

func saveConfig(filePath string, authority CertAuth) {
	viper.Set("common_name", authority.CommonName)
	viper.Set("country", authority.Country)
	viper.Set("domain", authority.Domain)
	viper.Set("authority_name", authority.Name)
	viper.Set("ocsp", authority.OCSP)
	viper.Set("organization", authority.Organization)
	viper.Set("public_access", authority.Public)
	viper.Set("timestamp", authority.TimeStamp)
	viper.Set("type", authority.Type)
	viper.Set("serial", authority.Serial)

	if authority.Type == "root" {
		viper.Set("subordinates", authority.Subordinates)
	} else {
		viper.Set("subordinates", []Subordinate{})
	}

	viper.WriteConfigAs(filePath)
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
