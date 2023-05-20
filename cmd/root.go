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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.szostok.io/version/extension"
)

type CertAuth struct {
	Type         string
	Public       bool
	Name         string
	Domain       string
	Country      string
	Organization string
	CommonName   string
	OCSP         bool
	TimeStamp    bool
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

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "specify configuration file")
	rootCmd.PersistentFlags().StringVar(&folderPath, "path", pwd, "path to certificate authority folder")

	cobra.OnInitialize(initConfig)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		pwd, err := os.Getwd()
		cobra.CheckErr(err)

		viper.AddConfigPath(pwd)
		viper.SetConfigType("yml")
		viper.SetConfigName(".cert-auth")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}

	settings.Type = viper.GetString("type")
	settings.Public = viper.GetBool("public")
	settings.Name = viper.GetString("name")
	settings.Domain = viper.GetString("domain")
	settings.Country = viper.GetString("country")
	settings.Organization = viper.GetString("organization")
	settings.CommonName = viper.GetString("common_name")
	settings.OCSP = viper.GetBool("ocsp")
	settings.TimeStamp = viper.GetBool("timestamp")
}

func ensureAuthorityDirectory() {
	if workingDirectory != folderPath {
		if err := os.Chdir(folderPath); err != nil {
			cobra.CheckErr(err)
			os.Exit(1)
		}
	}
}

func ensureWorkingDirectoryAndExit() {
	if workingDirectory != folderPath {
		if err := os.Chdir(workingDirectory); err != nil {
			cobra.CheckErr(err)
			os.Exit(1)
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
		cobra.CheckErr(err)
		ensureWorkingDirectoryAndExit()
	}
}
