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

// Package cmd implements the command-line interface for cert-auth using Cobra.
// It defines the root command and registers all subcommands for managing
// a certificate authority, including initialization, certificate issuance,
// revocation, and subordinate CA management.
package cmd

import (
	"fmt"
	"os"

	"github.com/dcjulian29/cert-auth/cmd/certificate"
	"github.com/dcjulian29/cert-auth/cmd/crl"
	"github.com/dcjulian29/cert-auth/cmd/importauthority"
	"github.com/dcjulian29/cert-auth/cmd/newauthority"
	"github.com/dcjulian29/cert-auth/cmd/ocsp"
	"github.com/dcjulian29/cert-auth/cmd/publish"
	"github.com/dcjulian29/cert-auth/cmd/remove"
	"github.com/dcjulian29/cert-auth/cmd/revoke"
	"github.com/dcjulian29/cert-auth/cmd/settings"
	"github.com/dcjulian29/cert-auth/cmd/timestamp"
	"github.com/dcjulian29/cert-auth/cmd/update"
	"github.com/dcjulian29/go-toolbox/textformat"
	"github.com/spf13/cobra"
	"go.szostok.io/version/extension"
)

var rootCmd = &cobra.Command{
	Use:           "cert-auth",
	Short:         "cert-auth provides the commands to run a certificate authority",
	Long:          `cert-auth provides the commands to run a certificate authority`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

// Execute adds the version command (with upgrade notice) to the root command
// and runs the CLI. If the root command returns an error, it is printed to
// stderr as a fatal-formatted message and the process exits with code 1.
func Execute() {
	rootCmd.AddCommand(
		extension.NewVersionCobraCmd(
			extension.WithUpgradeNotice("dcjulian29", "cert-auth"),
		),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "\n"+textformat.Fatal(err.Error()))
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(certificate.NewCommand())
	rootCmd.AddCommand(crl.NewCommand())
	rootCmd.AddCommand(importauthority.NewCommand())
	rootCmd.AddCommand(newauthority.NewCommand())
	rootCmd.AddCommand(ocsp.NewCommand())
	rootCmd.AddCommand(publish.NewCommand())
	rootCmd.AddCommand(remove.NewCommand())
	rootCmd.AddCommand(revoke.NewCommand())
	rootCmd.AddCommand(settings.NewCommand())
	rootCmd.AddCommand(timestamp.NewCommand())
	rootCmd.AddCommand(update.NewCommand())
}
