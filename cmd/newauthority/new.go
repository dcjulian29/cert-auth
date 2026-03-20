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

// Package newauthority provides the CLI command for creating new root and
// subordinate certificate authorities.
package newauthority

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/dcjulian29/go-toolbox/execute"
	"github.com/dcjulian29/go-toolbox/filesystem"
	"github.com/dcjulian29/go-toolbox/textformat"
	"github.com/spf13/cobra"
)

var (
	// strictPolicy enforces that certificate requests must match both the
	// organization and country of the authority.
	strictPolicy bool

	// keyPass holds the CA private key password collected interactively during
	// authority creation.
	keyPass string

	// privateKeyType is the cryptographic algorithm used when generating the CA
	// private key, defaulting to Elliptic (EC secp521r1).
	privateKeyType shared.KeyType = shared.Elliptic

	// rootAuth holds the settings of the root certificate authority when
	// creating a subordinate authority.
	rootAuth shared.Authority

	// settings holds the settings for the authority being created.
	settings shared.Authority
)

// NewCommand returns a cobra.Command that creates a new root or subordinate
// certificate authority. For a root authority, the command verifies that the
// current directory is not already an authority. For a subordinate authority,
// it verifies that the current directory is a root certificate authority. The
// command initializes the authority directory structure (certs, csr, db,
// private), generates a serial number, creates ca.cnf, generates a private
// key and CSR, then either self-signs the root CA certificate or imports the
// subordinate CSR into the root authority, builds the certificate chain, and
// registers the subordinate in the root's settings. If OCSP or timestamping
// are enabled, their respective certificates are generated immediately after
// creation. For root authorities, optional SCM support files (.gitignore,
// .gitattributes, .editorconfig) can also be generated. Returns an error if
// any directory, file, OpenSSL, or settings operation fails.
//
// Flags:
//
//	    --root           create a new root certificate authority (default: true)
//	    --subordinate    create a new subordinate certificate authority
//	    --cn             common name for the authority
//	-c, --country        country where the authority resides legally (default: US)
//	-d, --domain         domain serviced by the authority (default: contoso.local)
//	-n, --name           name of the authority
//	-o, --ocsp           enable OCSP in this authority
//	    --org            organization name serviced by the authority (default: Contoso)
//	-t, --timestamp      enable timestamping in this authority
//	-p, --public         enable this authority for third-party certificates
//	-s, --strict         match both organization and country in certificate requests
//	    --scm            include generation of SCM support files (root only)
//	    --keytype        algorithm to use for the private key: edwards, elliptic, rsa
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Create a new certificate authority.",
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			if s, _ := cmd.Flags().GetBool("subordinate"); s {
				return shared.IsRootCertificateAuthority()
			}

			if err := shared.IsCertificateAuthority(); err == nil {
				return errors.New("this is already a certificate authority")
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			pwd, _ := os.Getwd()

			if s, _ := cmd.Flags().GetBool("subordinate"); s {
				name, _ := cmd.Flags().GetString("name")

				if !cmd.Flags().Lookup("name").Changed {
					name = "subca"
				}

				if filesystem.FileExists(filepath.Join(pwd, name, "ca.yml")) {
					return fmt.Errorf("'%s' is already a subordinate authority", name)
				}

				fmt.Println(textformat.Info("Creating new subordinate authority folder ..."))
				if err := filesystem.EnsureDirectoryExist(name); err != nil {
					return err
				}

				if err := os.Chdir(name); err != nil {
					return err
				}

			}

			fmt.Println(textformat.Info("Creating certificate authority directories..."))

			for _, folder := range []string{"certs", "csr", "db", "private"} {
				if err := filesystem.EnsureDirectoryExist(folder); err != nil {
					return err
				}
			}

			fmt.Println(textformat.Info("Initalizing certificate authority..."))

			if s, _ := cmd.Flags().GetBool("subordinate"); s {
				var err error
				rootAuth, err = shared.GetSettings()
				if err != nil {
					return err
				}

				settings.Type = "subordinate"
			} else {
				settings.Type = "root"
			}

			settings.Public, _ = cmd.Flags().GetBool("public")

			if !cmd.Flags().Lookup("name").Changed {
				if s, _ := cmd.Flags().GetBool("subordinate"); s {
					settings.Name = "intermediate"
				} else {
					settings.Name = "root"
				}
			} else {
				settings.Name, _ = cmd.Flags().GetString("name")
			}

			if cmd.Flags().Lookup("cn").Changed {
				settings.CommonName, _ = cmd.Flags().GetString("cn")
			} else {
				settings.CommonName = settings.Name
			}

			if s, _ := cmd.Flags().GetBool("subordinate"); s && !cmd.Flags().Lookup("domain").Changed {
				settings.Domain = rootAuth.Domain
			} else {
				settings.Domain, _ = cmd.Flags().GetString("domain")
			}

			if s, _ := cmd.Flags().GetBool("subordinate"); s && !cmd.Flags().Lookup("country").Changed {
				settings.Country = rootAuth.Country
			} else {
				settings.Country, _ = cmd.Flags().GetString("country")
			}

			if s, _ := cmd.Flags().GetBool("subordinate"); s && !cmd.Flags().Lookup("org").Changed {
				settings.Organization = rootAuth.Organization
			} else {
				settings.Organization, _ = cmd.Flags().GetString("org")
			}

			settings.OCSP, _ = cmd.Flags().GetBool("ocsp")
			settings.TimeStamp, _ = cmd.Flags().GetBool("timestamp")

			serialnum, _ := shared.RandomID(15)

			if err := filesystem.EnsureFileExist("db/index", []byte{}); err != nil {
				return err
			}

			if err := filesystem.EnsureFileExist("db/serial", []byte(serialnum)); err != nil {
				return err
			}

			if err := filesystem.EnsureFileExist("db/crlnumber", []byte(`1001`)); err != nil {
				return err
			}

			if err := authorityConfig(); err != nil {
				return err
			}

			fmt.Println(textformat.Info("Generating the certificate authority private key..."))

			pass, err := shared.AskPrivateKeyPassword()
			if err != nil {
				return err
			}

			keyPass = pass

			if err := shared.NewPrivateKey("private/ca.key", privateKeyType, keyPass); err != nil {
				return err
			}

			fmt.Println(textformat.Info("Generating the certificate authority request..."))

			if err := execute.ExternalProgram("openssl", []string{
				"req",
				"-new",
				"-config ca.cnf",
				"-out csr/ca.csr",
				"-key private/ca.key",
				"-text",
				fmt.Sprintf("-passin pass:%s", keyPass),
			}...); err != nil {
				return err
			}

			var serial string

			if settings.Type == "root" {
				fmt.Println(textformat.Info("Generating the certificate for this root authority..."))

				if err := execute.ExternalProgram("openssl", []string{
					"ca",
					"-selfsign",
					"-config ca.cnf",
					"-in csr/ca.csr",
					"-out certs/ca.pem",
					"-extensions ca_ext",
					"-days 7300",
					fmt.Sprintf("-passin pass:%s", keyPass),
				}...); err != nil {
					return err
				}

				var err error
				serial, err = execute.ExternalProgramCapture("openssl", []string{
					"x509",
					"-noout",
					"-in ./certs/ca.pem",
					"-serial",
				}...)
				if err != nil {
					return err
				}

				serial = strings.TrimRight(strings.Replace(serial, "serial=", "", 1), "\r\n")
				settings.Serial = serial
			} else {
				if err := os.Chdir("../"); err != nil {
					return err
				}

				fmt.Println(textformat.Info("Importing subordinate authority into root authority..."))

				_, serial, err := shared.ImportSubordinate(fmt.Sprintf("%s/csr/ca.csr", settings.Name), "")
				if err != nil {
					return err
				}

				if err := filesystem.CopyFile(fmt.Sprintf("certs/%s.pem", serial), fmt.Sprintf("./%s/certs/ca.pem", settings.Name)); err != nil {
					return err
				}

				settings.Serial = serial

				rootAuth.Subordinates, err = shared.AddSubordinate(rootAuth, settings.Name, serial)
				if err != nil {
					return err
				}

				fmt.Println(textformat.Info("Writing updated root authority configuration file..."))

				if err := shared.SaveSettings(&rootAuth); err != nil {
					return err
				}

				fmt.Println(textformat.Info("Writing subordinate authority chain certificate..."))

				root, err := os.ReadFile("./certs/ca.pem")
				if err != nil {
					return err
				}

				sub, err := os.ReadFile(fmt.Sprintf("./%s/certs/ca.pem", settings.Name))
				if err != nil {
					return err
				}

				chain := fmt.Sprintf("%s\n%s\n", string(root), string(sub))
				err = filesystem.EnsureFileExist(fmt.Sprintf("./%s/certs/ca-chain.pem", settings.Name), []byte(chain))
				if err != nil {
					return err
				}

				if err := os.Chdir(filepath.Join(pwd, settings.Name)); err != nil {
					return err
				}

				fmt.Println(textformat.Info("Writing subordinate authority configuration file..."))

				if err := shared.SaveSubordinateSettings(settings); err != nil {
					return err
				}
			}

			if err := shared.SaveSettings(&settings); err != nil {
				return err
			}

			if settings.OCSP {
				if err := shared.EnableOCSP(keyPass); err != nil {
					return err
				}
			}

			if settings.TimeStamp {
				if err := shared.EnableTimestamp(keyPass); err != nil {
					return err
				}
			}

			switch settings.Type {
			case "root":
				if s, _ := cmd.Flags().GetBool("scm"); s {
					fmt.Println(textformat.Info("Adding source control supporting files..."))
					if err := gitIgnore(); err != nil {
						return err
					}

					if err := gitAttributes(); err != nil {
						return err
					}

					if err := editorConfig(); err != nil {
						return err
					}
				}

				fmt.Println(textformat.Info(`Creation of a root certificate authority complete...

~~~~~
A root certificate authority should only have subordinate authorities and not
used to create server or user certificates so you should create at least one
subordinate certificate authority to sign certificates within this authority...`))

			case "subordinate":
				fmt.Println(textformat.Info(`Creation of a subordinate certificate authority complete...

~~~~~
This subordinate authority can only be used to sign certificates within this authority...`))
			}

			return nil
		},
	}

	cmd.Flags().Bool("root", true, "create a new root certificate authority")
	cmd.Flags().Bool("subordinate", false, "create a new subordinate authority")

	cmd.MarkFlagsMutuallyExclusive("root", "subordinate")

	cmd.Flags().String("cn", "", "common name for the authority")
	cmd.Flags().StringP("country", "c", "US", "country where the authority resides legally")
	cmd.Flags().StringP("domain", "d", "contoso.local", "domain serviced by the authority")
	cmd.Flags().StringP("name", "n", "", "name of the authority")
	cmd.Flags().BoolP("ocsp", "o", false, "use OCSP in this authority")
	cmd.Flags().String("org", "Contoso", "organization name serviced by the authority")
	cmd.Flags().BoolP("timestamp", "t", false, "use timestamping in this authority")
	cmd.Flags().BoolP("public", "p", false, "enable this authority for third-party certificates")
	cmd.Flags().BoolVarP(&strictPolicy, "strict", "s", false, "match both organization and country in requests")

	cmd.MarkFlagsMutuallyExclusive("public", "strict")

	cmd.Flags().Bool("scm", false, "include generation of SCM files")

	cmd.MarkFlagsMutuallyExclusive("scm", "subordinate")

	cmd.Flags().Var(&privateKeyType, "keytype", `algorithm to use for private key (allowed "edwards", "elliptic", "rsa"s`)

	return cmd
}
