/*
Copyright © 2023 Julian Easterling <julian@julianscorner.com>

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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"

	"github.com/spf13/cobra"
)

var (
	certificateKeyType      KeyType
	certificateRevokeReason RevokeType = unspecified

	certificateCmd = &cobra.Command{
		Use:     "certificate [<id}]",
		Aliases: []string{"cert"},
		Short:   "Manage certificates within this authority.",
		Long:    "Manage certificates within this authority.",
		PreRun: func(cmd *cobra.Command, args []string) {
			if len(settings.Name) == 0 {
				cobra.CheckErr(fmt.Errorf("'%s' is not a certificate authority", folderPath))
			}
		},
		PostRun: func(cmd *cobra.Command, args []string) {
			ensureWorkingDirectoryAndExit()
		},
		Run: func(cmd *cobra.Command, args []string) {
			id := ""

			if len(args) > 0 {
				id = args[0]
			}

			if f, _ := cmd.Flags().GetBool("issued"); f {
				certificate_show(id, false)
				return
			}

			if f, _ := cmd.Flags().GetBool("requests"); f {
				requests_show(id)
				return
			}

			if f, _ := cmd.Flags().GetBool("revoked"); f {
				certificate_show(id, true)
				return
			}

			cmd.Help()
		},
	}

	certificateApproveCmd = &cobra.Command{
		Use:   "approve",
		Short: "Approve a certificate request",
		Long:  "Approve a certificate request",
		PreRun: func(cmd *cobra.Command, args []string) {
			if len(settings.Name) == 0 {
				cobra.CheckErr(fmt.Errorf("'%s' is not a certificate authority", folderPath))
			}
		},
		PostRun: func(cmd *cobra.Command, args []string) {
			ensureWorkingDirectoryAndExit()
		},
		Run: func(cmd *cobra.Command, args []string) {
			days, _ := cmd.Flags().GetInt("days")

			if f, _ := cmd.Flags().GetBool("server"); f {
				if len(args) > 0 {
					certificate_approve(args[0], certificate_type_server, days)
					return
				} else {
					cobra.CheckErr(errors.New("ID of the imported request missing"))
				}
			}

			if f, _ := cmd.Flags().GetBool("client"); f {
				if len(args) > 0 {
					certificate_approve(args[0], certificate_type_client, days)
					return
				} else {
					cobra.CheckErr(errors.New("ID of the imported request missing"))
				}
			}

			cmd.Help()
		},
	}

	certificateNewCmd = &cobra.Command{
		Use:   "new",
		Short: "Create a new certificate",
		Long:  "Create a new certificate",
		PreRun: func(cmd *cobra.Command, args []string) {
			if len(settings.Name) == 0 {
				cobra.CheckErr(fmt.Errorf("'%s' is not a certificate authority", folderPath))
			}
		},
		PostRun: func(cmd *cobra.Command, args []string) {
			ensureWorkingDirectoryAndExit()
		},
		Run: func(cmd *cobra.Command, args []string) {
			days, _ := cmd.Flags().GetInt("days")
			name, _ := cmd.Flags().GetString("name")
			country, _ := cmd.Flags().GetString("country")
			state, _ := cmd.Flags().GetString("state")
			city, _ := cmd.Flags().GetString("locality")
			ou, _ := cmd.Flags().GetString("ou")
			org, _ := cmd.Flags().GetString("org")
			san, _ := cmd.Flags().GetStringSlice("san")

			certRequest := CertRequestData{
				Name:               name,
				Country:            country,
				State:              state,
				Locality:           city,
				Organization:       org,
				OrganizationalUnit: ou,
				AdditionalNames:    san,
			}

			if f, _ := cmd.Flags().GetBool("server"); f {
				certRequest.RequestType = certificate_type_server
				certificate_new(certRequest, days)
				return
			}

			if f, _ := cmd.Flags().GetBool("client"); f {
				certRequest.RequestType = certificate_type_client
				certificate_new(certRequest, days)
				return
			}

			cmd.Help()
		},
	}

	certificateRequestCmd = &cobra.Command{
		Use:   "request",
		Short: "Create or import a certificate request",
		Long:  "Create or import a certificate request",
		PreRun: func(cmd *cobra.Command, args []string) {
			if len(settings.Name) == 0 {
				cobra.CheckErr(fmt.Errorf("'%s' is not a certificate authority", folderPath))
			}
		},
		PostRun: func(cmd *cobra.Command, args []string) {
			ensureWorkingDirectoryAndExit()
		},
		Run: func(cmd *cobra.Command, args []string) {
			name, _ := cmd.Flags().GetString("name")
			country, _ := cmd.Flags().GetString("country")
			state, _ := cmd.Flags().GetString("state")
			city, _ := cmd.Flags().GetString("locality")
			ou, _ := cmd.Flags().GetString("ou")
			org, _ := cmd.Flags().GetString("org")
			san, _ := cmd.Flags().GetStringSlice("san")

			certRequest := CertRequestData{
				Name:               name,
				Country:            country,
				State:              state,
				Locality:           city,
				Organization:       org,
				OrganizationalUnit: ou,
				AdditionalNames:    san,
			}

			if f, _ := cmd.Flags().GetBool("server"); f {
				certRequest.RequestType = certificate_type_server
				certificate_request_new(certRequest)
				return
			}

			if f, _ := cmd.Flags().GetBool("client"); f {
				certRequest.RequestType = certificate_type_client
				certificate_request_new(certRequest)
				return
			}

			if f, _ := cmd.Flags().GetBool("import"); f {
				certificate_request_import(name)
				return
			}

			cmd.Help()
		},
	}

	certificateRevokeCmd = &cobra.Command{
		Use:   "revoke <serial>",
		Short: "Revoke a issued certificate",
		Long:  "Revoke a issued certificate",
		PreRun: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				cobra.CheckErr(errors.New("serial number of certificate was not provided"))
			}

			if len(settings.Name) == 0 {
				cobra.CheckErr(fmt.Errorf("'%s' is not a certificate authority", folderPath))
			}
		},
		PostRun: func(cmd *cobra.Command, args []string) {
			ensureWorkingDirectoryAndExit()
		},
		Run: func(cmd *cobra.Command, args []string) {
			filePath := path.Join("certs", fmt.Sprintf("%s.pem", args[0]))

			certificate_revoke(filePath, certificateRevokeReason)
		},
	}

	certificateValidateCmd = &cobra.Command{
		Use:   "validate <filePath>",
		Short: "Validate the signature of a certificate",
		Long:  "Validate the signature of a certificate",
		PreRun: func(cmd *cobra.Command, args []string) {
			if len(settings.Name) == 0 {
				cobra.CheckErr(fmt.Errorf("'%s' is not a certificate authority", folderPath))
			}
		},
		PostRun: func(cmd *cobra.Command, args []string) {
			ensureWorkingDirectoryAndExit()
		},
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				cobra.CheckErr(errors.New("path to certificate file was not provided"))
			}

			if f, _ := cmd.Flags().GetBool("bundle"); f {
				certificate_validate(args[0], true)
			} else {
				certificate_validate(args[0], false)
			}
		},
	}
)

func init() {
	certificateCmd.AddCommand(certificateApproveCmd)
	certificateCmd.AddCommand(certificateNewCmd)
	certificateCmd.AddCommand(certificateRequestCmd)
	certificateCmd.AddCommand(certificateRevokeCmd)
	certificateCmd.AddCommand(certificateValidateCmd)
	rootCmd.AddCommand(certificateCmd)

	certificateCmd.Flags().Bool("issued", false, "Show issued certificate(s)")
	certificateCmd.Flags().Bool("requests", false, "Show certificate request(s)")
	certificateCmd.Flags().Bool("revoked", false, "Show revoked certificate(s)")

	certificateCmd.MarkFlagsMutuallyExclusive("issued", "requests", "revoked")

	certificateApproveCmd.Flags().String("client", "", "Approve a client certificate request")
	certificateApproveCmd.Flags().String("server", "", "Approve a server certificate request")
	certificateApproveCmd.Flags().Int("days", 365, "days for the certificate to be valid")

	certificateApproveCmd.MarkFlagsMutuallyExclusive("client", "server")

	certificateNewCmd.Flags().Bool("client", false, "Create a new client certificate")
	certificateNewCmd.Flags().Bool("server", false, "Create a new server certificate")

	certificateNewCmd.Flags().StringP("name", "n", "", "the Fully Qualified Domain Name of the server")
	certificateNewCmd.Flags().String("country", settings.Country, "country of the organization")
	certificateNewCmd.Flags().String("state", "", "state or province name")
	certificateNewCmd.Flags().String("locality", "", "city or town name")
	certificateNewCmd.Flags().String("ou", "", "organization unit name")
	certificateNewCmd.Flags().String("org", settings.Organization, "organization name")
	certificateNewCmd.Flags().StringSlice("san", []string{}, "additional names to include in certificate")
	certificateNewCmd.Flags().Int("days", 365, "days for the certificate to be valid")

	certificateNewCmd.Flags().Var(&certificateKeyType, "keytype", `algorithm to use for private key (allowed "edwards", "elliptic", "rsa" default "edwards")`)

	certificateNewCmd.MarkFlagsMutuallyExclusive("client", "server")

	certificateRequestCmd.Flags().Bool("client", false, "Create a new client certificate request")
	certificateRequestCmd.Flags().Bool("server", false, "Create a new server certificate request")
	certificateRequestCmd.Flags().Bool("import", false, "Import a certificate request")

	certificateRequestCmd.Flags().StringP("name", "n", "", "the Fully Qualified Domain Name of the server")
	certificateRequestCmd.Flags().String("country", settings.Country, "country of the organization")
	certificateRequestCmd.Flags().String("state", "", "state or province name")
	certificateRequestCmd.Flags().String("locality", "", "city or town name")
	certificateRequestCmd.Flags().String("ou", "", "organization unit name")
	certificateRequestCmd.Flags().String("org", settings.Organization, "organization name")
	certificateRequestCmd.Flags().StringSlice("san", []string{}, "additional names to include in certificate")

	certificateRequestCmd.Flags().Var(&certificateKeyType, "keytype", `algorithm to use for private key (allowed "edwards", "elliptic", "rsa" default "edwards")`)

	certificateRequestCmd.MarkFlagsMutuallyExclusive("client", "server", "import")

	certificateRevokeCmd.Flags().VarP(&certificateRevokeReason, "reason", "r", "reason for revocation")

	certificateValidateCmd.Flags().Bool("bundle", false, "use Mozilla CA certificate store to validate")
}

func certificate_approve(id string, certType CertificateType, days int) {
	csrName := path.Join("csr", fmt.Sprintf("%s.csr", id))
	pass := askPassword("private/ca.key")

	executeExternalProgram("openssl", []string{
		"ca",
		"-batch",
		fmt.Sprintf("-config %s", "ca.cnf"),
		fmt.Sprintf("-extensions %s_ext", certType),
		fmt.Sprintf("-days %d", days),
		fmt.Sprintf("-passin pass:%s", pass),
		fmt.Sprintf("-infiles %s", csrName),
	}...)
}

func certificate_new(request CertRequestData, days int) {
	id := certificate_request_new(request)

	certificate_approve(id, request.RequestType, days)
}

func certificate_request_import(filePath string) {
	if !fileExists(filePath) {
		cobra.CheckErr(fmt.Errorf("'%s' doesn't exist or is not accessable", filePath))
	}

	request := load_request(filePath)

	if !request.SignatureValid {
		cobra.CheckErr(fmt.Errorf("'%s' is not a valid certificate request", filePath))
	}

	id := getRandomId(8)
	csrName := path.Join("csr", fmt.Sprintf("%s.csr", id))

	fmt.Printf("    ...    %s\n", filePath)

	copyFile(filePath, csrName)

	fmt.Printf("    ...    %s\n", csrName)
}

func certificate_request_new(request CertRequestData) string {
	id := getRandomId(8)
	keyName := path.Join("private", fmt.Sprintf("%s.key", id))
	csrName := path.Join("csr", fmt.Sprintf("%s.csr", id))
	pass := askPassword(keyName)

	new_private_key(keyName, certificateKeyType, pass)
	new_certificate_request(csrName, keyName, pass, request)

	return id
}

func certificate_revoke(filePath string, reason RevokeType) {
	if !fileExists(filePath) {
		cobra.CheckErr(fmt.Errorf("certificate '%s' was not found", filePath))
	}

	pass := askPassword("private/ca.key")

	executeExternalProgram("openssl", []string{
		"ca",
		fmt.Sprintf("-config %s", "ca.cnf"),
		fmt.Sprintf("-revoke %s", filePath),
		fmt.Sprintf("-crl_reason %s", reason),
		fmt.Sprintf("-passin pass:%s", pass),
	}...)

	os.Rename(filePath, fmt.Sprintf("%s.revoked", filePath))
}

func certificate_show(id string, revoked bool) {
	if len(id) > 0 {
		pemFile := path.Join("certs", fmt.Sprintf("%s.pem", id))

		if revoked {
			pemFile = fmt.Sprintf("%s.revoked", pemFile)
		}

		if !fileExists(pemFile) {
			cobra.CheckErr(fmt.Errorf("certificate '%s' was not found", id))
		}

		executeExternalProgram("openssl", []string{
			"x509",
			"-text",
			"-noout",
			fmt.Sprintf("-in %s", pemFile),
		}...)
	} else {
		certs := load_certificate_db(revoked)

		json, _ := json.MarshalIndent(certs, "", "  ")

		fmt.Printf("%s\n", string(json))
	}
}

func certificate_validate(filepath string, bundle bool) {
	if !fileExists(filepath) {
		cobra.CheckErr(fmt.Errorf("'%s' does not exists or is not accessable", filepath))
	}

	ca := path.Join("certs", "ca-chain.pem")

	if !fileExists(ca) {
		ca = path.Join("certs", "ca.pem")
	}

	if bundle {
		ca = path.Join("certs", "ca-bundle.pem")

		info("Downloading Mozilla's ca-bundle.pem...")

		resp, err := http.Get("https://curl.se/ca/cacert.pem")
		cobra.CheckErr(err)

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		cobra.CheckErr(err)

		touchFile(ca, body)
	}

	executeExternalProgram("openssl", []string{
		"verify",
		fmt.Sprintf("-CAfile %s", ca),
		filepath,
	}...)
}

func requests_show(id string) {
	if len(id) > 0 {
		csrFile := path.Join("csr", fmt.Sprintf("%s.csr", id))

		if !fileExists(csrFile) {
			cobra.CheckErr(fmt.Errorf("request '%s' was not found", id))
		}

		executeExternalProgram("openssl", []string{
			"req",
			"-text",
			"-noout",
			"-verify",
			fmt.Sprintf("-in %s", csrFile),
		}...)
	} else {
		var requests []CertRequest

		files := findFiles("csr", ".csr")

		for _, file := range files {
			requests = append(requests, load_request(file))
		}

		json, _ := json.MarshalIndent(requests, "", "  ")

		fmt.Printf("%s\n", string(json))
	}
}
