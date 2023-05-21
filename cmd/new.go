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
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

var (
	strictPolicy bool
	keyPass      string
	keyType      KeyType

	newCmd = &cobra.Command{
		Use:   "new",
		Short: "Create a new certificate authority.",
		Long:  "Create a new certificate authority.",
		Run: func(cmd *cobra.Command, args []string) {
			if workingDirectory != folderPath {
				if _, err := os.Stat(folderPath); os.IsNotExist(err) {
					info("Creating certificate authority folder...")
					if err := os.MkdirAll(folderPath, 0755); err != nil {
						cobra.CheckErr(err)
					}
				}

				ensureAuthorityDirectory()
			}

			info("Creating certificate authority directories...")

			for _, folder := range []string{"certs", "csr", "db", "private"} {
				ensureDir(folder)
			}

			info("Initalizing certificate authority...")

			strictPolicy, _ = cmd.Flags().GetBool("strict")

			if r, _ := cmd.Flags().GetBool("root"); r {
				settings.Type = "root"
			} else {
				settings.Type = "subordinate"
			}

			settings.Public, _ = cmd.Flags().GetBool("public")
			settings.Name, _ = cmd.Flags().GetString("name")
			settings.Domain, _ = cmd.Flags().GetString("domain")
			settings.Country, _ = cmd.Flags().GetString("country")
			settings.Organization, _ = cmd.Flags().GetString("org")
			settings.CommonName, _ = cmd.Flags().GetString("cn")
			settings.OCSP, _ = cmd.Flags().GetBool("ocsp")
			settings.TimeStamp, _ = cmd.Flags().GetBool("timestamp")

			viper.Set("common_name", settings.CommonName)
			viper.Set("country", settings.Country)
			viper.Set("domain", settings.Domain)
			viper.Set("name", settings.Name)
			viper.Set("ocsp", settings.OCSP)
			viper.Set("organization", settings.Organization)
			viper.Set("public_access", settings.Public)
			viper.Set("timestamp", settings.TimeStamp)
			viper.Set("type", settings.Type)

			bytes := make([]byte, 15)
			_, err := rand.Read(bytes)
			cobra.CheckErr(err)

			touchFile("db/index", []byte{})
			touchFile("db/serial", []byte(hex.EncodeToString(bytes)))
			touchFile("db/crlnumber", []byte(`1001`))

			cnf_ca()

			info("Generating the root certificate private key...")

			new_private_key("private/ca.key")

			info("Generating the root certificate request...")

			executeExternalProgram("openssl", []string{
				"req",
				"-new",
				"-config ca.cnf",
				"-out csr/ca.csr",
				"-key private/ca.key",
				"-text",
				fmt.Sprintf("-passin pass:%s", keyPass),
			}...)

			fmt.Printf("    ...    %s\n", "csr/ca.csr")

			info("Generating the root certificate for this authority...")

			executeExternalProgram("openssl", []string{
				"ca",
				"-selfsign",
				"-config ca.cnf",
				"-in csr/ca.csr",
				"-out certs/ca.pem",
				"-extensions ca_ext",
				fmt.Sprintf("-passin pass:%s", keyPass),
			}...)

			info("Writing authority configuration file...")

			viper.WriteConfigAs("ca.yml")
			fmt.Printf("    ...    %s\n", "ca.yml")

			if settings.OCSP {
				ocsp_setup()
			}

			if settings.TimeStamp {
				timestamp_setup()
			}

			if s, _ := cmd.Flags().GetBool("scm"); s {
				info("Adding source control supporting files...")
				git_ignore()
				git_attributes()
				editor_config()
			}

			info(`Creation of a root certificate authority complete...

~~~~~
A root certificate authority should only have subordinate authorities and not
used to create server or user certificates so you should create at least one
subordinate certificate authority to sign certificates within this authority...`)
		},
		PreRun: func(cmd *cobra.Command, args []string) {
			if s, _ := cmd.Flags().GetBool("subordinate"); s {
				ensureAuthorityDirectory()
			}

			if r, _ := cmd.Flags().GetBool("root"); r {
				if len(settings.Name) > 0 {
					cobra.CheckErr(fmt.Errorf("'%s' is already a certificate authority", folderPath))
				}
			}
		},
		PostRun: func(cmd *cobra.Command, args []string) {
			ensureWorkingDirectoryAndExit()
		},
	}
)

func init() {
	rootCmd.AddCommand(newCmd)

	newCmd.Flags().Bool("root", true, "create a new root certificate authority")
	newCmd.Flags().Bool("subordinate", false, "create a new subordinate authority")

	newCmd.MarkFlagsMutuallyExclusive("root", "subordinate")

	newCmd.Flags().String("cn", "authority", "common name for the authority")
	newCmd.Flags().StringP("country", "c", "US", "country where the authority resides legally")
	newCmd.Flags().StringP("domain", "d", "contoso.local", "domain serviced by the authority")
	newCmd.Flags().StringP("name", "n", "root", "name of the authority")
	newCmd.Flags().BoolP("ocsp", "o", false, "use OCSP in this authority")
	newCmd.Flags().String("org", "Contoso", "organization name serviced by the authority")
	newCmd.Flags().BoolP("timestamp", "t", false, "use timestamping in this authority")

	newCmd.Flags().BoolP("public", "p", false, "enable this authority for third-party certificates")
	newCmd.Flags().BoolP("strict", "s", false, "match both organization and country in requests")

	newCmd.MarkFlagsMutuallyExclusive("public", "strict")

	newCmd.Flags().Bool("scm", false, "include generation of SCM files")

	newCmd.Flags().Var(&keyType, "keytype", `algorithm to use for private key (allowed "edwards", "elliptic", "rsa" default "edwards")`)
}

func cnf_ca() {
	var contents bytes.Buffer

	contents.WriteString("[default]\n")
	contents.WriteString(fmt.Sprintf("name                    = %s\n", settings.Name))
	contents.WriteString(fmt.Sprintf("domain_suffix           = %s\n", settings.Domain))

	contents.Write(cnf_default())

	contents.WriteString("\n[ca_dn]\n")
	contents.WriteString(fmt.Sprintf("countryName             = %s\n", settings.Country))
	contents.WriteString(fmt.Sprintf("organizationName        = %s\n", settings.Organization))
	contents.WriteString(fmt.Sprintf("commonName              = %s\n", settings.CommonName))

	contents.Write(cnf_default_ca())

	contents.WriteString("copy_extensions         = none\n")
	contents.WriteString("default_days            = 7300\n")
	contents.WriteString("default_crl_days        = 365\n")

	if !settings.Public {
		contents.Write(cnf_policy())
	}

	contents.Write(cnf_crl_info())

	if settings.OCSP {
		contents.Write(cnf_ocsp_info())
	} else {
		contents.Write(cnf_issuer_info())
	}

	if !settings.Public {
		contents.Write(cnf_name_constraints())
	}

	contents.WriteString("\n[req]\n")
	contents.WriteString("encrypt_key             = yes\n")
	contents.WriteString("default_md              = sha256\n")
	contents.WriteString("utf8                    = yes\n")
	contents.WriteString("string_mask             = utf8only\n")
	contents.WriteString("prompt                  = no\n")
	contents.WriteString("distinguished_name      = ca_dn\n")
	contents.WriteString("req_extensions          = ca_ext\n")

	contents.Write(ext_ca())

	if settings.OCSP {
		contents.Write(ext_ocsp())
	}

	if settings.TimeStamp {
		contents.Write(ext_timestamp())
	}

	contents.Write(ext_subca())

	touchFile("ca.cnf", contents.Bytes())
}

func cnf_crl_info() []byte {
	var contents bytes.Buffer

	contents.WriteString("\n[crl_info]\n")
	contents.WriteString("URI.0                   = $crl_url\n")

	return contents.Bytes()
}

func cnf_default() []byte {
	var contents bytes.Buffer

	contents.WriteString("aia_url                 = http://pki.$domain_suffix/$name.crt\n")
	contents.WriteString("crl_url                 = http://pki.$domain_suffix/$name.crt\n")

	if settings.OCSP {
		contents.WriteString("ocsp_url                =  http://ocsp-$name.$domain_suffix\n")
	}

	contents.WriteString("default_ca              = ca_default\n")
	contents.WriteString("name_opt                = utf8,esc_ctrl,multiline,lname,align\n")

	return contents.Bytes()
}

func cnf_default_ca() []byte {
	var contents bytes.Buffer

	contents.WriteString("\n[ca_default]\n")
	contents.WriteString("home                    = .\n")
	contents.WriteString("database                = $home/db/index\n")
	contents.WriteString("serial                  = $home/db/serial\n")
	contents.WriteString("crlnumber               = $home/db/crlnumber\n")
	contents.WriteString("certificate             = $home/certs/ca.pem\n")
	contents.WriteString("private_key             = $home/private/ca.key\n")
	contents.WriteString("RANDFILE                = $home/private/random\n")
	contents.WriteString("new_certs_dir           = $home/certs\n")
	contents.WriteString("unique_subject          = no\n")
	contents.WriteString("default_md              = sha256\n")

	return contents.Bytes()
}

func cnf_issuer_info() []byte {
	var contents bytes.Buffer

	contents.WriteString("\n[issuer_info]\n")
	contents.WriteString("caIssuers;URI.0         = $aia_url\n")

	return contents.Bytes()
}

func cnf_name_constraints() []byte {
	var contents bytes.Buffer

	contents.WriteString("\n[name_constraints]\n")
	contents.WriteString("permitted;DNS.0         = $domain_suffix\n")
	contents.WriteString("excluded;IP.0           = 0.0.0.0/0.0.0.0\n")
	contents.WriteString("excluded;IP.1           = 0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0\n")

	return contents.Bytes()
}

func cnf_ocsp_info() []byte {
	var contents bytes.Buffer

	contents.WriteString("\n[issuer_info]\n")
	contents.WriteString("caIssuers;URI.0         = $aia_url\n")
	contents.WriteString("OCSP;URI.0              = $ocsp_url\n")

	return contents.Bytes()
}

func cnf_policy() []byte {
	var contents bytes.Buffer
	var policy string

	if strictPolicy {
		policy = "policy_c_o_match"
	} else {
		policy = "policy_o_match"
	}

	contents.WriteString(fmt.Sprintf("policy                  = %s\n", policy))
	contents.WriteString("\n[policy_c_o_match]\n")
	contents.WriteString("countryName             = match\n")
	contents.WriteString("stateOrProvinceName     = optional\n")
	contents.WriteString("organizationName        = match\n")
	contents.WriteString("organizationalUnitName  = optional\n")
	contents.WriteString("commonName              = supplied\n")
	contents.WriteString("emailAddress            = optional\n")
	contents.WriteString("\n[policy_o_match]\n")
	contents.WriteString("countryName             = optional\n")
	contents.WriteString("stateOrProvinceName     = optional\n")
	contents.WriteString("organizationName        = match\n")
	contents.WriteString("organizationalUnitName  = optional\n")
	contents.WriteString("commonName              = supplied\n")
	contents.WriteString("emailAddress            = optional\n")

	return contents.Bytes()
}

func ext_ca() []byte {
	var contents bytes.Buffer

	contents.WriteString("\n[ca_ext]\n")
	contents.WriteString("basicConstraints        = critical,CA:true\n")
	contents.WriteString("keyUsage                = critical,keyCertSign,cRLSign\n")
	contents.WriteString("subjectKeyIdentifier    = hash\n")

	return contents.Bytes()
}

func ext_ocsp() []byte {
	var contents bytes.Buffer

	contents.WriteString("\n[ocsp_ext]\n")
	contents.WriteString("authorityInfoAccess     = @issuer_info\n")
	contents.WriteString("authorityKeyIdentifier  = keyid:always\n")
	contents.WriteString("basicConstraints        = critical,CA:false\n")
	contents.WriteString("extendedKeyUsage        = critical,OCSPSigning\n")
	contents.WriteString("keyUsage                = critical,digitalSignature\n")
	contents.WriteString("subjectKeyIdentifier    = hash\n")
	contents.WriteString("basicConstraints        = critical,CA:true\n")
	contents.WriteString("keyUsage                = critical,keyCertSign,cRLSign\n")
	contents.WriteString("subjectKeyIdentifier    = hash\n")

	return contents.Bytes()
}

func ext_subca() []byte {
	var contents bytes.Buffer

	contents.WriteString("\n[subca_ext]\n")
	contents.WriteString("authorityInfoAccess     = @issuer_info\n")
	contents.WriteString("authorityKeyIdentifier  = keyid:always\n")
	contents.WriteString("basicConstraints        = critical,CA:true,pathlen:0\n")
	contents.WriteString("crlDistributionPoints   = @crl_info\n")
	contents.WriteString("extendedKeyUsage        = clientAuth,serverAuth\n")
	contents.WriteString("keyUsage                = critical,keyCertSign,cRLSign\n")
	contents.WriteString("subjectKeyIdentifier    = hash\n")

	if !settings.Public {
		contents.WriteString("nameConstraints         = @name_constraints\n")
	}

	return contents.Bytes()
}

func ext_timestamp() []byte {
	var contents bytes.Buffer

	contents.WriteString("\n[timestamp_ext]\n")
	contents.WriteString("authorityInfoAccess     = @issuer_info\n")
	contents.WriteString("authorityKeyIdentifier  = keyid:always\n")
	contents.WriteString("basicConstraints        = CA:false\n")
	contents.WriteString("crlDistributionPoints   = @crl_info\n")
	contents.WriteString("extendedKeyUsage        = critical,timeStamping\n")
	contents.WriteString("keyUsage                = critical,digitalSignature\n")
	contents.WriteString("subjectKeyIdentifier    = hash\n")

	return contents.Bytes()
}

func editor_config() {
	var contents bytes.Buffer

	contents.WriteString("root = true\n\n")
	contents.WriteString("[*]\n")
	contents.WriteString("end_of_line = lf\n")
	contents.WriteString("indent_style = space\n")
	contents.WriteString("indent_size = 2\n")
	contents.WriteString("trim_trailing_whitespace = true\n")
	contents.WriteString("insert_final_newline = true\n\n")
	contents.WriteString("[{*.pem,*.crl,*.csr,*.key}]\n")
	contents.WriteString("insert_final_newline = false\n")

	if !fileExists(".editorconfig") {
		touchFile(".editorconfig", contents.Bytes())
	}
}

func git_attributes() {
	var contents bytes.Buffer

	contents.WriteString("*       text eol=lf\n")
	contents.WriteString("*.cer   binary\n")
	contents.WriteString("*.csr   text\n")
	contents.WriteString("*.crl   text\n")
	contents.WriteString("*.crt   binary\n")
	contents.WriteString("*.der   binary\n")
	contents.WriteString("*.pem   text\n")
	contents.WriteString("*.p12   binary\n")
	contents.WriteString("*.pfx   binary\n")
	contents.WriteString("*.key   text\n")

	if !fileExists(".gitattributes") {
		touchFile(".gitattributes", contents.Bytes())
	}
}

func git_ignore() {
	var contents bytes.Buffer

	contents.WriteString("/**/private/*\n")

	if !fileExists(".gitignore") {
		touchFile(".gitignore", contents.Bytes())
	}
}
func new_private_key(filePath string) {
	fmt.Printf("\033[1;35mEnter pass phrase for %s:\033[0m ", filePath)

	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	cobra.CheckErr(err)

	keyPass = string(password)

	var param []string

	fmt.Println("")
	switch keyType {
	case elliptic:
		param = []string{
			"ecparam",
			"-name secp521r1",
			"-genkey",
			"-noout",
			fmt.Sprintf("-out %s", filePath),
		}

		fmt.Println(param)
		executeExternalProgram("openssl", param...)

		param = []string{
			"ec",
			"-aes-256-cfb",
			fmt.Sprintf("-in %s", filePath),
			fmt.Sprintf("-out %s.tmp", filePath),
			fmt.Sprintf("-passout pass:%s", keyPass),
		}

		fmt.Println(param)
		executeExternalProgram("openssl", param...)

		os.Remove(filePath)
		os.Rename(fmt.Sprintf("%s.tmp", filePath), filePath)

	case rsa:
		param = []string{
			"genrsa",
			fmt.Sprintf("-out %s", filePath),
			"-verbose",
			"-aes-256-cfb",
			fmt.Sprintf("-passout pass:%s", keyPass),
		}

		if settings.Type == "root" {
			param = append(param, "4096")
		} else {
			param = append(param, "2048")
		}

		executeExternalProgram("openssl", param...)

	default:
		param = []string{
			"genpkey",
			"-algorithm ed25519",
			fmt.Sprintf("-out %s", filePath),
			"-aes-256-cfb",
			fmt.Sprintf("-pass pass:%s", keyPass),
		}

		executeExternalProgram("openssl", param...)
	}

	fmt.Printf("\n    ...    %s\n", filePath)
}

func ocsp_setup() {
	var contents bytes.Buffer

	info("Initializing OCSP configuration for this authority...")

	contents.WriteString("[req]\n")
	contents.WriteString("default_bits            = 2048\n")
	contents.WriteString("encrypt_key             = no\n")
	contents.WriteString("default_md              = sha256\n")
	contents.WriteString("utf8                    = yes\n")
	contents.WriteString("string_mask             = utf8only\n")
	contents.WriteString("prompt                  = no\n")
	contents.WriteString("distinguished_name      = req_subj\n\n")
	contents.WriteString("[req_subj]\n")
	contents.WriteString(fmt.Sprintf("countryName             = %s\n", settings.Country))
	contents.WriteString(fmt.Sprintf("organizationName        = %s\n", settings.Organization))
	contents.WriteString(fmt.Sprintf("commonName              = %s OCSP Responder\n", settings.CommonName))

	touchFile("ocsp.cnf", contents.Bytes())

	info("Generating the OCSP private key for this authority...")

	executeExternalProgram("openssl", []string{
		"genrsa",
		"-out private/ocsp.key",
		"-verbose",
		"2048",
	}...)

	info("Generating the OCSP certificate request...")

	executeExternalProgram("openssl", []string{
		"req",
		"-new",
		"-config ocsp.cnf",
		"-out csr/ocsp.csr",
		"-key private/ocsp.key",
	}...)

	fmt.Printf("    ...    %s\n", "csr/ocsp.csr")

	info("Generating the OCSP certificate for this authority...")

	executeExternalProgram("openssl", []string{
		"ca",
		"-batch",
		"-config ca.cnf",
		"-out certs/ocsp.pem",
		"-extensions ocsp_ext",
		"-days 90",
		fmt.Sprintf("-passin pass:%s", keyPass),
		"-infiles csr/ocsp.csr",
	}...)
}

func timestamp_setup() {
	var contents bytes.Buffer

	info("Initializing timestamping configuration for this authority...")

	contents.WriteString("[req]\n")
	contents.WriteString("default_bits            = 2048\n")
	contents.WriteString("encrypt_key             = no\n")
	contents.WriteString("default_md              = sha256\n")
	contents.WriteString("utf8                    = yes\n")
	contents.WriteString("string_mask             = utf8only\n")
	contents.WriteString("prompt                  = no\n")
	contents.WriteString("distinguished_name      = req_subj\n\n")
	contents.WriteString("[req_subj]\n")
	contents.WriteString(fmt.Sprintf("countryName             = %s\n", settings.Country))
	contents.WriteString(fmt.Sprintf("organizationName        = %s\n", settings.Organization))
	contents.WriteString(fmt.Sprintf("commonName              = %s Timestamp Authority\n", settings.CommonName))

	touchFile("timestamp.cnf", contents.Bytes())

	info("Generating the timestamping private key for this authority...")

	executeExternalProgram("openssl", []string{
		"genrsa",
		"-out private/timestamp.key",
		"-verbose",
		"2048",
	}...)

	info("Generating the timestamping certificate request...")

	executeExternalProgram("openssl", []string{
		"req",
		"-new",
		"-config timestamp.cnf",
		"-out csr/timestamp.csr",
		"-key private/timestamp.key",
	}...)

	fmt.Printf("    ...    %s\n", "csr/timestamp.csr")

	info("Generating the timestamping certificate for this authority...")

	executeExternalProgram("openssl", []string{
		"ca",
		"-batch",
		"-config ca.cnf",
		"-out certs/timestamp.pem",
		"-extensions timestamp_ext",
		"-days 90",
		fmt.Sprintf("-passin pass:%s", keyPass),
		"-infiles csr/timestamp.csr",
	}...)
}

func touchFile(filePath string, content []byte) {
	fmt.Printf("    ...    %s\n", filePath)

	file, err := os.Create(filePath)
	cobra.CheckErr(err)

	defer file.Close()

	if _, err = file.Write(content); err != nil {
		cobra.CheckErr(err)
	}
}
