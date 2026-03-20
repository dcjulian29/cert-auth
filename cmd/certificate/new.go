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

package certificate

import (
	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/spf13/cobra"
)

// newCmd returns a cobra.Command that creates a new certificate within the
// current certificate authority in a single step, generating both the private
// key and the signed certificate without a separate CSR workflow. The command
// verifies that the current directory is a certificate authority before
// running. The --server flag creates a new server certificate and --client
// creates a new client certificate; these flags are mutually exclusive. If
// neither flag is provided, the help text is displayed. Certificate subject
// fields default to the authority's own country and organization settings.
// Returns an error if the authority check fails or the certificate creation
// fails.
//
// Flags:
//
//	    --server      create a new server certificate
//	    --client      create a new client certificate
//	-n, --name        fully qualified domain name of the server
//	    --country     country of the organization
//	    --state       state or province name
//	    --locality    city or town name
//	    --ou          organizational unit name
//	    --org         organization name
//	    --san         additional subject alternative names
//	    --days        days for the certificate to be valid (default: 365)
//	    --keytype     algorithm to use for the private key: edwards, elliptic, rsa
func newCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Create a new certificate",
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return shared.IsCertificateAuthority()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			days, _ := cmd.Flags().GetInt("days")
			name, _ := cmd.Flags().GetString("name")
			country, _ := cmd.Flags().GetString("country")
			state, _ := cmd.Flags().GetString("state")
			city, _ := cmd.Flags().GetString("locality")
			ou, _ := cmd.Flags().GetString("ou")
			org, _ := cmd.Flags().GetString("org")
			san, _ := cmd.Flags().GetStringSlice("san")

			certRequest := shared.RequestData{
				Name:               name,
				Country:            country,
				State:              state,
				Locality:           city,
				Organization:       org,
				OrganizationalUnit: ou,
				AdditionalNames:    san,
			}

			if f, _ := cmd.Flags().GetBool("server"); f {
				certRequest.RequestType = shared.CertificateTypeServer
				_, err := shared.NewCertificate(certRequest, days)
				return err
			}

			if f, _ := cmd.Flags().GetBool("client"); f {
				certRequest.RequestType = shared.CertificateTypeClient
				_, err := shared.NewCertificate(certRequest, days)
				return err
			}

			return cmd.Help()
		},
	}

	settings, _ := shared.GetSettings()

	cmd.Flags().Bool("client", false, "Create a new client certificate")
	cmd.Flags().Bool("server", false, "Create a new server certificate")

	cmd.MarkFlagsMutuallyExclusive("client", "server")

	cmd.Flags().StringP("name", "n", "", "the Fully Qualified Domain Name of the server")
	cmd.Flags().String("country", settings.Country, "country of the organization")
	cmd.Flags().String("state", "", "state or province name")
	cmd.Flags().String("locality", "", "city or town name")
	cmd.Flags().String("ou", "", "organization unit name")
	cmd.Flags().String("org", settings.Organization, "organization name")
	cmd.Flags().StringSlice("san", []string{}, "additional names to include in certificate")
	cmd.Flags().Int("days", 365, "days for the certificate to be valid")

	cmd.Flags().Var(&certificateKeyType, "keytype", `algorithm to use for private key (allowed "edwards", "elliptic", "rsa" default "edwards")`)

	return cmd
}
