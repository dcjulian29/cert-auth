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

func requestCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "request",
		Short: "Create or import a certificate request",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return shared.IsCertificateAuthority()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
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
				_, err := shared.NewCertificate(certRequest, days)

				return err
			}

			if f, _ := cmd.Flags().GetBool("client"); f {
				certRequest.RequestType = shared.CertificateTypeClient
				_, err := shared.NewCertificate(certRequest, days)

				return err
			}

			if f, _ := cmd.Flags().GetBool("import"); f {
				path, _ := cmd.Flags().GetString("path")
				_, err := shared.ImportRequest(path)

				return err
			}

			return cmd.Help()
		},
	}

	cmd.Flags().Bool("client", false, "Create a new client certificate request")
	cmd.Flags().Bool("server", false, "Create a new server certificate request")
	cmd.Flags().Bool("import", false, "Import a certificate request")
	cmd.Flags().String("path", "", "path to certificate to revoke")

	settings, _ := shared.GetSettings()

	cmd.Flags().StringP("name", "n", "", "the fully qualified name")
	cmd.Flags().String("country", settings.Country, "country of the organization")
	cmd.Flags().String("state", "", "state or province name")
	cmd.Flags().String("locality", "", "city or town name")
	cmd.Flags().String("ou", "", "organization unit name")
	cmd.Flags().String("org", settings.Organization, "organization name")
	cmd.Flags().StringSlice("san", []string{}, "additional names to include in certificate")
	cmd.Flags().Int("days", 365, "days for the certificate to be valid")

	cmd.Flags().Var(&certificateKeyType, "keytype", `algorithm to use for private key (allowed "edwards", "elliptic", "rsa" default "edwards")`)

	cmd.MarkFlagsRequiredTogether("client", "name")
	cmd.MarkFlagsRequiredTogether("server", "name")
	cmd.MarkFlagsRequiredTogether("import", "path")
	cmd.MarkFlagsMutuallyExclusive("client", "server", "import")

	return cmd
}
