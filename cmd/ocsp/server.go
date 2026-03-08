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
package ocsp

import (
	"errors"

	"github.com/dcjulian29/cert-auth/internal/shared"
	"github.com/spf13/cobra"
)

func serverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Manage OCSP Responder suitable for low-volume traffic.",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return shared.IsCertificateAuthority()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			settings, err := shared.GetSettings()
			if err != nil {
				return err
			}

			if settings.OCSP {
				if t, _ := cmd.Flags().GetBool("start"); t {
					port, _ := cmd.Flags().GetInt("port")
					background, _ := cmd.Flags().GetBool("background")

					start(port, background)
				}

				if p, _ := cmd.Flags().GetBool("stop"); p {
					stop()
				}
			} else {
				return errors.New("OCSP is not enabled in this certificate authority")
			}

			return nil
		},
	}

	cmd.Flags().Bool("start", false, "start the OCSP responder")
	cmd.Flags().Bool("stop", false, "stop the OCSP responder")
	cmd.Flags().IntP("port", "p", 8080, "port for OCSP responder to listen on")
	cmd.Flags().BoolP("background", "b", false, "run the OCSP responder in the background")

	cmd.MarkFlagsMutuallyExclusive("start", "stop")
	cmd.MarkFlagsMutuallyExclusive("port", "stop")
	cmd.MarkFlagsMutuallyExclusive("background", "stop")

	return cmd
}
