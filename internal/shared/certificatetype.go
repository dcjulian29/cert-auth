package shared

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

import "errors"

// CertificateType represents the intended purpose or profile of an X.509 certificate.
// It determines which OpenSSL extensions and key usages are applied during issuance.
type CertificateType string

const (
	// CertificateTypeServer represents a certificate intended for TLS server authentication.
	CertificateTypeServer CertificateType = "server"

	// CertificateTypeClient represents a certificate intended for client authentication.
	CertificateTypeClient CertificateType = "client"
)

// String returns the string representation of the CertificateType.
// It satisfies the fmt.Stringer and pflag.Value interfaces.
func (e *CertificateType) String() string {
	return string(*e)
}

// Set validates and assigns a CertificateType from a string value.
// Accepted values are "server" and "client". Any other value returns
// an error. It satisfies the pflag.Value interface.
func (e *CertificateType) Set(v string) error {
	switch v {
	case "server", "client":
		*e = CertificateType(v)
		return nil
	default:
		return errors.New(`must be one of "server", "client"`)
	}
}

// Type returns the type name used in pflag usage messages.
// It satisfies the pflag.Value interface.
func (e *CertificateType) Type() string {
	return "CertificateType"
}
