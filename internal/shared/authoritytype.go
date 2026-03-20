package shared

/*
Copyright © 2026 Julian Easterling <julian@julianscorner.com>

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

// AuthorityType represents the role of a certificate authority within the PKI hierarchy.
// Valid values are "root", "subordinate", and "imported".
type AuthorityType string

const (
	// RootAuthority indicates the CA is a self-signed root certificate authority.
	RootAuthority AuthorityType = "root"

	// SubordinateAuthority indicates the CA is an intermediate CA signed by a root CA.
	SubordinateAuthority AuthorityType = "subordinate"

	// ImportedAuthority indicates the CA was imported from an external source
	// rather than created locally.
	ImportedAuthority AuthorityType = "imported"
)

// String returns the string representation of the AuthorityType.
// It satisfies the fmt.Stringer and pflag.Value interfaces.
func (e *AuthorityType) String() string {
	return string(*e)
}

// Set validates and assigns a CertificateType from a string value.
// Accepted values are "root", "subordinate", and "imported". Any other
// value returns an error. It satisfies the pflag.Value interface.
func (e *AuthorityType) Set(v string) error {
	switch v {
	case "root", "subordinate", "imported":
		*e = AuthorityType(v)
		return nil
	default:
		return errors.New(`must be one of "root", "subordinate", "imported"`)
	}
}

// Type returns the type name used in pflag usage messages.
// It satisfies the pflag.Value interface.
func (e *AuthorityType) Type() string {
	return "AuthorityType"
}
