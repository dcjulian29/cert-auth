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

package shared

import "errors"

// KeyType represents the cryptographic algorithm used when generating a private key.
type KeyType string

const (
	// DefaultKeyType is the key type used when none is explicitly specified.
	// It is set to Elliptic (EC secp521r1).
	DefaultKeyType KeyType = Elliptic

	// Edwards generates an Ed25519 private key encrypted with AES-256-CFB.
	Edwards KeyType = "edwards"

	// Elliptic generates an EC private key using the secp521r1 curve,
	// encrypted with AES-256-CFB.
	Elliptic KeyType = "elliptic"

	// RSA generates an RSA private key using a configurable bit length.
	RSA KeyType = "rsa"
)

// String returns the string representation of the KeyType value.
func (e *KeyType) String() string {
	return string(*e)
}

// Set parses and assigns a KeyType from the provided string value.
// Returns an error if the value is not one of "edwards", "elliptic", or "rsa".
func (e *KeyType) Set(v string) error {
	switch v {
	case "edwards", "elliptic", "rsa":
		*e = KeyType(v)
		return nil
	default:
		return errors.New(`must be one of "edwards", "elliptic", or "rsa"`)
	}
}

// Type returns the type name "KeyType", used for pflag/cobra flag registration.
func (e *KeyType) Type() string {
	return "KeyType"
}
