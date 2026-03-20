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

// CertificateRequest holds the parsed fields from an X.509 certificate signing
// request (CSR), including the subject identity, version, cryptographic
// algorithms used, and whether the request's signature has been verified.
type CertificateRequest struct {
	// Name is the filename or identifier associated with the CSR.
	Name string

	// Subject is the distinguished name (DN) of the entity requesting the
	// certificate, typically in the form "CN=..., O=..., C=...".
	Subject string

	// Version is the version number of the CSR (typically 0 for PKCS#10).
	Version int

	// PublicKeyAlgorithm is the algorithm used for the CSR's public key,
	// e.g. "RSA", "ECDSA", or "Ed25519".
	PublicKeyAlgorithm string

	// SignatureAlgorithm is the algorithm used to sign the CSR,
	// e.g. "SHA256-RSA" or "ECDSA-SHA384".
	SignatureAlgorithm string

	// SignatureValid reports whether the CSR's self-signature has been
	// successfully verified.
	SignatureValid bool
}
