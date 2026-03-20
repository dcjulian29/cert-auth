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

// RequestData carries the subject and extension fields needed to generate
// an OpenSSL certificate signing request (CSR) configuration file.
type RequestData struct {
	// Name is the primary subject name. For client certificates this becomes
	// the email address (SAN/CN); for server certificates it is the primary DNS name.
	Name string

	// Country is the two-letter ISO 3166-1 country code for the subject.
	// If empty, the value from the application settings is used.
	Country string

	// State is the state or province name (ST) for the certificate subject.
	State string

	// Locality is the locality or city name (L) for the certificate subject.
	Locality string

	// Organization is the O field of the subject DN.
	// If empty, the value from the application settings is used.
	Organization string

	// OrganizationalUnit is the organizational unit (OU) for the certificate subject.
	OrganizationalUnit string

	// AdditionalNames lists extra Subject Alternative Names (SANs) to include
	// in a server certificate request.
	AdditionalNames []string

	// RequestType distinguishes the intended usage of the certificate
	// (e.g. CertificateTypeServer or CertificateTypeClient).
	RequestType CertificateType
}
