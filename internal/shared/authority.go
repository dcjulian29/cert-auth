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

// Authority represents the configuration and identity of a certificate authority.
// It is serialized to and deserialized from a YAML configuration file (ca.yml)
// and describes whether the CA is a root, subordinate, or imported authority,
// along with its organizational identity, optional services (OCSP, timestamp),
// and any known subordinate CAs.
type Authority struct {
	// Type indicates whether this authority is a root, subordinate, or imported CA.
	Type AuthorityType `yaml:"type"`

	// Public indicates whether the CA is publicly accessible (e.g., CRL/OCSP URLs are public).
	Public bool `yaml:"public_access"`

	// Name is the short filesystem-friendly identifier for the authority directory.
	Name string `yaml:"authority_name"`

	// Domain is the DNS domain associated with the certificate authority.
	Domain string `yaml:"domain"`

	// Country is the two-letter ISO country code used in certificate subjects.
	Country string `yaml:"country"`

	// Organization is the organization name used in certificate subjects.
	Organization string `yaml:"organization"`

	// CommonName is the common name (CN) used in the CA certificate subject.
	CommonName string `yaml:"common_name"`

	// OCSP indicates whether an OCSP responder is configured for this authority.
	OCSP bool `yaml:"ocsp"`

	// TimeStamp indicates whether a timestamping certificates is configured for this authority.
	TimeStamp bool `yaml:"timestamp"`

	// Serial is the hexadecimal number used to identify the authority.
	Serial string `yaml:"serial"`

	// Subordinates is the list of subordinate CAs managed under this root authority.
	Subordinates []Subordinate `yaml:"subordinates"`
}

// Subordinate represents a reference to a subordinate certificate authority
// managed under a root CA. It is stored in the root CA's configuration file.
type Subordinate struct {
	// ID is the hexadecimal number used to identify the subordinate CA.
	ID string `yaml:"id"`

	// Name is the label of the subordinate CA.
	Name string `yaml:"name"`
}
