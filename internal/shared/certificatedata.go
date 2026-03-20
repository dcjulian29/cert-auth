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

import "time"

// CertificateData holds the parsed fields from a single certificate entry,
// including the serial number, subject distinguished name, validity period,
// and current revocation status.
type CertificateData struct {
	// SerialNumber is the unique hexadecimal serial number of the certificate.
	SerialNumber string

	// DistinguishedName is the full subject DN string from the certificate.
	DistinguishedName string

	// Status is the human-readable validity state of the certificate:
	// "Valid", "Expired", "Revoked", or "Unknown".
	Status string

	// ExpirationDate is the date and time at which the certificate expires.
	ExpirationDate time.Time

	// RevocationDate is the date and time the certificate was revoked,
	// if applicable.
	RevocationDate time.Time

	// RevocationReason is the reason string provided when the certificate
	// was revoked, if applicable.
	RevocationReason RevokeType
}
