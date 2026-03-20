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

// RevokeType represents the reason a certificate is being revoked, as defined
// by RFC 5280 CRL reason codes.
type RevokeType string

const (
	// Unspecified indicates no specific revocation reason was given.
	Unspecified RevokeType = "unspecified"

	// KeyCompromise indicates the private key associated with the certificate
	// has been compromised.
	KeyCompromise RevokeType = "keyCompromise"

	// CACompromise indicates the CA's private key has been compromised.
	CACompromise RevokeType = "CACompromise"

	// AffiliationChanged indicates the subject's affiliation has changed.
	AffiliationChanged RevokeType = "affiliationChanged"

	// Superseded indicates the certificate has been replaced by a new one.
	Superseded RevokeType = "superseded"

	// CessationOfOperation indicates the subject no longer operates the service
	// for which the certificate was issued.
	CessationOfOperation RevokeType = "cessationOfOperation"

	// CertificateHold indicates the certificate is temporarily suspended.
	CertificateHold RevokeType = "certificateHold"

	// RemoveFromCRL indicates a previously held certificate should be reinstated.
	RemoveFromCRL RevokeType = "removeFromCRL"
)

// String returns the string representation of the RevokeType value.
func (e *RevokeType) String() string {
	return string(*e)
}

// Set validates and assigns a RevokeType from the provided string value.
// Returns an error if the value is not one of the recognized revocation reason
// strings.
func (e *RevokeType) Set(v string) error {
	switch v {
	case "unspecified", "keyCompromise", "CACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL":
		*e = RevokeType(v)
		return nil
	default:
		return errors.New(`must be one of "unspecified", "keyCompromise", "CACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL"`)
	}
}

// Type returns the type name "RevokeType", used by flag/cobra parsing.
func (e *RevokeType) Type() string {
	return "RevokeType"
}
