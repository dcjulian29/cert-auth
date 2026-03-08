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
package shared

import "errors"

type RevokeType string

const (
	Unspecified          RevokeType = "unspecified"
	KeyCompromise        RevokeType = "keyCompromise"
	CACompromise         RevokeType = "CACompromise"
	AffiliationChanged   RevokeType = "affiliationChanged"
	Superseded           RevokeType = "superseded"
	CessationOfOperation RevokeType = "cessationOfOperation"
	CertificateHold      RevokeType = "certificateHold"
	RemoveFromCRL        RevokeType = "removeFromCRL"
)

func (e *RevokeType) String() string {
	return string(*e)
}

func (e *RevokeType) Set(v string) error {
	switch v {
	case "unspecified", "keyCompromise", "CACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL":
		*e = RevokeType(v)
		return nil
	default:
		return errors.New(`must be one of "unspecified", "keyCompromise", "CACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL"`)
	}
}

func (e *RevokeType) Type() string {
	return "RevokeType"
}
