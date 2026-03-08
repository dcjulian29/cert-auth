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

type AuthorityType string

const (
	RootAuthority        AuthorityType = "root"
	SubordinateAuthority AuthorityType = "subordinate"
	ImportedAuthority    AuthorityType = "imported"
)

func (e *AuthorityType) String() string {
	return string(*e)
}

func (e *AuthorityType) Set(v string) error {
	switch v {
	case "unspecified", "keyCompromise", "CACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL":
		*e = AuthorityType(v)
		return nil
	default:
		return errors.New(`must be one of "unspecified", "keyCompromise", "CACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "removeFromCRL"`)
	}
}

func (e *AuthorityType) Type() string {
	return "AuthorityType"
}
