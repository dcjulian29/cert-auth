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

import (
	"errors"
)

// IsRootCertificateAuthority checks whether the current working directory is a
// root certificate authority. It first verifies the presence of a ca.yml file
// via IsCertificateAuthority, then loads the authority settings and checks that
// the authority type is RootAuthority. Returns an error if the directory is not
// a certificate authority, the settings cannot be loaded, or the authority type
// is not RootAuthority.
func IsRootCertificateAuthority() error {
	if err := IsCertificateAuthority(); err != nil {
		return err
	}

	settings, err := GetSettings()
	if err != nil {
		return err
	}

	if settings.Type == RootAuthority {
		return nil
	}

	return errors.New("this is not a root certificate authority")
}
