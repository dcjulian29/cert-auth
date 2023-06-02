/*
Copyright © 2023 Julian Easterling <julian@julianscorner.com>

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
package cmd

import "errors"

type CertificateType string

const (
	certificate_type_server CertificateType = "server"
	certificate_type_client CertificateType = "client"
)

func (e *CertificateType) String() string {
	return string(*e)
}

func (e *CertificateType) Set(v string) error {
	switch v {
	case "server", "client":
		*e = CertificateType(v)
		return nil
	default:
		return errors.New(`must be one of "server", "client"`)
	}
}

func (e *CertificateType) Type() string {
	return "CertificateType"
}
