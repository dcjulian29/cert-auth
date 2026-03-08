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
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/dcjulian29/go-toolbox/execute"
)

func LoadRequest(filePath string) (CertificateRequest, error) {
	var request CertificateRequest
	filePath = strings.ReplaceAll(filePath, "\\", "/")

	text, err := execute.ExternalProgramCapture("openssl", []string{
		"req",
		fmt.Sprintf("-in %s", filePath),
		"-noout",
		"-text",
		"-verify",
	}...)

	if err != nil {
		return CertificateRequest{}, err
	}

	regex_version, err := regexp.Compile(`Version:\s(\d+)\s`)
	if err != nil {
		return CertificateRequest{}, err
	}

	regex_subject, err := regexp.Compile(`Subject:\s(.+)`)
	if err != nil {
		return CertificateRequest{}, err
	}

	regex_pub, err := regexp.Compile(`Public Key Algorithm:\s(\w+)`)
	if err != nil {
		return CertificateRequest{}, err
	}

	regex_sig, err := regexp.Compile(`Signature Algorithm:\s(\w+)`)
	if err != nil {
		return CertificateRequest{}, err
	}

	regex_valid, err := regexp.Compile("self-signature verify OK")
	if err != nil {
		return CertificateRequest{}, err
	}

	request.Version, _ = strconv.Atoi(regex_version.FindStringSubmatch(text)[1])
	request.Subject = strings.Trim(strings.ReplaceAll(regex_subject.FindStringSubmatch(text)[1], " ", ""), "\r\n")
	request.PublicKeyAlgorithm = regex_pub.FindStringSubmatch(text)[1]
	request.SignatureAlgorithm = regex_sig.FindStringSubmatch(text)[1]
	request.SignatureValid = len(regex_valid.FindString(text)) > 0

	parts := strings.Split(request.Subject, "=")
	request.Name = parts[len(parts)-1]

	return request, nil
}
