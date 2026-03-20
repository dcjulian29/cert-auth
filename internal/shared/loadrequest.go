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

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/dcjulian29/go-toolbox/execute"
)

// LoadRequest parses a PEM-encoded certificate signing request (CSR) at the
// given filePath using OpenSSL and returns a CertificateRequest populated with
// the extracted fields. The following fields are extracted from the OpenSSL text
// output via regular expressions:
//
//   - Version: the PKCS#10 version number.
//   - Subject: the distinguished name (DN), with whitespace trimmed.
//   - PublicKeyAlgorithm: the public key algorithm, e.g. "rsaEncryption" or "id-ecPublicKey".
//   - SignatureAlgorithm: the signature algorithm, e.g. "ecdsa-with-SHA256".
//   - SignatureValid: true if OpenSSL reports "self-signature verify OK".
//   - Name: the value of the last RDN component of the subject (e.g. the CN value).
//
// Returns an empty CertificateRequest and an error if OpenSSL fails, any regex
// fails to compile, or the expected fields are not found in the output.
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

	regexVersion, err := regexp.Compile(`Version:\s(\d+)\s`)
	if err != nil {
		return CertificateRequest{}, err
	}

	regexSubject, err := regexp.Compile(`Subject:\s(.+)`)
	if err != nil {
		return CertificateRequest{}, err
	}

	regexPublicKey, err := regexp.Compile(`Public Key Algorithm:\s(\w+)`)
	if err != nil {
		return CertificateRequest{}, err
	}

	regexSignature, err := regexp.Compile(`Signature Algorithm:\s(\w+)`)
	if err != nil {
		return CertificateRequest{}, err
	}

	regexValid, err := regexp.Compile("self-signature verify OK")
	if err != nil {
		return CertificateRequest{}, err
	}

	request.Version, _ = strconv.Atoi(regexVersion.FindStringSubmatch(text)[1])
	request.Subject = strings.Trim(strings.ReplaceAll(regexSubject.FindStringSubmatch(text)[1], " ", ""), "\r\n")
	request.PublicKeyAlgorithm = regexPublicKey.FindStringSubmatch(text)[1]
	request.SignatureAlgorithm = regexSignature.FindStringSubmatch(text)[1]
	request.SignatureValid = len(regexValid.FindString(text)) > 0

	parts := strings.Split(request.Subject, "=")
	request.Name = parts[len(parts)-1]

	return request, nil
}
