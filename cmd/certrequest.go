/*
Copyright © 2023 Julian Easterling julian@julianscorner.com

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

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

type CertRequest struct {
	Name               string
	Subject            string
	Version            int
	PublicKeyAlgorithm string
	SignatureAlgorithm string
	SignatureValid     bool
}

type CertRequestData struct {
	Name               string
	Country            string
	State              string
	Locality           string
	Organization       string
	OrganizationalUnit string
	AdditionalNames    []string
	RequestType        CertificateType
}

func load_request(filePath string) CertRequest {
	var request CertRequest
	filePath = strings.ReplaceAll(filePath, "\\", "/")

	text := executeExternalProgramCapture("openssl", []string{
		"req",
		fmt.Sprintf("-in %s", filePath),
		"-noout",
		"-text",
		"-verify",
	}...)

	regex_version, _ := regexp.Compile(`Version:\s(\d+)\s`)
	regex_subject, _ := regexp.Compile(`Subject:\s(.+)`)
	regex_pub, _ := regexp.Compile(`Public Key Algorithm:\s(\w+)`)
	regex_sig, _ := regexp.Compile(`Signature Algorithm:\s(\w+)`)
	regex_valid, _ := regexp.Compile("self-signature verify OK")

	request.Version, _ = strconv.Atoi(regex_version.FindStringSubmatch(text)[1])
	request.Subject = strings.Trim(strings.ReplaceAll(regex_subject.FindStringSubmatch(text)[1], " ", ""), "\r\n")
	request.PublicKeyAlgorithm = regex_pub.FindStringSubmatch(text)[1]
	request.SignatureAlgorithm = regex_sig.FindStringSubmatch(text)[1]
	request.SignatureValid = len(regex_valid.FindString(text)) > 0

	parts := strings.Split(request.Subject, "=")
	request.Name = parts[len(parts)-1]

	return request
}

func import_request(filePath string) string {
	request := load_request(filePath)

	if !request.SignatureValid {
		cobra.CheckErr(fmt.Errorf("'%s' is not a valid certificate request file", filePath))
	}

	fmt.Printf("    ...    %s\n", request.Subject)

	id := getRandomId(16)

	csr := path.Join("csr", fmt.Sprintf("%s.csr", id))

	copyFile(filePath, csr)

	return id
}

func sign_request(id, pass string, days int) {
	if len(pass) == 0 {
		pass = askPassword("private/ca.key")
	}

	executeExternalProgram("openssl", []string{
		"ca",
		"-batch",
		"-config ca.cnf",
		"-extensions subca_ext",
		fmt.Sprintf("-days %d", days),
		fmt.Sprintf("-passin pass:%s", pass),
		fmt.Sprintf("-out ./certs/%s.pem", id),
		fmt.Sprintf("-in ./csr/%s.csr", id),
	}...)

	serial := "TODO! Get the serial from DB"

	fmt.Printf("\n    ...    certs/%s.pem\n", serial)

}

func new_certificate_request(requestFile, keyFile, pass string, data CertRequestData) {
	if len(data.Country) == 0 {
		data.Country = settings.Country
	}

	if len(data.Organization) == 0 {
		data.Organization = settings.Organization
	}

	if data.RequestType == certificate_type_client {
		if !strings.Contains(data.Name, "@") {
			data.Name = fmt.Sprintf("%s@%s", data.Name, settings.Domain)
		}
	}

	configFile := fmt.Sprintf("%s.cnf", requestFile)

	var contents bytes.Buffer

	contents.WriteString("[req]\n")
	contents.WriteString("default_md = sha256\n")
	contents.WriteString("utf8 = yes\n")
	contents.WriteString("string_mask = utf8only\n")
	contents.WriteString("prompt = no\n")
	contents.WriteString("distinguished_name = req_subj\n")

	if data.RequestType == certificate_type_server {
		contents.WriteString("req_extensions = server_req\n\n")

		contents.Write(cnf_san(data.Name, data.AdditionalNames))
	}

	if data.RequestType == certificate_type_client {
		contents.WriteString("req_extensions = client_req\n\n")
		contents.WriteString("[ client_req ]\n")
		contents.WriteString("keyUsage = nonRepudiation, digitalSignature, keyEncipherment\n")
		contents.WriteString(fmt.Sprintf("subjectAltName = email:%s\n", data.Name))
	}

	contents.Write(req_subj(data))

	touchFile(configFile, contents.Bytes())

	if len(pass) == 0 {
		pass = askPassword(keyFile)
	}

	executeExternalProgram("openssl", []string{
		"req",
		fmt.Sprintf("-config %s", configFile),
		"-new",
		fmt.Sprintf("-key %s", keyFile),
		fmt.Sprintf("-out %s", requestFile),
		fmt.Sprintf("-passin pass:%s", pass),
	}...)
}

func cnf_san(name string, additionalNames []string) []byte {
	var contents bytes.Buffer
	var uri, dns, ip, email []string

	dns = append(dns, name)
	regex_uri, _ := regexp.Compile(`^.*://.*$`)
	regex_email, _ := regexp.Compile(`^.*@.*$`)
	regex_ipv4, _ := regexp.Compile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	regex_ipv6, _ := regexp.Compile(`^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$|^::(?:[A-F0-9]{1,4}:){0,5}[A-F0-9]{1,4}$|^(?:[A-F0-9]{1,4}:){1,6}::(?:[A-F0-9]{1,4}:){0,4}[A-F0-9]{1,4}$|^(?:[A-F0-9]{1,4}:){2,7}::$`)

	for _, n := range additionalNames {
		if regex_uri.MatchString(n) {
			uri = append(uri, n)
			continue
		}

		if regex_email.MatchString(n) {
			email = append(email, n)
			continue
		}

		if regex_ipv4.MatchString(n) || regex_ipv6.MatchString(n) {
			ip = append(ip, n)
			continue
		}

		if name != n {
			dns = append(dns, n)
		}
	}

	contents.WriteString("[server_req]\nsubjectAltName = @san_list\n\n[san_list]\n")

	for i, v := range uri {
		contents.WriteString(fmt.Sprintf("URI.%d = %s\n", i, v))
	}

	for i, v := range dns {
		contents.WriteString(fmt.Sprintf("DNS.%d = %s\n", i, v))
	}

	for i, v := range ip {
		contents.WriteString(fmt.Sprintf("IP.%d = %s\n", i, v))
	}

	for i, v := range email {
		contents.WriteString(fmt.Sprintf("email.%d = %s\n", i, v))
	}

	contents.WriteString("\n")

	return contents.Bytes()
}

func req_subj(data CertRequestData) []byte {
	var contents bytes.Buffer

	contents.WriteString(fmt.Sprintf("[req_subj]\ncountryName = %s\n", data.Country))

	if len(data.State) > 0 {
		contents.WriteString(fmt.Sprintf("stateOrProvinceName = %s\n", data.State))
	}

	if len(data.Locality) > 0 {
		contents.WriteString(fmt.Sprintf("localityName = %s\n", data.Locality))
	}

	contents.WriteString(fmt.Sprintf("organizationName = %s\n", data.Organization))

	if len(data.OrganizationalUnit) > 0 {
		contents.WriteString(fmt.Sprintf("organizationUnitName = %s\n", data.OrganizationalUnit))
	}

	contents.WriteString(fmt.Sprintf("commonName = %s\n", data.Name))

	return contents.Bytes()
}
