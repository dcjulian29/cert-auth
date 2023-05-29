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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

type CertRequest struct {
	Name      string
	Subject   string
	Version   int
	PublicKey string
	Signature string
	Valid     bool
}

func load_request(filePath string) CertRequest {
	var request CertRequest

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
	request.PublicKey = regex_pub.FindStringSubmatch(text)[1]
	request.Signature = regex_sig.FindStringSubmatch(text)[1]
	request.Valid = len(regex_valid.FindString(text)) > 0

	parts := strings.Split(request.Subject, "=")
	request.Name = parts[len(parts)-1]

	return request
}

func import_request(filePath string) string {
	request := load_request(filePath)

	if !request.Valid {
		cobra.CheckErr(fmt.Errorf("'%s' is not a valid certificate request file", filePath))
	}

	fmt.Printf("    ...    %s\n", request.Subject)

	bytes := make([]byte, 16)
	_, err := rand.Read(bytes)
	cobra.CheckErr(err)

	id := string([]byte(hex.EncodeToString(bytes)))

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
}
