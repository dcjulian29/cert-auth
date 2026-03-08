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
	"bytes"
	"fmt"
	"regexp"
)

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
