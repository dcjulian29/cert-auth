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

// SubjectAlternativeName builds the [server_req] and [san_list] sections of an
// OpenSSL configuration file for a server certificate's Subject Alternative
// Names (SANs) and returns the result as a byte slice. The primary name is
// always added as a DNS SAN. Each entry in additionalNames is classified by
// type using regular expressions and added to the appropriate SAN category:
//
//   - URI: matches entries containing "://" (e.g. "https://example.com").
//   - Email: matches entries containing "@" (e.g. "user@example.com").
//   - IP: matches IPv4 addresses (e.g. "192.168.1.1") or uppercase IPv6
//     addresses (e.g. "2001:DB8::1").
//   - DNS: all remaining entries, excluding duplicates of the primary name.
//
// Entries in each category are written in OpenSSL indexed format
// (e.g. "DNS.0", "DNS.1"). The order of categories in the output is URI, DNS,
// IP, then email.
func SubjectAlternativeName(name string, additionalNames []string) []byte {
	var contents bytes.Buffer
	var uri, dns, ip, email []string

	dns = append(dns, name)
	regexURI, _ := regexp.Compile(`^.*://.*$`)
	regexEmail, _ := regexp.Compile(`^.*@.*$`)
	regexIpv4, _ := regexp.Compile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	regexIpv6, _ := regexp.Compile(`(?i)` +
		`^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$|` +
		`^::(?:[A-F0-9]{1,4}:){0,5}[A-F0-9]{1,4}$|` +
		`^(?:[A-F0-9]{1,4}:){1,6}::(?:[A-F0-9]{1,4}:){0,4}[A-F0-9]{1,4}$|` +
		`^(?:[A-F0-9]{1,4}:){2,7}::$`)

	for _, n := range additionalNames {
		if regexURI.MatchString(n) {
			uri = append(uri, n)
			continue
		}

		if regexEmail.MatchString(n) {
			email = append(email, n)
			continue
		}

		if regexIpv4.MatchString(n) || regexIpv6.MatchString(n) {
			ip = append(ip, n)
			continue
		}

		if name != n {
			dns = append(dns, n)
		}
	}

	contents.WriteString("[server_req]\nsubjectAltName = @san_list\n\n[san_list]\n")

	for i, v := range uri {
		fmt.Fprintf(&contents, "URI.%d = %s\n", i, v)
	}

	for i, v := range dns {
		fmt.Fprintf(&contents, "DNS.%d = %s\n", i, v)
	}

	for i, v := range ip {
		fmt.Fprintf(&contents, "IP.%d = %s\n", i, v)
	}

	for i, v := range email {
		fmt.Fprintf(&contents, "email.%d = %s\n", i, v)
	}

	contents.WriteString("\n")

	return contents.Bytes()
}
