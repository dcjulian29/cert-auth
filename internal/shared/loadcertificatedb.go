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
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func LoadCertificateDB(revoked bool) ([]CertificateData, error) {
	var results []CertificateData
	p := filepath.Join("db", "index")
	r, _ := regexp.Compile(`(\w)\s+(\w+)(\s+\w+,\w+\s+|\s+)(\w+)\s+(\w+)\s(.+)`)
	f, err := os.Open(p)
	if err != nil {
		return []CertificateData{}, err
	}

	defer f.Close() //nolint

	s := bufio.NewScanner(f)

	for s.Scan() {
		l := s.Text()
		m := r.FindStringSubmatch(l)

		if len(m) == 0 {
			continue
		}

		var c CertificateData

		c.SerialNumber = m[4]
		c.DistinguishedName = m[6]

		switch m[1] {
		case "V":
			c.Status = "Valid"
		case "E":
			c.Status = "Expired"
		case "R":
			c.Status = "Revoked"
		default:
			c.Status = "Unknown"
		}

		t, err := time.Parse("060102150405Z", m[2])
		if err != nil {
			return []CertificateData{}, err
		}

		c.ExpirationDate = t

		r := strings.Trim(m[3], "\t")

		if len(r) > 0 {
			s := strings.Split(r, ",")
			t, err := time.Parse("060102150405Z", s[0])
			if err != nil {
				return []CertificateData{}, err
			}
			c.RevocationDate = t
			c.RevocationReason = RevokeType(s[1])
		}

		if revoked && c.Status == "Revoked" {
			results = append(results, c)
		}

		if !revoked && c.Status != "Revoked" {
			results = append(results, c)
		}
	}

	return results, nil
}
