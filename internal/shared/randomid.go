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
	"crypto/rand"
	"encoding/hex"
)

// RandomID generates a cryptographically random hex-encoded string by reading
// the specified number of random bytes from crypto/rand and encoding them as
// hexadecimal. The returned string will be twice the length of the requested
// byte count (e.g. a length of 15 produces a 30-character hex string). Returns
// an error if the random byte generation fails.
func RandomID(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}
