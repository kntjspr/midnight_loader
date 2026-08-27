package builder

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

// generatekey returns a 12-16 char alphanumeric xor key.
func GenerateKey() string {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	s := base64.StdEncoding.EncodeToString(raw)
	s = strings.NewReplacer("+", "", "/", "", "=", "").Replace(s)
	if len(s) > 16 {
		s = s[:16]
	}
	if len(s) < 12 {
		// pad with deterministic suffix (rare edge case)
		s = s + "AAAAAAAAAAAA"
		s = s[:12]
	}
	return s
}

// xorencrypt xors data with key cyclically.
func XOREncrypt(data []byte, key string) []byte {
	out := make([]byte, len(data))
	klen := len(key)
	for i, b := range data {
		out[i] = b ^ key[i%klen]
	}
	return out
}
