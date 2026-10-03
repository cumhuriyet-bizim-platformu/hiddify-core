package config

import (
	crand "crypto/rand"
	"encoding/hex"
)

// RandomClashApiSecret returns 32 bytes from crypto/rand, hex encoded (64 chars).
// Used as the default secret of the local Clash API (127.0.0.1 only).
func RandomClashApiSecret() string {
	b := make([]byte, 32)
	if _, err := crand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
