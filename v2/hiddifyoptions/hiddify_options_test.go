package hiddifyoptions

import (
	"regexp"
	"testing"
)

func TestDefaultWebSecretIsRandom32BytesHex(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{64}$`)
	a, b := DefaultHiddifyOptions().WebSecret, DefaultHiddifyOptions().WebSecret
	if !re.MatchString(a) {
		t.Fatalf("default WebSecret %q is not 64 hex chars", a)
	}
	if a == b {
		t.Fatal("two default WebSecrets are equal")
	}
}
