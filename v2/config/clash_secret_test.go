package config

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestRandomClashApiSecretIs32BytesHex(t *testing.T) {
	a, b := RandomClashApiSecret(), RandomClashApiSecret()
	if !hex64.MatchString(a) {
		t.Fatalf("secret %q is not 64 lowercase hex chars", a)
	}
	if a == b {
		t.Fatal("two generated secrets are equal")
	}
}

func TestDefaultHiddifyOptionsHasRandomClashSecret(t *testing.T) {
	if s := DefaultHiddifyOptions().ClashApiSecret; !hex64.MatchString(s) {
		t.Fatalf("default ClashApiSecret %q is not 64 hex chars", s)
	}
}

func TestAppWebSecretJSONKeyIsRead(t *testing.T) {
	want := strings.Repeat("cd", 32)
	h := DefaultHiddifyOptions()
	if err := json.Unmarshal([]byte(`{"web-secret":"`+want+`"}`), h); err != nil {
		t.Fatal(err)
	}
	if h.ClashApiSecret != want {
		t.Fatalf("ClashApiSecret = %q, want %q", h.ClashApiSecret, want)
	}
}

func TestSetExperimentalUsesAppSecret(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	hopt.ClashApiSecret = strings.Repeat("ab", 32)
	opts := &option.Options{}
	setExperimental(opts, hopt)
	if opts.Experimental == nil || opts.Experimental.ClashAPI == nil {
		t.Fatal("clash api not configured")
	}
	if got := opts.Experimental.ClashAPI.Secret; got != hopt.ClashApiSecret {
		t.Fatalf("secret = %q, want %q", got, hopt.ClashApiSecret)
	}
	if got := opts.Experimental.ClashAPI.ExternalController; got != "127.0.0.1:16756" {
		t.Fatalf("controller = %q, want 127.0.0.1:16756", got)
	}
}

func TestSetExperimentalFillsEmptySecretWith32Bytes(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	hopt.ClashApiSecret = ""
	opts := &option.Options{}
	setExperimental(opts, hopt)
	if got := opts.Experimental.ClashAPI.Secret; !hex64.MatchString(got) {
		t.Fatalf("fallback secret %q is not 64 hex chars", got)
	}
}
