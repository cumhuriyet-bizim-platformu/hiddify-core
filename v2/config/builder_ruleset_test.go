package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// The files the app bundles (apps/hiddify-app/assets/rule-set, copied from
// data/hiddify-geo/rule-set in the monorepo).
var bundledRuleSetFiles = []string{
	"block/geosite-category-ads-all.srs",
	"block/geosite-malware.srs",
	"block/geosite-phishing.srs",
	"block/geosite-cryptominers.srs",
	"block/geoip-phishing.srs",
	"block/geoip-malware.srs",
	"country/geoip-tr.srs",
}

func writeRuleSetDir(t *testing.T, files []string) string {
	t.Helper()
	dir := t.TempDir()
	for _, f := range files {
		p := filepath.Join(dir, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("srs"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func buildRouting(t *testing.T, hopt *HiddifyOptions) *option.Options {
	t.Helper()
	options := &option.Options{DNS: &option.DNSOptions{}}
	if err := setRoutingOptions(options, hopt); err != nil {
		t.Fatalf("setRoutingOptions: %v", err)
	}
	return options
}

func trOptions(ruleSetDir string) *HiddifyOptions {
	hopt := DefaultHiddifyOptions()
	hopt.Region = "tr"
	hopt.BlockAds = true
	hopt.RuleSetDir = ruleSetDir
	return hopt
}

func TestRuleSetsAreLocalUnderRuleSetDir(t *testing.T) {
	dir := writeRuleSetDir(t, bundledRuleSetFiles)
	options := buildRouting(t, trOptions(dir))

	if got := len(options.Route.RuleSet); got != len(bundledRuleSetFiles) {
		t.Fatalf("got %d rule-sets, want %d", got, len(bundledRuleSetFiles))
	}
	for _, rs := range options.Route.RuleSet {
		if rs.Type != C.RuleSetTypeLocal {
			t.Errorf("rule-set %v has type %q, want %q", rs.Tag, rs.Type, C.RuleSetTypeLocal)
		}
		if rs.RemoteOptions.URL != "" || rs.RemoteOptions.DownloadDetour != "" {
			t.Errorf("rule-set %v has remote options %+v", rs.Tag, rs.RemoteOptions)
		}
		rel, err := filepath.Rel(dir, rs.LocalOptions.Path)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			t.Errorf("rule-set %v path %q is not under %q", rs.Tag, rs.LocalOptions.Path, dir)
		}
	}
}

func TestGeneratedRouteJSONHasNoRemoteRuleSets(t *testing.T) {
	dir := writeRuleSetDir(t, bundledRuleSetFiles)
	options := buildRouting(t, trOptions(dir))

	data, err := json.Marshal(options.Route)
	if err != nil {
		t.Fatalf("marshal route: %v", err)
	}
	text := string(data)
	for _, forbidden := range []string{`"remote"`, "download_detour", "http://", "https://"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("route JSON contains %s: %s", forbidden, text)
		}
	}
	if !strings.Contains(text, `"local"`) {
		t.Errorf("route JSON has no local rule-set: %s", text)
	}
}

func TestMissingRuleSetFilesAreLeftOut(t *testing.T) {
	// Only the Turkey GeoIP set is present: no block lists, no geosite-tr.
	dir := writeRuleSetDir(t, []string{"country/geoip-tr.srs"})
	options := buildRouting(t, trOptions(dir))

	defined := map[string]bool{}
	for _, rs := range options.Route.RuleSet {
		defined[rs.Tag] = true
	}
	if len(defined) != 1 || !defined["geoip-tr"] {
		t.Fatalf("defined rule-sets = %v, want only geoip-tr", defined)
	}
	for _, rule := range options.Route.Rules {
		for _, tag := range rule.DefaultOptions.RuleSet {
			if !defined[tag] {
				t.Errorf("route rule references undefined rule-set %q", tag)
			}
		}
	}
	for _, rule := range options.DNS.Rules {
		for _, tag := range rule.DefaultOptions.RuleSet {
			if !defined[tag] {
				t.Errorf("DNS rule references undefined rule-set %q", tag)
			}
		}
	}
}

func TestNoRuleSetDirMeansNoRuleSets(t *testing.T) {
	options := buildRouting(t, trOptions(""))
	if got := len(options.Route.RuleSet); got != 0 {
		t.Fatalf("got %d rule-sets without a rule-set dir, want 0", got)
	}
}

func TestRuleSetDirIsReadFromSettingsJSON(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	if err := json.Unmarshal([]byte(`{"rule-set-dir":"/data/rule-set"}`), hopt); err != nil {
		t.Fatal(err)
	}
	if hopt.RuleSetDir != "/data/rule-set" {
		t.Fatalf("RuleSetDir = %q", hopt.RuleSetDir)
	}
}

// A subscription profile may override only fields tagged overridable. The
// rule-set directory is provided by the app, so a profile must never set it.
func TestRuleSetDirCannotBeOverriddenByProfile(t *testing.T) {
	got := GetOverridableHiddifyOptions(map[string][]string{
		"rule-set-dir": {"/evil/dir"},
		"block-ads":    {"true"}, // control: an overridable field is applied
	})
	if got.RuleSetDir != "" {
		t.Fatalf("profile override set RuleSetDir = %q, want empty", got.RuleSetDir)
	}
	if !got.BlockAds {
		t.Fatalf("control override block-ads was not applied")
	}
}
