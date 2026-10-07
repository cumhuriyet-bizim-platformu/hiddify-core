package config

import (
	"os"
	"path/filepath"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// Rule-sets are bundled with the app and read from HiddifyOptions.RuleSetDir.
// The core never downloads a rule-set. The layout under RuleSetDir mirrors
// data/hiddify-geo/rule-set in the derbent monorepo.
const (
	ruleSetBlockDir   = "block"
	ruleSetCountryDir = "country"
)

type bundledRuleSet struct {
	Tag  string
	File string // relative to RuleSetDir
	DNS  bool   // also used by the DNS reject rule
}

var blockRuleSets = []bundledRuleSet{
	{Tag: "geosite-ads", File: ruleSetBlockDir + "/geosite-category-ads-all.srs", DNS: true},
	{Tag: "geosite-malware", File: ruleSetBlockDir + "/geosite-malware.srs", DNS: true},
	{Tag: "geosite-phishing", File: ruleSetBlockDir + "/geosite-phishing.srs", DNS: true},
	{Tag: "geosite-cryptominers", File: ruleSetBlockDir + "/geosite-cryptominers.srs", DNS: true},
	{Tag: "geoip-phishing", File: ruleSetBlockDir + "/geoip-phishing.srs", DNS: false},
	{Tag: "geoip-malware", File: ruleSetBlockDir + "/geoip-malware.srs", DNS: false},
}

// localRuleSet returns a local binary rule-set for relPath under
// hopt.RuleSetDir. It returns false when the directory is not set or the file
// is missing, so the caller leaves the rule-set and its rules out instead of
// falling back to a download.
func localRuleSet(hopt *HiddifyOptions, tag string, relPath string) (option.RuleSet, bool) {
	if hopt.RuleSetDir == "" {
		return option.RuleSet{}, false
	}
	path := filepath.Join(hopt.RuleSetDir, filepath.FromSlash(relPath))
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return option.RuleSet{}, false
	}
	return option.RuleSet{
		Type:   C.RuleSetTypeLocal,
		Tag:    tag,
		Format: C.RuleSetFormatBinary,
		LocalOptions: option.LocalRuleSet{
			Path: path,
		},
	}, true
}

// derbentRoutingTag is the tag of the app-provided routing rule-set.
const derbentRoutingTag = "derbent-routing"

// derbentRoutingRuleSet returns the local source-format rule-set the app wrote
// for whitelist / bypass routing. Derbent: it returns false (so the caller uses
// today's full-VPN routing) unless the mode is "whitelist" or "full" and the
// file exists as a non-empty regular file.
func derbentRoutingRuleSet(hopt *HiddifyOptions) (option.RuleSet, bool) {
	if hopt.DerbentRoutingMode != "whitelist" && hopt.DerbentRoutingMode != "full" {
		return option.RuleSet{}, false
	}
	if hopt.DerbentRoutingRuleSet == "" {
		return option.RuleSet{}, false
	}
	info, err := os.Stat(hopt.DerbentRoutingRuleSet)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return option.RuleSet{}, false
	}
	return option.RuleSet{
		Type:         C.RuleSetTypeLocal,
		Tag:          derbentRoutingTag,
		Format:       C.RuleSetFormatSource,
		LocalOptions: option.LocalRuleSet{Path: hopt.DerbentRoutingRuleSet},
	}, true
}
