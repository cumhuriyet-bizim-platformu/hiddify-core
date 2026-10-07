package config

import (
	"context"
	stdjson "encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/json"
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
	if err := validateDerbentRoutingFile(hopt.DerbentRoutingRuleSet); err != nil {
		log.Printf("derbent routing rule-set ignored (full VPN): %v", err)
		return option.RuleSet{}, false
	}
	return option.RuleSet{
		Type:         C.RuleSetTypeLocal,
		Tag:          derbentRoutingTag,
		Format:       C.RuleSetFormatSource,
		LocalOptions: option.LocalRuleSet{Path: hopt.DerbentRoutingRuleSet},
	}, true
}

// derbentRoutingKeys are the only rule keys the panel/app emit.
var derbentRoutingKeys = map[string]bool{"domain": true, "domain_suffix": true, "ip_cidr": true}

// validateDerbentRoutingFile parses the file the way sing-box will (a file it
// rejects would stop the whole service from starting) and also enforces our
// own contract: version 3, at least one rule, only domain/domain_suffix/ip_cidr.
func validateDerbentRoutingFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	compat, err := json.UnmarshalExtended[option.PlainRuleSetCompat](content)
	if err != nil {
		return err
	}
	plain, err := compat.Upgrade()
	if err != nil {
		return err
	}
	if compat.Version != C.RuleSetVersion3 {
		return fmt.Errorf("rule-set version %d, want %d", compat.Version, C.RuleSetVersion3)
	}
	if len(plain.Rules) == 0 {
		return fmt.Errorf("rule-set has no rules")
	}
	var raw struct {
		Rules []map[string]stdjson.RawMessage `json:"rules"`
	}
	if err := stdjson.Unmarshal(content, &raw); err != nil {
		return err
	}
	if len(raw.Rules) != len(plain.Rules) {
		return fmt.Errorf("rule count mismatch")
	}
	for i, r := range raw.Rules {
		for k := range r {
			if !derbentRoutingKeys[k] {
				return fmt.Errorf("rule %d: unsupported key %q", i, k)
			}
		}
	}
	for i, r := range plain.Rules {
		d := r.DefaultOptions
		if r.Type != "" && r.Type != C.RuleTypeDefault {
			return fmt.Errorf("rule %d: unsupported rule type %q", i, r.Type)
		}
		// An empty rule matches everything in sing-box.
		if len(d.Domain)+len(d.DomainSuffix)+len(d.IPCIDR) == 0 {
			return fmt.Errorf("rule %d: no entries", i)
		}
		for _, c := range d.IPCIDR {
			pfx, err := netip.ParsePrefix(c)
			if err != nil {
				if _, aerr := netip.ParseAddr(c); aerr != nil {
					return fmt.Errorf("rule %d: bad cidr %q", i, c)
				}
				continue
			}
			if (pfx.Addr().Is4() && pfx.Bits() < 8) || (!pfx.Addr().Is4() && pfx.Bits() < 16) {
				return fmt.Errorf("rule %d: prefix %q too short", i, c)
			}
		}
		if _, err := rule.NewHeadlessRule(context.Background(), r); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}
	return nil
}
