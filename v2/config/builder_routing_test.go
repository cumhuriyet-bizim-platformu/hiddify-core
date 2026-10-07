package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// routingOptsIn builds options over a shared rule-set dir so marshalled output is comparable.
func routingOptsIn(t *testing.T, dir, mode string, withFile bool) *HiddifyOptions {
	t.Helper()
	hopt := trOptions(dir)
	hopt.DerbentRoutingMode = mode
	if withFile {
		p := filepath.Join(t.TempDir(), "routing.json")
		if err := os.WriteFile(p, []byte(`{"version":2,"rules":[{"domain_suffix":["example.com"]}]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		hopt.DerbentRoutingRuleSet = p
	} else if mode != "" {
		hopt.DerbentRoutingRuleSet = filepath.Join(t.TempDir(), "missing.json")
	}
	return hopt
}

func routingOpts(t *testing.T, mode string, withFile bool) *HiddifyOptions {
	t.Helper()
	return routingOptsIn(t, writeRuleSetDir(t, bundledRuleSetFiles), mode, withFile)
}

func derbentRouteIdx(o *option.Options) (int, string) {
	for i, r := range o.Route.Rules {
		for _, tag := range r.DefaultOptions.RuleSet {
			if tag == "derbent-routing" {
				return i, r.DefaultOptions.RouteOptions.Outbound
			}
		}
	}
	return -1, ""
}

func derbentDNSServer(o *option.Options) (bool, string) {
	for _, r := range o.DNS.Rules {
		for _, tag := range r.DefaultOptions.RuleSet {
			if tag == "derbent-routing" {
				return true, r.DefaultOptions.RouteOptions.Server
			}
		}
	}
	return false, ""
}

func hasDerbentRuleSet(o *option.Options) (option.RuleSet, bool) {
	for _, rs := range o.Route.RuleSet {
		if rs.Tag == "derbent-routing" {
			return rs, true
		}
	}
	return option.RuleSet{}, false
}

func TestRoutingWhitelist(t *testing.T) {
	hopt := routingOpts(t, "whitelist", true)
	o := buildRouting(t, hopt)
	rs, ok := hasDerbentRuleSet(o)
	if !ok || rs.Type != C.RuleSetTypeLocal || rs.Format != C.RuleSetFormatSource || rs.LocalOptions.Path != hopt.DerbentRoutingRuleSet {
		t.Fatalf("bad rule-set: %+v ok=%v", rs, ok)
	}
	if i, out := derbentRouteIdx(o); i < 0 || out != OutboundMainDetour {
		t.Fatalf("route rule idx=%d outbound=%q", i, out)
	}
	if o.Route.Final != OutboundDirectTag {
		t.Fatalf("final=%q", o.Route.Final)
	}
	if ok, srv := derbentDNSServer(o); !ok || srv != DNSRemoteTag {
		t.Fatalf("dns rule ok=%v server=%q", ok, srv)
	}
}

func TestRoutingFullBypass(t *testing.T) {
	o := buildRouting(t, routingOpts(t, "full", true))
	if i, out := derbentRouteIdx(o); i < 0 || out != OutboundDirectTag {
		t.Fatalf("route rule idx=%d outbound=%q", i, out)
	}
	if o.Route.Final != OutboundMainDetour {
		t.Fatalf("final=%q", o.Route.Final)
	}
	if ok, srv := derbentDNSServer(o); !ok || srv != DNSMultiDirectTag {
		t.Fatalf("dns rule ok=%v server=%q", ok, srv)
	}
}

func TestRoutingFailSafeIdenticalToToday(t *testing.T) {
	dir := writeRuleSetDir(t, bundledRuleSetFiles)
	base, _ := json.Marshal(buildRouting(t, routingOptsIn(t, dir, "", false)))
	cases := map[string]*HiddifyOptions{
		"empty mode":   routingOptsIn(t, dir, "", true),
		"missing file": routingOptsIn(t, dir, "whitelist", false),
		"unknown mode": routingOptsIn(t, dir, "bogus", true),
		"empty file":   emptyFileOpts(t, dir),
	}
	for name, hopt := range cases {
		o := buildRouting(t, hopt)
		if _, ok := hasDerbentRuleSet(o); ok {
			t.Errorf("%s: rule-set present", name)
		}
		if o.Route.Final != OutboundMainDetour {
			t.Errorf("%s: final=%q", name, o.Route.Final)
		}
		got, _ := json.Marshal(o)
		if string(got) != string(base) {
			t.Errorf("%s: config differs from today's", name)
		}
	}
}

func emptyFileOpts(t *testing.T, dir string) *HiddifyOptions {
	hopt := routingOptsIn(t, dir, "whitelist", false)
	p := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	hopt.DerbentRoutingRuleSet = p
	return hopt
}

func TestRoutingRuleOrder(t *testing.T) {
	for _, mode := range []string{"whitelist", "full"} {
		o := buildRouting(t, routingOpts(t, mode, true))
		di, _ := derbentRouteIdx(o)
		if di < 0 {
			t.Fatalf("%s: no derbent rule", mode)
		}
		var blockIdx, regionSuffixIdx, regionSetIdx = -1, -1, -1
		for i, r := range o.Route.Rules {
			d := r.DefaultOptions
			if d.Action == C.RuleActionTypeReject && len(d.RuleSet) > 0 {
				blockIdx = i
			}
			for _, s := range d.DomainSuffix {
				if s == ".tr" {
					regionSuffixIdx = i
				}
			}
			for _, s := range d.RuleSet {
				if s == "geoip-tr" {
					regionSetIdx = i
				}
			}
		}
		if blockIdx < 0 || regionSuffixIdx < 0 || regionSetIdx < 0 {
			t.Fatalf("%s: region/block rules missing (%d %d %d)", mode, blockIdx, regionSuffixIdx, regionSetIdx)
		}
		if !(blockIdx < di && di < regionSuffixIdx && di < regionSetIdx) {
			t.Errorf("%s: order block=%d derbent=%d tr-suffix=%d geoip=%d", mode, blockIdx, di, regionSuffixIdx, regionSetIdx)
		}
		// DNS: derbent rule before the region DNS rule (.tr suffix).
		dd, tr := -1, -1
		for i, r := range o.DNS.Rules {
			for _, s := range r.DefaultOptions.RuleSet {
				if s == "derbent-routing" {
					dd = i
				}
			}
			for _, s := range r.DefaultOptions.DomainSuffix {
				if s == ".tr" {
					tr = i
				}
			}
		}
		if dd < 0 || tr < 0 || dd > tr {
			t.Errorf("%s: dns order derbent=%d tr=%d", mode, dd, tr)
		}
	}
}

func TestRoutingFieldsNotOverridable(t *testing.T) {
	hopt := GetOverridableHiddifyOptions(map[string][]string{
		"derbent-routing-mode":     {"whitelist"},
		"derbent-routing-rule-set": {"/etc/passwd"},
		"block-ads":                {"true"},
	})
	if !hopt.BlockAds {
		t.Fatal("override mechanism not exercised: block-ads should apply")
	}
	if hopt.DerbentRoutingMode != "" || hopt.DerbentRoutingRuleSet != "" {
		t.Fatalf("overridden: %q %q", hopt.DerbentRoutingMode, hopt.DerbentRoutingRuleSet)
	}
}
