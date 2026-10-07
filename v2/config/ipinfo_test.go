package config

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/option"
)

func monitoringIPInfo(t *testing.T, hopt *HiddifyOptions) bool {
	t.Helper()
	opts := &option.Options{}
	setExperimental(opts, hopt)
	if opts.Experimental == nil || opts.Experimental.Monitoring == nil {
		t.Fatal("monitoring not configured")
	}
	return opts.Experimental.Monitoring.IPInfo
}

func TestIPInfoOffByDefault(t *testing.T) {
	if monitoringIPInfo(t, DefaultHiddifyOptions()) {
		t.Fatal("IP-info lookups enabled without the app setting")
	}
}

func TestIPInfoFollowsAppSetting(t *testing.T) {
	hopt := DefaultHiddifyOptions()
	if err := json.Unmarshal([]byte(`{"enable-ip-info":true}`), hopt); err != nil {
		t.Fatal(err)
	}
	if !monitoringIPInfo(t, hopt) {
		t.Fatal("IP-info lookups off although the app enabled them")
	}
}

func TestIPInfoNeverInWhitelistMode(t *testing.T) {
	hopt := routingOpts(t, "whitelist", true)
	hopt.EnableIPInfo = true
	if monitoringIPInfo(t, hopt) {
		t.Fatal("IP-info lookups enabled in whitelist mode")
	}
}

func TestIPInfoAllowedInBypassMode(t *testing.T) {
	hopt := routingOpts(t, "full", true)
	hopt.EnableIPInfo = true
	if !monitoringIPInfo(t, hopt) {
		t.Fatal("bypass mode should keep the app setting")
	}
}

func TestIPInfoNotOverridableByProfile(t *testing.T) {
	f, ok := reflect.TypeOf(HiddifyOptions{}).FieldByName("EnableIPInfo")
	if !ok {
		t.Fatal("EnableIPInfo field missing")
	}
	if f.Tag.Get("overridable") == "true" {
		t.Fatal("a profile must not be able to turn IP-info lookups on")
	}
}
