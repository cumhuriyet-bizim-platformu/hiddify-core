package config

import (
	"context"
	"encoding/json"
	"net"
	"reflect"
	"strings"
	"testing"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func phaseAOptions(t *testing.T) (*HiddifyOptions, *ReadOptions) {
	t.Helper()
	hopt := DefaultHiddifyOptions()
	hopt.EnableClashApi = true
	hopt.ConnectionTestUrl = "https://panel.example/c/generate_204"
	hopt.ConnectionTestUrls = nil
	in := &option.Options{Outbounds: []option.Outbound{
		{Type: C.TypeDirect, Tag: "a"},
		{Type: C.TypeDirect, Tag: "b"},
	}}
	return hopt, &ReadOptions{Options: in}
}

func TestPhaseATestUrlsArePanelPlusCloudflare(t *testing.T) {
	hopt, ro := phaseAOptions(t)
	options, err := BuildConfig(context.Background(), hopt, ro)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://panel.example/c/generate_204", "https://cp.cloudflare.com"}
	if options.Experimental == nil || options.Experimental.Monitoring == nil {
		t.Fatal("no monitoring options")
	}
	if got := options.Experimental.Monitoring.URLs; !reflect.DeepEqual(got, want) {
		t.Fatalf("monitoring URLs = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(hopt.ConnectionTestUrls, want) {
		t.Fatalf("ConnectionTestUrls = %v, want %v", hopt.ConnectionTestUrls, want)
	}
	b, _ := json.Marshal(options)
	for _, bad := range []string{"google.com", "captive.apple.com"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("config contains %q", bad)
		}
	}
}

func TestPhaseATestUrlsDedupeAndDropEmpty(t *testing.T) {
	hopt, ro := phaseAOptions(t)
	hopt.ConnectionTestUrl = ""
	if _, err := BuildConfig(context.Background(), hopt, ro); err != nil {
		t.Fatal(err)
	}
	if want := []string{"https://cp.cloudflare.com"}; !reflect.DeepEqual(hopt.ConnectionTestUrls, want) {
		t.Fatalf("got %v, want %v", hopt.ConnectionTestUrls, want)
	}
	hopt, ro = phaseAOptions(t)
	hopt.ConnectionTestUrl = "https://cp.cloudflare.com"
	if _, err := BuildConfig(context.Background(), hopt, ro); err != nil {
		t.Fatal(err)
	}
	if want := []string{"https://cp.cloudflare.com"}; !reflect.DeepEqual(hopt.ConnectionTestUrls, want) {
		t.Fatalf("got %v, want %v", hopt.ConnectionTestUrls, want)
	}
}

func TestPhaseABuildDoesNoDNSLookup(t *testing.T) {
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			t.Errorf("DNS lookup during build: %s %s", network, address)
			return nil, net.ErrClosed
		},
	}
	defer func() { net.DefaultResolver = old }()

	hopt, ro := phaseAOptions(t)
	hopt.ConnectionTestUrl = "https://unresolvable.panel.invalid/c/generate_204"
	if _, err := BuildConfig(context.Background(), hopt, ro); err != nil {
		t.Fatal(err)
	}
}
