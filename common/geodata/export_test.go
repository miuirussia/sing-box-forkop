package geodata

import (
	"bytes"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
)

func domainItem(kind uint64, value string, attribute string) []byte {
	b := uintField(1, kind)
	b = append(b, message(2, []byte(value))...)
	if attribute != "" {
		b = append(b, message(3, append(message(1, []byte(attribute)), uintField(2, 1)...))...)
	}
	return b
}

func exportRule(t *testing.T, kind string, data []byte, tag string) option.DefaultHeadlessRule {
	t.Helper()
	path := database(t, data)
	catalog, err := Index(path, kind)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err = Export(path, catalog, tag, &output); err != nil {
		t.Fatal(err)
	}
	rules, err := srs.Read(bytes.NewReader(output.Bytes()), true)
	if err != nil || len(rules.Options.Rules) != 1 {
		t.Fatalf("invalid SRS: %+v, %v", rules, err)
	}
	return rules.Options.Rules[0].DefaultOptions
}

func TestExportGeosite(t *testing.T) {
	t.Parallel()
	data := geoEntry("test", domainItem(0, "keyword", ""), domainItem(1, `^ads\.`, ""), domainItem(2, "example.com", "cn"), domainItem(3, "exact.example", ""))
	rule := exportRule(t, "geosite", data, "test")
	if len(rule.DomainKeyword) != 1 || rule.DomainKeyword[0] != "keyword" || len(rule.DomainRegex) != 1 {
		t.Fatalf("lost keyword/regex types: %+v", rule)
	}
	// The serialized matcher must include both the apex and its subdomains.
	if !rule.DomainMatcher.Match("example.com") || !rule.DomainMatcher.Match("sub.example.com") || !rule.DomainMatcher.Match("exact.example") || rule.DomainMatcher.Match("sub.exact.example") {
		t.Fatal("domain matching semantics changed")
	}
	filtered := exportRule(t, "geosite", data, "test@cn")
	if !filtered.DomainMatcher.Match("example.com") || filtered.DomainMatcher.Match("exact.example") || len(filtered.DomainKeyword) != 0 {
		t.Fatal("attribute filter was ignored")
	}
	negative := exportRule(t, "geosite", data, "test@!cn")
	if negative.DomainMatcher.Match("example.com") || !negative.DomainMatcher.Match("exact.example") {
		t.Fatal("negative attribute filter was ignored")
	}
}

func TestExportGeositeCase(t *testing.T) {
	t.Parallel()
	const regex = `^\D+\.example$`
	data := geoEntry("test", domainItem(0, "KeyWORD", ""), domainItem(1, regex, ""), domainItem(2, "Example.COM", ""), domainItem(3, "Exact.Example", ""))
	rule := exportRule(t, "geosite", data, "test")
	if !rule.DomainMatcher.Match("example.com") || !rule.DomainMatcher.Match("sub.example.com") || !rule.DomainMatcher.Match("exact.example") || rule.DomainMatcher.Match("sub.exact.example") {
		t.Fatal("mixed-case domains lost their matching semantics")
	}
	if len(rule.DomainKeyword) != 1 || rule.DomainKeyword[0] != "keyword" {
		t.Fatalf("keyword was not normalized: %v", rule.DomainKeyword)
	}
	if len(rule.DomainRegex) != 1 || rule.DomainRegex[0] != regex {
		t.Fatalf("regex case changed: %v", rule.DomainRegex)
	}
}

func TestExportGeoIP(t *testing.T) {
	t.Parallel()
	ipv4 := append(message(1, []byte{192, 0, 2, 7}), uintField(2, 24)...)
	ipv6 := append(message(1, []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}), uintField(2, 32)...)
	rule := exportRule(t, "geoip", geoEntry("test", ipv4, ipv6), "test")
	if len(rule.IPCIDR) != 2 || rule.IPCIDR[0] != "192.0.2.0/24" || rule.IPCIDR[1] != "2001:db8::/32" {
		t.Fatalf("invalid IP ranges: %v", rule.IPCIDR)
	}
	zero := exportRule(t, "geoip", geoEntry("all", message(1, []byte{0, 0, 0, 0})), "all")
	if len(zero.IPCIDR) != 1 || zero.IPCIDR[0] != "0.0.0.0/0" {
		t.Fatalf("lost /0: %v", zero.IPCIDR)
	}
}

func TestExportInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, kind, tag string
		data            []byte
	}{
		{"missing tag", "geosite", "missing", geoEntry("test", domainItem(3, "example.com", ""))},
		{"empty attribute", "geosite", "test@missing", geoEntry("test", domainItem(3, "example.com", ""))},
		{"unknown domain type", "geosite", "test", geoEntry("test", domainItem(99, "example.com", ""))},
		{"invalid regex", "geosite", "test", geoEntry("test", domainItem(1, "[", ""))},
		{"invalid IPv4 prefix", "geoip", "test", geoEntry("test", append(message(1, []byte{1, 2, 3, 4}), uintField(2, 33)...))},
		{"invalid IP length", "geoip", "test", geoEntry("test", message(1, []byte{1, 2, 3}))},
		{"attribute on IP", "geoip", "test@cn", geoEntry("test", message(1, []byte{1, 2, 3, 4}))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := database(t, test.data)
			catalog, err := Index(path, test.kind)
			if err != nil {
				t.Fatal(err)
			}
			if err = Export(path, catalog, test.tag, &bytes.Buffer{}); err == nil {
				t.Fatal("accepted invalid tag")
			}
		})
	}
}
