package geodata

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"

	"go4.org/netipx"
)

// Export writes exactly one tag. SRS compilation never holds unrelated tags,
// a decoded protobuf tree, a JSON copy, or a slice of printable CIDR strings.
func Export(path string, catalog *Catalog, tag string, output io.Writer) error {
	tag, err := NormalizeTag(tag)
	if err != nil {
		return err
	}
	base, attribute, _ := strings.Cut(tag, "@")
	if catalog.Kind == "geoip" && attribute != "" {
		return fmt.Errorf("geoip does not support attribute filters")
	}
	var entry *Entry
	for i := range catalog.Tags {
		if catalog.Tags[i].Name == base {
			entry = &catalog.Tags[i]
			break
		}
	}
	if entry == nil {
		return fmt.Errorf("%s tag %q not found", catalog.Kind, base)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() != catalog.Size || fmt.Sprint(st.ModTime().UnixNano()) != catalog.Mtime {
		return fmt.Errorf("geodata changed since indexing")
	}
	w := newWire(io.NewSectionReader(f, entry.Offset, entry.Length))
	var rule option.DefaultHeadlessRule
	var networks netipx.IPSetBuilder
	var count int
	for w.pos < entry.Length {
		field, wireType, err := w.tag(entry.Length)
		if err != nil {
			return err
		}
		if field == 2 && wireType == 2 {
			end, err := w.message(entry.Length)
			if err != nil {
				return err
			}
			if catalog.Kind == "geosite" {
				added, err := w.domain(end, attribute, &rule)
				if err != nil {
					return err
				}
				if added {
					count++
				}
			} else {
				prefix, err := w.cidr(end)
				if err != nil {
					return err
				}
				networks.AddPrefix(prefix)
				count++
			}
		} else if catalog.Kind == "geoip" && field == 3 && wireType == 0 {
			inverse, err := w.varint(entry.Length)
			if err != nil {
				return err
			}
			// Forkop exports positive CIDRs to nftables. An inverted set cannot
			// be represented by that path, so refuse it instead of misrouting.
			if inverse != 0 {
				return fmt.Errorf("inverse_match geoip tags are not supported")
			}
		} else if err = w.skip(wireType, entry.Length); err != nil {
			return err
		}
	}
	if count == 0 {
		return fmt.Errorf("%s tag %q is empty", catalog.Kind, tag)
	}
	if catalog.Kind == "geoip" {
		rule.IPSet, err = networks.IPSet()
		if err != nil {
			return err
		}
	} else {
		rule.Domain = unique(rule.Domain)
		rule.DomainSuffix = unique(rule.DomainSuffix)
		rule.DomainKeyword = unique(rule.DomainKeyword)
		rule.DomainRegex = unique(rule.DomainRegex)
	}
	return srs.Write(output, option.PlainRuleSet{Rules: []option.HeadlessRule{{Type: C.RuleTypeDefault, DefaultOptions: rule}}}, C.RuleSetVersion2)
}

func unique(values []string) []string {
	slices.Sort(values)
	return slices.Compact(values)
}

func (w *wire) domain(end int64, attribute string, rule *option.DefaultHeadlessRule) (bool, error) {
	var domainType uint64
	var value string
	wantAttribute := strings.TrimPrefix(attribute, "!")
	hasAttribute := false
	for w.pos < end {
		field, wireType, err := w.tag(end)
		if err != nil {
			return false, err
		}
		switch {
		case field == 1 && wireType == 0:
			domainType, err = w.varint(end)
		case field == 2 && wireType == 2:
			value, err = w.text(end, 16384)
		case field == 3 && wireType == 2 && attribute != "":
			var next int64
			next, err = w.message(end)
			if err == nil {
				var key string
				key, err = w.attribute(next)
				hasAttribute = hasAttribute || strings.EqualFold(key, wantAttribute)
			}
		default:
			err = w.skip(wireType, end)
		}
		if err != nil {
			return false, err
		}
	}
	if attribute != "" && hasAttribute != !strings.HasPrefix(attribute, "!") {
		return false, nil
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return false, fmt.Errorf("empty geosite domain")
	}
	switch domainType {
	case 0:
		rule.DomainKeyword = append(rule.DomainKeyword, strings.ToLower(value))
	case 1:
		if _, err := regexp.Compile(value); err != nil {
			return false, fmt.Errorf("invalid geosite regex: %w", err)
		}
		rule.DomainRegex = append(rule.DomainRegex, value)
	case 2:
		value = strings.ToLower(strings.TrimPrefix(value, "."))
		if value == "" {
			return false, fmt.Errorf("empty geosite root domain")
		}
		rule.Domain = append(rule.Domain, value)
		rule.DomainSuffix = append(rule.DomainSuffix, "."+value)
	case 3:
		rule.Domain = append(rule.Domain, strings.ToLower(value))
	default:
		return false, fmt.Errorf("unknown geosite domain type %d", domainType)
	}
	return true, nil
}

func (w *wire) attribute(end int64) (string, error) {
	var key string
	for w.pos < end {
		field, wireType, err := w.tag(end)
		if err != nil {
			return "", err
		}
		if field == 1 && wireType == 2 {
			key, err = w.text(end, 256)
		} else {
			err = w.skip(wireType, end)
		}
		if err != nil {
			return "", err
		}
	}
	return key, nil
}

func (w *wire) cidr(end int64) (netip.Prefix, error) {
	var address [16]byte
	var size int
	var prefix uint64
	for w.pos < end {
		field, wireType, err := w.tag(end)
		if err != nil {
			return netip.Prefix{}, err
		}
		switch {
		case field == 1 && wireType == 2:
			var next int64
			next, err = w.message(end)
			if err == nil {
				size = int(next - w.pos)
				if size != 4 && size != 16 {
					return netip.Prefix{}, fmt.Errorf("invalid geoip address length %d", size)
				}
				var bytes []byte
				bytes, err = w.reader.Peek(size)
				if err == nil {
					copy(address[:], bytes)
					err = w.discard(int64(size), end)
				}
			}
		case field == 2 && wireType == 0:
			prefix, err = w.varint(end)
		default:
			err = w.skip(wireType, end)
		}
		if err != nil {
			return netip.Prefix{}, err
		}
	}
	if size == 0 || prefix > uint64(size*8) {
		return netip.Prefix{}, fmt.Errorf("invalid geoip CIDR prefix %d", prefix)
	}
	if size == 4 {
		return netip.PrefixFrom(netip.AddrFrom4([4]byte(address[:4])), int(prefix)).Masked(), nil
	}
	return netip.PrefixFrom(netip.AddrFrom16(address), int(prefix)).Masked(), nil
}
