package desync

import (
	"reflect"
	"runtime"
	"strings"

	"github.com/sagernet/sing-box/option"
)

// Capabilities describes compiled support and runtime prerequisites separately;
// Validate/socket operations still check the actual kernel and privileges.
func Capabilities() map[string]any {
	parameters := map[string]any{}
	linuxOnly := map[string]bool{"fake_sni": true, "fake_host": true, "fake_payload": true, "fake_sni_pool": true, "ttl": true, "fooling": true, "seqovl": true, "autottl": true, "ipfrag": true, "syndata": true, "wsize": true, "wscale": true, "segment_order": true, "fake_placement": true, "fake_delay": true, "fake_tls_random": true, "fake_tls_size": true, "fake_tls_template": true, "hostfake_mode": true}
	t := reflect.TypeFor[option.DesyncOptions]()
	for i := 1; i < t.NumField(); i++ {
		key := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]
		if key == "" || key == "-" {
			continue
		}
		supported := !linuxOnly[key] || runtime.GOOS == "linux"
		reason := ""
		if linuxOnly[key] {
			reason = "Linux; raw/SYN features require CAP_NET_RAW and/or CAP_NET_ADMIN"
		}
		parameters[key] = map[string]any{"supported": supported, "requirements": reason}
	}
	parameters["udp_keep_socket"] = map[string]any{"supported": true, "requirements": "false uses ephemeral raw UDP injector, Linux CAP_NET_RAW; true retains original socket"}
	parameters["udplen"] = map[string]any{"supported": true, "requirements": "STUN PADDING and protected QUIC Initial v1/v2/draft29; non-Initial packets unchanged"}
	parameters["wscale"] = map[string]any{"supported": runtime.GOOS == "linux", "requirements": "pre-SYN TCP_WINDOW_CLAMP; positive scale conflicts with exact small wsize; restored receive buffer remains socket-locked"}
	parameters["quic_split_pos"] = map[string]any{"supported": true, "requirements": "authenticated Initial CRYPTO frames within one packet; numeric stream offsets or complete in-packet ClientHello for semantic markers"}
	parameters["quic_order"] = map[string]any{"supported": true, "requirements": "quic_split_pos required; packet number, CRYPTO offsets and coalesced tail preserved; no cross-packet reordering"}
	parameters["hostfake_mode"] = map[string]any{"supported": runtime.GOOS == "linux", "requirements": "hostfakesplit only; replace uses length-preserving host decoy at real sequence offsets with mandatory invalid TCP checksum"}
	modes := map[string]any{}
	for _, mode := range option.DesyncModes {
		raw := mode != "none" && mode != "split" && mode != "multi_split" && mode != "tlsrec"
		reason := ""
		if raw {
			reason = "Linux CAP_NET_RAW and CAP_NET_ADMIN"
		}
		modes[mode] = map[string]any{"supported": !raw || runtime.GOOS == "linux", "requirements": reason}
	}
	return map[string]any{"capability": Capability, "version": 1, "supported": true, "platform": runtime.GOOS, "modes": option.DesyncModes, "presets": option.DesyncPresets, "mode_support": modes, "parameters": parameters, "active_api": "/desync"}
}
