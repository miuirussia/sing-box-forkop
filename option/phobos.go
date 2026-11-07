package option

// PhobosEndpointOptions connects to a Phobos WireGuard obfuscator.
type PhobosEndpointOptions struct {
	WireGuardCommonOptions
	Obfuscation *PhobosObfuscationOptions `json:"obfuscation"`
}

type PhobosObfuscationOptions struct {
	Key            string `json:"key"`
	Masking        string `json:"masking,omitempty"`
	MaxDummy       *int   `json:"max_dummy,omitempty"`
	ObfuscateBytes *int   `json:"obfuscate_bytes,omitempty"`
	MediaPT        uint8  `json:"media_pt,omitempty"`
	MediaSSRC      uint32 `json:"media_ssrc,omitempty"`
	MediaClock     int    `json:"media_clock,omitempty"`
}
