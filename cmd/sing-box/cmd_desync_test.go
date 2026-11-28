package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/include"
)

func TestDesyncCLIConversion(t *testing.T) {
	for _, args := range [][]string{{"capabilities"}, {"import", "preset=auto auto_tune=false"}, {"check", `{"preset":"split"}`}, {"export", `{"preset":"GT2","udp_keep_socket":false}`}, {"check", `{"mode":"fake_split","tlsrec_first":true,"tlsrec_pos":"midsld","split_pos":"sni+1,endhost-1","segment_order":"2,1,3","fake_placement":"between","fake_delay":"0s","fake_tls_random":true,"fake_tls_size":4096,"fake_tls_template":"compact","http_mod":"hcsmix,rmspace","udp_mode":"quic","quic_split_pos":"1,midsld","quic_order":"reverse"}`}} {
		cmd := newDesyncCommand()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		if out.Len() == 0 {
			t.Fatalf("%v: empty output", args)
		}
		if args[0] != "export" && !json.Valid(out.Bytes()) {
			t.Fatalf("%v: invalid json %s", args, out.String())
		}
		if args[0] == "export" && !strings.Contains(out.String(), "udp_keep_socket=false") {
			t.Fatalf("export lost explicit false: %s", out.String())
		}
	}
}
func TestDesyncCLIHTTPProbe(t *testing.T) {
	globalCtx = include.Context(context.Background())
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(strings.Repeat("response", 1000)))
	}))
	defer server.Close()
	dir := t.TempDir()
	optionsFile := filepath.Join(dir, "strategy.json")
	if err := os.WriteFile(optionsFile, []byte(`{"mode":"split","split_pos":"1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	outputFile := filepath.Join(dir, "result.json")
	cmd := newDesyncCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"probe", "--options", optionsFile, "--target", server.URL, "--protocol", "http", "--max-bytes", "1024", "--timeout", "2s", "--output", outputFile})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var result desyncProbeResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Success || result.Bytes != 1024 || result.Status != 200 || requests != 1 {
		t.Fatalf("probe %+v requests=%d", result, requests)
	}
	saved, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatal(err)
	}
	var fileResult desyncProbeResult
	if err = json.Unmarshal(saved, &fileResult); err != nil || !fileResult.Success {
		t.Fatalf("saved result %s %v", saved, err)
	}
}
func TestDesyncCLIRejectsInvalidLimits(t *testing.T) {
	cmd := newDesyncCommand()
	cmd.SetArgs([]string{"probe", "--target", "127.0.0.1:443", "--timeout", "20s"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("accepted unbounded probe")
	}
}

func TestDesyncCLIFoolingContract(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fake strategies require Linux")
	}
	for _, token := range []string{"", "none", "badseq", "badack", "badsum", "md5", "md5_badack", "badseq_badack_badsum", "datanoack", "hopbyhop", "destopt", "ipfrag", "ts", "badtimestamp"} {
		t.Run("fooling="+token, func(t *testing.T) {
			input, _ := json.Marshal(map[string]any{"mode": "fake_split", "fooling": token, "auto_tune": false, "seqovl": 0})
			run := func(verb, input string) string {
				t.Helper()
				cmd := newDesyncCommand()
				var out bytes.Buffer
				cmd.SetOut(&out)
				cmd.SetArgs([]string{verb, input})
				if err := cmd.Execute(); err != nil {
					t.Fatal(err)
				}
				return out.String()
			}
			canonical := run("check", string(input))
			converted := run("check", run("export", canonical))
			if canonical != converted {
				t.Fatalf("roundtrip changed strategy: %s -> %s", canonical, converted)
			}
			var got map[string]any
			if err := json.Unmarshal([]byte(converted), &got); err != nil {
				t.Fatal(err)
			}
			if got["fooling"] != token || got["auto_tune"] != false || got["seqovl"] != float64(0) {
				t.Fatalf("lost explicit options: %s", converted)
			}
		})
	}
	for _, token := range []string{"magic", "badseq_magic", "badseq_badsum", "ts_badack"} {
		t.Run("reject="+token, func(t *testing.T) {
			cmd := newDesyncCommand()
			cmd.SetArgs([]string{"check", "mode=fake_split fooling=" + token})
			if err := cmd.Execute(); err == nil {
				t.Fatal("accepted unsupported fooling")
			}
		})
	}
}
