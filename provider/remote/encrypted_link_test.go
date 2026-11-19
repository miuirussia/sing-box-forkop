package provider

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestResolveProviderURLIncy(t *testing.T) {
	t.Parallel()
	// Generated with the public Incy format key using Python's AESGCM.
	const link = "incy://crypt1/AAAAAAAAAAAAAAAAUSV8DUmEbkhb4ASp31bbiUwMP2eRiKAD2yQR6ZahsSWVNOAncfVjDtkxTpHokz0cM1LI6sHMMhL8z0Gv1xvo-bSHDYffGVeYxRDnm-LQ"
	const fileLink = "incy://crypt1/AQEBAQEBAQEBAQEB_PNpydgQgwO3Q1hvBfrAzkhmcKoC4opquuJAaD1plVL5eIiT7f01Z_8vFBLzQ60ElSepxrmVWA"
	const expectedURL = "https://example.com/sub?x=synthetic"
	for _, test := range []struct {
		name   string
		link   string
		want   string
		errMsg string
	}{
		{name: "crypt1", link: link, want: expectedURL},
		{name: "uppercase scheme and trailing slash", link: "INCY" + link[4:] + "/", want: expectedURL},
		{name: "tampered tag", link: link[:len(link)-2] + "AA", errMsg: "authenticate payload"},
		{name: "unsupported format", link: "incy://crypt2/A", errMsg: "unsupported Incy"},
		{name: "non-web target", link: fileLink, errMsg: "HTTP(S) subscription URL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, encrypted, err := resolveProviderURL(test.link, "")
			if !encrypted {
				t.Fatal("encrypted link was treated as a plain URL")
			}
			if test.errMsg != "" {
				if err == nil || !strings.Contains(err.Error(), test.errMsg) {
					t.Fatalf("expected %q, got %v", test.errMsg, err)
				}
				if strings.Contains(err.Error(), "synthetic-token") || strings.Contains(err.Error(), test.link) {
					t.Fatal("the error contains the subscription link or its target")
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("resolved URL = %q, error = %v", got, err)
			}
		})
	}
	got, encrypted, err := resolveProviderURL(expectedURL, "")
	if err != nil || encrypted || got != expectedURL {
		t.Fatalf("plain URL = %q, encrypted = %v, error = %v", got, encrypted, err)
	}
}

func TestResolveProviderURLHapp(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keysDir := t.TempDir()
	const target = "https://example.com/fixtures/long-subscription-path?item=demo"
	for _, format := range []string{"crypt", "crypt2", "crypt3", "crypt4", "crypt5-Abcd1234"} {
		block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
		if format == "crypt4" || strings.HasPrefix(format, "crypt5-") {
			encoded, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			block = &pem.Block{Type: "PRIVATE KEY", Bytes: encoded}
		}
		if err := os.WriteFile(filepath.Join(keysDir, format+".pem"), pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	legacy := append(encryptHappRSA(t, key, []byte(target[:25])), encryptHappRSA(t, key, []byte(target[25:]))...)
	for _, test := range []struct {
		name string
		link string
	}{
		{name: "crypt", link: "happ://crypt/" + base64.StdEncoding.EncodeToString(legacy)},
		{name: "crypt2", link: "happ://crypt2/" + base64.RawURLEncoding.EncodeToString(legacy)},
		{name: "crypt3", link: "HaPp://Crypt3/" + base64.URLEncoding.EncodeToString(legacy)},
		{name: "crypt4", link: "happ://crypt4/" + base64.RawStdEncoding.EncodeToString(legacy)},
		{name: "crypt5 legacy", link: happCrypt5TestLink(t, key, target, "")},
		{name: "crypt5 salted", link: happCrypt5TestLink(t, key, target, "AB12cd34")},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, encrypted, err := resolveProviderURL(test.link, keysDir)
			if err != nil || !encrypted || got != target {
				t.Fatalf("resolved URL = %q, encrypted = %v, error = %v", got, encrypted, err)
			}
			_, _, err = resolveProviderURL(test.link, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), "private key is missing at") {
				t.Fatalf("expected missing-key error, got %v", err)
			}
		})
	}
}

func encryptHappRSA(t *testing.T, key *rsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, payload)
	if err != nil {
		t.Fatal(err)
	}
	return encrypted
}

func happCrypt5TestLink(t *testing.T, key *rsa.PrivateKey, target, salt string) string {
	t.Helper()
	sessionKey := make([]byte, 32)
	if _, err := rand.Read(sessionKey); err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	const nonce = "a1b2c3d4e5f6"
	plaintext := []byte(base64.StdEncoding.EncodeToString([]byte(target)))
	swapBytePairs(plaintext)
	sealed := base64.StdEncoding.EncodeToString(aead.Seal(nil, []byte(nonce), plaintext, nil))
	var saltedHeader string
	if salt != "" {
		saltedHeader = "ab" + salt
		for i := range sessionKey {
			sessionKey[i] ^= salt[i%len(salt)]
		}
	}
	encodedKey := []byte(base64.StdEncoding.EncodeToString(sessionKey))
	swapBytePairs(encodedKey)
	rsaBlock := base64.StdEncoding.EncodeToString(encryptHappRSA(t, key, encodedKey))
	wire := []byte(fmt.Sprintf("Abcd%s%s%d:%s%s1234", nonce, saltedHeader, len(sealed), sealed, rsaBlock))
	for i := 0; i+3 < len(wire); i += 4 {
		firstHalf := [2]byte{wire[i], wire[i+1]}
		copy(wire[i:i+2], wire[i+2:i+4])
		copy(wire[i+2:i+4], firstHalf[:])
	}
	return "happ://crypt5/" + string(wire)
}

func incyProviderTestLink(t *testing.T, target string) string {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(incyCrypt1Key)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"v": 1, "url": target})
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{1}, aead.NonceSize())
	return "incy://crypt1/" + base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, payload, nil))
}
