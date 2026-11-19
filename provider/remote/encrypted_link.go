package provider

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	happKeysDir         = "/etc/forkop/happ"
	maxEncryptedLinkLen = 16400
	maxHappKeyFileSize  = 16384

	// Public crypt1 format key from INCY-DEV/incy-link-encoder.
	incyCrypt1Key = "9tQOoMioiZ18aC0Jug1BZd/is91F5rs+JcsjPPAMJGI="
)

func resolveProviderURL(raw, keysDir string) (resolved string, encrypted bool, err error) {
	link := strings.TrimSpace(raw)
	scheme, rest, _ := strings.Cut(link, "://")
	scheme = strings.ToLower(scheme)
	if scheme != "incy" && scheme != "happ" {
		return raw, false, nil
	}
	if len(link) > maxEncryptedLinkLen {
		return "", true, errors.New("encrypted subscription link is too long")
	}
	format, payload, _ := strings.Cut(rest, "/")
	if payload == "" || strings.ContainsAny(payload, "\r\n") {
		return "", true, errors.New("invalid encrypted subscription link")
	}

	format = strings.ToLower(format)
	if scheme == "incy" {
		if format != "crypt1" {
			return "", true, errors.New("unsupported Incy subscription link format")
		}
		resolved, err = decryptIncyLink(payload)
	} else {
		resolved, err = decryptHappLink(format, payload, keysDir)
	}
	if err != nil {
		return "", true, fmt.Errorf("decrypt %s subscription link: %w", scheme, err)
	}

	resolved = strings.TrimSpace(resolved)
	target, err := url.Parse(resolved)
	if err != nil || !isSubscriptionHTTPURL(target, resolved) {
		return "", true, errors.New("the encrypted link does not contain an HTTP(S) subscription URL")
	}
	return resolved, true, nil
}

func isSubscriptionHTTPURL(target *url.URL, raw string) bool {
	if target.Scheme != "http" && target.Scheme != "https" {
		return false
	}
	return target.Hostname() != "" && strings.IndexFunc(raw, unicode.IsControl) < 0 && !strings.ContainsAny(raw, " |\\")
}

func decryptIncyLink(payload string) (string, error) {
	wire, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(payload, "/"))
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(incyCrypt1Key)
	if err != nil {
		return "", fmt.Errorf("decode format key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("initialize AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("initialize GCM: %w", err)
	}
	nonceSize := aead.NonceSize()
	if len(wire) <= nonceSize+aead.Overhead() {
		return "", errors.New("encrypted payload is too short")
	}
	plaintext, err := aead.Open(nil, wire[:nonceSize], wire[nonceSize:], nil)
	if err != nil {
		return "", fmt.Errorf("authenticate payload: %w", err)
	}
	var data struct {
		Version int    `json:"v"`
		URL     string `json:"url"`
	}
	if err := json.Unmarshal(plaintext, &data); err != nil || data.Version != 1 || data.URL == "" {
		// JSON errors can include characters from the decrypted data.
		return "", errors.New("invalid Incy subscription data")
	}
	return data.URL, nil
}

func decryptHappLink(format, payload, keysDir string) (string, error) {
	switch format {
	case "crypt5":
		return decryptHappCrypt5(payload, keysDir)
	case "crypt", "crypt2", "crypt3", "crypt4":
	default:
		return "", errors.New("unsupported Happ subscription link format")
	}
	ciphertext, err := decodeHappBase64(payload)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	key, err := readHappKey(keysDir, format)
	if err != nil {
		return "", err
	}
	size := key.Size()
	if len(ciphertext) == 0 || len(ciphertext)%size != 0 {
		return "", errors.New("invalid Happ RSA ciphertext length")
	}
	var plaintext strings.Builder
	for offset := 0; offset < len(ciphertext); offset += size {
		block, err := rsa.DecryptPKCS1v15(nil, key, ciphertext[offset:offset+size])
		if err != nil {
			return "", fmt.Errorf("decrypt Happ RSA block: %w", err)
		}
		plaintext.Write(block)
	}
	return plaintext.String(), nil
}

var happBase64Alphabet = strings.NewReplacer("-", "+", "_", "/")

func decodeHappBase64(value string) ([]byte, error) {
	if strings.ContainsAny(value, "\r\n") {
		return nil, errors.New("invalid base64 payload")
	}
	value = happBase64Alphabet.Replace(value)
	if strings.HasSuffix(value, "=") {
		return base64.StdEncoding.DecodeString(value)
	}
	return base64.RawStdEncoding.DecodeString(value)
}

func readHappKey(dir, name string) (*rsa.PrivateKey, error) {
	// The name is a recognized format or a validated alphanumeric crypt5 marker.
	path := filepath.Join(dir, name+".pem")
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("the Happ private key is missing at %s", path)
	}
	if err != nil {
		return nil, fmt.Errorf("open Happ private key: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxHappKeyFileSize+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return nil, fmt.Errorf("read Happ private key at %s: %w", path, err)
	}
	if len(data) > maxHappKeyFileSize {
		return nil, fmt.Errorf("the Happ private key file is too large at %s", path)
	}
	block, _ := pem.Decode(data)
	if block != nil && len(block.Headers) == 0 {
		switch block.Type {
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err == nil {
				return key, nil
			}
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if rsaKey, isRSA := key.(*rsa.PrivateKey); err == nil && isRSA {
				return rsaKey, nil
			}
		}
	}
	return nil, fmt.Errorf("invalid unencrypted RSA private key at %s", path)
}

func decryptHappCrypt5(payload, keysDir string) (string, error) {
	wire := []byte(payload)
	const markerHalf = 4
	if len(wire) < 2*markerHalf+chacha20poly1305.NonceSize+1 {
		return "", errors.New("invalid Happ crypt5 payload length")
	}
	for i := 0; i+3 < len(wire); i += 4 {
		wire[i], wire[i+1], wire[i+2], wire[i+3] = wire[i+2], wire[i+3], wire[i], wire[i+1]
	}
	marker := string(wire[:markerHalf]) + string(wire[len(wire)-markerHalf:])
	for i := range len(marker) {
		c := marker[i]
		lower := c | 0x20
		if !isASCIIDigit(c) && (lower < 'a' || lower > 'z') {
			return "", errors.New("invalid Happ crypt5 key identifier")
		}
	}
	key, err := readHappKey(keysDir, "crypt5-"+marker)
	if err != nil {
		return "", err
	}
	body := wire[markerHalf : len(wire)-markerHalf]
	// The legacy format puts the decimal field length right after the nonce.
	salted := !isASCIIDigit(body[chacha20poly1305.NonceSize])
	decoded, err := openHappCrypt5Body(body, key, salted)
	if err == nil {
		return decoded, nil
	}
	decoded, fallbackErr := openHappCrypt5Body(body, key, !salted)
	if fallbackErr == nil {
		return decoded, nil
	}
	return "", fmt.Errorf("invalid Happ crypt5 payload: %w", errors.Join(err, fallbackErr))
}

func openHappCrypt5Body(body []byte, key *rsa.PrivateKey, salted bool) (string, error) {
	const nonceSize = chacha20poly1305.NonceSize
	const saltSize = 8
	fieldsOffset := nonceSize
	if salted {
		fieldsOffset += 2 + saltSize
	}
	if len(body) <= fieldsOffset {
		return "", errors.New("crypt5 header is too short")
	}
	lengthField, packed, _ := strings.Cut(string(body[fieldsOffset:]), ":")
	for i := range len(lengthField) {
		if !isASCIIDigit(lengthField[i]) {
			return "", errors.New("invalid crypt5 ciphertext length")
		}
	}
	length, err := strconv.Atoi(lengthField)
	if err != nil || length <= 0 || length >= len(packed) {
		return "", errors.New("invalid crypt5 ciphertext length")
	}
	rsaBlock, err := decodeHappBase64(packed[length:])
	if err != nil || len(rsaBlock) != key.Size() {
		return "", errors.New("invalid crypt5 RSA block")
	}
	encodedKey, err := rsa.DecryptPKCS1v15(nil, key, rsaBlock)
	if err != nil {
		return "", fmt.Errorf("decrypt crypt5 RSA block: %w", err)
	}
	swapBytePairs(encodedKey)
	sessionKey, err := decodeHappBase64(string(encodedKey))
	if err != nil || len(sessionKey) != chacha20poly1305.KeySize {
		return "", errors.New("invalid crypt5 session key")
	}
	if salted {
		salt := body[fieldsOffset-saltSize : fieldsOffset]
		for i := range sessionKey {
			sessionKey[i] ^= salt[i%saltSize]
		}
	}
	sealed, err := decodeHappBase64(packed[:length])
	if err != nil {
		return "", fmt.Errorf("decode crypt5 ciphertext: %w", err)
	}
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return "", fmt.Errorf("initialize crypt5 cipher: %w", err)
	}
	plaintext, err := aead.Open(nil, body[:nonceSize], sealed, nil)
	if err != nil {
		return "", fmt.Errorf("authenticate crypt5 payload: %w", err)
	}
	swapBytePairs(plaintext)
	decoded, err := decodeHappBase64(string(plaintext))
	if err != nil {
		return "", fmt.Errorf("decode crypt5 plaintext: %w", err)
	}
	return string(decoded), nil
}

func swapBytePairs(value []byte) {
	for i := 0; i+1 < len(value); i += 2 {
		value[i], value[i+1] = value[i+1], value[i]
	}
}

func isASCIIDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
