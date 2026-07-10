package wrap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/tink-crypto/tink-go/v2/kwp/subtle"
)

// TestWrapRoundTrip plays the role of the KMS HSM: unwrap the blob produced
// by Wrap and check the original key material comes back.
func TestWrapRoundTrip(t *testing.T) {
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("generating wrapping key: %v", err)
	}
	wrappingKeyDER, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	if err != nil {
		t.Fatalf("marshalling wrapping public key: %v", err)
	}

	material := make([]byte, 1218) // typical RSA-2048 PKCS#8 DER size
	if _, err := rand.Read(material); err != nil {
		t.Fatalf("generating material: %v", err)
	}

	blob, err := Wrap(material, wrappingKeyDER)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// First part: the ephemeral AES key under RSAES-OAEP-SHA256, sized to
	// the wrapping key modulus.
	oaepLen := wrappingKey.Size()
	if len(blob) <= oaepLen {
		t.Fatalf("blob length %d, want > %d (OAEP block + KWP payload)", len(blob), oaepLen)
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), nil, wrappingKey, blob[:oaepLen], nil)
	if err != nil {
		t.Fatalf("OAEP-decrypting AES key: %v", err)
	}
	if len(aesKey) != 32 {
		t.Fatalf("AES key length = %d, want 32", len(aesKey))
	}

	// Second part: the key material under AES-KWP (RFC 5649).
	kwp, err := subtle.NewKWP(aesKey)
	if err != nil {
		t.Fatalf("NewKWP: %v", err)
	}
	unwrapped, err := kwp.Unwrap(blob[oaepLen:])
	if err != nil {
		t.Fatalf("KWP-unwrapping material: %v", err)
	}
	if !bytes.Equal(unwrapped, material) {
		t.Error("unwrapped material differs from input")
	}
}

func TestWrapUniquePerCall(t *testing.T) {
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating wrapping key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	if err != nil {
		t.Fatalf("marshalling wrapping public key: %v", err)
	}
	material := bytes.Repeat([]byte{0x42}, 64)

	a, err := Wrap(material, der)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	b, err := Wrap(material, der)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("two Wrap calls produced identical output; ephemeral AES key is not fresh")
	}
}

func TestWrapRejectsBadWrappingKey(t *testing.T) {
	material := bytes.Repeat([]byte{0x42}, 64)

	if _, err := Wrap(material, []byte("not DER")); err == nil {
		t.Error("Wrap accepted garbage wrapping key DER")
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("marshalling EC public key: %v", err)
	}
	if _, err := Wrap(material, ecDER); err == nil {
		t.Error("Wrap accepted a non-RSA wrapping key")
	}
}
