// Package wrap encrypts key material for AWS KMS import using the
// RSA_AES_KEY_WRAP_SHA_256 wrapping algorithm: the material is wrapped with a
// fresh AES-256 key using AES-KWP (RFC 5649), the AES key is encrypted to the
// KMS wrapping public key with RSAES-OAEP-SHA256, and the two ciphertexts are
// concatenated (OAEP block first).
package wrap

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	"github.com/tink-crypto/tink-go/v2/kwp/subtle"
)

// Wrap encrypts pkcs8DER under the DER-encoded RSA wrapping public key
// returned by GetParametersForImport, producing the EncryptedKeyMaterial blob
// for ImportKeyMaterial.
func Wrap(pkcs8DER, wrappingKeyDER []byte) ([]byte, error) {
	pub, err := x509.ParsePKIXPublicKey(wrappingKeyDER)
	if err != nil {
		return nil, fmt.Errorf("parsing wrapping public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("wrapping public key is %T, want *rsa.PublicKey", pub)
	}

	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("generating ephemeral AES key: %w", err)
	}
	defer clear(aesKey)

	kwp, err := subtle.NewKWP(aesKey)
	if err != nil {
		return nil, fmt.Errorf("initialising AES-KWP: %w", err)
	}
	wrappedMaterial, err := kwp.Wrap(pkcs8DER)
	if err != nil {
		return nil, fmt.Errorf("wrapping key material: %w", err)
	}

	wrappedAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rsaPub, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypting ephemeral AES key: %w", err)
	}

	return append(wrappedAESKey, wrappedMaterial...), nil
}
