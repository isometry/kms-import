package keymaterial

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// secp256k1 test fixtures generated with:
//
//	openssl ecparam -name secp256k1 -genkey -noout
//	openssl pkcs8 -topk8 -nocrypt
const (
	secp256k1SEC1PEM = `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIClJr/+36ojt8rFnUu51psMXdwBdZP0fvD2cBIeukJW1oAcGBSuBBAAK
oUQDQgAEAx6rxbEMmWUVT1EARxn4WtMyeHgKmg+OynVBM8OHsMEcNUog8SoYjiBs
mesxZ15J2A9ihb8sv8CyDH+i0OABUQ==
-----END EC PRIVATE KEY-----
`
	secp256k1PKCS8PEM = `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgKUmv/7fqiO3ysWdS7nWm
wxd3AF1k/R+8PZwEh66QlbWhRANCAAQDHqvFsQyZZRVPUQBHGfha0zJ4eAqaD47K
dUEzw4ewwRw1SiDxKhiOIGyZ6zFnXknYD2KFvyy/wLIMf6LQ4AFR
-----END PRIVATE KEY-----
`
	encryptedPKCS8PEM = `-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBBE3Z2hB5XjL4tjlove
1YWlAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQd7sMT7RVdwawGoun
epN7ewSBkHdJvdGp7U4o7/flTwX9gUJ84gnwinzu/owyRKD8v0EBoYHn7lSnJmu+
Z214y7KRcQitHr0oNlvFcClAMFxPxjgpv/yeJTE6aaJrXP+qYBocEw66T0pu8rn1
8oL9EswgHiRdqSOPbnwbMAx/yAqgC1fCAm4Gt7xHXJs5D/HW9DNCPpaqzkgE0y3Q
MlVvTwIg8Q==
-----END ENCRYPTED PRIVATE KEY-----
`
	encryptedLegacyPEM = `-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,A546A6247EBE25F9337A82B0D41124C9

tI2kUhj2NSN8+vJ0F49sN137sIWPt+1uNaLuuLybRdutcNf8UPtDGK5tIBvjqyiV
K2IS74ETqMEsj+jgMRRhq8WWqMWiBjVqZGqPAijPuZPltHX4jq0Q1NfUiAEJ6who
eGYCCBaMFoq2Ifk4uBG/WAUZty43IGzoLIhp0LTgGqg=
-----END EC PRIVATE KEY-----
`
)

func pemEncode(t *testing.T, blockType string, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func mustPKCS8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return der
}

func TestParseRSA(t *testing.T) {
	specs := map[int]types.KeySpec{
		2048: types.KeySpecRsa2048,
		3072: types.KeySpecRsa3072,
		4096: types.KeySpecRsa4096,
	}
	for bits, wantSpec := range specs {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatalf("GenerateKey(%d): %v", bits, err)
		}
		pkcs1 := x509.MarshalPKCS1PrivateKey(key)
		pkcs8 := mustPKCS8(t, key)

		encodings := map[string][]byte{
			"pkcs1-der": pkcs1,
			"pkcs1-pem": pemEncode(t, "RSA PRIVATE KEY", pkcs1),
			"pkcs8-der": pkcs8,
			"pkcs8-pem": pemEncode(t, "PRIVATE KEY", pkcs8),
		}
		for name, data := range encodings {
			t.Run(strings.ReplaceAll(name, "pkcs", "rsa-"+string(wantSpec)+"-pkcs"), func(t *testing.T) {
				km, err := Parse(data)
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				if km.KeySpec != wantSpec {
					t.Errorf("KeySpec = %v, want %v", km.KeySpec, wantSpec)
				}
				parsed, err := x509.ParsePKCS8PrivateKey(km.PKCS8DER)
				if err != nil {
					t.Fatalf("output not valid PKCS#8: %v", err)
				}
				got, ok := parsed.(*rsa.PrivateKey)
				if !ok {
					t.Fatalf("output key type = %T, want *rsa.PrivateKey", parsed)
				}
				if !got.Equal(key) {
					t.Error("round-tripped key differs from input")
				}
			})
		}
	}
}

func TestParseECDSA(t *testing.T) {
	specs := map[elliptic.Curve]types.KeySpec{
		elliptic.P256(): types.KeySpecEccNistP256,
		elliptic.P384(): types.KeySpecEccNistP384,
		elliptic.P521(): types.KeySpecEccNistP521,
	}
	for curve, wantSpec := range specs {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", curve.Params().Name, err)
		}
		sec1, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatalf("MarshalECPrivateKey: %v", err)
		}
		pkcs8 := mustPKCS8(t, key)

		encodings := map[string][]byte{
			"sec1-der":  sec1,
			"sec1-pem":  pemEncode(t, "EC PRIVATE KEY", sec1),
			"pkcs8-der": pkcs8,
			"pkcs8-pem": pemEncode(t, "PRIVATE KEY", pkcs8),
		}
		for name, data := range encodings {
			t.Run(string(wantSpec)+"-"+name, func(t *testing.T) {
				km, err := Parse(data)
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				if km.KeySpec != wantSpec {
					t.Errorf("KeySpec = %v, want %v", km.KeySpec, wantSpec)
				}
				parsed, err := x509.ParsePKCS8PrivateKey(km.PKCS8DER)
				if err != nil {
					t.Fatalf("output not valid PKCS#8: %v", err)
				}
				got, ok := parsed.(*ecdsa.PrivateKey)
				if !ok {
					t.Fatalf("output key type = %T, want *ecdsa.PrivateKey", parsed)
				}
				if !got.Equal(key) {
					t.Error("round-tripped key differs from input")
				}
			})
		}
	}
}

func TestParseEd25519(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pkcs8 := mustPKCS8(t, key)

	encodings := map[string][]byte{
		"pkcs8-der": pkcs8,
		"pkcs8-pem": pemEncode(t, "PRIVATE KEY", pkcs8),
	}
	for name, data := range encodings {
		t.Run(name, func(t *testing.T) {
			km, err := Parse(data)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if km.KeySpec != types.KeySpecEccNistEdwards25519 {
				t.Errorf("KeySpec = %v, want %v", km.KeySpec, types.KeySpecEccNistEdwards25519)
			}
			parsed, err := x509.ParsePKCS8PrivateKey(km.PKCS8DER)
			if err != nil {
				t.Fatalf("output not valid PKCS#8: %v", err)
			}
			got, ok := parsed.(ed25519.PrivateKey)
			if !ok {
				t.Fatalf("output key type = %T, want ed25519.PrivateKey", parsed)
			}
			if !got.Equal(key) {
				t.Error("round-tripped key differs from input")
			}
		})
	}
}

func TestParseSecp256k1(t *testing.T) {
	for name, data := range map[string]string{
		"sec1-pem":  secp256k1SEC1PEM,
		"pkcs8-pem": secp256k1PKCS8PEM,
	} {
		t.Run(name, func(t *testing.T) {
			km, err := Parse([]byte(data))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if km.KeySpec != types.KeySpecEccSecgP256k1 {
				t.Errorf("KeySpec = %v, want %v", km.KeySpec, types.KeySpecEccSecgP256k1)
			}
			// stdlib cannot parse secp256k1, so verify the emitted PKCS#8
			// matches the openssl-produced PKCS#8 encoding of the same key.
			block, _ := pem.Decode([]byte(secp256k1PKCS8PEM))
			if string(km.PKCS8DER) != string(block.Bytes) {
				t.Error("PKCS8DER does not match openssl PKCS#8 encoding")
			}
		})
	}
}

func TestParsePEMWithSurroundingJunk(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pemData := pemEncode(t, "PRIVATE KEY", mustPKCS8(t, key))
	data := append([]byte("some preamble text\n"), pemData...)
	data = append(data, []byte("trailing junk\n")...)

	km, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if km.KeySpec != types.KeySpecEccNistP256 {
		t.Errorf("KeySpec = %v, want %v", km.KeySpec, types.KeySpecEccNistP256)
	}
}

func TestParseRejections(t *testing.T) {
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey(1024): %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&rsa1024.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	cases := map[string]struct {
		data    []byte
		errWant string
	}{
		"encrypted-pkcs8":  {[]byte(encryptedPKCS8PEM), "encrypted"},
		"encrypted-legacy": {[]byte(encryptedLegacyPEM), "encrypted"},
		"rsa-1024":         {pemEncode(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsa1024)), "1024"},
		"public-key":       {pemEncode(t, "PUBLIC KEY", pubDER), "private"},
		"garbage":          {[]byte("not a key at all"), ""},
		"empty":            {nil, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(tc.data)
			if err == nil {
				t.Fatal("Parse succeeded, want error")
			}
			if tc.errWant != "" && !strings.Contains(err.Error(), tc.errWant) {
				t.Errorf("error %q does not mention %q", err, tc.errWant)
			}
		})
	}
}

// secp256k1 fixture public key SPKI and fingerprint, precomputed with:
//
//	openssl pkey -in k1-sec1.pem -pubout -outform der | base64
//	openssl pkey -in k1-sec1.pem -pubout -outform der | openssl dgst -sha256 -binary | openssl base64
const (
	secp256k1SPKIBase64  = "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEAx6rxbEMmWUVT1EARxn4WtMyeHgKmg+OynVBM8OHsMEcNUog8SoYjiBsmesxZ15J2A9ihb8sv8CyDH+i0OABUQ=="
	secp256k1Fingerprint = "SHA256:qF+rpjA3mbmCyZW6Fn/Z1gVekfo+8rO0Z6/Ayf1Ofng="
)

func spkiFingerprint(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	sum := sha256.Sum256(der)
	return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:])
}

func TestFingerprint(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	cases := map[string]struct {
		data []byte
		want string
	}{
		"rsa":             {pemEncode(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)), spkiFingerprint(t, &rsaKey.PublicKey)},
		"ecdsa":           {pemEncode(t, "PRIVATE KEY", mustPKCS8(t, ecKey)), spkiFingerprint(t, &ecKey.PublicKey)},
		"ed25519":         {pemEncode(t, "PRIVATE KEY", mustPKCS8(t, edKey)), spkiFingerprint(t, edPub)},
		"secp256k1-sec1":  {[]byte(secp256k1SEC1PEM), secp256k1Fingerprint},
		"secp256k1-pkcs8": {[]byte(secp256k1PKCS8PEM), secp256k1Fingerprint},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			km, err := Parse(tc.data)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if km.Fingerprint != tc.want {
				t.Errorf("Fingerprint = %q, want %q", km.Fingerprint, tc.want)
			}
			if len(km.PublicKeyDER) == 0 {
				t.Error("PublicKeyDER is empty")
			}
		})
	}
}

func TestPublicKeyEqual(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	rsaKM, err := Parse(pemEncode(t, "PRIVATE KEY", mustPKCS8(t, rsaKey)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	mustSPKI := func(pub any) []byte {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}
		return der
	}

	if eq, err := rsaKM.PublicKeyEqual(mustSPKI(&rsaKey.PublicKey)); err != nil || !eq {
		t.Errorf("same RSA key: eq=%v err=%v, want true", eq, err)
	}
	if eq, err := rsaKM.PublicKeyEqual(mustSPKI(&otherRSA.PublicKey)); err != nil || eq {
		t.Errorf("different RSA key: eq=%v err=%v, want false", eq, err)
	}
	if eq, err := rsaKM.PublicKeyEqual(mustSPKI(&ecKey.PublicKey)); err != nil || eq {
		t.Errorf("cross-type: eq=%v err=%v, want false", eq, err)
	}
	if _, err := rsaKM.PublicKeyEqual([]byte("not DER")); err == nil {
		t.Error("garbage SPKI accepted")
	}

	k1KM, err := Parse([]byte(secp256k1SEC1PEM))
	if err != nil {
		t.Fatalf("Parse secp256k1: %v", err)
	}
	k1SPKI, err := base64.StdEncoding.DecodeString(secp256k1SPKIBase64)
	if err != nil {
		t.Fatalf("decoding fixture SPKI: %v", err)
	}
	if eq, err := k1KM.PublicKeyEqual(k1SPKI); err != nil || !eq {
		t.Errorf("secp256k1 same key: eq=%v err=%v, want true", eq, err)
	}
	if eq, err := k1KM.PublicKeyEqual(mustSPKI(&ecKey.PublicKey)); err != nil || eq {
		t.Errorf("secp256k1 vs P-256: eq=%v err=%v, want false", eq, err)
	}
}
