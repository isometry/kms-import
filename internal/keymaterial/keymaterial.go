// Package keymaterial parses local private key files and normalises them to
// the PKCS#8 DER encoding that AWS KMS requires for imported key material.
package keymaterial

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KeyMaterial is a private key normalised for import into AWS KMS.
type KeyMaterial struct {
	// PKCS8DER is the key encoded as an unencrypted PKCS#8 PrivateKeyInfo.
	PKCS8DER []byte
	// KeySpec is the AWS KMS key spec matching the key material.
	KeySpec types.KeySpec
	// PublicKeyDER is the derived public key as DER-encoded SubjectPublicKeyInfo,
	// the same encoding KMS returns from GetPublicKey.
	PublicKeyDER []byte
	// Fingerprint is "sha256:<hex>" over PublicKeyDER, used to tag and look up
	// KMS keys holding this material.
	Fingerprint string

	// publicKey enables semantic comparison for stdlib-supported key types;
	// nil for secp256k1, which is compared structurally via PublicKeyDER.
	publicKey crypto.PublicKey
}

// PublicKeyEqual reports whether spkiDER (e.g. the KMS GetPublicKey response)
// contains the same public key as this material. Comparison is semantic, not
// byte-wise, so encoding differences between producers do not matter.
func (k *KeyMaterial) PublicKeyEqual(spkiDER []byte) (bool, error) {
	if bytes.Equal(spkiDER, k.PublicKeyDER) {
		return true, nil
	}
	if k.publicKey != nil {
		pub, err := x509.ParsePKIXPublicKey(spkiDER)
		if err != nil {
			// A structurally valid SPKI the stdlib cannot handle (e.g.
			// secp256k1) is simply a different key, not an error.
			if _, _, spkiErr := parseSPKI(spkiDER); spkiErr == nil {
				return false, nil
			}
			return false, fmt.Errorf("parsing public key: %w", err)
		}
		pk, ok := k.publicKey.(interface{ Equal(crypto.PublicKey) bool })
		return ok && pk.Equal(pub), nil
	}

	// secp256k1: compare algorithm identifiers and public points structurally.
	ownAlgo, ownPoint, err := parseSPKI(k.PublicKeyDER)
	if err != nil {
		return false, fmt.Errorf("parsing own public key: %w", err)
	}
	algo, point, err := parseSPKI(spkiDER)
	if err != nil {
		return false, fmt.Errorf("parsing public key: %w", err)
	}
	return ownAlgo.Algorithm.Equal(algo.Algorithm) &&
		bytes.Equal(ownAlgo.Parameters.FullBytes, algo.Parameters.FullBytes) &&
		bytes.Equal(ownPoint.RightAlign(), point.RightAlign()), nil
}

type subjectPublicKeyInfo struct {
	Algo      pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func parseSPKI(der []byte) (pkix.AlgorithmIdentifier, asn1.BitString, error) {
	var info subjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil {
		return pkix.AlgorithmIdentifier{}, asn1.BitString{}, err
	} else if len(rest) != 0 {
		return pkix.AlgorithmIdentifier{}, asn1.BitString{}, errors.New("trailing data after SubjectPublicKeyInfo")
	}
	return info.Algo, info.PublicKey, nil
}

func fingerprint(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var (
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSecp256k1   = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
)

var errEncrypted = errors.New("key material is encrypted: decrypt it first, e.g. `openssl pkey -in <keyfile>`")

// Parse reads a private key in PEM or DER form (PKCS#1, PKCS#8 or SEC1) and
// returns it as PKCS#8 DER together with the matching KMS key spec.
func Parse(data []byte) (*KeyMaterial, error) {
	var otherBlock string
	for rest := data; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "ENCRYPTED PRIVATE KEY" || block.Headers["Proc-Type"] == "4,ENCRYPTED" {
			return nil, errEncrypted
		}
		switch block.Type {
		case "PRIVATE KEY":
			return fromPKCS8(block.Bytes)
		case "RSA PRIVATE KEY":
			return fromPKCS1(block.Bytes)
		case "EC PRIVATE KEY":
			return fromSEC1(block.Bytes)
		default:
			otherBlock = block.Type
		}
	}
	if otherBlock != "" {
		return nil, fmt.Errorf("no private key found in input (found %q PEM block)", otherBlock)
	}

	// No PEM: try raw DER encodings.
	if km, err := fromPKCS8(data); err == nil {
		return km, nil
	}
	if km, err := fromPKCS1(data); err == nil {
		return km, nil
	}
	if km, err := fromSEC1(data); err == nil {
		return km, nil
	}
	return nil, errors.New("unrecognised key material: expected an unencrypted private key in PEM or DER form (PKCS#1, PKCS#8 or SEC1)")
}

func fromPKCS8(der []byte) (*KeyMaterial, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		// The stdlib rejects secp256k1; detect it ourselves and pass the
		// original encoding through verbatim.
		if km, k1err := secp256k1FromPKCS8(der); k1err == nil {
			return km, nil
		}
		return nil, fmt.Errorf("parsing PKCS#8 key: %w", err)
	}
	return fromKey(key)
}

func fromPKCS1(der []byte) (*KeyMaterial, error) {
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS#1 RSA key: %w", err)
	}
	return fromKey(key)
}

func fromSEC1(der []byte) (*KeyMaterial, error) {
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		if km, k1err := secp256k1FromSEC1(der); k1err == nil {
			return km, nil
		}
		return nil, fmt.Errorf("parsing SEC1 EC key: %w", err)
	}
	return fromKey(key)
}

// fromKey classifies a stdlib private key, validates it against the specs KMS
// accepts for imported key material, and re-encodes it as PKCS#8 DER.
func fromKey(key any) (*KeyMaterial, error) {
	var spec types.KeySpec
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if len(k.Primes) != 2 {
			return nil, fmt.Errorf("unsupported RSA key with %d primes: KMS only accepts two-prime keys", len(k.Primes))
		}
		switch bits := k.N.BitLen(); bits {
		case 2048:
			spec = types.KeySpecRsa2048
		case 3072:
			spec = types.KeySpecRsa3072
		case 4096:
			spec = types.KeySpecRsa4096
		default:
			return nil, fmt.Errorf("unsupported RSA key size %d bits: KMS accepts 2048, 3072 or 4096", bits)
		}
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			spec = types.KeySpecEccNistP256
		case elliptic.P384():
			spec = types.KeySpecEccNistP384
		case elliptic.P521():
			spec = types.KeySpecEccNistP521
		default:
			return nil, fmt.Errorf("unsupported elliptic curve %q", k.Curve.Params().Name)
		}
	case ed25519.PrivateKey:
		spec = types.KeySpecEccNistEdwards25519
	default:
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encoding key as PKCS#8: %w", err)
	}

	pub := key.(crypto.Signer).Public()
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("encoding public key: %w", err)
	}
	return &KeyMaterial{
		PKCS8DER:     der,
		KeySpec:      spec,
		PublicKeyDER: pubDER,
		Fingerprint:  fingerprint(pubDER),
		publicKey:    pub,
	}, nil
}

// ASN.1 structures for the secp256k1 paths the stdlib refuses to handle.
type pkcs8PrivateKeyInfo struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type sec1PrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// sec1 variants used when re-encoding inside PKCS#8, where RFC 5915 says the
// curve parameters must be omitted (they live in the AlgorithmIdentifier).
type sec1InnerWithPub struct {
	Version    int
	PrivateKey []byte
	PublicKey  asn1.BitString `asn1:"optional,explicit,tag:1"`
}

type sec1Inner struct {
	Version    int
	PrivateKey []byte
}

func secp256k1FromPKCS8(der []byte) (*KeyMaterial, error) {
	var info pkcs8PrivateKeyInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil || len(rest) != 0 {
		return nil, errors.New("not a PKCS#8 structure")
	}
	if !info.Algo.Algorithm.Equal(oidECPublicKey) {
		return nil, errors.New("not an EC key")
	}
	var curve asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(info.Algo.Parameters.FullBytes, &curve); err != nil || !curve.Equal(oidSecp256k1) {
		return nil, errors.New("not a secp256k1 key")
	}
	var inner sec1PrivateKey
	if _, err := asn1.Unmarshal(info.PrivateKey, &inner); err != nil {
		return nil, fmt.Errorf("parsing inner EC key: %w", err)
	}
	return secp256k1Material(der, inner.PublicKey)
}

// secp256k1Material assembles the KeyMaterial for a secp256k1 key from its
// final PKCS#8 encoding and the public point embedded in the source encoding.
// The stdlib has no secp256k1 curve math, so a key without an embedded public
// point cannot be fingerprinted.
func secp256k1Material(pkcs8DER []byte, point asn1.BitString) (*KeyMaterial, error) {
	if point.BitLength == 0 {
		return nil, errors.New("secp256k1 key has no embedded public key: cannot derive its fingerprint")
	}
	params, err := asn1.Marshal(oidSecp256k1)
	if err != nil {
		return nil, fmt.Errorf("encoding curve OID: %w", err)
	}
	pubDER, err := asn1.Marshal(subjectPublicKeyInfo{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  oidECPublicKey,
			Parameters: asn1.RawValue{FullBytes: params},
		},
		PublicKey: point,
	})
	if err != nil {
		return nil, fmt.Errorf("encoding public key: %w", err)
	}
	return &KeyMaterial{
		PKCS8DER:     pkcs8DER,
		KeySpec:      types.KeySpecEccSecgP256k1,
		PublicKeyDER: pubDER,
		Fingerprint:  fingerprint(pubDER),
	}, nil
}

func secp256k1FromSEC1(der []byte) (*KeyMaterial, error) {
	var key sec1PrivateKey
	if rest, err := asn1.Unmarshal(der, &key); err != nil || len(rest) != 0 {
		return nil, errors.New("not a SEC1 structure")
	}
	if !key.NamedCurveOID.Equal(oidSecp256k1) {
		return nil, errors.New("not a secp256k1 key")
	}

	var inner []byte
	var err error
	if key.PublicKey.BitLength > 0 {
		inner, err = asn1.Marshal(sec1InnerWithPub{Version: key.Version, PrivateKey: key.PrivateKey, PublicKey: key.PublicKey})
	} else {
		inner, err = asn1.Marshal(sec1Inner{Version: key.Version, PrivateKey: key.PrivateKey})
	}
	if err != nil {
		return nil, fmt.Errorf("re-encoding SEC1 key: %w", err)
	}

	params, err := asn1.Marshal(oidSecp256k1)
	if err != nil {
		return nil, fmt.Errorf("encoding curve OID: %w", err)
	}
	pkcs8, err := asn1.Marshal(pkcs8PrivateKeyInfo{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  oidECPublicKey,
			Parameters: asn1.RawValue{FullBytes: params},
		},
		PrivateKey: inner,
	})
	if err != nil {
		return nil, fmt.Errorf("encoding PKCS#8: %w", err)
	}
	return secp256k1Material(pkcs8, key.PublicKey)
}
