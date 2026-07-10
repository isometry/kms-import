# kms-import

Import a locally-held private key into AWS KMS.

`kms-import` automates the [AWS KMS key material import process](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-conceptual.html)
for asymmetric keys — for example a GitHub App private key, so JWTs can be
signed via KMS instead of holding the PEM on disk:

1. `CreateKey` with `Origin=EXTERNAL` and a key spec matching your key file
2. `GetParametersForImport` with the `RSA_AES_KEY_WRAP_SHA_256` wrapping
   algorithm and an `RSA_4096` wrapping key
3. Wrap the key material locally: PKCS#8 DER under a fresh AES-256 key with
   AES-KWP (RFC 5649), the AES key under RSAES-OAEP-SHA256
4. `ImportKeyMaterial` (optionally with an expiry)
5. `CreateAlias` for each requested alias

If anything fails after the key is created but before the material is
imported, the unusable key is scheduled for deletion (7-day window) so no
orphaned `PendingImport` keys accumulate.

## Supported key material

Unencrypted private keys in PEM or DER form (PKCS#1, PKCS#8 or SEC1):

| Key | KMS key spec |
|---|---|
| RSA 2048 / 3072 / 4096 | `RSA_2048` / `RSA_3072` / `RSA_4096` |
| ECDSA P-256 / P-384 / P-521 | `ECC_NIST_P256` / `ECC_NIST_P384` / `ECC_NIST_P521` |
| secp256k1 | `ECC_SECG_P256K1` |
| Ed25519 | `ECC_NIST_EDWARDS25519` |

Note: for asymmetric KMS keys, key material can only ever be imported once —
the same material can be reimported (e.g. to reset expiry), but never replaced.

## Usage

```console
$ kms-import github-app.private-key.pem \
    --alias github-app \
    --tags Name=github-app --tags Team=platform
imported key material into new KMS key
  key id:  1234abcd-12ab-34cd-56ef-1234567890ab
  arn:     arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
  spec:    RSA_2048
  aliases: alias/github-app
  expires: never
```

### Flags

| Flag | Description |
|---|---|
| `--alias` | alias to create (repeatable; `alias/` prefix optional) |
| `--tags` | `key=value` tag to set on the key (repeatable) |
| `--usage` | `SIGN_VERIFY` (default) or `ENCRYPT_DECRYPT` (RSA only) |
| `--expires` | key material expiry: Go duration (`8760h`) or RFC3339 timestamp (default: never) |
| `--description` | KMS key description |
| `--output` | `text` (default) or `json` |
| `--dry-run` | validate the key file and print the plan; no AWS calls |
| `--region`, `--profile` | AWS SDK overrides |

Every flag can also be set via the environment with a `KMS_IMPORT_` prefix
(e.g. `KMS_IMPORT_REGION=eu-west-1`). AWS credentials use the standard SDK
resolution chain (environment, shared config, SSO, IMDS, …).

### Machine-readable output

```console
$ kms-import key.pem --alias my-key --output json
{
  "keyId": "1234abcd-12ab-34cd-56ef-1234567890ab",
  "arn": "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-...",
  "keySpec": "RSA_2048",
  "aliases": ["alias/my-key"]
}
```

## Required IAM permissions

- `kms:CreateKey`
- `kms:GetParametersForImport`
- `kms:ImportKeyMaterial`
- `kms:CreateAlias` (when using `--alias`)
- `kms:TagResource` (when using `--tags`)
- `kms:ScheduleKeyDeletion` (for cleanup of keys whose import failed)

## Security notes

- Key material is wrapped in memory and never written to disk; plaintext
  buffers are cleared after use (best-effort — Go's GC may retain copies).
- The wrapping algorithm is `RSA_AES_KEY_WRAP_SHA_256`, the strongest KMS
  offers and the only family valid for RSA private key material.
- Expired key material is deleted by KMS and the key becomes unusable until
  the same material is reimported — only use `--expires` if you retain the
  source key and have a reimport process.

## Licence

MIT
