# kms-import

Idempotently import a locally-held private key into AWS KMS.

`kms-import` automates the [AWS KMS key material import process](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-conceptual.html)
for asymmetric keys — for example a GitHub App private key, so JWTs can be
signed via KMS instead of holding the PEM on disk:

1. Look up keys already holding this material (see *Idempotence* below); if a
   verified match exists, converge its aliases/tags and stop
2. Otherwise `CreateKey` with `Origin=EXTERNAL` and a key spec matching your
   key file
3. `GetParametersForImport` with the `RSA_AES_KEY_WRAP_SHA_256` wrapping
   algorithm and an `RSA_4096` wrapping key
4. Wrap the key material locally: PKCS#8 DER under a fresh AES-256 key with
   AES-KWP (RFC 5649), the AES key under RSAES-OAEP-SHA256
5. `ImportKeyMaterial` (optionally with an expiry)
6. `CreateAlias` for each requested alias

If anything fails after a key is created but before the material is imported,
the unusable key is scheduled for deletion (7-day window) so no orphaned
`PendingImport` keys accumulate.

## Idempotence

Running kms-import twice with the same key file converges instead of
duplicating. The identity of a key is its **public key**, not metadata: KMS
derives the public key from imported private material (`GetPublicKey`), and
kms-import derives the same public key locally from the file.

- Every imported key is tagged `fingerprint: sha256:<hex>` — the SHA-256 of
  the public key's DER SPKI encoding (the same value
  `openssl pkey -in key.pem -pubout -outform der | openssl dgst -sha256`
  prints).
- The tag is only an *index*: candidates are discovered via the Resource
  Groups Tagging API, then always **verified** by comparing `GetPublicKey`
  output against the local public key. A tag that lies is detected and
  reported, never trusted.
- A verified match is converged: missing aliases are created and requested
  tags applied (nothing is ever removed or repointed); status `exists`.
- A match in `PendingImport` (failed import, expired material) is healed by
  reimporting — KMS itself proves identity, rejecting material that differs
  from what the key originally held; status `reimported`.
- If `tag:GetResources` is denied, the lookup is skipped with a warning and a
  new key is created (fail-open).

Keys imported by other means can be brought under management with
`--adopt <key-id>`: the key is verified against the local material (or, if
`PendingImport`, healed by reimport) and then fingerprint-tagged; status
`adopted`.

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
  key id:      1234abcd-12ab-34cd-56ef-1234567890ab
  arn:         arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
  spec:        RSA_2048
  fingerprint: sha256:9f2c8b6d...
  aliases:     alias/github-app
  expires:     never

$ kms-import github-app.private-key.pem --alias github-app
KMS key already holds this key material
  key id:      1234abcd-12ab-34cd-56ef-1234567890ab
  ...
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
| `--adopt` | key id/ARN of an existing key to verify and bring under management |
| `--dry-run` | validate the key file and print the plan (incl. fingerprint); no AWS calls |
| `--region`, `--profile` | AWS SDK overrides |

Every flag can also be set via the environment with a `KMS_IMPORT_` prefix
(e.g. `KMS_IMPORT_REGION=eu-west-1`). AWS credentials use the standard SDK
resolution chain (environment, shared config, SSO, IMDS, …).

### Machine-readable output

```console
$ kms-import key.pem --alias my-key --output json
{
  "status": "created",
  "keyId": "1234abcd-12ab-34cd-56ef-1234567890ab",
  "arn": "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-...",
  "keySpec": "RSA_2048",
  "fingerprint": "sha256:9f2c8b6d...",
  "aliases": ["alias/my-key"]
}
```

## Required IAM permissions

- `kms:CreateKey` — create the EXTERNAL-origin key
- `kms:GetParametersForImport`, `kms:ImportKeyMaterial` — the import itself
- `kms:TagResource` — fingerprint tag and user tags
- `kms:CreateAlias` — when using `--alias`
- `kms:ScheduleKeyDeletion` — cleanup of just-created keys whose import failed
- `tag:GetResources` — idempotent lookup (without it the tool warns and always
  creates)
- `kms:DescribeKey`, `kms:GetPublicKey`, `kms:ListAliases`,
  `kms:ListResourceTags` — verification and convergence of existing keys

<details>
<summary>Complete IAM policy</summary>

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CreateExternalOriginKeys",
      "Effect": "Allow",
      "Action": "kms:CreateKey",
      "Resource": "*",
      "Condition": { "StringEquals": { "kms:KeyOrigin": "EXTERNAL" } }
    },
    {
      "Sid": "DiscoverKeysByFingerprintTag",
      "Effect": "Allow",
      "Action": ["tag:GetResources", "kms:ListAliases"],
      "Resource": "*"
    },
    {
      "Sid": "FetchImportParameters",
      "Effect": "Allow",
      "Action": "kms:GetParametersForImport",
      "Resource": "arn:aws:kms:*:111122223333:key/*",
      "Condition": {
        "StringEquals": {
          "kms:WrappingAlgorithm": "RSA_AES_KEY_WRAP_SHA_256",
          "kms:WrappingKeySpec": "RSA_4096"
        }
      }
    },
    {
      "Sid": "ManageImportedKeys",
      "Effect": "Allow",
      "Action": [
        "kms:DescribeKey",
        "kms:GetPublicKey",
        "kms:ImportKeyMaterial",
        "kms:ListResourceTags",
        "kms:TagResource",
        "kms:ScheduleKeyDeletion"
      ],
      "Resource": "arn:aws:kms:*:111122223333:key/*"
    },
    {
      "Sid": "CreateAliases",
      "Effect": "Allow",
      "Action": "kms:CreateAlias",
      "Resource": [
        "arn:aws:kms:*:111122223333:alias/*",
        "arn:aws:kms:*:111122223333:key/*"
      ]
    }
  ]
}
```

Notes:

- Replace `111122223333` with your AWS account id; narrow the region wildcard
  if desired.
- `kms:CreateKey`, `kms:ListAliases` and `tag:GetResources` do not support
  resource-level scoping and must be granted on `Resource: "*"`. The
  `kms:KeyOrigin` condition restricts key creation to import-style
  (`EXTERNAL`) keys only, and the wrapping conditions pin
  `GetParametersForImport` to the only parameters kms-import ever requests.
- `kms:CreateAlias` requires permission on **both** the alias ARN and the
  target key ARN.
- `kms:ScheduleKeyDeletion` is used solely to clean up a just-created key
  whose import failed. Omit it if you prefer; failed runs will then leave
  unusable `PendingImport` keys behind for manual deletion.
- Keys created by kms-import get the default key policy, which delegates
  authorisation to IAM policies like this one.

</details>

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
