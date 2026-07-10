// Package importer idempotently ensures a KMS key holding the given key
// material exists: it looks up candidate keys by fingerprint tag, verifies
// them against the locally-derived public key, converges aliases and tags on
// a verified match, reimports into PendingImport keys, and otherwise creates
// a fresh EXTERNAL-origin key and imports the material into it.
package importer

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	taggingtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/smithy-go"

	"github.com/isometry/kms-import/internal/keymaterial"
	"github.com/isometry/kms-import/internal/wrap"
)

// FingerprintTagKey is the KMS tag used as a lookup index for the material's
// public-key fingerprint. The tag is only an index: identity is always
// verified against GetPublicKey (or by KMS itself on reimport).
const FingerprintTagKey = "fingerprint"

// deletionWindowDays is the shortest window KMS allows when scheduling
// deletion of a key we created but failed to import material into.
const deletionWindowDays = 7

// Result.Status values.
const (
	StatusCreated    = "created"    // new key created and material imported
	StatusExists     = "exists"     // verified existing key, converged
	StatusReimported = "reimported" // material reimported into a PendingImport key
	StatusAdopted    = "adopted"    // existing key verified and fingerprint-tagged
)

// Params describes the KMS key to ensure and the material behind it.
type Params struct {
	Material    *keymaterial.KeyMaterial
	Description string
	Usage       types.KeyUsageType
	Aliases     []string
	Tags        map[string]string
	// ValidTo sets key material expiry; nil means the material never expires.
	ValidTo *time.Time
	// AdoptKeyID, when set, skips discovery and brings the named existing key
	// under management: verify, fingerprint-tag, converge.
	AdoptKeyID string
}

// Result reports the ensured key.
type Result struct {
	Status      string     `json:"status"`
	KeyID       string     `json:"keyId"`
	ARN         string     `json:"arn"`
	KeySpec     string     `json:"keySpec"`
	Fingerprint string     `json:"fingerprint"`
	Aliases     []string   `json:"aliases,omitempty"`
	Expires     *time.Time `json:"expires,omitempty"`
	Warnings    []string   `json:"warnings,omitempty"`
}

// Ensure makes a KMS key holding p.Material exist and match the requested
// aliases and tags. An alias or tag failure after the key is usable returns
// both a non-nil Result and an error: the key exists and is usable.
func Ensure(ctx context.Context, api KMSAPI, tagging TaggingAPI, p Params) (*Result, error) {
	if p.AdoptKeyID != "" {
		return adopt(ctx, api, p)
	}

	candidates, warnings, err := lookup(ctx, tagging, p.Material.Fingerprint)
	if err != nil {
		return nil, err
	}
	if len(candidates) > 0 {
		if len(candidates) > 1 {
			warnings = append(warnings, fmt.Sprintf("fingerprint tag matches %d keys; using %s", len(candidates), candidates[0]))
		}
		res, err := ensureExisting(ctx, api, candidates[0], p)
		if res != nil {
			res.Warnings = append(warnings, res.Warnings...)
		}
		return res, err
	}

	res, err := create(ctx, api, p)
	if res != nil {
		res.Warnings = append(warnings, res.Warnings...)
	}
	return res, err
}

// lookup finds candidate key ARNs via the fingerprint tag index. A permission
// error fails open (create path) with a warning; other errors fail closed.
func lookup(ctx context.Context, tagging TaggingAPI, fp string) (arns, warnings []string, err error) {
	out, err := tagging.GetResources(ctx, &resourcegroupstaggingapi.GetResourcesInput{
		ResourceTypeFilters: []string{"kms:key"},
		TagFilters: []taggingtypes.TagFilter{{
			Key:    aws.String(FingerprintTagKey),
			Values: []string{fp},
		}},
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && strings.HasPrefix(apiErr.ErrorCode(), "AccessDenied") {
			return nil, []string{fmt.Sprintf(
				"tag:GetResources denied; skipping idempotent lookup and creating a new key (%s)", err)}, nil
		}
		return nil, nil, fmt.Errorf("looking up keys by fingerprint: %w", err)
	}
	for _, mapping := range out.ResourceTagMappingList {
		arns = append(arns, aws.ToString(mapping.ResourceARN))
	}
	return arns, nil, nil
}

// ensureExisting verifies a fingerprint-tagged candidate key and converges it.
func ensureExisting(ctx context.Context, api KMSAPI, keyARN string, p Params) (*Result, error) {
	desc, err := api.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyARN)})
	if err != nil {
		return nil, fmt.Errorf("describing candidate key %s: %w", keyARN, err)
	}
	md := desc.KeyMetadata
	keyID := aws.ToString(md.KeyId)
	res := &Result{
		KeyID:       keyID,
		ARN:         aws.ToString(md.Arn),
		KeySpec:     string(p.Material.KeySpec),
		Fingerprint: p.Material.Fingerprint,
	}

	switch md.KeyState {
	case types.KeyStateEnabled:
		pub, err := api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
		if err != nil {
			return nil, fmt.Errorf("fetching public key of candidate %s: %w", keyID, err)
		}
		match, err := p.Material.PublicKeyEqual(pub.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("comparing public key of candidate %s: %w", keyID, err)
		}
		if !match {
			return nil, fmt.Errorf(
				"key %s carries fingerprint tag %s but its public key does not match the local key material; refusing to continue",
				keyID, p.Material.Fingerprint)
		}
		res.Status = StatusExists
		res.Expires = md.ValidTo
	case types.KeyStatePendingImport:
		// KMS verifies identity: reimporting different material fails with
		// IncorrectKeyMaterialException. Never delete a pre-existing key.
		if err := importMaterial(ctx, api, keyID, p); err != nil {
			return nil, fmt.Errorf("reimporting material into existing key %s: %w", keyID, err)
		}
		res.Status = StatusReimported
		res.Expires = p.ValidTo
	default:
		return nil, fmt.Errorf(
			"key %s matches fingerprint %s but is in state %s; resolve it manually (enable, cancel deletion, or remove the tag)",
			keyID, p.Material.Fingerprint, md.KeyState)
	}

	if err := converge(ctx, api, keyID, p, res); err != nil {
		return res, err
	}
	return res, nil
}

// adopt brings an operator-named key under management: verify it holds the
// local material, then fingerprint-tag and converge it.
func adopt(ctx context.Context, api KMSAPI, p Params) (*Result, error) {
	desc, err := api.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(p.AdoptKeyID)})
	if err != nil {
		return nil, fmt.Errorf("describing key %s: %w", p.AdoptKeyID, err)
	}
	md := desc.KeyMetadata
	keyID := aws.ToString(md.KeyId)
	if md.Origin != types.OriginTypeExternal {
		return nil, fmt.Errorf("key %s has origin %s, not EXTERNAL: it cannot hold imported key material", keyID, md.Origin)
	}

	res := &Result{
		Status:      StatusAdopted,
		KeyID:       keyID,
		ARN:         aws.ToString(md.Arn),
		KeySpec:     string(p.Material.KeySpec),
		Fingerprint: p.Material.Fingerprint,
	}

	switch md.KeyState {
	case types.KeyStateEnabled:
		pub, err := api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
		if err != nil {
			return nil, fmt.Errorf("fetching public key of %s: %w", keyID, err)
		}
		match, err := p.Material.PublicKeyEqual(pub.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("comparing public key of %s: %w", keyID, err)
		}
		if !match {
			return nil, fmt.Errorf("key %s does not hold this key material (public keys differ); refusing to adopt", keyID)
		}
		res.Expires = md.ValidTo
	case types.KeyStatePendingImport:
		if err := importMaterial(ctx, api, keyID, p); err != nil {
			return nil, fmt.Errorf("reimporting material into key %s: %w", keyID, err)
		}
		res.Expires = p.ValidTo
	default:
		return nil, fmt.Errorf("key %s is in state %s; cannot adopt", keyID, md.KeyState)
	}

	if err := converge(ctx, api, keyID, p, res); err != nil {
		return res, err
	}
	return res, nil
}

// create provisions a fresh EXTERNAL-origin key and imports the material,
// scheduling deletion of the new key if any step before success fails.
func create(ctx context.Context, api KMSAPI, p Params) (*Result, error) {
	tags := map[string]string{FingerprintTagKey: p.Material.Fingerprint}
	maps.Copy(tags, p.Tags)
	// The fingerprint is the identity; a user-supplied tag must not mask it.
	tags[FingerprintTagKey] = p.Material.Fingerprint

	created, err := api.CreateKey(ctx, &kms.CreateKeyInput{
		Origin:      types.OriginTypeExternal,
		KeySpec:     p.Material.KeySpec,
		KeyUsage:    p.Usage,
		Description: optional(p.Description),
		Tags:        tagList(tags),
	})
	if err != nil {
		return nil, fmt.Errorf("creating KMS key: %w", err)
	}
	keyID := aws.ToString(created.KeyMetadata.KeyId)

	if err := importMaterial(ctx, api, keyID, p); err != nil {
		return nil, cleanup(ctx, api, keyID, err)
	}

	res := &Result{
		Status:      StatusCreated,
		KeyID:       keyID,
		ARN:         aws.ToString(created.KeyMetadata.Arn),
		KeySpec:     string(p.Material.KeySpec),
		Fingerprint: p.Material.Fingerprint,
		Expires:     p.ValidTo,
	}
	for _, alias := range normalizeAliases(p.Aliases) {
		if _, err := api.CreateAlias(ctx, &kms.CreateAliasInput{
			AliasName:   aws.String(alias),
			TargetKeyId: aws.String(keyID),
		}); err != nil {
			return res, fmt.Errorf("key %s imported successfully, but creating alias %q failed: %w", keyID, alias, err)
		}
		res.Aliases = append(res.Aliases, alias)
	}
	return res, nil
}

// converge makes the existing key carry all requested aliases and tags plus
// the fingerprint tag. It never removes anything and never repoints an alias
// owned by another key.
func converge(ctx context.Context, api KMSAPI, keyID string, p Params, res *Result) error {
	aliases, err := api.ListAliases(ctx, &kms.ListAliasesInput{KeyId: aws.String(keyID)})
	if err != nil {
		return fmt.Errorf("key %s is usable, but listing its aliases failed: %w", keyID, err)
	}
	existing := make(map[string]bool, len(aliases.Aliases))
	for _, alias := range aliases.Aliases {
		existing[aws.ToString(alias.AliasName)] = true
	}
	for _, alias := range normalizeAliases(p.Aliases) {
		if !existing[alias] {
			if _, err := api.CreateAlias(ctx, &kms.CreateAliasInput{
				AliasName:   aws.String(alias),
				TargetKeyId: aws.String(keyID),
			}); err != nil {
				return fmt.Errorf("key %s is usable, but creating alias %q failed: %w", keyID, alias, err)
			}
		}
		res.Aliases = append(res.Aliases, alias)
	}

	tags, err := api.ListResourceTags(ctx, &kms.ListResourceTagsInput{KeyId: aws.String(keyID)})
	if err != nil {
		return fmt.Errorf("key %s is usable, but listing its tags failed: %w", keyID, err)
	}
	current := make(map[string]string, len(tags.Tags))
	for _, tag := range tags.Tags {
		current[aws.ToString(tag.TagKey)] = aws.ToString(tag.TagValue)
	}
	desired := map[string]string{FingerprintTagKey: p.Material.Fingerprint}
	maps.Copy(desired, p.Tags)
	desired[FingerprintTagKey] = p.Material.Fingerprint
	drifted := make(map[string]string)
	for key, value := range desired {
		if current[key] != value {
			drifted[key] = value
		}
	}
	if len(drifted) > 0 {
		if _, err := api.TagResource(ctx, &kms.TagResourceInput{
			KeyId: aws.String(keyID),
			Tags:  tagList(drifted),
		}); err != nil {
			return fmt.Errorf("key %s is usable, but tagging it failed: %w", keyID, err)
		}
	}
	return nil
}

func importMaterial(ctx context.Context, api KMSAPI, keyID string, p Params) error {
	params, err := api.GetParametersForImport(ctx, &kms.GetParametersForImportInput{
		KeyId:             aws.String(keyID),
		WrappingAlgorithm: types.AlgorithmSpecRsaAesKeyWrapSha256,
		WrappingKeySpec:   types.WrappingKeySpecRsa4096,
	})
	if err != nil {
		return fmt.Errorf("getting import parameters: %w", err)
	}

	encrypted, err := wrap.Wrap(p.Material.PKCS8DER, params.PublicKey)
	if err != nil {
		return fmt.Errorf("wrapping key material: %w", err)
	}

	in := &kms.ImportKeyMaterialInput{
		KeyId:                aws.String(keyID),
		ImportToken:          params.ImportToken,
		EncryptedKeyMaterial: encrypted,
		ExpirationModel:      types.ExpirationModelTypeKeyMaterialDoesNotExpire,
	}
	if p.ValidTo != nil {
		in.ExpirationModel = types.ExpirationModelTypeKeyMaterialExpires
		in.ValidTo = p.ValidTo
	}
	if _, err := api.ImportKeyMaterial(ctx, in); err != nil {
		return fmt.Errorf("importing key material: %w", err)
	}
	return nil
}

// cleanup schedules deletion of a key we created whose import failed, folding
// any cleanup failure into the returned error.
func cleanup(ctx context.Context, api KMSAPI, keyID string, cause error) error {
	_, err := api.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
		KeyId:               aws.String(keyID),
		PendingWindowInDays: aws.Int32(deletionWindowDays),
	})
	if err != nil {
		return errors.Join(
			cause,
			fmt.Errorf("cleaning up unusable key %s also failed (delete it manually): %w", keyID, err),
		)
	}
	return fmt.Errorf("%w (created key %s has been scheduled for deletion in %d days)", cause, keyID, deletionWindowDays)
}

func normalizeAliases(aliases []string) []string {
	normalized := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		if !strings.HasPrefix(alias, "alias/") {
			alias = "alias/" + alias
		}
		normalized = append(normalized, alias)
	}
	return normalized
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return aws.String(s)
}

func tagList(tags map[string]string) []types.Tag {
	if len(tags) == 0 {
		return nil
	}
	list := make([]types.Tag, 0, len(tags))
	for _, k := range slices.Sorted(maps.Keys(tags)) {
		list = append(list, types.Tag{TagKey: aws.String(k), TagValue: aws.String(tags[k])})
	}
	return list
}
