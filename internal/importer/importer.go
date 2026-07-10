// Package importer orchestrates the AWS KMS key material import process:
// CreateKey (EXTERNAL origin) → GetParametersForImport → wrap locally →
// ImportKeyMaterial → CreateAlias.
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

	"github.com/isometry/kms-import/internal/keymaterial"
	"github.com/isometry/kms-import/internal/wrap"
)

// deletionWindowDays is the shortest window KMS allows when scheduling
// deletion of a key we failed to import material into.
const deletionWindowDays = 7

// Params describes the KMS key to create and the material to import into it.
type Params struct {
	Material    *keymaterial.KeyMaterial
	Description string
	Usage       types.KeyUsageType
	Aliases     []string
	Tags        map[string]string
	// ValidTo sets key material expiry; nil means the material never expires.
	ValidTo *time.Time
}

// Result reports the imported key.
type Result struct {
	KeyID   string     `json:"keyId"`
	ARN     string     `json:"arn"`
	KeySpec string     `json:"keySpec"`
	Aliases []string   `json:"aliases"`
	Expires *time.Time `json:"expires,omitempty"`
}

// Run creates an EXTERNAL-origin KMS key and imports p.Material into it. If
// any step between key creation and successful import fails, the orphaned key
// is scheduled for deletion. An alias failure after successful import returns
// both a non-nil Result and an error: the key exists and is usable.
func Run(ctx context.Context, api KMSAPI, p Params) (*Result, error) {
	created, err := api.CreateKey(ctx, &kms.CreateKeyInput{
		Origin:      types.OriginTypeExternal,
		KeySpec:     p.Material.KeySpec,
		KeyUsage:    p.Usage,
		Description: optional(p.Description),
		Tags:        tagList(p.Tags),
	})
	if err != nil {
		return nil, fmt.Errorf("creating KMS key: %w", err)
	}
	keyID := aws.ToString(created.KeyMetadata.KeyId)

	if err := importMaterial(ctx, api, keyID, p); err != nil {
		return nil, cleanup(ctx, api, keyID, err)
	}

	res := &Result{
		KeyID:   keyID,
		ARN:     aws.ToString(created.KeyMetadata.Arn),
		KeySpec: string(p.Material.KeySpec),
		Expires: p.ValidTo,
	}
	for _, alias := range p.Aliases {
		name := alias
		if !strings.HasPrefix(name, "alias/") {
			name = "alias/" + name
		}
		if _, err := api.CreateAlias(ctx, &kms.CreateAliasInput{
			AliasName:   aws.String(name),
			TargetKeyId: aws.String(keyID),
		}); err != nil {
			return res, fmt.Errorf("key %s imported successfully, but creating alias %q failed: %w", keyID, name, err)
		}
		res.Aliases = append(res.Aliases, name)
	}
	return res, nil
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

// cleanup schedules deletion of a key whose import failed, folding any
// cleanup failure into the returned error.
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
