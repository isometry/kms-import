package importer

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// KMSAPI is the subset of *kms.Client used by this package.
type KMSAPI interface {
	CreateKey(ctx context.Context, in *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	GetParametersForImport(ctx context.Context, in *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error)
	ImportKeyMaterial(ctx context.Context, in *kms.ImportKeyMaterialInput, optFns ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error)
	CreateAlias(ctx context.Context, in *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	ScheduleKeyDeletion(ctx context.Context, in *kms.ScheduleKeyDeletionInput, optFns ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error)
}
