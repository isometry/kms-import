package importer

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
)

// KMSAPI is the subset of *kms.Client used by this package.
type KMSAPI interface {
	CreateKey(ctx context.Context, in *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	ListAliases(ctx context.Context, in *kms.ListAliasesInput, optFns ...func(*kms.Options)) (*kms.ListAliasesOutput, error)
	ListResourceTags(ctx context.Context, in *kms.ListResourceTagsInput, optFns ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error)
	TagResource(ctx context.Context, in *kms.TagResourceInput, optFns ...func(*kms.Options)) (*kms.TagResourceOutput, error)
	GetParametersForImport(ctx context.Context, in *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error)
	ImportKeyMaterial(ctx context.Context, in *kms.ImportKeyMaterialInput, optFns ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error)
	CreateAlias(ctx context.Context, in *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	ScheduleKeyDeletion(ctx context.Context, in *kms.ScheduleKeyDeletionInput, optFns ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error)
}

// TaggingAPI is the subset of the Resource Groups Tagging API client used to
// look up KMS keys by fingerprint tag.
type TaggingAPI interface {
	GetResources(ctx context.Context, in *resourcegroupstaggingapi.GetResourcesInput, optFns ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error)
}
