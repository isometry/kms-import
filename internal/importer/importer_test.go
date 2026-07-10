package importer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	taggingtypes "github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi/types"
	"github.com/aws/smithy-go"

	"github.com/isometry/kms-import/internal/keymaterial"
)

const (
	testKeyID = "1234abcd-12ab-34cd-56ef-1234567890ab"
	testARN   = "arn:aws:kms:eu-west-1:111122223333:key/" + testKeyID
)

// mockKMS implements KMSAPI, recording inputs and delegating to overridable
// stubs that default to success.
type mockKMS struct {
	wrappingKeyDER []byte

	// state served by DescribeKey / GetPublicKey for the looked-up key
	keyState  types.KeyState
	keyOrigin types.OriginType
	publicKey []byte
	validTo   *time.Time

	createKeyIn  *kms.CreateKeyInput
	describeIn   *kms.DescribeKeyInput
	getPublicIn  *kms.GetPublicKeyInput
	getParamsIn  *kms.GetParametersForImportInput
	importIn     *kms.ImportKeyMaterialInput
	aliasIn      []*kms.CreateAliasInput
	tagIn        *kms.TagResourceInput
	deleteIn     *kms.ScheduleKeyDeletionInput
	listAliasOut []types.AliasListEntry
	listTagsOut  []types.Tag

	describeErr  error
	getPublicErr error
	getParamsErr error
	importErr    error
	aliasErr     error
	tagErr       error
	deleteErr    error
}

func newMockKMS(t *testing.T) *mockKMS {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating mock wrapping key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshalling mock wrapping key: %v", err)
	}
	return &mockKMS{
		wrappingKeyDER: der,
		keyState:       types.KeyStateEnabled,
		keyOrigin:      types.OriginTypeExternal,
	}
}

func (m *mockKMS) CreateKey(_ context.Context, in *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	m.createKeyIn = in
	return &kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{
		KeyId: aws.String(testKeyID),
		Arn:   aws.String(testARN),
	}}, nil
}

func (m *mockKMS) DescribeKey(_ context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	m.describeIn = in
	if m.describeErr != nil {
		return nil, m.describeErr
	}
	return &kms.DescribeKeyOutput{KeyMetadata: &types.KeyMetadata{
		KeyId:    aws.String(testKeyID),
		Arn:      aws.String(testARN),
		KeyState: m.keyState,
		Origin:   m.keyOrigin,
		ValidTo:  m.validTo,
	}}, nil
}

func (m *mockKMS) GetPublicKey(_ context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	m.getPublicIn = in
	if m.getPublicErr != nil {
		return nil, m.getPublicErr
	}
	return &kms.GetPublicKeyOutput{PublicKey: m.publicKey}, nil
}

func (m *mockKMS) ListAliases(_ context.Context, _ *kms.ListAliasesInput, _ ...func(*kms.Options)) (*kms.ListAliasesOutput, error) {
	return &kms.ListAliasesOutput{Aliases: m.listAliasOut}, nil
}

func (m *mockKMS) ListResourceTags(_ context.Context, _ *kms.ListResourceTagsInput, _ ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error) {
	return &kms.ListResourceTagsOutput{Tags: m.listTagsOut}, nil
}

func (m *mockKMS) TagResource(_ context.Context, in *kms.TagResourceInput, _ ...func(*kms.Options)) (*kms.TagResourceOutput, error) {
	m.tagIn = in
	if m.tagErr != nil {
		return nil, m.tagErr
	}
	return &kms.TagResourceOutput{}, nil
}

func (m *mockKMS) GetParametersForImport(_ context.Context, in *kms.GetParametersForImportInput, _ ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error) {
	m.getParamsIn = in
	if m.getParamsErr != nil {
		return nil, m.getParamsErr
	}
	return &kms.GetParametersForImportOutput{
		ImportToken: []byte("import-token"),
		PublicKey:   m.wrappingKeyDER,
	}, nil
}

func (m *mockKMS) ImportKeyMaterial(_ context.Context, in *kms.ImportKeyMaterialInput, _ ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error) {
	m.importIn = in
	if m.importErr != nil {
		return nil, m.importErr
	}
	return &kms.ImportKeyMaterialOutput{}, nil
}

func (m *mockKMS) CreateAlias(_ context.Context, in *kms.CreateAliasInput, _ ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	m.aliasIn = append(m.aliasIn, in)
	if m.aliasErr != nil {
		return nil, m.aliasErr
	}
	return &kms.CreateAliasOutput{}, nil
}

func (m *mockKMS) ScheduleKeyDeletion(_ context.Context, in *kms.ScheduleKeyDeletionInput, _ ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error) {
	m.deleteIn = in
	if m.deleteErr != nil {
		return nil, m.deleteErr
	}
	return &kms.ScheduleKeyDeletionOutput{}, nil
}

// mockTagging implements TaggingAPI.
type mockTagging struct {
	in   *resourcegroupstaggingapi.GetResourcesInput
	arns []string
	err  error
}

func (m *mockTagging) GetResources(_ context.Context, in *resourcegroupstaggingapi.GetResourcesInput, _ ...func(*resourcegroupstaggingapi.Options)) (*resourcegroupstaggingapi.GetResourcesOutput, error) {
	m.in = in
	if m.err != nil {
		return nil, m.err
	}
	out := &resourcegroupstaggingapi.GetResourcesOutput{}
	for _, arn := range m.arns {
		out.ResourceTagMappingList = append(out.ResourceTagMappingList,
			taggingtypes.ResourceTagMapping{ResourceARN: aws.String(arn)})
	}
	return out, nil
}

type apiError struct{ code string }

func (e *apiError) Error() string                 { return e.code }
func (e *apiError) ErrorCode() string             { return e.code }
func (e *apiError) ErrorMessage() string          { return e.code }
func (e *apiError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

var _ smithy.APIError = (*apiError)(nil)

func testMaterial(t *testing.T) *keymaterial.KeyMaterial {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating material: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling material: %v", err)
	}
	km, err := keymaterial.Parse(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatalf("parsing material: %v", err)
	}
	return km
}

func otherPublicKeyDER(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating other key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshalling other key: %v", err)
	}
	return der
}

func TestEnsureCreatesWhenNoCandidates(t *testing.T) {
	m := newMockKMS(t)
	tg := &mockTagging{}
	material := testMaterial(t)
	validTo := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)

	res, err := Ensure(context.Background(), m, tg, Params{
		Material:    material,
		Description: "github app key",
		Usage:       types.KeyUsageTypeSignVerify,
		Aliases:     []string{"alias/my-app"},
		Tags:        map[string]string{"Team": "platform"},
		ValidTo:     &validTo,
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	// Lookup used the fingerprint tag as index, filtered to KMS keys.
	if tg.in == nil {
		t.Fatal("GetResources not called")
	}
	if len(tg.in.ResourceTypeFilters) != 1 || tg.in.ResourceTypeFilters[0] != "kms:key" {
		t.Errorf("ResourceTypeFilters = %v", tg.in.ResourceTypeFilters)
	}
	if len(tg.in.TagFilters) != 1 || aws.ToString(tg.in.TagFilters[0].Key) != FingerprintTagKey ||
		len(tg.in.TagFilters[0].Values) != 1 || tg.in.TagFilters[0].Values[0] != material.Fingerprint {
		t.Errorf("TagFilters = %+v", tg.in.TagFilters)
	}

	ck := m.createKeyIn
	if ck == nil {
		t.Fatal("CreateKey not called")
	}
	if ck.Origin != types.OriginTypeExternal || ck.KeySpec != types.KeySpecRsa2048 ||
		ck.KeyUsage != types.KeyUsageTypeSignVerify {
		t.Errorf("CreateKey input = origin %v spec %v usage %v", ck.Origin, ck.KeySpec, ck.KeyUsage)
	}
	if aws.ToString(ck.Description) != "github app key" {
		t.Errorf("Description = %q", aws.ToString(ck.Description))
	}
	// Tags: the user tag plus the fingerprint tag.
	want := map[string]string{"Team": "platform", FingerprintTagKey: material.Fingerprint}
	if len(ck.Tags) != len(want) {
		t.Fatalf("CreateKey Tags = %+v, want %v", ck.Tags, want)
	}
	for _, tag := range ck.Tags {
		if want[aws.ToString(tag.TagKey)] != aws.ToString(tag.TagValue) {
			t.Errorf("unexpected tag %s=%s", aws.ToString(tag.TagKey), aws.ToString(tag.TagValue))
		}
	}

	if m.importIn == nil || m.importIn.ExpirationModel != types.ExpirationModelTypeKeyMaterialExpires {
		t.Error("import not performed with expiry")
	}
	if len(m.aliasIn) != 1 || aws.ToString(m.aliasIn[0].AliasName) != "alias/my-app" {
		t.Errorf("aliases = %+v", m.aliasIn)
	}

	if res.Status != StatusCreated {
		t.Errorf("Status = %q, want %q", res.Status, StatusCreated)
	}
	if res.KeyID != testKeyID || res.ARN != testARN {
		t.Errorf("identifiers = %q / %q", res.KeyID, res.ARN)
	}
	if res.Fingerprint != material.Fingerprint {
		t.Errorf("Fingerprint = %q", res.Fingerprint)
	}
	if res.Expires == nil || !res.Expires.Equal(validTo) {
		t.Errorf("Expires = %v", res.Expires)
	}
}

func TestEnsureNoExpiryAndNilDescription(t *testing.T) {
	m := newMockKMS(t)
	res, err := Ensure(context.Background(), m, &mockTagging{}, Params{
		Material: testMaterial(t),
		Usage:    types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if m.importIn.ExpirationModel != types.ExpirationModelTypeKeyMaterialDoesNotExpire || m.importIn.ValidTo != nil {
		t.Errorf("expiry = %v/%v", m.importIn.ExpirationModel, m.importIn.ValidTo)
	}
	if m.createKeyIn.Description != nil {
		t.Errorf("Description = %v, want nil", m.createKeyIn.Description)
	}
	if res.Expires != nil {
		t.Errorf("Expires = %v, want nil", res.Expires)
	}
}

func TestEnsureExistingKeyConverges(t *testing.T) {
	m := newMockKMS(t)
	material := testMaterial(t)
	m.publicKey = material.PublicKeyDER
	m.listAliasOut = []types.AliasListEntry{{AliasName: aws.String("alias/have")}}
	m.listTagsOut = []types.Tag{
		{TagKey: aws.String(FingerprintTagKey), TagValue: aws.String(material.Fingerprint)},
		{TagKey: aws.String("Team"), TagValue: aws.String("old")},
	}
	tg := &mockTagging{arns: []string{testARN}}

	res, err := Ensure(context.Background(), m, tg, Params{
		Material: material,
		Usage:    types.KeyUsageTypeSignVerify,
		Aliases:  []string{"alias/have", "alias/new"},
		Tags:     map[string]string{"Team": "platform"},
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if m.createKeyIn != nil {
		t.Error("CreateKey called for existing key")
	}
	if m.importIn != nil {
		t.Error("ImportKeyMaterial called for enabled existing key")
	}
	// Only the missing alias is created.
	if len(m.aliasIn) != 1 || aws.ToString(m.aliasIn[0].AliasName) != "alias/new" {
		t.Errorf("aliases created = %+v", m.aliasIn)
	}
	// Only the drifted tag is (re)applied.
	if m.tagIn == nil {
		t.Fatal("TagResource not called for drifted tag")
	}
	if len(m.tagIn.Tags) != 1 || aws.ToString(m.tagIn.Tags[0].TagKey) != "Team" ||
		aws.ToString(m.tagIn.Tags[0].TagValue) != "platform" {
		t.Errorf("TagResource tags = %+v", m.tagIn.Tags)
	}
	if res.Status != StatusExists {
		t.Errorf("Status = %q, want %q", res.Status, StatusExists)
	}
	if res.KeyID != testKeyID {
		t.Errorf("KeyID = %q", res.KeyID)
	}
	if len(res.Aliases) != 2 {
		t.Errorf("Aliases = %v, want both requested aliases", res.Aliases)
	}
}

func TestEnsureConvergedKeyIsNoOp(t *testing.T) {
	m := newMockKMS(t)
	material := testMaterial(t)
	m.publicKey = material.PublicKeyDER
	m.listAliasOut = []types.AliasListEntry{{AliasName: aws.String("alias/my-app")}}
	m.listTagsOut = []types.Tag{
		{TagKey: aws.String(FingerprintTagKey), TagValue: aws.String(material.Fingerprint)},
	}
	tg := &mockTagging{arns: []string{testARN}}

	res, err := Ensure(context.Background(), m, tg, Params{
		Material: material,
		Usage:    types.KeyUsageTypeSignVerify,
		Aliases:  []string{"alias/my-app"},
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if m.createKeyIn != nil || m.importIn != nil || len(m.aliasIn) != 0 || m.tagIn != nil {
		t.Error("fully converged key still mutated")
	}
	if res.Status != StatusExists {
		t.Errorf("Status = %q", res.Status)
	}
}

func TestEnsurePublicKeyMismatchFails(t *testing.T) {
	m := newMockKMS(t)
	m.publicKey = otherPublicKeyDER(t)
	tg := &mockTagging{arns: []string{testARN}}

	_, err := Ensure(context.Background(), m, tg, Params{
		Material: testMaterial(t),
		Usage:    types.KeyUsageTypeSignVerify,
	})
	if err == nil {
		t.Fatal("Ensure succeeded despite public key mismatch")
	}
	if !strings.Contains(err.Error(), testKeyID) {
		t.Errorf("error %q does not name the conflicting key", err)
	}
	if m.createKeyIn != nil || m.importIn != nil || len(m.aliasIn) != 0 || m.tagIn != nil {
		t.Error("mutations performed despite mismatch")
	}
}

func TestEnsurePendingImportReimports(t *testing.T) {
	m := newMockKMS(t)
	material := testMaterial(t)
	m.keyState = types.KeyStatePendingImport
	tg := &mockTagging{arns: []string{testARN}}

	res, err := Ensure(context.Background(), m, tg, Params{
		Material: material,
		Usage:    types.KeyUsageTypeSignVerify,
		Aliases:  []string{"alias/my-app"},
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if m.createKeyIn != nil {
		t.Error("CreateKey called; reimport must target the existing key")
	}
	if m.importIn == nil || aws.ToString(m.importIn.KeyId) != testKeyID {
		t.Fatalf("ImportKeyMaterial in = %+v, want key %s", m.importIn, testKeyID)
	}
	if m.deleteIn != nil {
		t.Error("ScheduleKeyDeletion must never run against a pre-existing key")
	}
	if res.Status != StatusReimported {
		t.Errorf("Status = %q, want %q", res.Status, StatusReimported)
	}
}

func TestEnsureReimportFailureDoesNotDeleteKey(t *testing.T) {
	m := newMockKMS(t)
	m.keyState = types.KeyStatePendingImport
	m.importErr = errors.New("boom: incorrect material")
	tg := &mockTagging{arns: []string{testARN}}

	_, err := Ensure(context.Background(), m, tg, Params{
		Material: testMaterial(t),
		Usage:    types.KeyUsageTypeSignVerify,
	})
	if err == nil {
		t.Fatal("Ensure succeeded, want error")
	}
	if m.deleteIn != nil {
		t.Error("ScheduleKeyDeletion called against a pre-existing key")
	}
}

func TestEnsureBadStatesFail(t *testing.T) {
	for name, state := range map[string]types.KeyState{
		"disabled":         types.KeyStateDisabled,
		"pending-deletion": types.KeyStatePendingDeletion,
	} {
		t.Run(name, func(t *testing.T) {
			m := newMockKMS(t)
			m.keyState = state
			tg := &mockTagging{arns: []string{testARN}}

			_, err := Ensure(context.Background(), m, tg, Params{
				Material: testMaterial(t),
				Usage:    types.KeyUsageTypeSignVerify,
			})
			if err == nil {
				t.Fatal("Ensure succeeded, want error")
			}
			if !strings.Contains(err.Error(), testKeyID) || !strings.Contains(err.Error(), string(state)) {
				t.Errorf("error %q must name key and state", err)
			}
			if m.createKeyIn != nil {
				t.Error("CreateKey called despite matching key in bad state")
			}
		})
	}
}

func TestEnsureFailsOpenOnTaggingAccessDenied(t *testing.T) {
	m := newMockKMS(t)
	material := testMaterial(t)
	tg := &mockTagging{err: &apiError{code: "AccessDeniedException"}}

	res, err := Ensure(context.Background(), m, tg, Params{
		Material: material,
		Usage:    types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if m.createKeyIn == nil {
		t.Fatal("CreateKey not called on fail-open")
	}
	if res.Status != StatusCreated {
		t.Errorf("Status = %q", res.Status)
	}
	if len(res.Warnings) == 0 {
		t.Error("fail-open produced no warning")
	}
}

func TestEnsureFailsClosedOnOtherTaggingErrors(t *testing.T) {
	m := newMockKMS(t)
	tg := &mockTagging{err: errors.New("boom: network")}

	_, err := Ensure(context.Background(), m, tg, Params{
		Material: testMaterial(t),
		Usage:    types.KeyUsageTypeSignVerify,
	})
	if err == nil {
		t.Fatal("Ensure succeeded despite lookup failure")
	}
	if m.createKeyIn != nil {
		t.Error("CreateKey called despite failed lookup")
	}
}

func TestEnsureCleansUpOnCreateFailure(t *testing.T) {
	for name, setup := range map[string]func(*mockKMS){
		"get-parameters-fails": func(m *mockKMS) { m.getParamsErr = errors.New("boom: parameters") },
		"import-fails":         func(m *mockKMS) { m.importErr = errors.New("boom: import") },
	} {
		t.Run(name, func(t *testing.T) {
			m := newMockKMS(t)
			setup(m)

			_, err := Ensure(context.Background(), m, &mockTagging{}, Params{
				Material: testMaterial(t),
				Usage:    types.KeyUsageTypeSignVerify,
			})
			if err == nil {
				t.Fatal("Ensure succeeded, want error")
			}
			if !strings.Contains(err.Error(), "boom") {
				t.Errorf("error %q does not contain root cause", err)
			}
			if m.deleteIn == nil {
				t.Fatal("ScheduleKeyDeletion not called")
			}
			if aws.ToInt32(m.deleteIn.PendingWindowInDays) != 7 {
				t.Errorf("PendingWindowInDays = %d, want 7", aws.ToInt32(m.deleteIn.PendingWindowInDays))
			}
			if !strings.Contains(err.Error(), testKeyID) {
				t.Errorf("error %q does not mention the cleaned-up key id", err)
			}
		})
	}
}

func TestEnsureCleanupFailureIsReported(t *testing.T) {
	m := newMockKMS(t)
	m.importErr = errors.New("boom: import")
	m.deleteErr = errors.New("boom: delete")

	_, err := Ensure(context.Background(), m, &mockTagging{}, Params{
		Material: testMaterial(t),
		Usage:    types.KeyUsageTypeSignVerify,
	})
	if err == nil {
		t.Fatal("Ensure succeeded, want error")
	}
	for _, want := range []string{"boom: import", "boom: delete"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestEnsureAliasFailureKeepsKey(t *testing.T) {
	m := newMockKMS(t)
	m.aliasErr = errors.New("boom: alias")

	res, err := Ensure(context.Background(), m, &mockTagging{}, Params{
		Material: testMaterial(t),
		Usage:    types.KeyUsageTypeSignVerify,
		Aliases:  []string{"alias/my-app"},
	})
	if err == nil {
		t.Fatal("Ensure succeeded, want partial-failure error")
	}
	if m.deleteIn != nil {
		t.Error("ScheduleKeyDeletion called after successful import")
	}
	if res == nil || res.KeyID != testKeyID {
		t.Fatalf("result = %+v; imported key must still be reported", res)
	}
	if !strings.Contains(err.Error(), "alias") {
		t.Errorf("error %q does not mention alias failure", err)
	}
}

func TestEnsureAdopt(t *testing.T) {
	m := newMockKMS(t)
	material := testMaterial(t)
	m.publicKey = material.PublicKeyDER
	tg := &mockTagging{}

	res, err := Ensure(context.Background(), m, tg, Params{
		Material:   material,
		Usage:      types.KeyUsageTypeSignVerify,
		AdoptKeyID: testKeyID,
	})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if tg.in != nil {
		t.Error("tag lookup performed in adopt mode")
	}
	if aws.ToString(m.describeIn.KeyId) != testKeyID {
		t.Errorf("DescribeKey id = %q", aws.ToString(m.describeIn.KeyId))
	}
	if m.createKeyIn != nil {
		t.Error("CreateKey called in adopt mode")
	}
	if m.tagIn == nil {
		t.Fatal("TagResource not called; fingerprint tag must be applied")
	}
	found := false
	for _, tag := range m.tagIn.Tags {
		if aws.ToString(tag.TagKey) == FingerprintTagKey && aws.ToString(tag.TagValue) == material.Fingerprint {
			found = true
		}
	}
	if !found {
		t.Errorf("fingerprint tag missing from TagResource: %+v", m.tagIn.Tags)
	}
	if res.Status != StatusAdopted {
		t.Errorf("Status = %q, want %q", res.Status, StatusAdopted)
	}
}

func TestEnsureAdoptRejectsMismatch(t *testing.T) {
	m := newMockKMS(t)
	m.publicKey = otherPublicKeyDER(t)

	_, err := Ensure(context.Background(), m, &mockTagging{}, Params{
		Material:   testMaterial(t),
		Usage:      types.KeyUsageTypeSignVerify,
		AdoptKeyID: testKeyID,
	})
	if err == nil {
		t.Fatal("adopt succeeded despite mismatched public key")
	}
	if m.tagIn != nil {
		t.Error("TagResource called despite mismatch")
	}
}

func TestEnsureAdoptRejectsWrongOrigin(t *testing.T) {
	m := newMockKMS(t)
	material := testMaterial(t)
	m.publicKey = material.PublicKeyDER
	m.keyOrigin = types.OriginTypeAwsKms

	_, err := Ensure(context.Background(), m, &mockTagging{}, Params{
		Material:   material,
		Usage:      types.KeyUsageTypeSignVerify,
		AdoptKeyID: testKeyID,
	})
	if err == nil {
		t.Fatal("adopt succeeded despite AWS_KMS origin")
	}
}
