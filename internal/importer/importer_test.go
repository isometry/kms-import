package importer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

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

	createKeyIn *kms.CreateKeyInput
	getParamsIn *kms.GetParametersForImportInput
	importIn    *kms.ImportKeyMaterialInput
	aliasIn     []*kms.CreateAliasInput
	deleteIn    *kms.ScheduleKeyDeletionInput

	getParamsErr error
	importErr    error
	aliasErr     error
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
	return &mockKMS{wrappingKeyDER: der}
}

func (m *mockKMS) CreateKey(_ context.Context, in *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	m.createKeyIn = in
	return &kms.CreateKeyOutput{KeyMetadata: &types.KeyMetadata{
		KeyId: aws.String(testKeyID),
		Arn:   aws.String(testARN),
	}}, nil
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
	return &keymaterial.KeyMaterial{PKCS8DER: der, KeySpec: types.KeySpecRsa2048}
}

func TestRunHappyPath(t *testing.T) {
	m := newMockKMS(t)
	validTo := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)

	res, err := Run(context.Background(), m, Params{
		Material:    testMaterial(t),
		Description: "github app key",
		Usage:       types.KeyUsageTypeSignVerify,
		Aliases:     []string{"my-app", "alias/already-prefixed"},
		Tags:        map[string]string{"Team": "platform"},
		ValidTo:     &validTo,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// CreateKey
	ck := m.createKeyIn
	if ck == nil {
		t.Fatal("CreateKey not called")
	}
	if ck.Origin != types.OriginTypeExternal {
		t.Errorf("Origin = %v, want EXTERNAL", ck.Origin)
	}
	if ck.KeySpec != types.KeySpecRsa2048 {
		t.Errorf("KeySpec = %v, want RSA_2048", ck.KeySpec)
	}
	if ck.KeyUsage != types.KeyUsageTypeSignVerify {
		t.Errorf("KeyUsage = %v, want SIGN_VERIFY", ck.KeyUsage)
	}
	if aws.ToString(ck.Description) != "github app key" {
		t.Errorf("Description = %q", aws.ToString(ck.Description))
	}
	if len(ck.Tags) != 1 || aws.ToString(ck.Tags[0].TagKey) != "Team" || aws.ToString(ck.Tags[0].TagValue) != "platform" {
		t.Errorf("Tags = %+v, want Team=platform", ck.Tags)
	}

	// GetParametersForImport
	gp := m.getParamsIn
	if gp == nil {
		t.Fatal("GetParametersForImport not called")
	}
	if aws.ToString(gp.KeyId) != testKeyID {
		t.Errorf("GetParametersForImport KeyId = %q", aws.ToString(gp.KeyId))
	}
	if gp.WrappingAlgorithm != types.AlgorithmSpecRsaAesKeyWrapSha256 {
		t.Errorf("WrappingAlgorithm = %v, want RSA_AES_KEY_WRAP_SHA_256", gp.WrappingAlgorithm)
	}
	if gp.WrappingKeySpec != types.WrappingKeySpecRsa4096 {
		t.Errorf("WrappingKeySpec = %v, want RSA_4096", gp.WrappingKeySpec)
	}

	// ImportKeyMaterial
	im := m.importIn
	if im == nil {
		t.Fatal("ImportKeyMaterial not called")
	}
	if aws.ToString(im.KeyId) != testKeyID {
		t.Errorf("ImportKeyMaterial KeyId = %q", aws.ToString(im.KeyId))
	}
	if string(im.ImportToken) != "import-token" {
		t.Error("import token not passed through")
	}
	if len(im.EncryptedKeyMaterial) == 0 {
		t.Error("EncryptedKeyMaterial is empty")
	}
	if im.ExpirationModel != types.ExpirationModelTypeKeyMaterialExpires {
		t.Errorf("ExpirationModel = %v, want KEY_MATERIAL_EXPIRES", im.ExpirationModel)
	}
	if im.ValidTo == nil || !im.ValidTo.Equal(validTo) {
		t.Errorf("ValidTo = %v, want %v", im.ValidTo, validTo)
	}

	// Aliases: bare names get the alias/ prefix, existing prefixes are kept.
	if len(m.aliasIn) != 2 {
		t.Fatalf("CreateAlias called %d times, want 2", len(m.aliasIn))
	}
	if got := aws.ToString(m.aliasIn[0].AliasName); got != "alias/my-app" {
		t.Errorf("alias[0] = %q, want alias/my-app", got)
	}
	if got := aws.ToString(m.aliasIn[1].AliasName); got != "alias/already-prefixed" {
		t.Errorf("alias[1] = %q, want alias/already-prefixed", got)
	}
	if got := aws.ToString(m.aliasIn[0].TargetKeyId); got != testKeyID {
		t.Errorf("alias target = %q, want key id", got)
	}

	// Result
	if res.KeyID != testKeyID || res.ARN != testARN {
		t.Errorf("Result identifiers = %q / %q", res.KeyID, res.ARN)
	}
	if res.KeySpec != string(types.KeySpecRsa2048) {
		t.Errorf("Result.KeySpec = %q", res.KeySpec)
	}
	if len(res.Aliases) != 2 || res.Aliases[0] != "alias/my-app" {
		t.Errorf("Result.Aliases = %v", res.Aliases)
	}
	if res.Expires == nil || !res.Expires.Equal(validTo) {
		t.Errorf("Result.Expires = %v", res.Expires)
	}
	if m.deleteIn != nil {
		t.Error("ScheduleKeyDeletion called on happy path")
	}
}

func TestRunNoExpiry(t *testing.T) {
	m := newMockKMS(t)
	res, err := Run(context.Background(), m, Params{
		Material: testMaterial(t),
		Usage:    types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if m.importIn.ExpirationModel != types.ExpirationModelTypeKeyMaterialDoesNotExpire {
		t.Errorf("ExpirationModel = %v, want KEY_MATERIAL_DOES_NOT_EXPIRE", m.importIn.ExpirationModel)
	}
	if m.importIn.ValidTo != nil {
		t.Errorf("ValidTo = %v, want nil", m.importIn.ValidTo)
	}
	if m.createKeyIn.Description != nil {
		t.Errorf("Description = %v, want nil when empty", m.createKeyIn.Description)
	}
	if res.Expires != nil {
		t.Errorf("Result.Expires = %v, want nil", res.Expires)
	}
}

func TestRunCleansUpOnFailure(t *testing.T) {
	for name, setup := range map[string]func(*mockKMS){
		"get-parameters-fails": func(m *mockKMS) { m.getParamsErr = errors.New("boom: parameters") },
		"import-fails":         func(m *mockKMS) { m.importErr = errors.New("boom: import") },
	} {
		t.Run(name, func(t *testing.T) {
			m := newMockKMS(t)
			setup(m)

			_, err := Run(context.Background(), m, Params{
				Material: testMaterial(t),
				Usage:    types.KeyUsageTypeSignVerify,
			})
			if err == nil {
				t.Fatal("Run succeeded, want error")
			}
			if !strings.Contains(err.Error(), "boom") {
				t.Errorf("error %q does not contain root cause", err)
			}
			if m.deleteIn == nil {
				t.Fatal("ScheduleKeyDeletion not called")
			}
			if aws.ToString(m.deleteIn.KeyId) != testKeyID {
				t.Errorf("deletion KeyId = %q", aws.ToString(m.deleteIn.KeyId))
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

func TestRunCleanupFailureIsReported(t *testing.T) {
	m := newMockKMS(t)
	m.importErr = errors.New("boom: import")
	m.deleteErr = errors.New("boom: delete")

	_, err := Run(context.Background(), m, Params{
		Material: testMaterial(t),
		Usage:    types.KeyUsageTypeSignVerify,
	})
	if err == nil {
		t.Fatal("Run succeeded, want error")
	}
	for _, want := range []string{"boom: import", "boom: delete"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestRunAliasFailureKeepsKey(t *testing.T) {
	m := newMockKMS(t)
	m.aliasErr = errors.New("boom: alias")

	res, err := Run(context.Background(), m, Params{
		Material: testMaterial(t),
		Usage:    types.KeyUsageTypeSignVerify,
		Aliases:  []string{"my-app"},
	})
	if err == nil {
		t.Fatal("Run succeeded, want partial-failure error")
	}
	if m.deleteIn != nil {
		t.Error("ScheduleKeyDeletion called after successful import")
	}
	if res == nil {
		t.Fatal("Result is nil; imported key must still be reported")
	}
	if res.KeyID != testKeyID {
		t.Errorf("Result.KeyID = %q", res.KeyID)
	}
	if len(res.Aliases) != 0 {
		t.Errorf("Result.Aliases = %v, want none (creation failed)", res.Aliases)
	}
	if !strings.Contains(err.Error(), "alias") {
		t.Errorf("error %q does not mention alias failure", err)
	}
}
