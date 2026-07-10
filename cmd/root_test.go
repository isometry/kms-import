package cmd

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

func TestParseTags(t *testing.T) {
	got, err := parseTags([]string{"Name=test", "Team=platform", "Name=override"})
	if err != nil {
		t.Fatalf("parseTags: %v", err)
	}
	want := map[string]string{"Name": "override", "Team": "platform"}
	if len(got) != len(want) {
		t.Fatalf("parseTags = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("tag %q = %q, want %q", k, got[k], v)
		}
	}

	if _, err := parseTags([]string{"missing-equals"}); err == nil {
		t.Error("parseTags accepted entry without '='")
	}
	if _, err := parseTags([]string{"=value"}); err == nil {
		t.Error("parseTags accepted empty key")
	}
}

func TestParseExpires(t *testing.T) {
	now := time.Now()

	got, err := parseExpires("720h", now)
	if err != nil {
		t.Fatalf("parseExpires(720h): %v", err)
	}
	if want := now.Add(720 * time.Hour); !got.Equal(want) {
		t.Errorf("parseExpires(720h) = %v, want %v", got, want)
	}

	stamp := now.Add(48 * time.Hour).Truncate(time.Second)
	got, err = parseExpires(stamp.Format(time.RFC3339), now)
	if err != nil {
		t.Fatalf("parseExpires(RFC3339): %v", err)
	}
	if !got.Equal(stamp) {
		t.Errorf("parseExpires(RFC3339) = %v, want %v", got, stamp)
	}

	for name, in := range map[string]string{
		"past":      now.Add(-time.Hour).Format(time.RFC3339),
		"too-far":   "9000h", // > 365 days
		"garbage":   "next tuesday",
		"negative":  "-24h",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseExpires(in, now); err == nil {
				t.Errorf("parseExpires(%q) succeeded, want error", in)
			}
		})
	}
}

func TestUsageFor(t *testing.T) {
	if _, err := usageFor("SIGN_VERIFY", types.KeySpecEccNistP256); err != nil {
		t.Errorf("SIGN_VERIFY + ECC rejected: %v", err)
	}
	if _, err := usageFor("ENCRYPT_DECRYPT", types.KeySpecRsa2048); err != nil {
		t.Errorf("ENCRYPT_DECRYPT + RSA rejected: %v", err)
	}
	if _, err := usageFor("ENCRYPT_DECRYPT", types.KeySpecEccNistP256); err == nil {
		t.Error("ENCRYPT_DECRYPT + ECC accepted")
	}
	if _, err := usageFor("SIGN_EVERYTHING", types.KeySpecRsa2048); err == nil {
		t.Error("bogus usage accepted")
	}
}

func writeTestKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func runCommand(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := newRootCmd()
	var out, errBuf bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errBuf.String(), err
}

func TestDryRunText(t *testing.T) {
	keyPath := writeTestKey(t)
	stdout, _, err := runCommand(t, keyPath, "--dry-run", "--tags", "Name=test", "--alias", "my-app")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	for _, want := range []string{"RSA_2048", "SIGN_VERIFY", "alias/my-app", "Name=test", "dry-run"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("dry-run output missing %q:\n%s", want, stdout)
		}
	}
}

func TestDryRunJSON(t *testing.T) {
	keyPath := writeTestKey(t)
	stdout, _, err := runCommand(t, keyPath, "--dry-run", "--output", "json", "--alias", "my-app")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	var plan struct {
		DryRun  bool     `json:"dryRun"`
		KeySpec string   `json:"keySpec"`
		Usage   string   `json:"usage"`
		Aliases []string `json:"aliases"`
	}
	if err := json.Unmarshal([]byte(stdout), &plan); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, stdout)
	}
	if !plan.DryRun || plan.KeySpec != "RSA_2048" || plan.Usage != "SIGN_VERIFY" {
		t.Errorf("plan = %+v", plan)
	}
	if len(plan.Aliases) != 1 || plan.Aliases[0] != "alias/my-app" {
		t.Errorf("aliases = %v", plan.Aliases)
	}
}

func TestEnvOverride(t *testing.T) {
	t.Setenv("KMS_IMPORT_USAGE", "ENCRYPT_DECRYPT")
	keyPath := writeTestKey(t)
	stdout, _, err := runCommand(t, keyPath, "--dry-run")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !strings.Contains(stdout, "ENCRYPT_DECRYPT") {
		t.Errorf("KMS_IMPORT_USAGE env override not applied:\n%s", stdout)
	}
}

func TestValidationErrors(t *testing.T) {
	keyPath := writeTestKey(t)
	cases := map[string][]string{
		"bad-tag":        {keyPath, "--dry-run", "--tags", "notag"},
		"bad-expires":    {keyPath, "--dry-run", "--expires", "never"},
		"bad-usage":      {keyPath, "--dry-run", "--usage", "SIGN_EVERYTHING"},
		"bad-output":     {keyPath, "--dry-run", "--output", "yaml"},
		"missing-file":   {filepath.Join(t.TempDir(), "nope.pem"), "--dry-run"},
		"no-positional":  {"--dry-run"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := runCommand(t, args...); err == nil {
				t.Error("command succeeded, want error")
			}
		})
	}
}
