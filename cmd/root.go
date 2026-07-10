// Package cmd implements the kms-import command line interface.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/isometry/kms-import/internal/importer"
	"github.com/isometry/kms-import/internal/keymaterial"
)

// maxKeyFileSize caps key file reads; genuine private keys are a few KiB.
const maxKeyFileSize = 1 << 20

func newRootCmd() *cobra.Command {
	v := viper.New()

	cmd := &cobra.Command{
		Use:   "kms-import <keyfile>",
		Short: "Import local private key material into AWS KMS",
		Long: `kms-import creates an AWS KMS key with EXTERNAL origin and imports the
private key material from <keyfile> into it, wrapping the material with
RSA_AES_KEY_WRAP_SHA_256 in transit.

Accepts unencrypted RSA (2048/3072/4096) and ECC (P-256/384/521, secp256k1,
Ed25519) private keys in PEM or DER form (PKCS#1, PKCS#8 or SEC1).`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, v, args[0])
		},
	}

	flags := cmd.Flags()
	flags.StringSlice("alias", nil, "alias to create for the key (repeatable; 'alias/' prefix optional)")
	flags.StringArray("tags", nil, "key=value tag to set on the key (repeatable)")
	flags.String("usage", "SIGN_VERIFY", "key usage: SIGN_VERIFY or ENCRYPT_DECRYPT (RSA only)")
	flags.String("expires", "", "key material expiry as Go duration (e.g. 8760h) or RFC3339 timestamp (default: never)")
	flags.String("description", "", "KMS key description")
	flags.String("output", "text", "output format: text or json")
	flags.Bool("dry-run", false, "validate the key file and print the plan without calling AWS")
	flags.String("region", "", "AWS region (default: SDK resolution)")
	flags.String("profile", "", "AWS shared-config profile (default: SDK resolution)")

	if err := v.BindPFlags(flags); err != nil {
		panic(err)
	}
	v.SetEnvPrefix("KMS_IMPORT")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	return cmd
}

// Execute runs the root command, exiting non-zero on error.
func Execute(version string) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd := newRootCmd()
	cmd.Version = version
	if err := cmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "kms-import: %v\n", err)
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, v *viper.Viper, keyPath string) error {
	outputFormat := v.GetString("output")
	if outputFormat != "text" && outputFormat != "json" {
		return fmt.Errorf("invalid --output %q: use text or json", outputFormat)
	}

	tags, err := parseTags(v.GetStringSlice("tags"))
	if err != nil {
		return err
	}

	var validTo *time.Time
	if s := v.GetString("expires"); s != "" {
		t, err := parseExpires(s, time.Now())
		if err != nil {
			return err
		}
		validTo = &t
	}

	material, err := readKeyFile(keyPath)
	if err != nil {
		return err
	}

	usage, err := usageFor(v.GetString("usage"), material.KeySpec)
	if err != nil {
		return err
	}

	aliases := make([]string, 0, len(v.GetStringSlice("alias")))
	for _, alias := range v.GetStringSlice("alias") {
		if !strings.HasPrefix(alias, "alias/") {
			alias = "alias/" + alias
		}
		aliases = append(aliases, alias)
	}

	params := importer.Params{
		Material:    material,
		Description: v.GetString("description"),
		Usage:       usage,
		Aliases:     aliases,
		Tags:        tags,
		ValidTo:     validTo,
	}

	if v.GetBool("dry-run") {
		return renderPlan(cmd.OutOrStdout(), outputFormat, keyPath, params)
	}

	ctx := cmd.Context()
	stderr := cmd.ErrOrStderr()

	var opts []func(*config.LoadOptions) error
	if region := v.GetString("region"); region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	if profile := v.GetString("profile"); profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("loading AWS configuration: %w", err)
	}

	fmt.Fprintf(stderr, "importing %s key material into a new KMS key...\n", material.KeySpec)
	result, runErr := importer.Run(ctx, kms.NewFromConfig(cfg), params)
	if result != nil {
		if err := renderResult(cmd.OutOrStdout(), outputFormat, result); err != nil {
			return err
		}
	}
	return runErr
}

func readKeyFile(path string) (*keymaterial.KeyMaterial, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(data) > maxKeyFileSize {
		return nil, fmt.Errorf("%s is larger than %d bytes; not a private key file", path, maxKeyFileSize)
	}
	material, err := keymaterial.Parse(data)
	clear(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return material, nil
}

func parseTags(entries []string) (map[string]string, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	tags := make(map[string]string, len(entries))
	for _, entry := range entries {
		key, value, found := strings.Cut(entry, "=")
		if !found || key == "" {
			return nil, fmt.Errorf("invalid --tags entry %q: expected key=value", entry)
		}
		tags[key] = value
	}
	return tags, nil
}

func parseExpires(s string, now time.Time) (time.Time, error) {
	var t time.Time
	if d, err := time.ParseDuration(s); err == nil {
		t = now.Add(d)
	} else if ts, tsErr := time.Parse(time.RFC3339, s); tsErr == nil {
		t = ts
	} else {
		return time.Time{}, fmt.Errorf("invalid --expires %q: use a Go duration (e.g. 8760h) or an RFC3339 timestamp", s)
	}
	if !t.After(now) {
		return time.Time{}, fmt.Errorf("--expires %q is not in the future", s)
	}
	if t.After(now.Add(365 * 24 * time.Hour)) {
		return time.Time{}, fmt.Errorf("--expires %q is more than 365 days away, the KMS maximum", s)
	}
	return t, nil
}

func usageFor(usage string, spec types.KeySpec) (types.KeyUsageType, error) {
	switch usage {
	case "SIGN_VERIFY":
		return types.KeyUsageTypeSignVerify, nil
	case "ENCRYPT_DECRYPT":
		if !strings.HasPrefix(string(spec), "RSA_") {
			return "", fmt.Errorf("--usage ENCRYPT_DECRYPT is only valid for RSA keys, not %s", spec)
		}
		return types.KeyUsageTypeEncryptDecrypt, nil
	default:
		return "", fmt.Errorf("invalid --usage %q: use SIGN_VERIFY or ENCRYPT_DECRYPT", usage)
	}
}

func renderPlan(w io.Writer, format, keyPath string, p importer.Params) error {
	if format == "json" {
		return writeJSON(w, struct {
			DryRun      bool              `json:"dryRun"`
			KeyFile     string            `json:"keyFile"`
			KeySpec     string            `json:"keySpec"`
			Usage       string            `json:"usage"`
			Description string            `json:"description,omitempty"`
			Aliases     []string          `json:"aliases,omitempty"`
			Tags        map[string]string `json:"tags,omitempty"`
			Expires     *time.Time        `json:"expires,omitempty"`
		}{true, keyPath, string(p.Material.KeySpec), string(p.Usage), p.Description, p.Aliases, p.Tags, p.ValidTo})
	}

	fmt.Fprintln(w, "dry-run: validated key material; no AWS calls made")
	fmt.Fprintf(w, "  key file:    %s\n", keyPath)
	fmt.Fprintf(w, "  key spec:    %s\n", p.Material.KeySpec)
	fmt.Fprintf(w, "  usage:       %s\n", p.Usage)
	if p.Description != "" {
		fmt.Fprintf(w, "  description: %s\n", p.Description)
	}
	if len(p.Aliases) > 0 {
		fmt.Fprintf(w, "  aliases:     %s\n", strings.Join(p.Aliases, ", "))
	}
	if len(p.Tags) > 0 {
		pairs := make([]string, 0, len(p.Tags))
		for _, k := range slices.Sorted(maps.Keys(p.Tags)) {
			pairs = append(pairs, k+"="+p.Tags[k])
		}
		fmt.Fprintf(w, "  tags:        %s\n", strings.Join(pairs, ", "))
	}
	fmt.Fprintf(w, "  expires:     %s\n", expiryString(p.ValidTo))
	return nil
}

func renderResult(w io.Writer, format string, r *importer.Result) error {
	if format == "json" {
		return writeJSON(w, r)
	}
	fmt.Fprintln(w, "imported key material into new KMS key")
	fmt.Fprintf(w, "  key id:  %s\n", r.KeyID)
	fmt.Fprintf(w, "  arn:     %s\n", r.ARN)
	fmt.Fprintf(w, "  spec:    %s\n", r.KeySpec)
	if len(r.Aliases) > 0 {
		fmt.Fprintf(w, "  aliases: %s\n", strings.Join(r.Aliases, ", "))
	}
	fmt.Fprintf(w, "  expires: %s\n", expiryString(r.Expires))
	return nil
}

func expiryString(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Format(time.RFC3339)
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
