// Package cmd implements the kms-import command line interface.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "kms-import <keyfile>",
		Short: "Import local private key material into AWS KMS",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("not implemented")
		},
	}
	return cmd
}

// Execute runs the root command, exiting non-zero on error.
func Execute(version string) {
	cmd := newRootCmd()
	cmd.Version = version
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
