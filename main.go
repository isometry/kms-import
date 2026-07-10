package main

import "github.com/isometry/kms-import/cmd"

var version = "dev"

func main() {
	cmd.Execute(version)
}
