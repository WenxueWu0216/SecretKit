// Command secretkit is the SecretKit CLI.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/WenxueWu0216/SecretKit/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	// Signals are forwarded to `secretkit run` children instead of killing
	// the CLI first, so the child can shut down cleanly.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)

	os.Exit(cli.Execute(context.Background(), cli.Env{
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Getenv:  os.Getenv,
		Environ: os.Environ,
		Tokens:  cli.KeyringStore{},
		Version: version,
		Signals: sigs,
	}, os.Args[1:]))
}
