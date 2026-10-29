package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/WenxueWu0216/SecretKit/internal/redact"
	"github.com/spf13/cobra"
)

func (a *app) runCmd() *cobra.Command {
	var only []string
	cmd := &cobra.Command{
		Use:   "run [--only NAME,...] -- COMMAND [ARGS...]",
		Short: "Run a command with secrets injected as environment variables",
		Long: "Run a command with secrets injected as environment variables. Any secret " +
			"value that appears in the command's stdout or stderr is replaced with " + redact.Marker + ".",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.ArgsLenAtDash() != 0 {
				return errors.New("separate the command with --, e.g. secretkit run -- env")
			}
			client, err := a.authedClient()
			if err != nil {
				return err
			}
			ctx := cmd.Context()

			names := only
			if len(names) == 0 {
				list, err := client.ListSecrets(ctx)
				if err != nil {
					return err
				}
				for _, s := range list {
					names = append(names, s.Name)
				}
			}
			injected := make(map[string]string, len(names))
			for _, name := range names {
				sec, err := client.GetSecret(ctx, name)
				if err != nil {
					return fmt.Errorf("fetching %s: %w", name, err)
				}
				a.redactions.Add(sec.Value)
				injected[sec.Name] = sec.Value
			}
			a.log.Debug("injecting secrets", "count", len(injected), "command", args[0])
			return a.runChild(args, injected)
		},
	}
	cmd.Flags().StringSliceVar(&only, "only", nil, "inject only these secrets (comma-separated)")
	return cmd
}

func (a *app) runChild(args []string, injected map[string]string) error {
	child := exec.Command(args[0], args[1:]...)
	child.Env = childEnv(a.env.Environ(), injected)
	child.Stdin = a.env.Stdin
	stdout := redact.NewWriter(a.env.Stdout, a.redactions)
	stderr := redact.NewWriter(a.env.Stderr, a.redactions)
	child.Stdout = stdout
	child.Stderr = stderr

	if err := child.Start(); err != nil {
		return err
	}
	forward := func(sig os.Signal) { _ = child.Process.Signal(sig) }
	a.forward.Store(&forward)
	defer a.forward.Store(nil)

	// Wait returns only after the output copiers finish, so flushing after
	// it cannot race with a late write.
	err := child.Wait()
	if ferr := errors.Join(stdout.Flush(), stderr.Flush()); ferr != nil && err == nil {
		err = ferr
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code := exitErr.ExitCode()
		if code < 0 {
			code = 1 // killed by a signal
		}
		return &ExitError{Code: code}
	}
	return err
}

// childEnv overrides inherited variables with secrets and drops the CLI's
// own credential so the child cannot reuse it.
func childEnv(base []string, injected map[string]string) []string {
	env := slices.DeleteFunc(slices.Clone(base), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		_, overridden := injected[name]
		return overridden || name == "SECRETKIT_TOKEN"
	})
	names := make([]string, 0, len(injected))
	for name := range injected {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		env = append(env, name+"="+injected[name])
	}
	return env
}
