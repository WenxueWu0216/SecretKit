// Package cli implements the secretkit command.
package cli

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"

	"github.com/WenxueWu0216/SecretKit/internal/redact"
	"github.com/WenxueWu0216/SecretKit/sdk/go/secretkit"
	"github.com/spf13/cobra"
)

// ClientID identifies the CLI to the authorization server.
const ClientID = "secretkit-cli"

const defaultServer = "http://127.0.0.1:8787"

// Env holds everything the CLI touches outside its own memory, so tests can
// substitute it.
type Env struct {
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Getenv  func(string) string
	Environ func() []string
	Tokens  TokenStore
	Version string
	// Signals cancels the running command, or is forwarded to the child
	// while `secretkit run` has one. Nil disables signal handling.
	Signals <-chan os.Signal
}

// ExitError carries a child process exit code out of `secretkit run`.
type ExitError struct{ Code int }

func (e *ExitError) Error() string { return "child exited with a non-zero status" }

type app struct {
	env     Env
	server  string
	verbose bool
	log     *slog.Logger
	// redactions holds every secret value and token this process has seen,
	// and is applied to log output and to child process output.
	redactions *redact.Set
	logOut     *redact.Writer
	// forward is set while a `run` child is alive.
	forward atomic.Pointer[func(os.Signal)]
}

// NewRootCommand builds the command tree.
func NewRootCommand(env Env) *cobra.Command {
	return newApp(env).rootCmd()
}

func newApp(env Env) *app { return &app{env: env, redactions: redact.NewSet()} }

func (a *app) rootCmd() *cobra.Command {
	env := a.env
	root := &cobra.Command{
		Use:           "secretkit",
		Short:         "Fetch secrets and inject them into processes",
		Version:       env.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(*cobra.Command, []string) {
			a.server = strings.TrimRight(a.server, "/")
			a.setupLogging()
		},
		PersistentPostRun: func(*cobra.Command, []string) { _ = a.logOut.Flush() },
	}
	root.SetIn(env.Stdin)
	root.SetOut(env.Stdout)
	root.SetErr(env.Stderr)

	serverDefault := env.Getenv("SECRETKIT_SERVER")
	if serverDefault == "" {
		serverDefault = defaultServer
	}
	root.PersistentFlags().StringVar(&a.server, "server", serverDefault, "server URL (env SECRETKIT_SERVER)")
	root.PersistentFlags().BoolVarP(&a.verbose, "verbose", "v", false, "log debug output to stderr (secret values are redacted)")

	root.AddCommand(a.loginCmd(), a.logoutCmd(), a.getCmd(), a.setCmd(), a.listCmd(), a.runCmd())
	return root
}

// setupLogging sends logs through the redaction set, so a value that ends
// up in a log attribute or error message is still masked.
func (a *app) setupLogging() {
	level := slog.LevelWarn
	if a.verbose {
		level = slog.LevelDebug
	}
	a.logOut = redact.NewWriter(a.env.Stderr, a.redactions)
	a.log = slog.New(slog.NewTextHandler(a.logOut, &slog.HandlerOptions{Level: level}))
}

func (a *app) newClient(opts ...secretkit.Option) (*secretkit.Client, error) {
	opts = append([]secretkit.Option{secretkit.WithUserAgent("secretkit-cli/" + a.env.Version)}, opts...)
	return secretkit.New(a.server, opts...)
}

// authedClient prefers SECRETKIT_TOKEN, then the keychain login.
func (a *app) authedClient() (*secretkit.Client, error) {
	if tok := a.env.Getenv("SECRETKIT_TOKEN"); tok != "" {
		a.redactions.Add(tok)
		a.log.Debug("using access token from SECRETKIT_TOKEN")
		return a.newClient(secretkit.WithToken(tok))
	}
	tok, err := a.env.Tokens.Load(a.server)
	if err != nil {
		return nil, err
	}
	a.redactions.Add(tok.AccessToken)
	a.redactions.Add(tok.RefreshToken)

	client, err := a.newClient()
	if err != nil {
		return nil, err
	}
	ts := client.NewRefreshingTokenSource(ClientID, tok)
	ts.OnRefresh = func(next secretkit.Token) error {
		a.redactions.Add(next.AccessToken)
		a.redactions.Add(next.RefreshToken)
		a.log.Debug("access token refreshed")
		return a.env.Tokens.Save(a.server, next)
	}
	return a.newClient(secretkit.WithTokenSource(ts))
}

// friendly rewrites SDK errors into actionable CLI messages.
func friendly(err error) error {
	switch {
	case errors.Is(err, secretkit.ErrInvalidGrant), errors.Is(err, secretkit.ErrUnauthorized):
		return errors.New("session expired or revoked; run `secretkit login` again (" + err.Error() + ")")
	case errors.Is(err, secretkit.ErrForbidden):
		return errors.New("permission denied: the current login lacks the required scope (" + err.Error() + ")")
	}
	return err
}

// Execute runs the CLI and returns the process exit code.
func Execute(ctx context.Context, env Env, args []string) int {
	a := newApp(env)
	root := a.rootCmd()
	root.SetArgs(args)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if env.Signals != nil {
		go func() {
			for {
				select {
				case sig := <-env.Signals:
					if f := a.forward.Load(); f != nil {
						(*f)(sig)
					} else {
						cancel()
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	err := root.ExecuteContext(ctx)
	if err == nil {
		return 0
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		return exit.Code
	}
	_, _ = io.WriteString(env.Stderr, "secretkit: "+friendly(err).Error()+"\n")
	return 1
}
