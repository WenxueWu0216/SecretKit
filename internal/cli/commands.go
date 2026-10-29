package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// infof prints user-facing status to stderr. A failed write to the
// terminal is not worth failing the command over.
func (a *app) infof(format string, args ...any) {
	_, _ = fmt.Fprintf(a.env.Stderr, format, args...)
}

func (a *app) loginCmd() *cobra.Command {
	var scope string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log in with the device authorization flow",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			client, err := a.newClient()
			if err != nil {
				return err
			}
			da, err := client.StartDeviceAuth(ctx, ClientID, scope)
			if err != nil {
				return err
			}
			uri := da.VerificationURIComplete
			if uri == "" {
				uri = da.VerificationURI
			}
			a.infof("To log in, open %s\nand confirm the code: %s\n", uri, da.UserCode)
			a.infof("Waiting for approval (expires in %s)...\n", time.Until(da.ExpiresAt).Round(time.Second))

			tok, err := client.PollToken(ctx, da)
			if err != nil {
				return err
			}
			a.redactions.Add(tok.AccessToken)
			a.redactions.Add(tok.RefreshToken)
			if err := a.env.Tokens.Save(a.server, tok); err != nil {
				// The server session would otherwise outlive the failed save.
				_ = client.RevokeToken(ctx, tok.RefreshToken)
				return err
			}
			a.infof("Logged in to %s (scopes: %s)\n", a.server, tok.Scope)
			return nil
		},
	}
	cmd.Flags().StringVar(&scope, "scope", "secrets:read secrets:write", "space-separated scopes to request")
	return cmd
}

func (a *app) logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Revoke the session and remove tokens from the keychain",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tok, err := a.env.Tokens.Load(a.server)
			if errors.Is(err, errNotLoggedIn) {
				a.infof("Not logged in.\n")
				return nil
			}
			if err != nil {
				return err
			}
			a.redactions.Add(tok.RefreshToken)
			client, err := a.newClient()
			if err != nil {
				return err
			}
			if err := client.RevokeToken(cmd.Context(), tok.RefreshToken); err != nil {
				// Still remove local tokens: logging out must work offline.
				a.log.Warn("could not revoke session on server", "error", err)
			}
			if err := a.env.Tokens.Delete(a.server); err != nil {
				return err
			}
			a.infof("Logged out.\n")
			return nil
		},
	}
}

func (a *app) getCmd() *cobra.Command {
	var noNewline bool
	cmd := &cobra.Command{
		Use:   "get NAME",
		Short: "Print a secret value to stdout",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := a.authedClient()
			if err != nil {
				return err
			}
			sec, err := client.GetSecret(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			a.redactions.Add(sec.Value)
			a.log.Debug("fetched secret", "name", sec.Name, "version", sec.Version)
			// stdout is the one place a value is printed on purpose.
			out := sec.Value
			if !noNewline {
				out += "\n"
			}
			_, err = io.WriteString(a.env.Stdout, out)
			return err
		},
	}
	cmd.Flags().BoolVarP(&noNewline, "no-newline", "n", false, "do not print a trailing newline")
	return cmd
}

func (a *app) setCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set NAME [VALUE]",
		Short: "Create or update a secret",
		Long: "Create or update a secret. If VALUE is omitted it is read from stdin, " +
			"which keeps it out of shell history and process listings.",
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var value string
			if len(args) == 2 {
				value = args[1]
			} else {
				v, err := a.readValue()
				if err != nil {
					return err
				}
				value = v
			}
			a.redactions.Add(value)
			client, err := a.authedClient()
			if err != nil {
				return err
			}
			meta, err := client.PutSecret(cmd.Context(), args[0], value)
			if err != nil {
				return err
			}
			a.infof("Stored %s (version %d)\n", meta.Name, meta.Version)
			return nil
		},
	}
}

func (a *app) readValue() (string, error) {
	if f, ok := a.env.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		a.infof("Value (input hidden): ")
		b, err := term.ReadPassword(int(f.Fd()))
		a.infof("\n")
		return string(b), err
	}
	b, err := io.ReadAll(bufio.NewReader(io.LimitReader(a.env.Stdin, 1<<20)))
	if err != nil {
		return "", err
	}
	// `echo value | secretkit set` adds a newline the user did not mean to store.
	return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"), nil
}

func (a *app) listCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secret names and versions (never values)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := a.authedClient()
			if err != nil {
				return err
			}
			secrets, err := client.ListSecrets(cmd.Context())
			if err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(a.env.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(secrets)
			}
			tw := tabwriter.NewWriter(a.env.Stdout, 0, 4, 2, ' ', 0)
			// tabwriter buffers everything; write errors surface from Flush.
			_, _ = fmt.Fprintln(tw, "NAME\tVERSION\tUPDATED")
			for _, s := range secrets {
				_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\n", s.Name, s.Version, s.UpdatedAt.Format(time.RFC3339))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	return cmd
}
