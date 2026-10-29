// Command secretkit-server runs the in-memory SecretKit mock server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/WenxueWu0216/SecretKit/server"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "secretkit-server:", err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", "127.0.0.1:8787", "listen address; use port 0 for a random port")
	accessTTL := flag.Duration("access-ttl", 15*time.Minute, "access token lifetime")
	refreshTTL := flag.Duration("refresh-ttl", 24*time.Hour, "refresh token lifetime")
	deviceTTL := flag.Duration("device-ttl", 10*time.Minute, "device code lifetime")
	interval := flag.Duration("poll-interval", 5*time.Second, "minimum device polling interval")
	rateLimit := flag.Float64("rate-limit", 0, "requests per second per caller (0 = unlimited)")
	devTokenScope := flag.String("dev-token-scope", "secrets:read secrets:write", "scopes for the token in SECRETKIT_DEV_TOKEN")
	quiet := flag.Bool("quiet", false, "disable request logging")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if *quiet {
		logger = slog.New(slog.DiscardHandler)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	baseURL := "http://" + ln.Addr().String()

	srv := server.New(server.Config{
		BaseURL:         baseURL,
		AccessTokenTTL:  *accessTTL,
		RefreshTokenTTL: *refreshTTL,
		DeviceCodeTTL:   *deviceTTL,
		PollInterval:    *interval,
		RateLimit:       *rateLimit,
		Logger:          logger,
	})
	// The dev token comes from the environment rather than a flag so it does
	// not show up in process listings.
	if tok := os.Getenv("SECRETKIT_DEV_TOKEN"); tok != "" {
		srv.Tokens.AddStaticToken(tok, strings.Fields(*devTokenScope))
	}

	// Printed on stdout so test harnesses can discover a random port.
	fmt.Println("listening on " + baseURL)

	httpSrv := &http.Server{Handler: srv, ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()
	if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
