package secretkit_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http/httptest"

	"github.com/WenxueWu0216/SecretKit/sdk/go/secretkit"
	"github.com/WenxueWu0216/SecretKit/server"
)

func Example() {
	// A local mock server with a pre-registered token stands in for a real deployment.
	srv := server.New(server.Config{})
	srv.Tokens.AddStaticToken("fake-example-token", []string{secretkit.ScopeRead, secretkit.ScopeWrite})
	ts := httptest.NewServer(srv)
	defer ts.Close()

	ctx := context.Background()
	client, err := secretkit.New(ts.URL, secretkit.WithToken("fake-example-token"))
	if err != nil {
		log.Fatal(err)
	}

	if _, err := client.PutSecret(ctx, "DB_PASSWORD", "fake-db-password"); err != nil {
		log.Fatal(err)
	}
	secret, err := client.GetSecret(ctx, "DB_PASSWORD")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(secret.Name, secret.Version, secret.Value)

	_, err = client.GetSecret(ctx, "MISSING")
	var apiErr *secretkit.APIError
	if errors.Is(err, secretkit.ErrNotFound) && errors.As(err, &apiErr) {
		fmt.Println(apiErr.StatusCode, apiErr.Code)
	}
	// Output:
	// DB_PASSWORD 1 fake-db-password
	// 404 not_found
}
