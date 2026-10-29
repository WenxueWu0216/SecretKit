package secretkit

import (
	"context"

	"github.com/WenxueWu0216/SecretKit/sdk/go/api"
)

// SecretMetadata describes a secret without its value.
type SecretMetadata = api.SecretMetadata

// Secret is a secret with its value.
type Secret = api.Secret

// ListSecrets returns metadata for all secrets, sorted by name.
func (c *Client) ListSecrets(ctx context.Context) ([]SecretMetadata, error) {
	var out []SecretMetadata
	err := c.authorized(ctx, func(auth api.RequestEditorFn) error {
		resp, err := c.api.ListSecretsWithResponse(ctx, auth)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil {
			return newAPIError(resp.HTTPResponse, resp.JSON401, resp.JSON403, resp.JSON429, resp.JSON500)
		}
		out = resp.JSON200.Secrets
		return nil
	})
	return out, err
}

// GetSecret returns a secret and its value.
func (c *Client) GetSecret(ctx context.Context, name string) (Secret, error) {
	var out Secret
	err := c.authorized(ctx, func(auth api.RequestEditorFn) error {
		resp, err := c.api.GetSecretWithResponse(ctx, name, auth)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil {
			return newAPIError(resp.HTTPResponse, resp.JSON400, resp.JSON401, resp.JSON403, resp.JSON404, resp.JSON429, resp.JSON500)
		}
		out = *resp.JSON200
		return nil
	})
	return out, err
}

// PutSecret creates or replaces a secret and returns its new metadata.
func (c *Client) PutSecret(ctx context.Context, name, value string) (SecretMetadata, error) {
	var out SecretMetadata
	err := c.authorized(ctx, func(auth api.RequestEditorFn) error {
		resp, err := c.api.PutSecretWithResponse(ctx, name, api.PutSecretRequest{Value: value}, auth)
		if err != nil {
			return err
		}
		if resp.JSON200 == nil {
			return newAPIError(resp.HTTPResponse, resp.JSON400, resp.JSON401, resp.JSON403, resp.JSON429, resp.JSON500)
		}
		out = *resp.JSON200
		return nil
	})
	return out, err
}
