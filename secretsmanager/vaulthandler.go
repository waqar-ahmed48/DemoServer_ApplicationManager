package secretsmanager

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"DemoServer_ApplicationManager/configuration"
	"DemoServer_ApplicationManager/helper"
	"DemoServer_ApplicationManager/utilities"

	_ "github.com/lib/pq"
	"go.opentelemetry.io/otel"
)

type VaultHandler struct {
	c            *configuration.Config
	l            *slog.Logger
	hc           *http.Client
	vaultAddress string
}

func (vh *VaultHandler) GetToken(ctx context.Context) (string, error) {

	tr := otel.Tracer(vh.c.Server.PrefixMain)
	_, span := tr.Start(ctx, utilities.GetFunctionName())
	defer span.End()

	// Create the authentication payload
	authData := map[string]string{
		"role_id":   vh.c.Vault.RoleID,
		"secret_id": vh.c.Vault.SecretID,
	}
	authDataJSON, err := json.Marshal(authData)
	if err != nil {
		return "", err
	}

	// Construct the authentication request
	url := fmt.Sprintf("%s/v1/%s", vh.vaultAddress, "auth/approle/login")
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(authDataJSON))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute the HTTP request
	resp, err := vh.hc.Do(req)
	if err != nil {
		return "", err
	}

	defer func() { _ = resp.Body.Close() }()

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to enable secrets engine: %s", string(body))
		//return "", helper.ErrVaultAuthenticationFailed
	}

	// Parse the response
	var respData struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		return "", fmt.Errorf("failed to parse response: %v", err)
	}

	return respData.Auth.ClientToken, nil
}

func NewVaultHandler(c *configuration.Config, l *slog.Logger) (*VaultHandler, error) {

	var vaultAddress string

	if c.Vault.HTTPS {
		vaultAddress += "https://"
	} else {
		vaultAddress += "http://"
	}
	vaultAddress += c.Vault.Host

	if c.Vault.Port != -1 {
		vaultAddress += ":" + strconv.Itoa(c.Vault.Port)
	}

	// Create a custom transport with TLS verification disabled
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: c.Vault.TLSSkipVerify}, // Set TLS verification according to requested configuration
	}

	// Create an HTTP client with the custom transport
	hc := &http.Client{
		Transport: transport,
	}

	vh := &VaultHandler{c, l, hc, vaultAddress}

	err := vh.Ping(context.Background())
	if err != nil {
		return nil, err
	}

	return vh, nil
}

func (vh *VaultHandler) Ping(ctx context.Context) error {

	tr := otel.Tracer(vh.c.Server.PrefixMain)
	_, span := tr.Start(ctx, utilities.GetFunctionName())
	defer span.End()

	// Ping the Vault server by checking its health
	healthCheckURL := fmt.Sprintf("%s/v1/sys/health", vh.vaultAddress)

	resp, err := vh.hc.Get(healthCheckURL)
	if err != nil {
		return err
	}

	defer func() { _ = resp.Body.Close() }()

	// Check the HTTP status code
	switch resp.StatusCode {
	case 200:
		return nil
	case 429:
		return helper.ErrVaultUnsealedButInStandby
	case 500:
		return helper.ErrVaultSealedOrInErrorState
	case 501:
		return helper.ErrVaultNotInitialized
	default:
		return helper.ErrVaultPingUnexpectedResponseCode
	}
}
