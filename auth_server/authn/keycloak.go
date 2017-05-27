package authn

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"net/http"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"

	"github.com/cesanta/glog"
)

type KeycloakAuthConfig struct {
	Domain       string   `yaml:"domain,omitempty"`
	ClientID     string   `yaml:"client_id,omitempty"`
	ClientSecret string   `yaml:"client_secret,omitempty"`
	Scopes       []string `yaml:"scopes,omitempty"`
	OIDCURL      string   `yaml:"oidc_url,omitempty"`
	CAFile       string   `yaml:"ca_file,omitempty"`
}

type KeycloakAuth struct {
	config   *KeycloakAuthConfig
	ctx      context.Context
	oauth2   *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func NewKeycloakAuth(c *KeycloakAuthConfig) (*KeycloakAuth, error) {
	ca, err := ioutil.ReadFile(c.CAFile)
	if err != nil {
		glog.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM([]byte(ca))

	tlsConfig := &tls.Config{
		RootCAs:            caCertPool,
		InsecureSkipVerify: false,
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}

	client := &http.Client{Transport: transport}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, client)

	provider, err := oidc.NewProvider(ctx, c.OIDCURL)
	if err != nil {
		return nil, err
	}

	oauth2 := &oauth2.Config{ClientID: c.ClientID, ClientSecret: c.ClientSecret, Endpoint: provider.Endpoint(), Scopes: c.Scopes}

	oidcConfig := &oidc.Config{ClientID: c.ClientID, SkipNonceCheck: true}

	return &KeycloakAuth{
		config:   c,
		ctx:      ctx,
		oauth2:   oauth2,
		verifier: provider.Verifier(oidcConfig),
	}, nil
}

func (kca *KeycloakAuth) Authenticate(username string, password PasswordString) (bool, Labels, error) {

	oauth2Token, err := kca.oauth2.PasswordCredentialsToken(kca.ctx, username, string(password))
	if err != nil {
		glog.Error("Failed to exchange token: " + err.Error())
		return false, nil, err
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		glog.Error("No id_token field in oauth2 token.")
		return false, nil, errors.New("no id_token field in oauth2 token")
	}
	idToken, err := kca.verifier.Verify(kca.ctx, rawIDToken)
	if err != nil {
		glog.Error("Failed to verify ID Token: " + err.Error())
		return false, nil, err
	}
	glog.Infof("id token = %s", idToken)

	// Extract custom claims
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}

	if err := idToken.Claims(&claims); err != nil {
		glog.Error("Failed to extract claims: " + err.Error())
	}

	labels := make(Labels)

	labels["email"] = []string{claims.Email}

	return true, labels, nil // TODO transform claims from idToken to labels
}

func (kca *KeycloakAuth) Stop() {
}

func (kca *KeycloakAuth) Name() string {
	return "Keycloak"
}
