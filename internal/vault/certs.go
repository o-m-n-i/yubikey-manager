package vault

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/bobbydams/yubikey-manager/internal/piv"
)

// Role settings for a registered YubiKey. yubikey-admin is the policy the
// break-glass login hands out.
const (
	RolePrefix  = "yubikey-"
	RolePolicy  = "yubikey-admin"
	RoleTTL     = "8h"
	RoleMaxTTL  = "24h"
	certsPrefix = "auth/" + DefaultMount + "/certs"
)

// CertRole is one cert-auth role with the fingerprints of its certificates.
type CertRole struct {
	Name         string
	Fingerprints []string
}

// ListCertRoles reads every role under auth/cert/certs/ and the fingerprints
// of the certificates it trusts. It needs a token that may list and read them.
func (c *Client) ListCertRoles(ctx context.Context) ([]CertRole, error) {
	var list struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := c.do(ctx, "LIST", certsPrefix, nil, &list); err != nil {
		if IsNotFound(err) {
			return nil, nil // no roles yet
		}
		return nil, fmt.Errorf("listing cert roles: %w", err)
	}
	names := list.Data.Keys
	sort.Strings(names)

	roles := make([]CertRole, 0, len(names))
	for _, name := range names {
		var rd struct {
			Data struct {
				Certificate string `json:"certificate"`
			} `json:"data"`
		}
		if err := c.do(ctx, http.MethodGet, certsPrefix+"/"+escapeSegment(name), nil, &rd); err != nil {
			return nil, fmt.Errorf("reading cert role %q: %w", name, err)
		}
		role := CertRole{Name: name}
		if certs, err := piv.ParseCertificatesPEM([]byte(rd.Data.Certificate)); err == nil {
			for _, ct := range certs {
				role.Fingerprints = append(role.Fingerprints, piv.Fingerprint(ct))
			}
		}
		roles = append(roles, role)
	}
	return roles, nil
}

// RolesWithFingerprint returns the names of the roles that trust fingerprint.
func RolesWithFingerprint(roles []CertRole, fingerprint string) []string {
	var names []string
	for _, r := range roles {
		for _, fp := range r.Fingerprints {
			if strings.EqualFold(fp, fingerprint) {
				names = append(names, r.Name)
				break
			}
		}
	}
	return names
}

// RegisterCert writes auth/cert/certs/<role> for the YubiKey certificate.
func (c *Client) RegisterCert(ctx context.Context, role string, cert *x509.Certificate) error {
	pemBytes := pemEncode(cert)
	body := map[string]any{
		"certificate":    pemBytes,
		"display_name":   role,
		"token_policies": RolePolicy,
		"token_ttl":      RoleTTL,
		"token_max_ttl":  RoleMaxTTL,
	}
	if err := c.do(ctx, http.MethodPost, certsPrefix+"/"+escapeSegment(role), body, nil); err != nil {
		return fmt.Errorf("writing cert role %q: %w", role, err)
	}
	return nil
}

func pemEncode(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}
