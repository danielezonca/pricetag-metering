package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/redhat-et/pricetag-metering/internal/config"
)

func TestLoginValidationDoesNotForwardKeysOnRedirect(t *testing.T) {
	var forwarded bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer destination.Close()
	validator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer validator.Close()
	t.Setenv("MAAS_VALIDATE_URL", validator.URL)
	t.Setenv("SESSION_SECRET", "test-session-secret")
	h := NewAuthHandler(config.Config{DeploymentMode: config.DeploymentModeStandalone, ManagementPublicOrigin: "https://app.example"})
	req := httptest.NewRequest("POST", "/login", strings.NewReader("api_key=synthetic-test-key"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	h.HandleLogin(w, req)
	if forwarded {
		t.Fatal("validation redirect forwarded the submitted key")
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("redirect created a session")
	}
}

func loginTransport(t *testing.T, h *AuthHandler) *http.Transport {
	t.Helper()
	tr, ok := h.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("login client transport = %T, want *http.Transport", h.httpClient.Transport)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("login client has no TLS config")
	}
	return tr
}

func TestLoginValidatorKeepsClusterTLSDefaults(t *testing.T) {
	t.Setenv("SESSION_SECRET", "test-session-secret")
	h := NewAuthHandler(config.Config{DeploymentMode: config.DeploymentModeCluster})
	tr := loginTransport(t, h)
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("cluster login client must not skip TLS verification")
	}
	if tr.TLSClientConfig.RootCAs != nil {
		t.Fatal("cluster login client must use system roots, not a custom CA pool")
	}
}

func TestLoginValidatorHonorsStandaloneSkipVerify(t *testing.T) {
	t.Setenv("SESSION_SECRET", "test-session-secret")
	h := NewAuthHandler(config.Config{
		DeploymentMode: config.DeploymentModeStandalone,
		MaaSAPITLS:     config.MaaSAPITLS{InsecureSkipVerify: true},
	})
	tr := loginTransport(t, h)
	if !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("standalone login client must honor MAAS_API_INSECURE_SKIP_VERIFY")
	}
	if tr.TLSClientConfig.RootCAs != nil {
		t.Fatal("skip-verify must not also install a custom CA pool")
	}
}

func TestLoginValidatorHonorsStandaloneCAFile(t *testing.T) {
	t.Setenv("SESSION_SECRET", "test-session-secret")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pricetag login test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "maas-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	h := NewAuthHandler(config.Config{
		DeploymentMode: config.DeploymentModeStandalone,
		MaaSAPITLS:     config.MaaSAPITLS{CAFile: caFile},
	})
	tr := loginTransport(t, h)
	if tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("standalone login client must honor MAAS_API_CA_FILE")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("CA file must not disable verification")
	}
}
