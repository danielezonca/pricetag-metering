package maasapi

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRejectUntrustedTLS(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"id":"x"}`)) }))
	defer s.Close()
	client, err := NewClientWithOptions(s.URL, "", ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateAPIKey(context.Background(), "alice", "users", "test"); err == nil {
		t.Fatal("accepted untrusted TLS")
	}
}
func TestRejectKeyRedirect(t *testing.T) {
	forwarded := false
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = true }))
	defer dest.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, dest.URL, 307) }))
	defer src.Close()
	client, err := NewClientWithOptions(src.URL, "", ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.CreateAPIKey(context.Background(), "alice", "users", "test")
	if err == nil || forwarded {
		t.Fatal("followed credential redirect")
	}
}

func TestTLSOptions(t *testing.T) {
	if _, err := NewClientWithOptions("https://maas.example", "", ClientOptions{TLSOptions: TLSOptions{CAFile: "ca.pem", InsecureSkipVerify: true}}); err == nil {
		t.Fatal("mutually exclusive TLS options were accepted")
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"id":"x"}`)) }))
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, certificatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	client, err := NewClientWithOptions(server.URL, "", ClientOptions{TLSOptions: TLSOptions{CAFile: caFile}})
	if err != nil {
		t.Fatalf("valid CA bundle rejected: %v", err)
	}
	if _, err := client.CreateAPIKey(context.Background(), "alice", "users", "test"); err != nil {
		t.Fatalf("internal-CA request failed: %v", err)
	}
}

// Proxy use is an explicit construction option: the key client connects
// directly (the transport before standalone management existed), while login
// validation opts into the environment proxy because it historically ran on
// http.DefaultTransport.
func TestUseEnvProxyOption(t *testing.T) {
	direct, err := NewHTTPClient(ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if direct.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("default transport must connect directly, without an environment proxy")
	}
	proxied, err := NewHTTPClient(ClientOptions{UseEnvProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	if proxied.Transport.(*http.Transport).Proxy == nil {
		t.Fatal("UseEnvProxy must install http.ProxyFromEnvironment")
	}
	if NewClient("https://maas.example", "").client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("deprecated NewClient must keep the legacy direct transport")
	}
}
