package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"codex-proxy/internal/database"
)

func TestSendTestDeliversSignedEvent(t *testing.T) {
	var gotBody []byte
	var gotSig, gotEvent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotSig = r.Header.Get("X-Signature")
		gotEvent = r.Header.Get("X-Event")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	d := New(nil)
	if err := d.SendTest(database.WebhookConfig{URL: srv.URL, Secret: "s3cret"}); err != nil {
		t.Fatalf("SendTest: %v", err)
	}

	if gotEvent != "webhook.test" {
		t.Errorf("X-Event = %q, want webhook.test", gotEvent)
	}
	var env struct {
		Event string `json:"event"`
	}
	if err := json.Unmarshal(gotBody, &env); err != nil || env.Event != "webhook.test" {
		t.Errorf("body = %s (err %v), want event webhook.test", gotBody, err)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(gotBody)
	if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); gotSig != want {
		t.Errorf("X-Signature = %q, want %q", gotSig, want)
	}
}

func TestSendTestReportsReceiverError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unknown Webhook", http.StatusNotFound)
	}))
	defer srv.Close()

	err := New(nil).SendTest(database.WebhookConfig{URL: srv.URL})
	if err == nil || !strings.Contains(err.Error(), "404") || !strings.Contains(err.Error(), "Unknown Webhook") {
		t.Fatalf("err = %v, want it to carry the 404 status and body", err)
	}
}

func TestDeliveryErrorOmitsURL(t *testing.T) {
	err := New(nil).SendTest(database.WebhookConfig{URL: "http://127.0.0.1:1/hooks/secret-token"})
	if err == nil {
		t.Fatal("expected an error for an unreachable receiver")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Errorf("error leaks the webhook URL: %v", err)
	}
}
