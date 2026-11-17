package webhook

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"codex-proxy/internal/database"

	"gorm.io/gorm"
)

// Dispatcher sends HTTP webhooks when events occur.
type Dispatcher struct {
	db       *gorm.DB
	client   *http.Client
	sent     map[string]time.Time // dedup: event+target → last sent time
	sentMu   sync.Mutex
	cooldown time.Duration // minimum time between identical notifications
}

func New(db *gorm.DB) *Dispatcher {
	return &Dispatcher{
		db:       db,
		client:   &http.Client{Timeout: 5 * time.Second},
		sent:     make(map[string]time.Time),
		cooldown: 10 * time.Minute,
	}
}

// Dispatch fires all active webhooks subscribed to the given event (async).
// Deduplicates: same event+payload key is only sent once per cooldown period (10 min).
func (d *Dispatcher) Dispatch(event string, payload interface{}) {
	// Build dedup key from event + payload summary
	keyData, _ := json.Marshal(payload)
	dedupKey := event + ":" + string(keyData)

	d.sentMu.Lock()
	if last, ok := d.sent[dedupKey]; ok && time.Since(last) < d.cooldown {
		d.sentMu.Unlock()
		return // already sent recently, skip
	}
	d.sent[dedupKey] = time.Now()
	// Prune old entries
	for k, t := range d.sent {
		if time.Since(t) > d.cooldown {
			delete(d.sent, k)
		}
	}
	d.sentMu.Unlock()

	var hooks []database.WebhookConfig
	if err := d.db.Where("active = ?", true).Find(&hooks).Error; err != nil {
		return
	}
	for _, h := range hooks {
		if !hasEvent(h.Events, event) {
			continue
		}
		go d.send(h, event, payload)
	}
}

func isDiscordURL(u string) bool {
	return strings.Contains(u, "discord.com/api/webhooks") ||
		strings.Contains(u, "discordapp.com/api/webhooks")
}

func discordColor(event string) int {
	switch event {
	case "account.exhausted":
		return 16744272 // orange
	case "account.error":
		return 15548997 // red
	case "quota.warning":
		return 16776960 // yellow
	default:
		return 3447003 // blue
	}
}

func discordEmoji(event string) string {
	switch event {
	case "account.exhausted":
		return ":warning:"
	case "account.error":
		return ":x:"
	case "quota.warning":
		return ":chart_with_upwards_trend:"
	default:
		return ":bell:"
	}
}

func marshalDiscordPayload(event string, payload interface{}) ([]byte, error) {
	// Build human-readable fields from payload
	data, _ := json.Marshal(payload)
	var fields []map[string]interface{}
	var flat map[string]interface{}
	if json.Unmarshal(data, &flat) == nil {
		for k, v := range flat {
			fields = append(fields, map[string]interface{}{
				"name":   strings.ReplaceAll(k, "_", " "),
				"value":  fmt.Sprintf("`%v`", v),
				"inline": true,
			})
		}
	}

	embed := map[string]interface{}{
		"title":     fmt.Sprintf("%s  %s", discordEmoji(event), event),
		"color":     discordColor(event),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"footer":    map[string]string{"text": "OurCodex"},
	}
	if len(fields) > 0 {
		embed["fields"] = fields
	}

	return json.Marshal(map[string]interface{}{
		"embeds": []map[string]interface{}{embed},
	})
}

// buildRequest renders the event in the format the receiver expects (Discord
// embed, Slack text, or the generic signed JSON envelope).
func buildRequest(hook database.WebhookConfig, event string, payload interface{}) (*http.Request, error) {
	var body []byte
	var err error

	if isDiscordURL(hook.URL) {
		body, err = marshalDiscordPayload(event, payload)
	} else if strings.Contains(hook.URL, "hooks.slack.com") {
		detailsJSON, _ := json.Marshal(payload)
		body, err = json.Marshal(map[string]interface{}{
			"text": fmt.Sprintf("*[%s]* %s\n```%s```", event, event, detailsJSON),
		})
	} else {
		body, err = json.Marshal(map[string]interface{}{
			"event":     event,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"data":      payload,
		})
	}
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	if !isDiscordURL(hook.URL) {
		req.Header.Set("X-Event", event)
		req.Header.Set("X-Timestamp", time.Now().UTC().Format(time.RFC3339))
		if hook.Secret != "" {
			mac := hmac.New(sha256.New, []byte(hook.Secret))
			mac.Write(body)
			req.Header.Set("X-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
	}
	return req, nil
}

// deliver makes a single delivery attempt and reports why it failed, if it did.
func (d *Dispatcher) deliver(hook database.WebhookConfig, event string, payload interface{}) error {
	req, err := buildRequest(hook, event, payload)
	if err != nil {
		return err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		// The URL usually embeds a credential, so keep it out of the message.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return fmt.Errorf("receiver answered %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return nil
}

// SendTest delivers a "webhook.test" event to one webhook right away,
// regardless of its subscriptions or active flag, and returns the outcome.
func (d *Dispatcher) SendTest(hook database.WebhookConfig) error {
	return d.deliver(hook, "webhook.test", map[string]interface{}{
		"message": "Test notification — this webhook is reachable.",
	})
}

func (d *Dispatcher) send(hook database.WebhookConfig, event string, payload interface{}) {
	const maxRetries = 3
	var err error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(math.Pow(2, float64(attempt-1))) * time.Second)
		}
		if err = d.deliver(hook, event, payload); err == nil {
			return
		}
		log.Printf("webhook: %s to webhook %d failed (attempt %d/%d): %v", event, hook.ID, attempt+1, maxRetries, err)
	}
	log.Printf("webhook: gave up delivering %s to webhook %d: %v", event, hook.ID, err)
}

func hasEvent(events, event string) bool {
	for _, e := range strings.Split(events, ",") {
		if strings.TrimSpace(e) == event {
			return true
		}
	}
	return false
}
