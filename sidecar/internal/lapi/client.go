// Package lapi provides a client for the CrowdSec LAPI.
package lapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// Decision represents a CrowdSec ban decision.
type Decision struct {
	ID        int    `json:"id"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Simulated bool   `json:"simulated"`
	UUID      string `json:"uuid,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`

	// Parsed fields for scoring
	ParsedDuration time.Duration `json:"-"`
	ParsedCreated  time.Time     `json:"-"`

	// Calculated score
	Score int `json:"-"`
}

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
	logger     *slog.Logger
}

func NewClient(baseURL, apiKey string, timeout time.Duration, optLogger ...*slog.Logger) *Client {
	if timeout <= 0 {
		timeout = 120 * time.Second // default for large decision sets
	}
	var logger *slog.Logger
	if len(optLogger) > 0 && optLogger[0] != nil {
		logger = optLogger[0]
	} else {
		logger = slog.Default()
	}
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger: logger,
	}
}

func (c *Client) GetDecisions(ctx context.Context, queryParams url.Values) ([]Decision, error) {
	reqURL := c.baseURL + "/v1/decisions"
	if len(queryParams) > 0 {
		reqURL += "?" + queryParams.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("LAPI returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	// LAPI returns null for empty decisions
	if string(body) == "null" {
		return []Decision{}, nil
	}

	var decisions []Decision
	if err := json.Unmarshal(body, &decisions); err != nil {
		return nil, fmt.Errorf("parsing decisions: %w", err)
	}

	// Parse durations and created_at for all decisions
	for i := range decisions {
		if decisions[i].Duration != "" {
			var err error
			decisions[i].ParsedDuration, err = time.ParseDuration(decisions[i].Duration)
			if err != nil {
				c.logger.Debug("failed to parse decision duration",
					"id", decisions[i].ID,
					"duration", decisions[i].Duration,
					"error", err,
				)
			}
		}
		if decisions[i].CreatedAt != "" {
			decisions[i].ParsedCreated, _ = parseCreatedAt(decisions[i].CreatedAt)
		}
	}

	return decisions, nil
}

// GetDecisionsStream fetches decisions from the streaming endpoint.
func (c *Client) GetDecisionsStream(ctx context.Context, startup bool) (*DecisionStream, error) {
	reqURL := c.baseURL + "/v1/decisions/stream"
	if startup {
		reqURL += "?startup=true"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("LAPI returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	var stream DecisionStream
	if err := json.Unmarshal(body, &stream); err != nil {
		return nil, fmt.Errorf("parsing decision stream: %w", err)
	}

	// Parse durations and created_at for new decisions
	for i := range stream.New {
		if stream.New[i].Duration != "" {
			var err error
			stream.New[i].ParsedDuration, err = time.ParseDuration(stream.New[i].Duration)
			if err != nil {
				c.logger.Debug("failed to parse decision duration",
					"id", stream.New[i].ID,
					"duration", stream.New[i].Duration,
					"error", err,
				)
			}
		}
		if stream.New[i].CreatedAt != "" {
			stream.New[i].ParsedCreated, _ = parseCreatedAt(stream.New[i].CreatedAt)
		}
	}

	return &stream, nil
}

// DecisionStream represents the response from the streaming endpoint.
type DecisionStream struct {
	New     []Decision `json:"new"`
	Deleted []Decision `json:"deleted"`
}

// Alert represents a CrowdSec alert (minimal fields for false-negative detection).
type Alert struct {
	ID       int         `json:"id"`
	Scenario string      `json:"scenario"`
	Source   AlertSource `json:"source"`
}

// AlertSource represents the source of an alert.
type AlertSource struct {
	IP    string `json:"ip"`
	Scope string `json:"scope"`
	Value string `json:"value"`
}

// GetAlerts fetches alerts from the LAPI with optional query parameters.
func (c *Client) GetAlerts(ctx context.Context, params url.Values) ([]Alert, error) {
	reqURL := c.baseURL + "/v1/alerts"
	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("LAPI returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if string(body) == "null" {
		return []Alert{}, nil
	}

	var alerts []Alert
	if err := json.Unmarshal(body, &alerts); err != nil {
		return nil, fmt.Errorf("parsing alerts: %w", err)
	}

	return alerts, nil
}

// parseCreatedAt parses the created_at timestamp from LAPI responses.
func parseCreatedAt(s string) (time.Time, error) {
	// CrowdSec LAPI uses RFC3339-like format
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02 15:04:05 +0000 UTC",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse created_at: %s", s)
}

// Health checks if the LAPI is healthy.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("LAPI health check returned status %d", resp.StatusCode)
	}

	return nil
}
