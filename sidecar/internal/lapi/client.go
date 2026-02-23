// Package lapi provides a client for the CrowdSec LAPI.
package lapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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

// Client is an HTTP client for the CrowdSec LAPI.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new LAPI client with the specified timeout.
func NewClient(baseURL, apiKey string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 120 * time.Second // default for large decision sets
	}
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// GetDecisions fetches all active decisions from the LAPI.
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
			decisions[i].ParsedDuration, _ = parseDuration(decisions[i].Duration)
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
			stream.New[i].ParsedDuration, _ = parseDuration(stream.New[i].Duration)
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

// parseDuration parses CrowdSec duration format (e.g., "4h", "24h", "168h").
func parseDuration(s string) (time.Duration, error) {
	// CrowdSec uses Go-style durations, but may also use "s", "m", "h" suffixes
	return time.ParseDuration(s)
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
