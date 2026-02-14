package proxy

import (
	"net/http"
	"net/url"
	"strings"
)

// Config holds HTTP proxy configuration for exchange connectors.
type Config struct {
	ProxyURL  *url.URL
	Exchanges map[string]bool
}

// ParseConfig parses proxy configuration from environment variables.
func ParseConfig(proxyURL, exchanges string) *Config {
	cfg := &Config{
		Exchanges: make(map[string]bool),
	}

	if proxyURL != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			cfg.ProxyURL = u
		}
	}

	if exchanges == "" {
		exchanges = "binance"
	}
	for _, e := range strings.Split(exchanges, ",") {
		e = strings.TrimSpace(strings.ToLower(e))
		if e != "" {
			cfg.Exchanges[e] = true
		}
	}

	return cfg
}

// ShouldProxy returns true if the exchange should use the proxy.
func (c *Config) ShouldProxy(exchange string) bool {
	if c == nil || c.ProxyURL == nil {
		return false
	}
	return c.Exchanges[strings.ToLower(exchange)]
}

// ConfigureTransport returns an http.Transport with proxy configured, or nil if no proxy needed.
func (c *Config) ConfigureTransport(exchange string) *http.Transport {
	if !c.ShouldProxy(exchange) {
		return nil
	}
	return &http.Transport{
		Proxy: http.ProxyURL(c.ProxyURL),
	}
}

// NewClient creates an http.Client with optional proxy for the given exchange.
func (c *Config) NewClient(exchange string) *http.Client {
	transport := c.ConfigureTransport(exchange)
	if transport == nil {
		return &http.Client{}
	}
	return &http.Client{Transport: transport}
}
