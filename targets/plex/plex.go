package plex

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/cloudbox/autoscan"
)

type Config struct {
	URL              string             `yaml:"url"`
	Token            string             `yaml:"token"`
	Rewrite          []autoscan.Rewrite `yaml:"rewrite"`
	Verbosity        string             `yaml:"verbosity"`
	Timeout          string             `yaml:"timeout"`
	Product          string             `yaml:"product"`
	ClientIdentifier string             `yaml:"client-identifier"`
}

type target struct {
	url       string
	token     string
	libraries []library

	log     zerolog.Logger
	rewrite autoscan.Rewriter
	api     *apiClient
}

func New(c Config) (autoscan.Target, error) {
	l := autoscan.GetLogger(c.Verbosity).With().
		Str("target", "plex").
		Str("url", c.URL).Logger()

	rewriter, err := autoscan.NewRewriter(c.Rewrite)
	if err != nil {
		return nil, err
	}

	timeout, err := parseTimeout(c.Timeout)
	if err != nil {
		return nil, err
	}

	product := c.Product
	if strings.TrimSpace(product) == "" {
		product = "autoscan"
	}

	clientIdentifier := c.ClientIdentifier
	if strings.TrimSpace(clientIdentifier) == "" {
		clientIdentifier = defaultClientIdentifier(c.URL)
	}

	api := newAPIClient(c.URL, c.Token, l, timeout, product, clientIdentifier)

	version, err := api.Version()
	if err != nil {
		return nil, err
	}

	l.Debug().Msgf("Plex version: %s", version)
	if !isSupportedVersion(version) {
		return nil, fmt.Errorf("plex running unsupported version %s: %w", version, autoscan.ErrFatal)
	}

	libraries, err := api.Libraries()
	if err != nil {
		return nil, err
	}

	l.Debug().
		Interface("libraries", libraries).
		Msg("Retrieved libraries")

	return &target{
		url:       c.URL,
		token:     c.Token,
		libraries: libraries,

		log:     l,
		rewrite: rewriter,
		api:     api,
	}, nil
}

func parseTimeout(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return 0, nil
	}

	timeout, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid plex timeout %q: %w", raw, err)
	}

	if timeout <= 0 {
		return 0, fmt.Errorf("invalid plex timeout %q: must be greater than zero", raw)
	}

	return timeout, nil
}

func defaultClientIdentifier(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return "autoscan"
	}

	host := strings.TrimPrefix(parsed.Host, "www.")
	if host == "" {
		return "autoscan"
	}

	return fmt.Sprintf("autoscan-%s", host)
}

func (t target) Available() error {
	_, err := t.api.Version()
	return err
}

func (t target) Scan(scan autoscan.Scan) error {
	// determine library for this scan
	scanFolder := t.rewrite(scan.Folder)

	libs, err := t.getScanLibrary(scanFolder)
	if err != nil {
		t.log.Warn().
			Err(err).
			Msg("No target libraries found")

		return nil
	}

	// send scan request
	for _, lib := range libs {
		l := t.log.With().
			Str("path", scanFolder).
			Str("library", lib.Name).
			Logger()

		l.Trace().Msg("Sending scan request")

		if err := t.api.Scan(scanFolder, lib.ID); err != nil {
			return err
		}

		l.Info().Msg("Scan moved to target")
	}

	return nil
}

func (t target) getScanLibrary(folder string) ([]library, error) {
	libraries := make([]library, 0)

	for _, l := range t.libraries {
		if strings.HasPrefix(folder, l.Path) {
			libraries = append(libraries, l)
		}
	}

	if len(libraries) == 0 {
		return nil, fmt.Errorf("%v: failed determining libraries", folder)
	}

	return libraries, nil
}

func isSupportedVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false
	}

	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])

	if major >= 2 || (major == 1 && minor >= 20) {
		return true
	}

	return false
}
