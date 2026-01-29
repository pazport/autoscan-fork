package main

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/hlog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/cloudbox/autoscan/processor"
)

const webUIPort = 4040

func webUIAddr(host string) string {
	baseHost := host
	if strings.Contains(host, ":") {
		if parsed, _, err := net.SplitHostPort(host); err == nil {
			baseHost = parsed
		}
	}

	if strings.Contains(baseHost, ":") && !strings.HasPrefix(baseHost, "[") {
		baseHost = "[" + baseHost + "]"
	}

	return fmt.Sprintf("%s:%d", baseHost, webUIPort)
}

func getWebRouter(c config, proc *processor.Processor) chi.Router {
	r := chi.NewRouter()

	r.Use(middleware.Recoverer)
	r.Use(hlog.NewHandler(log.Logger))
	r.Use(hlog.RequestIDHandler("id", "request-id"))
	r.Use(hlog.URLHandler("url"))
	r.Use(hlog.MethodHandler("method"))

	if c.Auth.Username != "" && c.Auth.Password != "" {
		r.Use(middleware.BasicAuth("Autoscan UI", createCredentials(c)))
	}

	r.Get("/", func(rw http.ResponseWriter, r *http.Request) {
		http.Redirect(rw, r, "/status", http.StatusFound)
	})

	r.Get("/status", statusHandler(proc))
	r.Get("/config", configHandler(c))
	r.Get("/trigger", triggerHandler(c.Port))

	return r
}

func statusHandler(proc *processor.Processor) http.HandlerFunc {
	startedAt := time.Now()
	return func(rw http.ResponseWriter, r *http.Request) {
		remaining, err := proc.ScansRemaining()
		if err != nil {
			remaining = -1
		}

		data := map[string]any{
			"title":          "Autoscan Status",
			"remaining":      remaining,
			"processed":      proc.ScansProcessed(),
			"uptime":         time.Since(startedAt).Round(time.Second),
			"version":        Version,
			"gitCommit":      GitCommit,
			"buildTimestamp": Timestamp,
		}

		renderTemplate(rw, statusTemplate, data)
	}
}

func configHandler(c config) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		raw, err := yaml.Marshal(c)
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}

		data := map[string]any{
			"title":       "Autoscan Config",
			"configYaml":  redactConfig(string(raw)),
			"description": "Sensitive fields are redacted.",
		}

		renderTemplate(rw, configTemplate, data)
	}
}

func triggerHandler(port int) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		baseURL := triggerBaseURL(r, port)
		data := map[string]any{
			"title":     "Autoscan Triggers",
			"baseURL":   baseURL,
			"manualURL": fmt.Sprintf("%s/triggers/manual", baseURL),
		}

		renderTemplate(rw, triggerTemplate, data)
	}
}

func triggerBaseURL(r *http.Request, port int) string {
	host := r.Host
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}

	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	return fmt.Sprintf("%s://%s:%d", scheme, host, port)
}

func redactConfig(raw string) string {
	lines := strings.Split(raw, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "token:"):
			lines[i] = redactLine(line, "token")
		case strings.HasPrefix(trimmed, "password:"):
			lines[i] = redactLine(line, "password")
		case strings.HasPrefix(trimmed, "apiKey:"):
			lines[i] = redactLine(line, "apiKey")
		}
	}

	return strings.Join(lines, "\n")
}

func redactLine(line string, key string) string {
	indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
	return fmt.Sprintf("%s%s: \"REDACTED\"", indent, key)
}

func renderTemplate(rw http.ResponseWriter, tmpl string, data map[string]any) {
	t, err := template.New("page").Parse(tmpl)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(rw, data); err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
	}
}

const statusTemplate = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{{.title}}</title>
    <style>
      body { font-family: sans-serif; margin: 2rem; color: #222; }
      nav a { margin-right: 1rem; }
      .card { padding: 1rem; border: 1px solid #ddd; border-radius: 6px; max-width: 520px; }
      .grid { display: grid; grid-template-columns: 180px 1fr; gap: 0.5rem; }
      code { background: #f3f3f3; padding: 0.1rem 0.3rem; border-radius: 4px; }
    </style>
  </head>
  <body>
    <nav>
      <a href="/status">Status</a>
      <a href="/config">Config</a>
      <a href="/trigger">Trigger</a>
    </nav>
    <h1>{{.title}}</h1>
    <div class="card">
      <div class="grid">
        <div>Scans remaining</div><div>{{.remaining}}</div>
        <div>Scans processed</div><div>{{.processed}}</div>
        <div>Uptime</div><div>{{.uptime}}</div>
        <div>Version</div><div><code>{{.version}}</code></div>
        <div>Commit</div><div><code>{{.gitCommit}}</code></div>
        <div>Build time</div><div><code>{{.buildTimestamp}}</code></div>
      </div>
    </div>
  </body>
</html>`

const configTemplate = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{{.title}}</title>
    <style>
      body { font-family: sans-serif; margin: 2rem; color: #222; }
      nav a { margin-right: 1rem; }
      pre { background: #f7f7f7; padding: 1rem; border-radius: 6px; overflow-x: auto; }
    </style>
  </head>
  <body>
    <nav>
      <a href="/status">Status</a>
      <a href="/config">Config</a>
      <a href="/trigger">Trigger</a>
    </nav>
    <h1>{{.title}}</h1>
    <p>{{.description}}</p>
    <pre>{{.configYaml}}</pre>
  </body>
</html>`

const triggerTemplate = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{{.title}}</title>
    <style>
      body { font-family: sans-serif; margin: 2rem; color: #222; }
      nav a { margin-right: 1rem; }
      code { background: #f3f3f3; padding: 0.1rem 0.3rem; border-radius: 4px; }
      label { display: block; margin-bottom: 0.5rem; }
      input[type="text"] { width: 100%; max-width: 480px; padding: 0.5rem; }
      button { margin-top: 0.75rem; padding: 0.5rem 1rem; }
    </style>
  </head>
  <body>
    <nav>
      <a href="/status">Status</a>
      <a href="/config">Config</a>
      <a href="/trigger">Trigger</a>
    </nav>
    <h1>{{.title}}</h1>
    <p>Trigger base URL: <code>{{.baseURL}}</code></p>
    <p>Manual trigger endpoint: <code>{{.manualURL}}</code></p>
    <form method="post" action="{{.manualURL}}">
      <label>
        Directory to scan
        <input type="text" name="dir" placeholder="/path/to/media">
      </label>
      <button type="submit">Submit manual scan</button>
    </form>
    <p>You can add multiple <code>dir</code> query parameters by editing the URL manually.</p>
  </body>
</html>`
