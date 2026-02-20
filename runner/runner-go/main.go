package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

type Health struct {
	OK          bool   `json:"ok"`
	Service     string `json:"service"`
	TimeUTC     string `json:"time_utc"`
	DockerHost  string `json:"docker_host"`
	DataDir     string `json:"data_dir"`
	CacheDir    string `json:"cache_dir"`
}

func main() {
	addr := envDefault("RUNNER_LISTEN", "0.0.0.0:8080")

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		h := Health{
			OK:         true,
			Service:    "openclaw-runner-mvp",
			TimeUTC:    time.Now().UTC().Format(time.RFC3339),
			DockerHost: os.Getenv("DOCKER_HOST"),
			DataDir:    os.Getenv("RUNNER_DATA_DIR"),
			CacheDir:   os.Getenv("RUNNER_CACHE_DIR"),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h)
	})

	// Placeholder: в следующем шаге добавим /v1/jobs/run + allowlist + docker API calls
	mux.HandleFunc("/v1/jobs/run", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not implemented (next step)", http.StatusNotImplemented)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           logMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("[runner] listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func envDefault(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}

func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).String())
	})
}
