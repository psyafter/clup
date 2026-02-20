package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultListenAddr = ":8080"

	envDataDir  = "RUNNER_DATA_DIR"
	envCacheDir = "RUNNER_CACHE_DIR"

	statusQueued    = "queued"
	statusRunning   = "running"
	statusSucceeded = "succeeded"
	statusFailed    = "failed"
)

type JobRequest struct {
	Type   string                 `json:"type"`
	Params map[string]interface{} `json:"params,omitempty"`
}

type JobStatus struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Message    string    `json:"message,omitempty"`
}

type Server struct {
	dataDir  string
	cacheDir string

	allow map[string]struct{}

	mu    sync.Mutex
	queue chan string

	http *http.Server
}

func main() {
	dataDir := getenvDefault(envDataDir, "/runner-data")
	cacheDir := getenvDefault(envCacheDir, "/runner-cache")

	s := &Server{
		dataDir:  dataDir,
		cacheDir: cacheDir,
		allow: map[string]struct{}{
			"android_audit":     {},
			"android_build":     {},
			"android_unit_test": {},
			"android_lint":      {},
			// later: android_connected_test
		},
		queue: make(chan string, 100),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/v1/jobs", s.handleJobsRoot)    // POST enqueue
	mux.HandleFunc("/v1/jobs/", s.handleJobsWithID) // GET status/logs/artifacts
	mux.HandleFunc("/v1/jobs/run", s.handleNotImpl) // keep legacy stub
	mux.HandleFunc("/", s.handleNotFound)

	s.http = &http.Server{
		Addr:              defaultListenAddr,
		Handler:           withRequestLog(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Worker (single) for MVP
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.workerLoop(ctx)

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("runner starting: addr=%s data_dir=%s cache_dir=%s", s.http.Addr, s.dataDir, s.cacheDir)

	go func() {
		<-stop
		log.Printf("runner shutting down...")
		cancel()

		ctxTO, cancelTO := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelTO()
		_ = s.http.Shutdown(ctxTO)
	}()

	if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("listen error: %v", err)
	}

	log.Printf("runner stopped")
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	type resp struct {
		OK       bool   `json:"ok"`
		Service  string `json:"service"`
		TimeUTC  string `json:"time_utc"`
		DataDir  string `json:"data_dir"`
		CacheDir string `json:"cache_dir"`
	}
	writeJSON(w, http.StatusOK, resp{
		OK:       true,
		Service:  "openclaw-runner-mvp",
		TimeUTC:  time.Now().UTC().Format(time.RFC3339),
		DataDir:  s.dataDir,
		CacheDir: s.cacheDir,
	})
}

func (s *Server) handleJobsRoot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleEnqueue(w, r)
	default:
		writeText(w, http.StatusMethodNotAllowed, "method not allowed\n")
	}
}

func (s *Server) handleJobsWithID(w http.ResponseWriter, r *http.Request) {
	// /v1/jobs/{id}
	// /v1/jobs/{id}/logs
	// /v1/jobs/{id}/artifacts
	path := strings.TrimPrefix(r.URL.Path, "/v1/jobs/")
	path = strings.Trim(path, "/")
	if path == "" {
		writeText(w, http.StatusNotFound, "not found\n")
		return
	}

	parts := strings.Split(path, "/")
	jobID := parts[0]
	if jobID == "" {
		writeText(w, http.StatusNotFound, "not found\n")
		return
	}

	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			writeText(w, http.StatusMethodNotAllowed, "method not allowed\n")
			return
		}
		s.handleGetStatus(w, r, jobID)
		return
	}

	switch parts[1] {
	case "logs":
		if r.Method != http.MethodGet {
			writeText(w, http.StatusMethodNotAllowed, "method not allowed\n")
			return
		}
		s.handleGetLogs(w, r, jobID)
		return
	case "artifacts":
		if r.Method != http.MethodGet {
			writeText(w, http.StatusMethodNotAllowed, "method not allowed\n")
			return
		}
		s.handleListArtifacts(w, r, jobID)
		return
	default:
		writeText(w, http.StatusNotFound, "not found\n")
		return
	}
}

func (s *Server) handleEnqueue(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB max
	if err != nil {
		writeText(w, http.StatusBadRequest, "bad request\n")
		return
	}
	defer r.Body.Close()

	var req JobRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeText(w, http.StatusBadRequest, "invalid json\n")
		return
	}
	req.Type = strings.TrimSpace(req.Type)
	if req.Type == "" {
		writeText(w, http.StatusBadRequest, "missing type\n")
		return
	}
	if _, ok := s.allow[req.Type]; !ok {
		writeText(w, http.StatusBadRequest, "job type not allowlisted\n")
		return
	}
	if req.Params == nil {
		req.Params = map[string]interface{}{}
	}

	jobID := newID()
	jobDir := s.jobDir(jobID)
	if err := os.MkdirAll(jobDir, 0o750); err != nil {
		writeText(w, http.StatusInternalServerError, "cannot create job dir\n")
		return
	}
	// Keep directories predictable
	_ = os.MkdirAll(filepath.Join(jobDir, "artifacts"), 0o750)

	// Persist request + initial status
	if err := writeFileJSON(filepath.Join(jobDir, "request.json"), req); err != nil {
		writeText(w, http.StatusInternalServerError, "cannot write request\n")
		return
	}

	st := JobStatus{
		ID:        jobID,
		Type:      req.Type,
		State:     statusQueued,
		CreatedAt: time.Now().UTC(),
		Message:   "queued",
	}
	if err := writeFileJSON(filepath.Join(jobDir, "status.json"), st); err != nil {
		writeText(w, http.StatusInternalServerError, "cannot write status\n")
		return
	}

	// Enqueue in memory
	s.enqueue(jobID)

	type resp struct {
		ID string `json:"id"`
	}
	writeJSON(w, http.StatusAccepted, resp{ID: jobID})
}

func (s *Server) handleGetStatus(w http.ResponseWriter, r *http.Request, jobID string) {
	st, err := s.readStatus(jobID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeText(w, http.StatusNotFound, "not found\n")
			return
		}
		writeText(w, http.StatusInternalServerError, "error\n")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleGetLogs(w http.ResponseWriter, r *http.Request, jobID string) {
	logPath := filepath.Join(s.jobDir(jobID), "logs.txt")
	b, err := os.ReadFile(logPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeText(w, http.StatusNotFound, "not found\n")
			return
		}
		writeText(w, http.StatusInternalServerError, "error\n")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func (s *Server) handleListArtifacts(w http.ResponseWriter, r *http.Request, jobID string) {
	dir := filepath.Join(s.jobDir(jobID), "artifacts")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeText(w, http.StatusNotFound, "not found\n")
			return
		}
		writeText(w, http.StatusInternalServerError, "error\n")
		return
	}

	type item struct {
		Name string `json:"name"`
		Size int64  `json:"size_bytes"`
	}
	out := make([]item, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, item{Name: e.Name(), Size: info.Size()})
	}

	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleNotImpl(w http.ResponseWriter, r *http.Request) {
	writeText(w, http.StatusNotImplemented, "not implemented (next step)\n")
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeText(w, http.StatusNotFound, "404 page not found\n")
}

func (s *Server) enqueue(jobID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case s.queue <- jobID:
	default:
		// queue full -> mark failed
		_ = s.appendLog(jobID, "queue full; failing job\n")
		_ = s.updateStatus(jobID, func(st *JobStatus) {
			st.State = statusFailed
			st.FinishedAt = time.Now().UTC()
			st.Message = "queue full"
		})
	}
}

func (s *Server) workerLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case jobID := <-s.queue:
			s.runJob(ctx, jobID)
		}
	}
}

func (s *Server) runJob(ctx context.Context, jobID string) {
	reqPath := filepath.Join(s.jobDir(jobID), "request.json")
	b, err := os.ReadFile(reqPath)
	if err != nil {
		return
	}
	var req JobRequest
	if err := json.Unmarshal(b, &req); err != nil {
		return
	}

	_ = s.updateStatus(jobID, func(st *JobStatus) {
		st.State = statusRunning
		st.StartedAt = time.Now().UTC()
		st.Message = "running"
	})
	_ = s.appendLog(jobID, fmt.Sprintf("job started: id=%s type=%s\n", jobID, req.Type))

	// SAFETY: no docker execution yet. Stub runner.
	// Next milestone will implement android_audit as read-only scanner.
	select {
	case <-ctx.Done():
		_ = s.appendLog(jobID, "shutdown requested; failing job\n")
		_ = s.updateStatus(jobID, func(st *JobStatus) {
			st.State = statusFailed
			st.FinishedAt = time.Now().UTC()
			st.Message = "shutdown"
		})
		return
	case <-time.After(500 * time.Millisecond):
	}

	_ = s.appendLog(jobID, "job handler stub: succeeded (no-op)\n")
	_ = s.updateStatus(jobID, func(st *JobStatus) {
		st.State = statusSucceeded
		st.FinishedAt = time.Now().UTC()
		st.Message = "succeeded (stub)"
	})
}

func (s *Server) jobDir(jobID string) string {
	// Live policy: /srv/data/openclaw/runner/jobs/<job_id>/...
	return filepath.Join(s.dataDir, "jobs", jobID)
}

func (s *Server) readStatus(jobID string) (JobStatus, error) {
	var st JobStatus
	b, err := os.ReadFile(filepath.Join(s.jobDir(jobID), "status.json"))
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, err
	}
	return st, nil
}

func (s *Server) updateStatus(jobID string, fn func(*JobStatus)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, err := s.readStatus(jobID)
	if err != nil {
		return err
	}
	fn(&st)
	return writeFileJSON(filepath.Join(s.jobDir(jobID), "status.json"), st)
}

func (s *Server) appendLog(jobID, line string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	logPath := filepath.Join(s.jobDir(jobID), "logs.txt")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, _ = f.WriteString(line)
	return nil
}

func writeFileJSON(path string, v interface{}) error {
	tmp := path + ".tmp"
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	b, err := json.Marshal(v)
	if err != nil {
		writeText(w, http.StatusInternalServerError, "error\n")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n"))
}

func writeText(w http.ResponseWriter, code int, s string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(s))
}

func getenvDefault(k, def string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	return v
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		_ = start
	})
}
