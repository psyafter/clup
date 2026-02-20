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
	"regexp"
	"sort"
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
			// New canonical job for Gradle safety
			"gradle_safety": {},
			// Backwards compatible alias
			"android_audit": {},

			// future
			"android_build":     {},
			"android_unit_test": {},
			"android_lint":      {},
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.workerLoop(ctx)

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
	_ = os.MkdirAll(filepath.Join(jobDir, "artifacts"), 0o750)

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
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })

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

	select {
	case <-ctx.Done():
		_ = s.appendLog(jobID, "shutdown requested; failing job\n")
		_ = s.updateStatus(jobID, func(st *JobStatus) {
			st.State = statusFailed
			st.FinishedAt = time.Now().UTC()
			st.Message = "shutdown"
		})
		return
	default:
	}

	jobType := req.Type
	if jobType == "android_audit" {
		jobType = "gradle_safety"
	}

	var runErr error
	switch jobType {
	case "gradle_safety":
		runErr = s.runGradleSafety(jobID, req.Params)
	default:
		// keep safe stub for other jobs
		_ = s.appendLog(jobID, "job handler stub: succeeded (no-op)\n")
		runErr = nil
	}

	if runErr != nil {
		_ = s.appendLog(jobID, fmt.Sprintf("job failed: %v\n", runErr))
		_ = s.updateStatus(jobID, func(st *JobStatus) {
			st.State = statusFailed
			st.FinishedAt = time.Now().UTC()
			st.Message = "failed"
		})
		return
	}

	_ = s.updateStatus(jobID, func(st *JobStatus) {
		st.State = statusSucceeded
		st.FinishedAt = time.Now().UTC()
		st.Message = "succeeded"
	})
}

func (s *Server) jobDir(jobID string) string {
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
		next.ServeHTTP(w, r)
	})
}

/* =========================
   Gradle Safety (MVP)
   ========================= */

type Verdict string

const (
	VerdictAllow              Verdict = "ALLOW"
	VerdictAllowWithCondition Verdict = "ALLOW_WITH_CONDITIONS"
	VerdictBlock              Verdict = "BLOCK"
)

type Finding struct {
	Severity string `json:"severity"` // HARD_BLOCK | WARN | INFO
	Rule     string `json:"rule"`
	File     string `json:"file"`
	Line     int    `json:"line,omitempty"`
	Match    string `json:"match,omitempty"`
	Message  string `json:"message"`
}

type GradleSafetyVerdict struct {
	Verdict   Verdict   `json:"verdict"`
	Summary   string    `json:"summary"`
	Workspace string    `json:"workspace"`
	Project   string    `json:"project_path"`
	Findings  []Finding `json:"findings"`
}

func (s *Server) runGradleSafety(jobID string, params map[string]interface{}) error {
	workspace := strings.TrimSpace(getString(params, "workspace"))
	projectPath := strings.TrimSpace(getString(params, "project_path"))
	if workspace == "" || projectPath == "" {
		return fmt.Errorf("missing params: workspace/project_path")
	}

	allowedWS := map[string]struct{}{
		"gw-admin":  {},
		"gw-psy":    {},
		"gw-wife":   {},
		"gw-kids":   {},
		"gw-family": {},
	}
	if _, ok := allowedWS[workspace]; !ok {
		return fmt.Errorf("invalid workspace")
	}

	// project_path must be relative and safe
	if filepath.IsAbs(projectPath) {
		return fmt.Errorf("project_path must be relative")
	}
	ppClean := filepath.Clean(projectPath)
	if ppClean == "." || strings.HasPrefix(ppClean, "..") || strings.Contains(ppClean, string(os.PathSeparator)+".."+string(os.PathSeparator)) {
		return fmt.Errorf("project_path traversal not allowed")
	}
	if strings.Contains(ppClean, "\x00") {
		return fmt.Errorf("project_path invalid")
	}

	root := filepath.Clean(filepath.Join("/workspaces", workspace))
	abs := filepath.Clean(filepath.Join(root, ppClean))
	// ensure inside root
	if abs != root && !strings.HasPrefix(abs, root+string(os.PathSeparator)) {
		return fmt.Errorf("project_path escapes workspace root")
	}

	_ = s.appendLog(jobID, fmt.Sprintf("gradle_safety: workspace=%s project=%s\n", workspace, ppClean))
	_ = s.appendLog(jobID, fmt.Sprintf("gradle_safety: resolved_path=%s\n", abs))

	// Collect target files
	targets := []string{
		"settings.gradle",
		"settings.gradle.kts",
		"build.gradle",
		"build.gradle.kts",
		"gradle.properties",
		filepath.Join("gradle", "wrapper", "gradle-wrapper.properties"),
	}
	files := make([]string, 0, len(targets))
	for _, rel := range targets {
		p := filepath.Join(abs, rel)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			files = append(files, p)
		}
	}

	// Also scan buildSrc presence (hard block if exists)
	if fi, err := os.Stat(filepath.Join(abs, "buildSrc")); err == nil && fi.IsDir() {
		// hard block
		files = append(files, filepath.Join(abs, "buildSrc")) // marker
	}

	findings := make([]Finding, 0, 32)

	// Rules (MVP subset aligning with design)
	reHard := []rule{
		{name: "REPO_JITPACK", severity: "HARD_BLOCK", re: regexp.MustCompile(`(?i)jitpack\.io`), msg: "JitPack repo detected"},
		{name: "REPO_MAVENLOCAL", severity: "HARD_BLOCK", re: regexp.MustCompile(`(?i)\bmavenLocal\s*\(`), msg: "mavenLocal() detected"},
		{name: "EXEC_PROCESS", severity: "HARD_BLOCK", re: regexp.MustCompile(`(?i)(Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(|\bproject\.exec\b|\bExec\s*\{|\bcommandLine\s+)`), msg: "Command execution pattern detected"},
		{name: "NETWORK_SHELL", severity: "HARD_BLOCK", re: regexp.MustCompile(`(?i)\b(curl|wget)\b`), msg: "curl/wget detected in build scripts"},
	}
	reWarn := []rule{
		{name: "DYNAMIC_VERSION", severity: "WARN", re: regexp.MustCompile(`(?i)(:\s*"\+|latest\.release|latest\.integration)`), msg: "Dynamic dependency version detected"},
		{name: "URL_HTTP", severity: "WARN", re: regexp.MustCompile(`(?i)\bhttp://`), msg: "Insecure http:// URL detected"},
		{name: "NETWORK_APIS", severity: "WARN", re: regexp.MustCompile(`(?i)(HttpURLConnection|new\s+URL\s*\(|OkHttpClient)`), msg: "Network API usage detected in build logic"},
	}

	// Wrapper distributionUrl allowlist (hard block if not allowed)
	allowedWrapperHosts := []string{"services.gradle.org", "downloads.gradle.org"}

	for _, f := range files {
		// buildSrc marker
		if strings.HasSuffix(f, string(os.PathSeparator)+"buildSrc") {
			findings = append(findings, Finding{
				Severity: "HARD_BLOCK",
				Rule:     "BUILDSRC_PRESENT",
				File:     relFrom(abs, f),
				Message:  "buildSrc directory present (arbitrary code execution surface)",
			})
			continue
		}

		content, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		lines := splitLines(string(content))

		// Special: gradle-wrapper.properties checks
		if strings.HasSuffix(f, filepath.Join("gradle", "wrapper", "gradle-wrapper.properties")) {
			for i, ln := range lines {
				l := strings.TrimSpace(ln)
				if strings.HasPrefix(l, "distributionUrl=") {
					u := strings.TrimSpace(strings.TrimPrefix(l, "distributionUrl="))
					// hard block non-https
					if strings.HasPrefix(u, "http://") {
						findings = append(findings, Finding{
							Severity: "HARD_BLOCK",
							Rule:     "WRAPPER_HTTP",
							File:     relFrom(abs, f),
							Line:     i + 1,
							Match:    u,
							Message:  "Gradle wrapper distributionUrl must be https",
						})
					}
					// hard block host not allowlisted
					host := extractHost(u)
					if host != "" && !containsString(allowedWrapperHosts, host) {
						findings = append(findings, Finding{
							Severity: "HARD_BLOCK",
							Rule:     "WRAPPER_HOST_NOT_ALLOWED",
							File:     relFrom(abs, f),
							Line:     i + 1,
							Match:    host,
							Message:  "Gradle wrapper host is not allowlisted",
						})
					}
				}
				// wrapper.jar tampering surface (very rough MVP)
				if strings.Contains(strings.ToLower(l), "wrapper.jar") {
					findings = append(findings, Finding{
						Severity: "HARD_BLOCK",
						Rule:     "WRAPPER_JAR_MENTION",
						File:     relFrom(abs, f),
						Line:     i + 1,
						Match:    l,
						Message:  "Reference to wrapper.jar detected (potential tampering)",
					})
				}
			}
		}

		// Regex scan per line
		findings = append(findings, scanFileLines(relFrom(abs, f), lines, reHard)...)
		findings = append(findings, scanFileLines(relFrom(abs, f), lines, reWarn)...)
	}

	verdict := VerdictAllow
	summary := "No critical findings"

	hasHard := false
	hasWarn := false
	for _, fd := range findings {
		if fd.Severity == "HARD_BLOCK" {
			hasHard = true
		}
		if fd.Severity == "WARN" {
			hasWarn = true
		}
	}
	if hasHard {
		verdict = VerdictBlock
		summary = "Hard block findings detected"
	} else if hasWarn {
		verdict = VerdictAllowWithCondition
		summary = "Warnings detected; requires review/conditions"
	}

	out := GradleSafetyVerdict{
		Verdict:   verdict,
		Summary:   summary,
		Workspace: workspace,
		Project:   ppClean,
		Findings:  findings,
	}

	artDir := filepath.Join(s.jobDir(jobID), "artifacts")
	_ = os.MkdirAll(artDir, 0o750)

	verdictPath := filepath.Join(artDir, "verdict.json")
	if err := writeFileJSON(verdictPath, out); err != nil {
		return err
	}

	reportPath := filepath.Join(artDir, "report.md")
	if err := os.WriteFile(reportPath, []byte(renderReport(out)), 0o640); err != nil {
		return err
	}

	_ = s.appendLog(jobID, fmt.Sprintf("gradle_safety verdict=%s findings=%d\n", out.Verdict, len(out.Findings)))
	return nil
}

type rule struct {
	name     string
	severity string
	re       *regexp.Regexp
	msg      string
}

func scanFileLines(rel string, lines []string, rules []rule) []Finding {
	out := []Finding{}
	for i, ln := range lines {
		for _, r := range rules {
			if r.re.MatchString(ln) {
				m := r.re.FindString(ln)
				out = append(out, Finding{
					Severity: r.severity,
					Rule:     r.name,
					File:     rel,
					Line:     i + 1,
					Match:    strings.TrimSpace(m),
					Message:  r.msg,
				})
			}
		}
	}
	return out
}

func renderReport(v GradleSafetyVerdict) string {
	var b strings.Builder
	b.WriteString("# Gradle Safety Report\n\n")
	b.WriteString(fmt.Sprintf("- Verdict: **%s**\n", v.Verdict))
	b.WriteString(fmt.Sprintf("- Summary: %s\n", v.Summary))
	b.WriteString(fmt.Sprintf("- Workspace: `%s`\n", v.Workspace))
	b.WriteString(fmt.Sprintf("- Project: `%s`\n\n", v.Project))

	if len(v.Findings) == 0 {
		b.WriteString("No findings.\n")
		return b.String()
	}

	b.WriteString("## Findings\n\n")
	// stable ordering
	fds := append([]Finding{}, v.Findings...)
	sort.Slice(fds, func(i, j int) bool {
		if fds[i].Severity != fds[j].Severity {
			return fds[i].Severity < fds[j].Severity
		}
		if fds[i].File != fds[j].File {
			return fds[i].File < fds[j].File
		}
		return fds[i].Line < fds[j].Line
	})

	for _, f := range fds {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		b.WriteString(fmt.Sprintf("- [%s] **%s** at `%s` — %s", f.Severity, f.Rule, loc, f.Message))
		if f.Match != "" {
			b.WriteString(fmt.Sprintf(" (match: `%s`)", sanitizeInline(f.Match)))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func sanitizeInline(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.TrimSpace(s)
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.Split(s, "\n")
}

func extractHost(u string) string {
	// gradle-wrapper.properties often escapes ":" as "\:" => "https\://..."
	u = strings.TrimSpace(u)
	u = strings.ReplaceAll(u, `\:`, `:`)
	u = strings.ReplaceAll(u, `\\`, `\`)     // defensive (rare)
	u = strings.ReplaceAll(u, `\//`, `//`)   // defensive
	u = strings.ReplaceAll(u, `\://`, `://`) // key fix

	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if u == "" {
		return ""
	}
	parts := strings.SplitN(u, "/", 2)
	host := parts[0]
	host = strings.SplitN(host, "?", 2)[0]
	host = strings.SplitN(host, "#", 2)[0]
	return strings.TrimSpace(host)
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func relFrom(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return filepath.ToSlash(rel)
}

func getString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}
