package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/SgtCoDFish/cert-manager-dashboard/pkg/github"
	"github.com/SgtCoDFish/cert-manager-dashboard/pkg/logging"
	"github.com/SgtCoDFish/cert-manager-dashboard/pkg/testgrid"

	githubsdk "github.com/google/go-github/v71/github"
	"golang.org/x/sync/errgroup"
)

const (
	maintainencePeriod = 60 * time.Minute

	ntfyTopic = "cert-manager-warnings"
)

var (

	//go:embed templates/index.html
	indexTemplateRaw string

	//go:embed static/robots.txt
	robotsTXTData []byte

	//go:embed static/favicon.ico
	faviconData []byte

	//go:embed static/css/bootstrap-v3.4.1.min.css
	bootstrapV341CSSData []byte

	lastNtfy string
)

type Config struct {
	GitHubToken string `json:"githubToken"`

	ShouldNtfy bool `json:"shouldNtfy"`
}

type DashboardHandler struct {
	indexTemplate *template.Template

	indexData     []byte
	indexDataLock sync.RWMutex

	githubClient *githubsdk.Client
	githubRepos  []*github.GitHubRepo

	testgridDashboards []*testgrid.Dashboard

	shouldNtfy bool
}

func NewDashboardHandler(config *Config) (*DashboardHandler, error) {
	if config == nil {
		return nil, fmt.Errorf("fatal: no config provided")
	}

	if config.GitHubToken == "" {
		return nil, fmt.Errorf("fatal: no GitHub token provided")
	}

	tmpl := template.New("index.html")
	tmpl = tmpl.Option("missingkey=error")

	var err error
	tmpl, err = tmpl.Parse(indexTemplateRaw)
	if err != nil {
		return nil, err
	}

	repos := []*github.GitHubRepo{
		github.NewGitHubRepo("cert-manager", "cert-manager", github.WithFriendlyName("master"), github.WithHasReleases(false)),
		github.NewGitHubRepo("cert-manager", "cert-manager", github.WithFriendlyName("release-1.18"), github.WithVersionFilter(`v1\.18\.[0-9]+`), github.WithHasGovulncheck(false)),
		github.NewGitHubRepo("cert-manager", "cert-manager", github.WithFriendlyName("release-1.17"), github.WithVersionFilter(`v1\.17\.[0-9]+`), github.WithHasGovulncheck(false)),
		github.NewGitHubRepo("cert-manager", "trust-manager"),
		github.NewGitHubRepo("cert-manager", "approver-policy"),
		github.NewGitHubRepo("cert-manager", "csi-driver"),
		github.NewGitHubRepo("cert-manager", "csi-driver-spiffe"),
		github.NewGitHubRepo("cert-manager", "istio-csr"),
		github.NewGitHubRepo("cert-manager", "cmctl"),
		github.NewGitHubRepo("cert-manager", "google-cas-issuer"),
		github.NewGitHubRepo("cert-manager", "openshift-routes"),
		github.NewGitHubRepo("cert-manager", "issuer-lib", github.WithHasReleases(false)),
		github.NewGitHubRepo("cert-manager", "csi-lib", github.WithHasReleases(false)),
	}

	testgridDashboards := []*testgrid.Dashboard{
		testgrid.New("cert-manager-periodics-master", []string{
			"ci-cert-manager-master-trivy-test-acmesolver",
			"ci-cert-manager-master-trivy-test-cainjector",
			"ci-cert-manager-master-trivy-test-controller",
			"ci-cert-manager-master-trivy-test-startupapicheck",
			"ci-cert-manager-master-trivy-test-webhook",
		}),
		testgrid.New("cert-manager-periodics-release-1.17", []string{
			"ci-cert-manager-release-1.17-trivy-test-acmesolver",
			"ci-cert-manager-release-1.17-trivy-test-cainjector",
			"ci-cert-manager-release-1.17-trivy-test-controller",
			"ci-cert-manager-release-1.17-trivy-test-startupapicheck",
			"ci-cert-manager-release-1.17-trivy-test-webhook",
		}),
		testgrid.New("cert-manager-periodics-release-1.18", []string{
			"ci-cert-manager-release-1.18-trivy-test-acmesolver",
			"ci-cert-manager-release-1.18-trivy-test-cainjector",
			"ci-cert-manager-release-1.18-trivy-test-controller",
			"ci-cert-manager-release-1.18-trivy-test-startupapicheck",
			"ci-cert-manager-release-1.18-trivy-test-webhook",
		}),
	}

	return &DashboardHandler{
		indexTemplate: tmpl,

		indexData:     []byte{},
		indexDataLock: sync.RWMutex{},

		githubClient: githubsdk.NewClient(&http.Client{Timeout: 5 * time.Second}).WithAuthToken(config.GitHubToken),
		githubRepos:  repos,

		testgridDashboards: testgridDashboards,

		shouldNtfy: config.ShouldNtfy,
	}, nil
}

func (dh *DashboardHandler) fetchData(ctx context.Context) error {
	wg, ctx := errgroup.WithContext(ctx)

	for _, repo := range dh.githubRepos {
		wg.Go(func() error { return repo.GetLatestRelease(ctx, dh.githubClient) })
		wg.Go(func() error { return repo.GetLatestRunResult(ctx, dh.githubClient) })
	}

	for _, dashboard := range dh.testgridDashboards {
		wg.Go(func() error { return dashboard.Fetch(ctx) })
	}

	return wg.Wait()
}

func (dh *DashboardHandler) maintain(ctx context.Context) {
	logger := logging.FromContext(ctx).With("source", "dataMaintainer")

	ticker := time.NewTicker(maintainencePeriod)

	logger.Info("starting data maintainer", "interval", maintainencePeriod.String())

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			logger.Info("updating dashboard data", "nextRun", time.Now().Add(maintainencePeriod))

			err := dh.Update(ctx)
			if err != nil {
				logger.Error("failed to update dashboard handler; data may be stale", "err", err)
				continue
			}

		}
	}
}

func (dh *DashboardHandler) Update(ctx context.Context) error {
	err := dh.fetchData(ctx)
	if err != nil {
		return err
	}

	dh.indexDataLock.Lock()
	defer dh.indexDataLock.Unlock()

	buf := &bytes.Buffer{}

	data := struct {
		LastUpdated  string
		Repos        []*github.GitHubRepo
		TestGridJobs []testgrid.Job
	}{
		LastUpdated:  time.Now().UTC().Format(time.DateTime),
		Repos:        dh.githubRepos,
		TestGridJobs: []testgrid.Job{},
	}

	for _, dashboard := range dh.testgridDashboards {
		data.TestGridJobs = append(data.TestGridJobs, dashboard.JobData()...)
	}

	slices.SortFunc(data.TestGridJobs, func(a, b testgrid.Job) int {
		if a.DashboardName != b.DashboardName {
			return strings.Compare(a.DashboardName, b.DashboardName)
		}

		return strings.Compare(a.Name, b.Name)
	})

	slices.SortFunc(data.Repos, func(a, b *github.GitHubRepo) int {
		if !a.HasReleases && !b.HasReleases {
			return 0
		}

		if a.HasReleases && !b.HasReleases {
			return -1
		} else if !a.HasReleases && b.HasReleases {
			return 1
		}

		return a.LastRelease.GetCreatedAt().Compare(b.LastRelease.GetCreatedAt().Time)
	})

	err = dh.indexTemplate.Execute(buf, data)
	if err != nil {
		return err
	}

	dh.indexData = buf.Bytes()

	var warnings []string

	for _, repo := range dh.githubRepos {
		_, warningMessage := repo.BootstrapWarnings()

		if warningMessage != "" {
			warnings = append(warnings, fmt.Sprintf("%s: %s", repo.RepoName, warningMessage))
		}
	}

	if len(warnings) > 0 && dh.shouldNtfy {
		logger := logging.FromContext(ctx)

		message := strings.Join(warnings, ", ")

		if message != lastNtfy {
			err = ntfy(ntfyTopic, message)
			if err != nil {
				logger.Error("got an error trying to publish to ntfy.sh", "err", err)
			}

			lastNtfy = message
		} else {
			logger.Info("skipping publishing to ntfy.sh as message is unchanged")
		}
	}

	return nil
}

func (dh *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path != "/" && path != "/index.html" && path != "/index.htm" {
		http.NotFoundHandler().ServeHTTP(w, r)
		return
	}

	dh.indexDataLock.RLock()
	defer dh.indexDataLock.RUnlock()

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dh.indexData)
}

func staticResourceHandler(w http.ResponseWriter, r *http.Request) {
	// This is very basic, and something like http.FileServerFS might work here, but we probably
	// won't need a tonne of static resources for this simple dashboard and there's little point
	// complicating things.
	switch r.URL.Path {
	case "/robots.txt":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(robotsTXTData)
		return

	case "/favicon.ico":
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write(faviconData)
		return

	case "/css/bootstrap-v3.4.1.min.css":
		w.Header().Set("content-Type", "text/css")
		_, _ = w.Write(bootstrapV341CSSData)
		return

	default:
		http.NotFoundHandler().ServeHTTP(w, r)
	}
}

// This function taken from a MIT-licensed project from github.com/SgtCoDFish
func ntfy(topic string, warnings string) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	ntfyMessage := fmt.Sprintf("got warnings on at least one project: %s", warnings)

	path, err := url.JoinPath("https://ntfy.sh/", topic)
	if err != nil {
		return err
	}

	_, err = client.Post(path, "text/plain", strings.NewReader(ntfyMessage))
	return err
}

func addSecurityHeaders(setHSTS bool, underlying http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none';")

		if setHSTS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		underlying.ServeHTTP(w, r)
	})
}

func run(ctx context.Context) error {
	ctx, done := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
	defer done()

	logger := logging.FromContext(ctx)

	config := &Config{}

	configFile := "/etc/cert-manager-dashboard/config.json"

	configData, err := os.ReadFile(configFile)
	if err != nil {
		token := os.Getenv("CERT_MANAGER_DASHBOARD_GITHUB_TOKEN")
		if token == "" {
			token = os.Getenv("GITHUB_TOKEN")
			if token == "" {
				return fmt.Errorf("no %s available and no CERT_MANAGER_DASHBOARD_GITHUB_TOKEN/GITHUB_TOKEN found in env", configFile)
			}
		}

		config.GitHubToken = token
	} else {
		err = json.Unmarshal(configData, &config)
		if err != nil {
			return fmt.Errorf("couldn't parse config file %s: %s", configFile, err)
		}
	}

	dashboardHandler, err := NewDashboardHandler(config)
	if err != nil {
		return err
	}

	err = dashboardHandler.Update(ctx)
	if err != nil {
		return fmt.Errorf("failed to complete initial sync for repo data: %s", err)
	}

	go dashboardHandler.maintain(ctx)

	mux := http.NewServeMux()

	mux.Handle("GET /", dashboardHandler)

	mux.HandleFunc("GET /favicon.ico", staticResourceHandler)
	mux.HandleFunc("GET /robots.txt", staticResourceHandler)
	mux.HandleFunc("GET /css/bootstrap-v3.4.1.min.css", staticResourceHandler)

	addr := "[::1]:49984"
	setHSTS := true

	server := &http.Server{
		Addr:        addr,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
		ErrorLog:    slog.NewLogLogger(logger.With("source", "httpServer").Handler(), slog.LevelError),
		Handler:     addSecurityHeaders(setHSTS, mux),
	}

	go func() {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			logger.Error("failed to listen with server", "err", err)
		}
	}()

	logger.Info("server listening", "addr", addr)

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	err = server.Shutdown(shutdownCtx)
	if err != nil {
		cancel()
		return err
	}

	cancel()

	<-shutdownCtx.Done()

	return nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx := logging.NewContext(context.Background(), logger)

	err := run(ctx)
	if err != nil {
		logger.Error("failed to execute", "err", err)
		os.Exit(1)
	}
}
