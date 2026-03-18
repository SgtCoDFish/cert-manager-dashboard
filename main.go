package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"flag"
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

type ActionRow struct {
	Repo           *github.Repo
	Action         *github.Action
	BootstrapClass string
	WarningMessage string
}

type DashboardHandler struct {
	indexTemplate *template.Template

	indexData     []byte
	indexDataLock sync.RWMutex

	githubClient *githubsdk.Client
	githubRepos  []*github.Repo

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

	supportedCertManagerMinorVersions := []string{"19", "20"}

	repos := []*github.Repo{
		github.NewRepo("cert-manager", "cert-manager",
			github.WithFriendlyName("master"),
			github.WithHasReleases(false),
			github.WithGovulncheckBranch("master"),
			github.WithActions(
				github.NewAction("govulncheck", "govulncheck.yaml"),
			),
		),
		github.NewRepo("cert-manager", "trust-manager",
			github.WithActions(
				github.NewAction("govulncheck", "govulncheck.yaml"),
				github.NewAction("trust-package-security-scan", "trust-package-security-scan.yaml"),
			),
		),
		github.NewRepo("cert-manager", "approver-policy",
			github.WithActions(
				github.NewAction("govulncheck", "govulncheck.yaml"),
			),
		),
		github.NewRepo("cert-manager", "csi-driver",
			github.WithActions(
				github.NewAction("govulncheck", "govulncheck.yaml"),
			),
		),
		github.NewRepo("cert-manager", "csi-driver-spiffe",
			github.WithActions(
				github.NewAction("govulncheck", "govulncheck.yaml"),
			),
		),
		github.NewRepo("cert-manager", "istio-csr",
			github.WithActions(
				github.NewAction("govulncheck", "govulncheck.yaml"),
			),
		),
		github.NewRepo("cert-manager", "cmctl",
			github.WithActions(
				github.NewAction("govulncheck", "govulncheck.yaml"),
			),
		),
		github.NewRepo("cert-manager", "google-cas-issuer",
			github.WithActions(
				github.NewAction("govulncheck", "govulncheck.yaml"),
			),
		),
		github.NewRepo("cert-manager", "openshift-routes",
			github.WithActions(
				github.NewAction("govulncheck", "govulncheck.yaml"),
			),
		),
		github.NewRepo("cert-manager", "issuer-lib",
			github.WithHasReleases(false),
			github.WithActions(
				github.NewAction("govulncheck", "govulncheck.yaml"),
			),
		),
		github.NewRepo("cert-manager", "csi-lib",
			github.WithHasReleases(false),
			github.WithActions(
				github.NewAction("govulncheck", "govulncheck.yaml"),
			),
		),
	}

	testgridDashboards := []*testgrid.Dashboard{
		testgrid.New("cert-manager-periodics-master", []string{
			"ci-cert-manager-master-trivy-test-acmesolver",
			"ci-cert-manager-master-trivy-test-cainjector",
			"ci-cert-manager-master-trivy-test-controller",
			"ci-cert-manager-master-trivy-test-startupapicheck",
			"ci-cert-manager-master-trivy-test-webhook",
		}),
	}

	for _, minor := range supportedCertManagerMinorVersions {
		branch := fmt.Sprintf("release-1.%s", minor)
		versionFilter := fmt.Sprintf(`v1\.%s\.[0-9]+`, minor)

		repos = append(
			repos,
			github.NewRepo(
				"cert-manager", "cert-manager",
				github.WithFriendlyName(branch),
				github.WithVersionFilter(versionFilter),
			),
		)

		testgridDashboards = append(
			testgridDashboards,
			testgrid.New(
				fmt.Sprintf("cert-manager-periodics-release-1.%s", minor),
				[]string{
					fmt.Sprintf("ci-cert-manager-release-1.%s-trivy-test-acmesolver", minor),
					fmt.Sprintf("ci-cert-manager-release-1.%s-trivy-test-cainjector", minor),
					fmt.Sprintf("ci-cert-manager-release-1.%s-trivy-test-controller", minor),
					fmt.Sprintf("ci-cert-manager-release-1.%s-trivy-test-startupapicheck", minor),
					fmt.Sprintf("ci-cert-manager-release-1.%s-trivy-test-webhook", minor),
				},
			),
		)
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
		Repos        []*github.Repo
		ActionRows   []ActionRow
		TestGridJobs []testgrid.Job
	}{
		LastUpdated:  time.Now().UTC().Format(time.DateTime),
		Repos:        dh.githubRepos,
		ActionRows:   []ActionRow{},
		TestGridJobs: []testgrid.Job{},
	}

	// Create ActionRows from repos and their actions
	for _, repo := range dh.githubRepos {
		if len(repo.Actions) == 0 {
			continue
		}

		for _, action := range repo.Actions {
			// Calculate warnings for this specific action
			bootstrapClass, warningMessage := action.Warnings()

			data.ActionRows = append(data.ActionRows, ActionRow{
				Repo:           repo,
				Action:         action,
				BootstrapClass: bootstrapClass,
				WarningMessage: warningMessage,
			})
		}
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

	slices.SortFunc(data.Repos, func(a, b *github.Repo) int {
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

	// otherWarnings tracks the number of warnings which are not "danger" level so won't be sent in their entirety to ntfy.sh
	// but will be summarised instead
	otherWarnings := 0
	var warnings []string

	// Check ActionRows for action-related warnings
	for _, actionRow := range data.ActionRows {
		if actionRow.WarningMessage != "" {
			if actionRow.BootstrapClass == "danger" {
				warnings = append(warnings, fmt.Sprintf("%s/%s (%s): %s",
					actionRow.Repo.OrgName, actionRow.Repo.RepoName, actionRow.Action.Name, actionRow.WarningMessage))
			} else {
				otherWarnings++
			}
		}
	}

	// Check repos for release-related warnings
	for _, repo := range dh.githubRepos {
		if !repo.HasReleases {
			continue
		}

		if repo.LastRelease == nil {
			warnings = append(warnings, fmt.Sprintf("%s: no data for last release", repo.RepoName))
		} else if time.Since(repo.LastRelease.GetCreatedAt().Time).Hours() > 2*24*30 { // 60 days
			warnings = append(warnings, fmt.Sprintf("%s: last release more than sixty days old", repo.RepoName))
		} else if time.Since(repo.LastRelease.GetCreatedAt().Time).Hours() > 24*30 { // 30 days
			otherWarnings++
		}
	}

	failingTrivyJobCount := 0
	for _, job := range data.TestGridJobs {
		if job.Failing() {
			failingTrivyJobCount++
		}
	}

	if failingTrivyJobCount > 0 {
		warnings = append(warnings, fmt.Sprintf("trivy jobs: %d failing", failingTrivyJobCount))
	}

	logger := logging.FromContext(ctx)

	if otherWarnings > 0 {
		logger.Info("skipping minor warnings", "otherWarningsCount", otherWarnings)
		// Previously we sent a message for minor warnings, but it was too noisy on ntfy
		// warnings = append(warnings, fmt.Sprintf("other: %d minor warnings", otherWarnings))
	}

	if len(warnings) > 0 {
		message := strings.Join(warnings, ", ")

		logger.Info("got warnings", "warnings", message, "shouldNtfy", dh.shouldNtfy)

		if dh.shouldNtfy {
			if message != lastNtfy {
				err = ntfy(ntfyTopic, message)
				if err != nil {
					logger.Error("got an error trying to publish to ntfy.sh", "err", err)
				}

				logger.Info("published to ntfy.sh")
				lastNtfy = message
			} else {
				logger.Info("skipping publishing to ntfy.sh as message is unchanged")
			}
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

	logging.FromContext(r.Context()).Info("request", "userAgent", r.UserAgent(), "path", path)

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

	flag.BoolVar(&config.ShouldNtfy, "ntfy", false, "If set, send warnings to ntfy.sh")
	flag.Parse()

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
