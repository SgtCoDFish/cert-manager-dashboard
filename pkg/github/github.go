package github

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"regexp"
	"time"

	"github.com/SgtCoDFish/cert-manager-dashboard/pkg/logging"

	githubsdk "github.com/google/go-github/v71/github"
)

const (
	twoDays    = 2 * 30
	thirtyDays = 24 * 30
)

var (
	lastRunTmpl = template.Must(template.New("lastRunTmpl").Parse(`<a href="{{ .LastRun.GetHTMLURL }}" title="Latest run of govulncheck for {{ .RepoName }}" target="_blank">{{ .LastRun.GetHeadBranch }}</a>`))

	latestReleaseTmpl = template.Must(template.New("latestReleaseTmpl").Parse(`<a href="{{ .LastRelease.GetHTMLURL }}" title="Latest release for {{ .RepoName }}" target="_blank">{{ .LastRelease.GetTagName }}</a>`))
)

type RepoOption func(*Repo)

func WithHasReleases(hasReleases bool) RepoOption {
	return func(t *Repo) {
		t.HasReleases = hasReleases
	}
}

func WithVersionFilter(versionFilter string) RepoOption {
	return func(t *Repo) {
		t.VersionFilter = versionFilter
	}
}

func WithFriendlyName(name string) RepoOption {
	return func(t *Repo) {
		t.FriendlyName = name
	}
}

func WithHasGovulncheck(hasGovulncheck bool) RepoOption {
	return func(t *Repo) {
		t.HasGovulncheck = hasGovulncheck
	}
}

func WithGovulncheckBranch(branch string) RepoOption {
	return func(t *Repo) {
		t.GovulncheckBranch = branch
	}
}

type Repo struct {
	OrgName  string
	RepoName string

	FriendlyName string

	HasGovulncheck bool
	HasReleases    bool

	GovulncheckWorkflowName string
	GovulncheckBranch       string

	LastRun *githubsdk.WorkflowRun

	LastRelease *githubsdk.RepositoryRelease

	VersionFilter string
}

func NewRepo(org string, name string, configurers ...RepoOption) *Repo {
	t := &Repo{
		OrgName:  org,
		RepoName: name,

		HasGovulncheck: true,
		HasReleases:    true,

		GovulncheckWorkflowName: "govulncheck.yaml",
		GovulncheckBranch:       "main",
	}

	for _, c := range configurers {
		c(t)
	}

	return t
}

func (tr *Repo) String() string {
	suffix := ""

	if tr.FriendlyName != "" {
		suffix = fmt.Sprintf(" (%s)", tr.FriendlyName)
	}

	return fmt.Sprintf("%s/%s%s", tr.OrgName, tr.RepoName, suffix)
}

func (tr *Repo) BootstrapClass() string {
	cls, _ := tr.BootstrapWarnings()
	return cls
}

func (tr *Repo) WarningMessage() string {
	_, wrn := tr.BootstrapWarnings()
	return wrn
}

func (tr *Repo) LastTag() string {
	if !tr.HasReleases || tr.LastRelease == nil {
		return "N/A"
	}

	return tr.LastRelease.GetTagName()
}

func (tr *Repo) LastReleaseTime() string {
	if !tr.HasReleases || tr.LastRelease == nil {
		return "N/A"
	}

	return tr.LastRelease.GetCreatedAt().Time.UTC().Format(time.DateOnly)
}

func (tr *Repo) LastGovulncheckTime() string {
	if !tr.HasGovulncheck || tr.LastRun == nil {
		return "N/A"
	}

	return tr.LastRun.GetCreatedAt().Time.UTC().Format(time.DateTime)
}

func (tr *Repo) GovulncheckHead() template.HTML {
	if !tr.HasGovulncheck {
		return "N/A"
	}

	if tr.LastRun == nil {
		return "No runs found"
	}

	buf := &bytes.Buffer{}

	err := lastRunTmpl.Execute(buf, tr)
	if err != nil {
		return "Failed to render template"
	}

	// NB: template.HTML can be dangerous, but this is safe since this is output from "template/html.Template.Execute"
	return template.HTML(buf.String())
}

func (tr *Repo) LatestReleaseLink() template.HTML {
	if !tr.HasReleases {
		return "N/A"
	}

	if tr.LastRelease == nil {
		return "No release found"
	}

	buf := &bytes.Buffer{}

	err := latestReleaseTmpl.Execute(buf, tr)
	if err != nil {
		return "Failed to render template"
	}

	// NB: template.HTML can be dangerous, but this is safe since this is output from "template/html.Template.Execute"
	return template.HTML(buf.String())
}

// BootstrapWarnings returns a bootstrap class[1] and a reason if there are any
// warnings which should be shown for this repo. Can return empty strings
// if no warnings are needed.
// [1] https://getbootstrap.com/docs/3.4/css/#tables-contextual-classes
func (tr *Repo) BootstrapWarnings() (string, string) {
	if tr.HasGovulncheck {
		if tr.LastRun == nil {
			return "danger", "no data for last govulncheck run"
		} else if tr.LastRun.GetConclusion() != "success" {
			return "danger", "last govulncheck run not successful"
		} else if time.Since(tr.LastRun.GetCreatedAt().Time).Hours() > twoDays {
			return "danger", "govulncheck stale for more than two days"
		}
	}

	if tr.HasReleases {
		if tr.LastRelease == nil {
			return "danger", "no data for last release"
		}

		if time.Since(tr.LastRelease.GetCreatedAt().Time).Hours() > 2*thirtyDays {
			return "danger", "last release more than sixty days old"
		} else if time.Since(tr.LastRelease.GetCreatedAt().Time).Hours() > thirtyDays {
			return "warning", "last release more than thirty days old"
		}
	}

	return "", ""
}

func (repo *Repo) GetLatestRunResult(ctx context.Context, client *githubsdk.Client) error {
	if !repo.HasGovulncheck {
		return nil
	}

	listOpts := &githubsdk.ListWorkflowRunsOptions{
		Created: lastWeek(),
		ListOptions: githubsdk.ListOptions{
			PerPage: 25,
		},
		Branch: repo.GovulncheckBranch,
	}

	runs, _, err := client.Actions.ListWorkflowRunsByFileName(ctx, repo.OrgName, repo.RepoName, repo.GovulncheckWorkflowName, listOpts)
	if err != nil {
		return err
	}

	for _, run := range runs.WorkflowRuns {
		if run.GetStatus() != "completed" {
			continue
		}

		repo.LastRun = run
		break
	}

	return nil
}

func (repo *Repo) GetLatestRelease(ctx context.Context, client *githubsdk.Client) error {
	if !repo.HasReleases {
		return nil
	}

	listOpts := &githubsdk.ListOptions{
		PerPage: 25,
	}

	releases, _, err := client.Repositories.ListReleases(ctx, repo.OrgName, repo.RepoName, listOpts)
	if err != nil {
		return err
	}

	if len(releases) == 0 {
		return fmt.Errorf("no releases found for %s/%s", repo.OrgName, repo.RepoName)
	}

	// set the first release in the GitHub response as the last release;
	// we might change this if there's a version filter set but at least this will return something sensible
	// if the version filter doesn't match anything
	repo.LastRelease = releases[0]

	if repo.VersionFilter == "" {
		// just use the first release and return
		return nil
	}

	foundMatch := false
	logger := logging.FromContext(ctx).With("repo", fmt.Sprintf("%s/%s", repo.OrgName, repo.RepoName), "versionFilter", repo.VersionFilter)

	for _, rel := range releases {
		tag := rel.GetTagName()

		match, err := regexp.MatchString(repo.VersionFilter, tag)
		if err != nil {
			logger.Error("failed to match version filter", "err", err, "tag", tag)
			continue
		}

		if match {
			repo.LastRelease = rel
			foundMatch = true
			break
		}
	}

	if !foundMatch {
		logger.Info("didn't find a matching release for version filter, will use latest")
	}

	return nil
}

func lastWeek() string {
	t := time.Now().Add(-1 * time.Hour * 24 * 7)

	return ">" + t.Format(time.DateOnly)

}
