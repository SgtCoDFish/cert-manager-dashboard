package github

import (
	"bytes"
	"fmt"
	"html/template"
	"time"

	githubsdk "github.com/google/go-github/v71/github"
)

var (
	actionRunTmpl = template.Must(template.New("actionRunTmpl").Parse(`<a href="{{ .URL }}" title="Latest run of {{ .ActionName }} for {{ .RepoName }}" target="_blank">{{ .Branch }}</a>`))
)

type Action struct {
	Name         string
	WorkflowName string
	LastRun      *githubsdk.WorkflowRun
}

func NewAction(name, workflowName string) *Action {
	return &Action{
		Name:         name,
		WorkflowName: workflowName,
	}
}

func (a *Action) LastRunTime() string {
	if a.LastRun == nil {
		return "N/A"
	}

	return a.LastRun.GetCreatedAt().Time.UTC().Format(time.DateTime)
}

func (a *Action) Status() string {
	if a.LastRun == nil {
		return "N/A"
	}

	return a.LastRun.GetConclusion()
}

func (a *Action) HeadLink(repo *Repo) template.HTML {
	if a.LastRun == nil {
		return "No runs found"
	}

	data := struct {
		URL        string
		ActionName string
		RepoName   string
		Branch     string
	}{
		URL:        a.LastRun.GetHTMLURL(),
		ActionName: a.Name,
		RepoName:   repo.RepoName,
		Branch:     a.LastRun.GetHeadBranch(),
	}

	buf := &bytes.Buffer{}
	err := actionRunTmpl.Execute(buf, data)
	if err != nil {
		return "Failed to render template"
	}

	return template.HTML(buf.String())
}

func (a *Action) Warnings() (string, string) {
	if a.LastRun == nil {
		return "danger", fmt.Sprintf("no data for action %s", a.Name)
	}

	if a.LastRun.GetConclusion() != "success" {
		return "danger", fmt.Sprintf("last %s action run not successful", a.Name)
	}

	if time.Since(a.LastRun.GetCreatedAt().Time).Hours() > twoDays {
		return "danger", fmt.Sprintf("%s action stale for more than two days", a.Name)
	}

	return "", ""
}
