package testgrid

import (
	"context"
	"fmt"

	"github.com/SgtCoDFish/cert-manager-dashboard/pkg/logging"
	k8stestgrid "k8s.io/release/pkg/testgrid"
)

type Job struct {
	Name           string
	DashboardName  string
	Status         string
	BootstrapClass string
	URL            string
}

func (j Job) Failing() bool {
	// testgrid will report tests as flaky if they failed recently; our security tests
	// run on an irregular basis so a failure a couple of days ago can cause the tests
	// to be marked as flaky even if they are currently passing.
	// As such, we assume jobs to be failing only if they are explicitly marked as failing
	// or stale, but we still colour flaky tests as "warning"s in the UI.
	return j.Status == string(k8stestgrid.Failing) || j.Status == string(k8stestgrid.Stale)
}

type Dashboard struct {
	Name string

	jobNames []string

	jobData []Job
}

func New(name string, jobNames []string) *Dashboard {
	return &Dashboard{
		Name:     name,
		jobNames: jobNames,
	}
}

func (d *Dashboard) Fetch(ctx context.Context) error {
	// ReqTestgridDashboardSummary harcodes testgrid.k8s.io as the base URL
	jobData, err := k8stestgrid.ReqTestgridDashboardSummary(ctx, k8stestgrid.DashboardName(d.Name))
	if err != nil {
		return err
	}

	var newJobData []Job

	for _, jobName := range d.jobNames {
		summary, ok := jobData[k8stestgrid.JobName(jobName)]
		if !ok {
			return fmt.Errorf("job %q not found in dashboard %q", jobName, d.Name)
		}

		bootstrapClass := ""

		switch summary.OverallStatus {
		case k8stestgrid.Failing:
			bootstrapClass = "danger"

		case k8stestgrid.Stale:
			bootstrapClass = "danger"

		case k8stestgrid.Flaky:
			bootstrapClass = "warning"

		case k8stestgrid.Passing:
			// do nothing

		default:
			logger := logging.FromContext(ctx)
			logger.Error("got an unexpected status for TestGrid job", "dashboard", d.Name, "job", jobName, "status", string(summary.OverallStatus))
		}

		newJobData = append(newJobData, Job{
			Name:           jobName,
			DashboardName:  d.Name,
			Status:         string(summary.OverallStatus),
			BootstrapClass: bootstrapClass,
			URL:            fmt.Sprintf("https://testgrid.k8s.io/%s#%s", d.Name, jobName),
		})
	}

	d.jobData = newJobData

	return nil
}

func (d *Dashboard) JobData() []Job {
	if d.jobData == nil {
		panic("job data not fetched; call Fetch() first")
	}

	return d.jobData
}
