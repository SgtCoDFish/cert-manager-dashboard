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
		case k8stestgrid.Flaky:
			bootstrapClass = "warning"

		case k8stestgrid.Passing:
			// do nothing

		default:
			logger := logging.FromContext(ctx)
			logger.Error("got an unexpected status for TestGrid job", "dashboard", d.Name, "job", jobName, "status", string(summary.OverallStatus))
		}

		d.jobData = append(d.jobData, Job{
			Name:           jobName,
			DashboardName:  d.Name,
			Status:         string(summary.OverallStatus),
			BootstrapClass: bootstrapClass,
			URL:            fmt.Sprintf("https://testgrid.k8s.io/%s#%s", d.Name, jobName),
		})
	}

	return nil
}

func (d *Dashboard) JobData() []Job {
	if d.jobData == nil {
		panic("job data not fetched; call Fetch() first")
	}

	return d.jobData
}
