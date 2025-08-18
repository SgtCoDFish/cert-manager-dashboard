# cert-manager-dashboard

This is a really simple dashboard application for fetching security data from the GitHub API for the various repos in the cert-manager organisation.

The dashboard is packaged as a single Go binary. The only configuration required is a GitHub API token, provided through the `GITHUB_TOKEN` environment variable.

The dashboard can be easily packaged for deployment on a Debian-based system using `make deb`. This will create a `.deb` file in `_bin` which can be installed directly onto a server. The `.deb.` archive depends on systemd, and requires nginx to front the deployment for handling TLS.
