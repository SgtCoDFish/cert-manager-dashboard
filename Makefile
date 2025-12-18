MAKEFLAGS += --warn-undefined-variables --no-builtin-rules
SHELL := /usr/bin/env bash
.SHELLFLAGS := -uo pipefail -c
.DELETE_ON_ERROR:
.SUFFIXES:

BINDIR := _bin

GOOS := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)

DASHBOARD_VERSION=0.6.0

GOLANGCILINT_VERSION=2.4.0
NFPM_VERSION=v2.43.0

GOLIST := $(shell ./hack/golist.sh) go.mod go.sum

# Get the files used to create the .deb file, so we can recreate the archive when they change
NFPM_DEPS := $(shell yq '.contents.[].src | select(. != null)' < nfpm.yaml)

.PHONY: lint
lint: $(BINDIR)/tools/golangci-lint-$(GOLANGCILINT_VERSION)
	$< run

.PHONY: build
build: $(BINDIR)/cert-manager-dashboard

.PHONY: build-all
build-all: $(BINDIR)/cert-manager-dashboard $(BINDIR)/cert-manager-dashboard-linux-amd64 $(BINDIR)/cert-managerdashboard-linux-arm64

$(BINDIR)/cert-manager-dashboard: $(GOLIST) | $(BINDIR)
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -ldflags '-extldflags "-static"' -o $@ main.go

$(BINDIR)/cert-manager-dashboard-linux-amd64: $(GOLIST) | $(BINDIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags '-extldflags "-static"' -o $@ main.go

$(BINDIR)/cert-manager-dashboard-linux-arm64: $(GOLIST) | $(BINDIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags '-extldflags "-static"' -o $@ main.go

.PHONY: deb
deb: $(BINDIR)/cert-manager-dashboard-$(DASHBOARD_VERSION).deb

$(BINDIR)/cert-manager-dashboard-$(DASHBOARD_VERSION).deb: dist/postinstall/postinstall.sh nfpm.yaml $(NFPM_DEPS) | $(BINDIR) $(BINDIR)/tools/nfpm-$(NFPM_VERSION)/nfpm
	DASHBOARD_VERSION=$(DASHBOARD_VERSION) $(BINDIR)/tools/nfpm-$(NFPM_VERSION)/nfpm package --packager deb --target $@

$(BINDIR)/tools/nfpm-$(NFPM_VERSION)/nfpm: | $(BINDIR)/tools
	GOBIN=$(PWD)/$(dir $@) go install github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)

$(BINDIR)/tools/golangci-lint-$(GOLANGCILINT_VERSION): $(BINDIR)/scratch/golangci-lint-$(GOLANGCILINT_VERSION)-$(GOOS)-$(GOARCH).tar.gz | $(BINDIR)/tools
	tar xfO $< golangci-lint-$(GOLANGCILINT_VERSION)-$(GOOS)-$(GOARCH)/golangci-lint > $@ && chmod +x $@

$(BINDIR)/scratch/golangci-lint-$(GOLANGCILINT_VERSION)-$(GOOS)-$(GOARCH).tar.gz: | $(BINDIR)/scratch
	curl -sSL -o $@ https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCILINT_VERSION)/golangci-lint-$(GOLANGCILINT_VERSION)-$(GOOS)-$(GOARCH).tar.gz

$(BINDIR) $(BINDIR)/scratch $(BINDIR)/tools $(BINDIR)/tools/nfpm-$(NFPM_VERSION):
	@mkdir -p $@

