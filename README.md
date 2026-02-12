# Cowboy

[![Build and Publish Container](https://github.com/rancher/cowboy/actions/workflows/publish-container.yaml/badge.svg)](https://github.com/rancher/cowboy/actions/workflows/publish-container.yaml)
[![Test Cowboy Action](https://github.com/rancher/cowboy/actions/workflows/test-action.yaml/badge.svg)](https://github.com/rancher/cowboy/actions/workflows/test-action.yaml)

Cowboy is a tool for processing Rancher CI log dump archives collected during cluster failures. It extracts, parses, and organizes diagnostic data from Rancher-managed Kubernetes clusters into a structured ZIP archive.

**Available as:**
- 🐹 **CLI tool** - Standalone binary for local use
- 🐳 **Container image** - `docker.io/rancher/cowboy:latest`
- ⚡ **GitHub Action** - Seamless CI/CD integration

## Overview

When Rancher CI encounters cluster failures, it generates log dumps containing base64-encoded gzip-compressed blobs of Kubernetes cluster resources, pod logs, and other diagnostic information. Cowboy:

1. **Extracts** - Finds and decodes base64+gzip compressed blobs from log dump files
2. **Parses** - Deserializes structured JSON data into typed Kubernetes resources
3. **Organizes** - Writes resources as individual YAML files in a navigable directory structure
4. **Archives** - Bundles everything into a ZIP file for easy distribution and analysis

## Quick Start

### Using as a GitHub Action

Add this to your workflow to automatically process log dumps:

```yaml
name: Process Log Dump
on: [push]

jobs:
  process:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Process Rancher log dump
        uses: rancher/cowboy@v1
        with:
          log-file-path: ./logs/failure-dump.txt
          output-file: diagnostic-bundle.zip
```

The processed ZIP file is automatically uploaded as a workflow artifact and can be downloaded from the Actions tab.

### Using the Container Image

```bash
# Process from stdin
cat logdump.txt | docker run -i docker.io/rancher/cowboy:latest

# Process from file (with volume mount)
docker run --rm -v $(pwd):/workspace -w /workspace \
  docker.io/rancher/cowboy:latest \
  -output results.zip < logdump.txt
```

### Installing the CLI

```bash
go build -o cowboy main.go
```

Or install globally:

```bash
go install .
```

## CLI Usage

### Input Modes

Cowboy supports two input methods:

#### From URL
```bash
cowboy -url "https://example.com/logdump.txt" -output failure_logs.zip
```

#### From stdin (pipe or redirect)
```bash
cat logdump.txt | cowboy -output extracted.zip
cowboy < logdump.txt -output extracted.zip
```

### Command Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-url` | (none) | URL to fetch log dump from |
| `-output` | `log_dump.zip` | Output ZIP file path |

## Output Structure

The generated ZIP archive contains the following structure:

```
output.zip
├── blob_1/
│   ├── capi_cluster.yaml          # Cluster API cluster resource
│   ├── cluster.yaml               # Rancher provisioning cluster
│   ├── infra_cluster.yaml         # RKE cluster resource
│   ├── rke_controlplane.yaml      # RKE control plane configuration
│   ├── mgmt_cluster.yaml          # Rancher management cluster
│   ├── full_decoded_raw_dump.json # Raw JSON for debugging
│   ├── machines/
│   │   └── machine_<name>.yaml    # CAPI machine resources
│   ├── machine_sets/
│   │   └── machineset_<name>.yaml # CAPI machine set resources
│   ├── machine_deployments/
│   │   └── machinedeployment_<name>.yaml
│   ├── infra_machines/
│   │   └── infra_machine_<name>.yaml
│   ├── rke_bootstraps/
│   │   └── rke_bootstrap_<name>.yaml
│   ├── etcd_snapshots/
│   │   └── snapshot_<name>.yaml
│   └── pod_logs/
│       └── <node_name>/
│           └── <pod_log_key>.txt  # Decoded pod logs
├── blob_2/
│   └── ...
└── rancher_logs/
    ├── rancher_log_1.txt          # Non-JSON log content
    └── ...
```

### Extracted Resources

| Type | Description |
|------|-------------|
| `CapiCluster` | Cluster API (CAPI) infrastructure-agnostic cluster definition |
| `Cluster` | Rancher provisioning cluster lifecycle and configuration |
| `InfraCluster` | RKE (Rancher Kubernetes Engine) infrastructure-specific configuration |
| `Machines` | CAPI machine resources for control plane and worker nodes |
| `MachineSets` | CAPI machine set definitions for declarative machine control |
| `MachineDeployments` | CAPI machine deployment resources |
| `InfraMachines` | Infrastructure machine objects defining cluster nodes |
| `RKEControlPlane` | RKE control plane resource configuration |
| `RKEBootstrap` | RKE bootstrap resources for node bootstrapping |
| `ETCDSnapshots` | etcd snapshot resources for backup/recovery |
| `PodLogs` | Container logs organized by node and pod |

## Development

### Running Tests

```bash
go test -v ./...
```

Tests validate:
- Blob extraction from compressed input
- Base64+gzip decoding functionality
- JSON/YAML parsing of Rancher resources
- ZIP archive creation with correct structure

### Dependencies

Cowboy uses the following key dependencies:

- [Rancher Kubernetes APIs](https://github.com/rancher/rancker/tree/master/pkg/apis) - Management, Provisioning, and RKE API types
- [Cluster API](https://github.com/kubernetes-sigs/cluster-api) - Infrastructure-agnostic cluster management
- [siggy YAML](https://github.com/kubernetes-sigs/yaml) - YAML marshaling for Go structs

## GitHub Action Reference

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `log-file-path` | Yes | - | Path to the Rancher log dump file to process |
| `output-file` | No | `<input-basename>_dump.zip` | Output ZIP file name |
| `upload-artifact` | No | `true` | Upload the generated ZIP as a GitHub Actions artifact |
| `artifact-retention-days` | No | `30` | Number of days to retain the artifact (1-90) |

### Outputs

| Output | Description |
|--------|-------------|
| `output-path` | Path to the generated ZIP file |
| `artifact-name` | Name of the uploaded artifact (if upload-artifact is true) |

### Example Workflows

#### Basic usage with default settings
```yaml
- uses: rancher/cowboy@v1
  with:
    log-file-path: ./logdump.txt
```

#### Custom output name without artifact upload
```yaml
- uses: rancher/cowboy@v1
  with:
    log-file-path: ./logs/cluster-failure.txt
    output-file: cluster-diagnostics.zip
    upload-artifact: 'false'
```

#### Process and upload with custom retention
```yaml
- uses: rancher/cowboy@v1
  with:
    log-file-path: ./dumps/production-failure.txt
    output-file: prod-diagnostics.zip
    artifact-retention-days: '90'
```

#### Using output path in subsequent steps
```yaml
- name: Process log dump
  id: cowboy
  uses: rancher/cowboy@v1
  with:
    log-file-path: ./logdump.txt

- name: Upload to S3
  run: |
    aws s3 cp ${{ steps.cowboy.outputs.output-path }} s3://my-bucket/diagnostics/
```

## Container Image Tags

The container image is available at `docker.io/rancher/cowboy` with the following tags:

- `latest` - Latest build from the main branch
- `v1`, `v1.0`, `v1.0.0` - Semantic version tags
- `main`, `master` - Branch-based tags
- `main-abc1234` - Git SHA tags for specific commits
