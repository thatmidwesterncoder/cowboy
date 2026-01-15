# Cowboy

Cowboy is a tool for processing Rancher CI log dump archives collected during cluster failures. It extracts, parses, and organizes diagnostic data from Rancher-managed Kubernetes clusters into a structured ZIP archive.

## Overview

When Rancher CI encounters cluster failures, it generates log dumps containing base64-encoded gzip-compressed blobs of Kubernetes cluster resources, pod logs, and other diagnostic information. Cowboy:

1. **Extracts** - Finds and decodes base64+gzip compressed blobs from log dump files
2. **Parses** - Deserializes structured JSON data into typed Kubernetes resources
3. **Organizes** - Writes resources as individual YAML files in a navigable directory structure
4. **Archives** - Bundles everything into a ZIP file for easy distribution and analysis

## Installation

```bash
go build -o cowboy main.go
```

Or install globally:

```bash
go install .
```

## Usage

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
