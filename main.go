// Package lumberjack processes Rancher log dump archives containing Kubernetes
// cluster resources, pod logs, and other diagnostic data. It extracts base64-encoded
// gzip-compressed blobs, parses structured log dump data, and organizes the extracted
// content into a ZIP archive with a directory structure for easy navigation.
//
// This tool is typically used to process log dumps collected from Rancher-managed
// clusters, extracting CAPI clusters, RKE clusters, machines, pod logs, and other
// Kubernetes resources into individual YAML files.
package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	mgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	provv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
	"sigs.k8s.io/yaml"
)

// gzipPattern matches base64-encoded gzip-compressed data commonly found in
// Rancher log dumps. The pattern identifies the "H4sI" prefix followed by
// base64 characters and padding, which indicates gzip-compressed content.
var gzipPattern = regexp.MustCompile(`H4sI[A-Za-z0-9+/]+=*`)

// LogDump represents the structured data extracted from a Rancher log dump blob.
// It contains various Kubernetes cluster resources organized by their API types.
//
// The struct is populated by decoding base64+gzip compressed JSON data that
// contains detailed information about a Rancher-managed Kubernetes cluster.
type LogDump struct {
	// CapiCluster contains the Cluster API (CAPI) cluster resource representing
	// the infrastructure-agnostic cluster definition.
	CapiCluster *capi.Cluster `json:"capiCluster"`

	// Cluster holds the Rancher provisioning cluster resource which manages
	// the cluster lifecycle and configuration.
	Cluster *provv1.Cluster `json:"cluster"`

	// InfraCluster contains the RKE (Rancher Kubernetes Engine) cluster resource
	// representing the infrastructure-specific cluster configuration.
	InfraCluster *rkev1.RKECluster `json:"infraCluster"`

	// InfraMachines is a list of infrastructure machine objects that define
	// the underlying nodes for the cluster.
	InfraMachines []map[string]any `json:"infraMachines"`

	// MachineDeployments contains the CAPI machine deployments for managing
	// groups of machines in the cluster.
	MachineDeployments *capi.MachineDeploymentList `json:"machineDeployments"`

	// MachineSets contains the CAPI machine sets which provide declarative
	// control over the number and configuration of machines.
	MachineSets *capi.MachineSetList `json:"machineSets"`

	// Machines is a list of all CAPI machines in the cluster, representing
	// individual worker or control plane nodes.
	Machines *capi.MachineList `json:"machines"`

	// MgmtCluster contains the Rancher management cluster resource which
	// represents the management plane configuration.
	MgmtCluster *mgmtv3.Cluster `json:"mgmtCluster"`

	// PodLogs is a nested map of pod logs organized by node name and then by
	// pod/log key. The values are base64-encoded gzip-compressed log content.
	PodLogs map[string]map[string]string `json:"podLogs"`

	// RkeBootstraps contains RKE bootstrap resources that handle node
	// bootstrapping for control plane nodes.
	RkeBootstraps []*rkev1.RKEBootstrapList `json:"rkeBootstraps"`

	// RKEControlPlane holds the RKE control plane resource managing the
	// control plane configuration and lifecycle.
	RKEControlPlane *rkev1.RKEControlPlane `json:"rkecontrolplane"`

	// Snapshots contains etcd snapshot resources for cluster backup and
	// recovery purposes.
	Snapshots *rkev1.ETCDSnapshotList `json:"snapshots"`
}

// unpack decodes a base64-encoded gzip-compressed string and returns the
// decompressed content as bytes. This is used to extract the original data
// from Rancher log dump blobs.
//
// Parameters:
//   - s: A base64-encoded string containing gzip-compressed data
//
// Returns:
//   - []byte: The decompressed original content
//   - error: Any error encountered during decoding or decompression
func unpack(s string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	reader, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		return nil, fmt.Errorf("gzip reader failed: %w", err)
	}
	defer reader.Close()

	return io.ReadAll(reader)
}

// extractBlobs scans a string for base64-encoded gzip-compressed blobs and
// returns them as a slice. Each blob is identified by the gzipPattern regex
// which matches the characteristic "H4sI" prefix of gzip-compressed base64 data.
//
// Parameters:
//   - body: The input string to search for gzip blobs (typically log dump content)
//
// Returns:
//   - []string: A list of matched base64-encoded gzip blobs found in the input
func extractBlobs(body string) []string {
	var blobs []string
	for _, match := range strings.Split(body, "\n") {
		line := strings.TrimSpace(match)
		if len(line) > 20 {
			if blob := gzipPattern.FindString(line); blob != "" {
				blobs = append(blobs, blob)
			}
		}
	}
	return blobs
}

// parseLogDump parses JSON-encoded log dump data into a LogDump struct.
// This function handles the structured data extracted from Rancher log dumps.
//
// Parameters:
//   - data: The raw JSON bytes containing log dump information
//
// Returns:
//   - *LogDump: A populated LogDump struct with all parsed resources
//   - error: Any error encountered during JSON unmarshaling
func parseLogDump(data []byte) (*LogDump, error) {
	var logDump LogDump
	if err := json.Unmarshal(data, &logDump); err != nil {
		return nil, fmt.Errorf("yaml unmarshal failed: %w", err)
	}
	return &logDump, nil
}

// fetchURL retrieves the content from a given URL using HTTP GET.
// The function uses a 30-second timeout to prevent hanging on unresponsive URLs.
//
// Parameters:
//   - url: The URL to fetch data from
//
// Returns:
//   - []byte: The response body content
//   - error: Any error during HTTP request, including non-200 status codes
func fetchURL(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP status error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}
	return body, nil
}

// decodePodLogContent decodes pod log content that may be base64+gzip encoded.
// Rancher uses a custom encoding where newlines are replaced with "SnewlineG"
// markers. This function handles both encoded and plain text content.
//
// The function first checks if the content appears to be gzip-encoded (starts
// with "H4sI" prefix). If not, it returns the original content unchanged.
// For encoded content, it decompresses and replaces the newline markers.
//
// Parameters:
//   - encoded: The potentially encoded pod log content
//
// Returns:
//   - string: The decoded log content with proper newlines
//   - error: Any error during decoding (non-fatal, returns original on error)
func decodePodLogContent(encoded string) (string, error) {
	if len(encoded) < 20 {
		return encoded, nil
	}

	if !strings.HasPrefix(encoded, "H4sI") {
		return encoded, nil
	}

	decoded, err := unpack(encoded)
	if err != nil {
		return encoded, fmt.Errorf("failed to decode pod log: %w", err)
	}

	result := string(decoded)
	result = strings.ReplaceAll(result, "SnewlineG", "\n")
	return result, nil
}

// sanitizeFilename converts a string into a safe filename by replacing
// characters that are problematic on most filesystems. This prevents issues
// with directory separators, colons, spaces, and pipe characters.
//
// Characters replaced:
//   - "/" (directory separator) -> "_"
//   - ":" (Windows drive letter indicator) -> "_"
//   - " " (space) -> "_"
//   - "|" (pipe) -> "_"
//
// Parameters:
//   - name: The original filename string
//
// Returns:
//   - string: A sanitized filename safe for writing to disk
func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "|", "_")
	return name
}

// writeYAML marshals Go data to YAML format and writes it to a file in the
// specified directory. The filename is sanitized before writing.
//
// Parameters:
//   - dir: The target directory for the file
//   - filename: The name of the file to create (will be sanitized)
//   - data: Any Go data that can be marshaled to YAML
//
// Returns:
//   - error: Any error during file creation, YAML marshaling, or writing
func writeYAML(dir string, filename string, data any) error {
	filepath := filepath.Join(dir, sanitizeFilename(filename))
	f, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filepath, err)
	}
	defer f.Close()

	yamlData, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	_, err = f.Write(yamlData)
	if err != nil {
		return fmt.Errorf("failed to write file %s: %w", filepath, err)
	}
	return nil
}

// writeText writes string content to a file in the specified directory.
// The filename is sanitized before writing to ensure filesystem safety.
//
// Parameters:
//   - dir: The target directory for the file
//   - filename: The name of the file to create (will be sanitized)
//   - content: The text content to write to the file
//
// Returns:
//   - error: Any error during file creation or writing
func writeText(dir string, filename string, content string) error {
	filepath := filepath.Join(dir, sanitizeFilename(filename))
	f, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filepath, err)
	}
	defer f.Close()

	_, err = f.WriteString(content)
	if err != nil {
		return fmt.Errorf("failed to write file %s: %w", filepath, err)
	}
	return nil
}

// addToZip adds a file with the given content to a ZIP archive writer.
// The file is added with the specified filename within the ZIP structure.
//
// Parameters:
//   - zipW: The ZIP writer to add the file to
//   - filename: The name for this file within the ZIP archive
//   - content: The byte content to write to the ZIP entry
//
// Returns:
//   - error: Any error during ZIP entry creation or writing
func addToZip(zipW *zip.Writer, filename string, content []byte) error {
	f, err := zipW.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create zip entry %s: %w", filename, err)
	}

	_, err = f.Write(content)
	if err != nil {
		return fmt.Errorf("failed to write zip entry %s: %w", filename, err)
	}
	return nil
}

// main is the entry point for the lumberjack tool. It processes Rancher log
// dumps by extracting base64-encoded gzip-compressed blobs, parsing structured
// log dump data, and organizing the extracted content into a ZIP archive.
//
// The tool supports two input modes:
//   - URL mode: Fetch log dump from a remote URL using the -url flag
//   - Stdin mode: Read log dump from standard input (default when no URL provided)
//
// Output is written to a ZIP file (default: log_dump.zip) containing:
//   - Kubernetes resources as individual YAML files organized by type
//   - Pod logs decoded and organized by node and pod name
//   - Raw JSON dumps for each blob for debugging purposes
//
// Usage:
//
//	lumberjack -url "https://example.com/logdump" -output my_logs.zip
//	cat logdump.txt | lumberjack -output extracted.zip
func main() {
	url := flag.String("url", "", "URL to fetch log dump from")
	output := flag.String("output", "log_dump.zip", "Output ZIP file path")
	flag.Parse()

	var body []byte
	var err error

	if *url != "" {
		fmt.Printf("Fetching from URL: %s\n", *url)
		body, err = fetchURL(*url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error fetching URL: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Reading from stdin...")
		body, err = io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
			os.Exit(1)
		}
	}

	bodyStr := string(body)
	blobs := extractBlobs(bodyStr)
	fmt.Printf("[%d] base64/gzipped blobs found!\n", len(blobs))

	// Create a temporary directory for extraction
	tempDir, err := os.MkdirTemp("", "lumberjack_*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tempDir)

	var rawLogs []string

	for i, blob := range blobs {
		fmt.Printf("\nParsing blob %d\n", i+1)

		raw, err := unpack(blob)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error unpacking blob %d: %v\n", i+1, err)
			continue
		}

		logDump, err := parseLogDump(raw)
		if err != nil {
			fmt.Printf("Blob %d is not a structured log dump (rancher logs), saving as raw log\n", i+1)
			rawLogs = append(rawLogs, string(raw))
			continue
		}

		// Create directory structure for this blob
		blobDir := filepath.Join(tempDir, fmt.Sprintf("blob_%d", i+1))
		os.MkdirAll(blobDir, 0755)

		// Write Kubernetes objects as YAML files
		if logDump.CapiCluster != nil {
			if err := writeYAML(blobDir, "capi_cluster.yaml", logDump.CapiCluster); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing capiCluster: %v\n", err)
			}
		}

		if logDump.Cluster != nil {
			if err := writeYAML(blobDir, "cluster.yaml", logDump.Cluster); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing cluster: %v\n", err)
			}
		}

		if logDump.InfraCluster != nil {
			if err := writeYAML(blobDir, "infra_cluster.yaml", logDump.InfraCluster); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing infraCluster: %v\n", err)
			}
		}

		if logDump.RKEControlPlane != nil {
			if err := writeYAML(blobDir, "rke_controlplane.yaml", logDump.RKEControlPlane); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing RKEControlPlane: %v\n", err)
			}
		}

		if logDump.MgmtCluster != nil {
			if err := writeYAML(blobDir, "mgmt_cluster.yaml", logDump.MgmtCluster); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing mgmtCluster: %v\n", err)
			}
		}

		if logDump.Machines != nil && len(logDump.Machines.Items) > 0 {
			machinesDir := filepath.Join(blobDir, "machines")
			os.MkdirAll(machinesDir, 0755)
			for _, machine := range logDump.Machines.Items {
				name := fmt.Sprintf("machine_%s.yaml", machine.Name)
				if err := writeYAML(machinesDir, name, machine); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing machine %s: %v\n", machine.Name, err)
				}
			}
		}

		if logDump.MachineSets != nil && len(logDump.MachineSets.Items) > 0 {
			machineSetsDir := filepath.Join(blobDir, "machine_sets")
			os.MkdirAll(machineSetsDir, 0755)
			for _, machineSet := range logDump.MachineSets.Items {
				name := fmt.Sprintf("machineset_%s.yaml", machineSet.Name)
				if err := writeYAML(machineSetsDir, name, machineSet); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing machineSet %s: %v\n", machineSet.Name, err)
				}
			}
		}

		if logDump.MachineDeployments != nil && len(logDump.MachineDeployments.Items) > 0 {
			machineDeploymentsDir := filepath.Join(blobDir, "machine_deployments")
			os.MkdirAll(machineDeploymentsDir, 0755)
			for _, machineDeployment := range logDump.MachineDeployments.Items {
				name := fmt.Sprintf("machinedeployment_%s.yaml", machineDeployment.Name)
				if err := writeYAML(machineDeploymentsDir, name, machineDeployment); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing machineDeployment %s: %v\n", machineDeployment.Name, err)
				}
			}
		}

		if len(logDump.InfraMachines) > 0 {
			infraMachinesDir := filepath.Join(blobDir, "infra_machines")
			os.MkdirAll(infraMachinesDir, 0755)
			for idx, infraMachine := range logDump.InfraMachines {
				name := "unknown"
				if nameVal, ok := infraMachine["name"].(string); ok && nameVal != "" {
					name = nameVal
				}
				filename := fmt.Sprintf("infra_machine_%s.yaml", name)
				if err := writeYAML(infraMachinesDir, filename, infraMachine); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing infra machine %d: %v\n", idx+1, err)
				}
			}
		}

		if len(logDump.RkeBootstraps) > 0 {
			rkeBootstrapsDir := filepath.Join(blobDir, "rke_bootstraps")
			os.MkdirAll(rkeBootstrapsDir, 0755)
			for _, bootstrapList := range logDump.RkeBootstraps {
				if bootstrapList == nil || len(bootstrapList.Items) == 0 {
					continue
				}
				for _, bootstrap := range bootstrapList.Items {
					name := fmt.Sprintf("rke_bootstrap_%s.yaml", bootstrap.Name)
					if err := writeYAML(rkeBootstrapsDir, name, bootstrap); err != nil {
						fmt.Fprintf(os.Stderr, "Error writing RKEBootstrap %s: %v\n", bootstrap.Name, err)
					}
				}
			}
		}

		if logDump.Snapshots != nil && len(logDump.Snapshots.Items) > 0 {
			snapshotsDir := filepath.Join(blobDir, "etcd_snapshots")
			os.MkdirAll(snapshotsDir, 0755)
			for _, snapshot := range logDump.Snapshots.Items {
				name := fmt.Sprintf("snapshot_%s.yaml", snapshot.Name)
				if err := writeYAML(snapshotsDir, name, snapshot); err != nil {
					fmt.Fprintf(os.Stderr, "Error writing snapshot %s: %v\n", snapshot.Name, err)
				}
			}
		}

		// Write pod logs
		if len(logDump.PodLogs) > 0 {
			podLogsDir := filepath.Join(blobDir, "pod_logs")
			os.MkdirAll(podLogsDir, 0755)

			for nodeName, nodeLogs := range logDump.PodLogs {
				nodeDir := filepath.Join(podLogsDir, sanitizeFilename(nodeName))
				os.MkdirAll(nodeDir, 0755)

				for logKey, encodedContent := range nodeLogs {
					if encodedContent == "" {
						continue
					}

					content, err := decodePodLogContent(encodedContent)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error decoding pod log %s/%s: %v\n", nodeName, logKey, err)
						continue
					}

					if content != "" {
						logFilename := fmt.Sprintf("%s.txt", logKey)
						if err := writeText(nodeDir, logFilename, content); err != nil {
							fmt.Fprintf(os.Stderr, "Error writing pod log %s/%s: %v\n", nodeName, logKey, err)
						}
					}
				}
			}
		}

		// Write the raw JSON dump
		if err := writeText(blobDir, "full_decoded_raw_dump.json", string(raw)); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing raw dump: %v\n", err)
		}

		fmt.Printf("Successfully parsed blob %d as log dump\n", i+1)
	}

	// Write rancher logs (non-JSON blobs)
	if len(rawLogs) > 0 {
		rancherLogsDir := filepath.Join(tempDir, "rancher_logs")
		os.MkdirAll(rancherLogsDir, 0755)

		for i, log := range rawLogs {
			logFilename := fmt.Sprintf("rancher_log_%d.txt", i+1)
			if err := writeText(rancherLogsDir, logFilename, log); err != nil {
				fmt.Fprintf(os.Stderr, "Error writing rancher log %d: %v\n", i+1, err)
			}
		}
	}

	// Create ZIP file
	zipFile, err := os.Create(*output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer zipFile.Close()

	zipW := zip.NewWriter(zipFile)
	defer zipW.Close()

	// Walk through the temp directory and add all files to ZIP
	err = filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Get relative path for ZIP entry
		relPath, err := filepath.Rel(tempDir, path)
		if err != nil {
			return err
		}

		// Read file content
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", path, err)
		}

		// Add to ZIP
		if err := addToZip(zipW, relPath, content); err != nil {
			return fmt.Errorf("failed to add %s to zip: %w", relPath, err)
		}

		return nil
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating ZIP file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nSuccessfully generated ZIP output: %s\n", *output)
}
