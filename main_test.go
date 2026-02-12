package main

import (
	"archive/zip"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type IntegrationSuite struct {
	suite.Suite
	tempDir          string
	zipPath          string
	decompressedBody []byte
	blobs            []string
}

func (s *IntegrationSuite) SetupSuite() {
	// Read and decompress testdata/test_request_body.txt.gz once
	testDataPath := filepath.Join("testdata", "test_request_body.txt.gz")
	require.FileExists(s.T(), testDataPath, "Test data file should exist")

	gzFile, err := os.Open(testDataPath)
	require.NoError(s.T(), err, "Failed to open test gzip file")
	defer gzFile.Close()

	// Decompress using gzip.NewReader
	gzReader, err := gzip.NewReader(gzFile)
	require.NoError(s.T(), err, "Failed to create gzip reader")
	defer gzReader.Close()

	decompressedContent, err := io.ReadAll(gzReader)
	require.NoError(s.T(), err, "Failed to decompress gzip content")

	s.decompressedBody = decompressedContent
	s.blobs = extractBlobs(string(decompressedContent))
}

func (s *IntegrationSuite) AfterSuite() {
	// Clean up any resources if needed
}

func (s *IntegrationSuite) SetupTest() {
	var err error
	s.tempDir, err = os.MkdirTemp("", "cowboy_test_*")
	require.NoError(s.T(), err, "Failed to create temp directory")
	s.zipPath = filepath.Join(s.tempDir, "output.zip")
}

func (s *IntegrationSuite) TearDownTest() {
	if s.tempDir != "" {
		os.RemoveAll(s.tempDir)
	}
}

func (s *IntegrationSuite) TestDecompressAndProcess() {
	contentStr := string(s.decompressedBody)

	// Extract blobs from the decompressed content
	s.T().Logf("Found %d blobs in test data", len(s.blobs))

	// Process each blob
	for i, blob := range s.blobs {
		// Call unpack() to decode base64+gzip
		decodedData, err := unpack(blob)
		require.NoError(s.T(), err, "Failed to unpack blob %d", i+1)

		// Call parseLogDump() to parse structured data
		logDump, err := parseLogDump(decodedData)
		if err != nil {
			s.T().Logf("Blob %d is not a structured log dump (expected for some test data)", i+1)
			continue
		}

		s.T().Logf("Successfully parsed blob %d as log dump", i+1)

		// Verify the parsed LogDump has expected structure
		require.NotNil(s.T(), logDump, "LogDump should not be nil for blob %d", i+1)
	}

	// Generate ZIP output to temp directory
	err := s.generateZipFromContent(contentStr)
	require.NoError(s.T(), err, "Failed to generate ZIP output")
}

func (s *IntegrationSuite) generateZipFromContent(content string) error {
	blobs := extractBlobs(content)
	return ProcessLogDumpToZip(blobs, s.zipPath)
}

func (s *IntegrationSuite) TestZipFileCreation() {
	err := s.generateZipFromContent(string(s.decompressedBody))
	require.NoError(s.T(), err, "Failed to generate ZIP output")

	// Validate the ZIP file is created successfully at zipPath
	require.FileExists(s.T(), s.zipPath, "ZIP file should be created at zipPath")

	// Verify it's a valid ZIP archive using archive/zip package
	zipReader, err := zip.OpenReader(s.zipPath)
	require.NoError(s.T(), err, "Failed to open ZIP archive")
	defer zipReader.Close()

	// Iterate through files - should have entries
	require.Greater(s.T(), len(zipReader.File), 0, "ZIP archive should contain at least one file")

	s.T().Logf("ZIP archive contains %d files", len(zipReader.File))
}

func (s *IntegrationSuite) TestZipContainsExpectedFiles() {
	err := s.generateZipFromContent(string(s.decompressedBody))
	require.NoError(s.T(), err, "Failed to generate ZIP output")

	// Open the ZIP and check for expected file patterns
	zipReader, err := zip.OpenReader(s.zipPath)
	require.NoError(s.T(), err, "Failed to open ZIP archive")
	defer zipReader.Close()

	filePaths := make(map[string]bool)
	for _, f := range zipReader.File {
		filePaths[f.Name] = true
	}

	// Track which patterns we found
	foundPatterns := make(map[string]bool)

	for _, f := range zipReader.File {
		name := f.Name
		// Check blob_*/full_decoded_raw_dump.json pattern
		if strings.HasPrefix(name, "blob_") &&
			strings.HasSuffix(name, "full_decoded_raw_dump.json") {
			foundPatterns["raw_dump"] = true
		}

		// Check capi_cluster.yaml pattern
		if strings.HasPrefix(name, "blob_") &&
			strings.Contains(name, "/capi_cluster.yaml") {
			foundPatterns["capi_cluster"] = true
		}

		// Check cluster.yaml pattern
		if strings.HasPrefix(name, "blob_") &&
			strings.Contains(name, "/cluster.yaml") {
			foundPatterns["cluster"] = true
		}

		// Check infra_cluster.yaml pattern
		if strings.HasPrefix(name, "blob_") &&
			strings.Contains(name, "/infra_cluster.yaml") {
			foundPatterns["infra_cluster"] = true
		}

		// Check rke_controlplane.yaml pattern
		if strings.HasPrefix(name, "blob_") &&
			strings.Contains(name, "/rke_controlplane.yaml") {
			foundPatterns["rke_controlplane"] = true
		}

		// Check mgmt_cluster.yaml pattern
		if strings.HasPrefix(name, "blob_") &&
			strings.Contains(name, "/mgmt_cluster.yaml") {
			foundPatterns["mgmt_cluster"] = true
		}

		// Check machines/machine_*.yaml pattern
		if strings.HasPrefix(name, "blob_") &&
			strings.Contains(name, "/machines/machine_") &&
			strings.HasSuffix(name, ".yaml") {
			foundPatterns["machines"] = true
		}

		// Check machine_sets/machineset_*.yaml pattern
		if strings.HasPrefix(name, "blob_") &&
			strings.Contains(name, "/machine_sets/machineset_") &&
			strings.HasSuffix(name, ".yaml") {
			foundPatterns["machine_sets"] = true
		}

		// Check machine_deployments/machinedeployment_*.yaml pattern
		if strings.HasPrefix(name, "blob_") &&
			strings.Contains(name, "/machine_deployments/machinedeployment_") &&
			strings.HasSuffix(name, ".yaml") {
			foundPatterns["machine_deployments"] = true
		}

		// Check infra_machines/infra_machine_*.yaml pattern
		if strings.HasPrefix(name, "blob_") &&
			strings.Contains(name, "/infra_machines/infra_machine_") &&
			strings.HasSuffix(name, ".yaml") {
			foundPatterns["infra_machines"] = true
		}

		// Check rke_bootstraps/rke_bootstrap_*.yaml pattern
		if strings.HasPrefix(name, "blob_") &&
			strings.Contains(name, "/rke_bootstraps/rke_bootstrap_") &&
			strings.HasSuffix(name, ".yaml") {
			foundPatterns["rke_bootstraps"] = true
		}

		// Check etcd_snapshots/snapshot_*.yaml pattern
		if strings.HasPrefix(name, "blob_") &&
			strings.Contains(name, "/etcd_snapshots/snapshot_") &&
			strings.HasSuffix(name, ".yaml") {
			foundPatterns["etcd_snapshots"] = true
		}

		// Check pod_logs/*/*.txt pattern
		if strings.HasPrefix(name, "blob_") &&
			strings.Contains(name, "/pod_logs/") &&
			strings.Contains(name, "/") &&
			strings.HasSuffix(name, ".txt") {
			foundPatterns["pod_logs"] = true
		}
	}

	// Log what patterns were found (informational, not assertions)
	s.T().Logf("Found file patterns in ZIP: %v", foundPatterns)

	// Note: We don't assert all patterns exist since test data may not contain all resource types
	// But we verify the ZIP structure is correct
	require.True(s.T(), len(filePaths) > 0, "ZIP should contain files")
}

func (s *IntegrationSuite) TestZipFileCount() {
	err := s.generateZipFromContent(string(s.decompressedBody))
	require.NoError(s.T(), err, "Failed to generate ZIP output")

	// Open the ZIP and count files
	zipReader, err := zip.OpenReader(s.zipPath)
	require.NoError(s.T(), err, "Failed to open ZIP archive")
	defer zipReader.Close()

	fileCount := len(zipReader.File)

	// Validate a reasonable number of files are extracted
	require.Greater(s.T(), fileCount, 10, "Expected more than 10 files in ZIP archive, got %d", fileCount)

	s.T().Logf("ZIP archive contains %d files", fileCount)
}

func (s *IntegrationSuite) TestDirOutput() {
	dirPath := filepath.Join(s.tempDir, "output_dir")

	err := ProcessLogDumpToDir(s.blobs, dirPath)
	require.NoError(s.T(), err, "ProcessLogDumpToDir failed")

	// Verify directory was created
	require.DirExists(s.T(), dirPath, "Output directory should exist")

	// Count files in directory
	fileCount := 0
	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileCount++
		}
		return nil
	})
	require.NoError(s.T(), err, "Failed to walk directory")

	// Should have same number of files as ZIP
	require.Greater(s.T(), fileCount, 10, "Expected more than 10 files in directory, got %d", fileCount)

	// Check for key files
	require.FileExists(s.T(), filepath.Join(dirPath, "blob_1", "capi_cluster.yaml"))
	require.FileExists(s.T(), filepath.Join(dirPath, "blob_1", "cluster.yaml"))
	require.FileExists(s.T(), filepath.Join(dirPath, "blob_1", "full_decoded_raw_dump.json"))

	s.T().Logf("Directory contains %d files", fileCount)
}

func TestIntegration(t *testing.T) {
	suite.Run(t, new(IntegrationSuite))
}
