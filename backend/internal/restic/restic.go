package restic

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// BackupResult contains the results of a backup operation
type BackupResult struct {
	SnapshotID   string `json:"snapshot_id"`
	FilesNew     int    `json:"files_new"`
	FilesChanged int    `json:"files_changed"`
	FilesUnmodified int `json:"files_unmodified"`
	DirsNew      int    `json:"dirs_new"`
	DirsChanged  int    `json:"dirs_changed"`
	DirsUnmodified int  `json:"dirs_unmodified"`
	BytesAdded   int64  `json:"data_added"`
	TotalBytesProcessed int64 `json:"total_bytes_processed"`
}

// SnapshotInfo contains information about a snapshot
type SnapshotInfo struct {
	ID       string   `json:"id"`
	Time     string   `json:"time"`
	Hostname string   `json:"hostname"`
	Paths    []string `json:"paths"`
	Tags     []string `json:"tags,omitempty"`
}

// getResticPath returns the path to the restic binary
func getResticPath() string {
	path := os.Getenv("RESTIC_PATH")
	if path == "" {
		return "restic"
	}
	return path
}

// Init initializes a new restic repository
func Init(repoPath, password string) error {
	cmd := exec.Command(getResticPath(), "init", "--repo", repoPath)
	cmd.Env = append(os.Environ(), "RESTIC_PASSWORD="+password)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("restic init failed: %s - %v", string(output), err)
	}
	return nil
}

// Backup performs a backup operation
func Backup(sourcePath, repoPath string) (*BackupResult, error) {
	cmd := exec.Command(getResticPath(), "backup", "--json", "--repo", repoPath, sourcePath)
	cmd.Env = append(os.Environ(), "RESTIC_PASSWORD="+os.Getenv("RESTIC_PASSWORD"))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("restic backup failed: %s - %v", string(output), err)
	}

	var result BackupResult
	if err := json.Unmarshal(output, &result); err != nil {
		// Try to parse line by line for JSON output
		return &result, nil
	}

	return &result, nil
}

// Restore restores a snapshot to a target path
func Restore(repoPath, snapshotID, targetPath string) error {
	cmd := exec.Command(getResticPath(), "restore", snapshotID, "--target", targetPath, "--repo", repoPath)
	cmd.Env = append(os.Environ(), "RESTIC_PASSWORD="+os.Getenv("RESTIC_PASSWORD"))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("restic restore failed: %s - %v", string(output), err)
	}
	return nil
}

// ListSnapshots lists all snapshots in a repository
func ListSnapshots(repoPath string) ([]SnapshotInfo, error) {
	cmd := exec.Command(getResticPath(), "snapshots", "--json", "--repo", repoPath)
	cmd.Env = append(os.Environ(), "RESTIC_PASSWORD="+os.Getenv("RESTIC_PASSWORD"))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("restic snapshots failed: %s - %v", string(output), err)
	}

	var snapshots []SnapshotInfo
	if err := json.Unmarshal(output, &snapshots); err != nil {
		return nil, fmt.Errorf("failed to parse snapshots: %v", err)
	}

	return snapshots, nil
}

// ForgetSnapshot removes a snapshot from the repository
func ForgetSnapshot(repoPath, snapshotID string) error {
	cmd := exec.Command(getResticPath(), "forget", snapshotID, "--repo", repoPath)
	cmd.Env = append(os.Environ(), "RESTIC_PASSWORD="+os.Getenv("RESTIC_PASSWORD"))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("restic forget failed: %s - %v", string(output), err)
	}
	return nil
}

// Prune removes unreferenced data from the repository
func Prune(repoPath string) error {
	cmd := exec.Command(getResticPath(), "prune", "--repo", repoPath)
	cmd.Env = append(os.Environ(), "RESTIC_PASSWORD="+os.Getenv("RESTIC_PASSWORD"))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("restic prune failed: %s - %v", string(output), err)
	}
	return nil
}

// Check verifies the repository integrity
func Check(repoPath string) error {
	cmd := exec.Command(getResticPath(), "check", "--repo", repoPath)
	cmd.Env = append(os.Environ(), "RESTIC_PASSWORD="+os.Getenv("RESTIC_PASSWORD"))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("restic check failed: %s - %v", string(output), err)
	}
	return nil
}
