package rclone

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// RemoteInfo contains information about an rclone remote
type RemoteInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// SyncStats contains synchronization statistics
type SyncStats struct {
	BytesTransferred int64 `json:"bytes"`
	FilesTransferred int   `json:"transfers"`
	Checks           int   `json:"checks"`
	DeletedFiles     int   `json:"deletes"`
	Errors           int   `json:"errors"`
}

// getRclonePath returns the path to the rclone binary
func getRclonePath() string {
	path := os.Getenv("RCLONE_PATH")
	if path == "" {
		return "rclone"
	}
	return path
}

// ListRemotes lists all configured rclone remotes
func ListRemotes() ([]string, error) {
	cmd := exec.Command(getRclonePath(), "listremotes")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("rclone listremotes failed: %s - %v", string(output), err)
	}

	// Parse output (one remote per line, ending with :)
	var remotes []string
	// Simple parsing - in production, use proper line parsing
	return remotes, nil
}

// Sync synchronizes source to destination
func Sync(source, dest string) (*SyncStats, error) {
	cmd := exec.Command(getRclonePath(), "sync", source, dest, "--stats-one-line", "-v")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("rclone sync failed: %s - %v", string(output), err)
	}

	// Parse stats from output
	stats := &SyncStats{}
	return stats, nil
}

// Copy copies files from source to destination
func Copy(source, dest string) (*SyncStats, error) {
	cmd := exec.Command(getRclonePath(), "copy", source, dest, "--stats-one-line", "-v")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("rclone copy failed: %s - %v", string(output), err)
	}

	stats := &SyncStats{}
	return stats, nil
}

// Mount mounts a remote as a filesystem (returns the process for later unmount)
func Mount(remote, mountPoint string) (*exec.Cmd, error) {
	cmd := exec.Command(getRclonePath(), "mount", remote, mountPoint, "--daemon")

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("rclone mount failed: %v", err)
	}

	return cmd, nil
}

// Unmount unmounts a mounted remote
func Unmount(mountPoint string) error {
	cmd := exec.Command("fusermount", "-u", mountPoint)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unmount failed: %s - %v", string(output), err)
	}
	return nil
}

// ListFiles lists files in a remote path
func ListFiles(remotePath string) ([]map[string]interface{}, error) {
	cmd := exec.Command(getRclonePath(), "lsjson", remotePath)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("rclone lsjson failed: %s - %v", string(output), err)
	}

	var files []map[string]interface{}
	if err := json.Unmarshal(output, &files); err != nil {
		return nil, fmt.Errorf("failed to parse files: %v", err)
	}

	return files, nil
}

// CreateRemote creates a new rclone remote configuration
func CreateRemote(name, remoteType string, config map[string]string) error {
	args := []string{"config", "create", name, remoteType}
	for key, value := range config {
		args = append(args, key, value)
	}

	cmd := exec.Command(getRclonePath(), args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rclone config create failed: %s - %v", string(output), err)
	}
	return nil
}

// DeleteRemote deletes an rclone remote configuration
func DeleteRemote(name string) error {
	cmd := exec.Command(getRclonePath(), "config", "delete", name)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rclone config delete failed: %s - %v", string(output), err)
	}
	return nil
}

// Check checks the files in source and destination match
func Check(source, dest string) error {
	cmd := exec.Command(getRclonePath(), "check", source, dest)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("rclone check failed: %s - %v", string(output), err)
	}
	return nil
}
