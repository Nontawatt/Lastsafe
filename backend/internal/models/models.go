package models

import (
	"time"

	"gorm.io/gorm"
)

// BackupJob represents a scheduled backup job
type BackupJob struct {
	gorm.Model
	Name        string    `json:"name" gorm:"not null"`
	SourcePath  string    `json:"source_path" gorm:"not null"`
	Destination string    `json:"destination" gorm:"not null"`
	Schedule    string    `json:"schedule"` // Cron expression
	Enabled     bool      `json:"enabled" gorm:"default:true"`
	LastRun     time.Time `json:"last_run"`
	NextRun     time.Time `json:"next_run"`
	Status      string    `json:"status" gorm:"default:idle"` // idle, running, success, failed
}

// BackupHistory stores backup execution history
type BackupHistory struct {
	gorm.Model
	JobID       uint      `json:"job_id" gorm:"not null"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Status      string    `json:"status"` // success, failed
	BytesAdded  int64     `json:"bytes_added"`
	FilesNew    int       `json:"files_new"`
	FilesChanged int      `json:"files_changed"`
	ErrorMsg    string    `json:"error_msg"`
	SnapshotID  string    `json:"snapshot_id"`
}

// StorageBackend represents a storage backend configuration
type StorageBackend struct {
	gorm.Model
	Name     string `json:"name" gorm:"not null;unique"`
	Type     string `json:"type" gorm:"not null"` // local, s3, gcs, azure, sftp, etc.
	Config   string `json:"config"`               // JSON configuration
	Enabled  bool   `json:"enabled" gorm:"default:true"`
}

// Repository represents a Restic repository
type Repository struct {
	gorm.Model
	Name           string `json:"name" gorm:"not null;unique"`
	Path           string `json:"path" gorm:"not null"`
	StorageBackend uint   `json:"storage_backend_id"`
	Password       string `json:"-"` // Encrypted password
	Initialized    bool   `json:"initialized" gorm:"default:false"`
}

// Snapshot represents a Restic snapshot
type Snapshot struct {
	gorm.Model
	SnapshotID   string    `json:"snapshot_id" gorm:"not null;unique"`
	RepositoryID uint      `json:"repository_id"`
	Hostname     string    `json:"hostname"`
	Paths        string    `json:"paths"` // JSON array
	Time         time.Time `json:"time"`
	Tags         string    `json:"tags"` // JSON array
}
