package scheduler

import (
	"log"
	"time"

	"github.com/nontawatt/lastsafe/internal/models"
	"github.com/nontawatt/lastsafe/internal/restic"
	"github.com/robfig/cron/v3"
	"gorm.io/gorm"
)

// Scheduler manages backup job scheduling
type Scheduler struct {
	cron *cron.Cron
	db   *gorm.DB
}

// NewScheduler creates a new scheduler instance
func NewScheduler(db *gorm.DB) *Scheduler {
	return &Scheduler{
		cron: cron.New(cron.WithSeconds()),
		db:   db,
	}
}

// Start begins the scheduler and loads all enabled jobs
func (s *Scheduler) Start() {
	log.Println("Starting backup scheduler...")

	// Load enabled jobs from database
	var jobs []models.BackupJob
	s.db.Where("enabled = ?", true).Find(&jobs)

	for _, job := range jobs {
		if job.Schedule != "" {
			s.addJob(job)
		}
	}

	s.cron.Start()
	log.Printf("Scheduler started with %d jobs", len(jobs))
}

// Stop stops the scheduler
func (s *Scheduler) Stop() {
	log.Println("Stopping backup scheduler...")
	s.cron.Stop()
}

// addJob adds a backup job to the scheduler
func (s *Scheduler) addJob(job models.BackupJob) {
	_, err := s.cron.AddFunc(job.Schedule, func() {
		s.runBackup(job.ID)
	})
	if err != nil {
		log.Printf("Failed to schedule job %d (%s): %v", job.ID, job.Name, err)
	} else {
		log.Printf("Scheduled job %d (%s) with cron: %s", job.ID, job.Name, job.Schedule)
	}
}

// runBackup executes a backup job
func (s *Scheduler) runBackup(jobID uint) {
	var job models.BackupJob
	if err := s.db.First(&job, jobID).Error; err != nil {
		log.Printf("Job %d not found: %v", jobID, err)
		return
	}

	// Update job status
	job.Status = "running"
	job.LastRun = time.Now()
	s.db.Save(&job)

	// Create history entry
	history := models.BackupHistory{
		JobID:     jobID,
		StartTime: time.Now(),
		Status:    "running",
	}
	s.db.Create(&history)

	// Execute backup using restic
	result, err := restic.Backup(job.SourcePath, job.Destination)

	history.EndTime = time.Now()
	if err != nil {
		history.Status = "failed"
		history.ErrorMsg = err.Error()
		job.Status = "failed"
	} else {
		history.Status = "success"
		history.SnapshotID = result.SnapshotID
		history.BytesAdded = result.BytesAdded
		history.FilesNew = result.FilesNew
		history.FilesChanged = result.FilesChanged
		job.Status = "success"
	}

	s.db.Save(&history)
	s.db.Save(&job)

	log.Printf("Backup job %d (%s) completed with status: %s", jobID, job.Name, history.Status)
}

// ReloadJob reloads a specific job's schedule
func (s *Scheduler) ReloadJob(jobID uint) error {
	var job models.BackupJob
	if err := s.db.First(&job, jobID).Error; err != nil {
		return err
	}

	// For simplicity, restart the entire scheduler
	// In production, you'd want to track cron entry IDs
	s.cron.Stop()
	s.cron = cron.New(cron.WithSeconds())
	s.Start()

	return nil
}
