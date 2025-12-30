package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/nontawatt/lastsafe/internal/models"
	"gorm.io/gorm"
)

// Health check handler
func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "lastsafe",
	})
}

// Job handlers
func listJobs(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var jobs []models.BackupJob
		if err := db.Find(&jobs).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, jobs)
	}
}

func createJob(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var job models.BackupJob
		if err := c.ShouldBindJSON(&job); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := db.Create(&job).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, job)
	}
}

func getJob(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var job models.BackupJob
		if err := db.First(&job, c.Param("id")).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
			return
		}
		c.JSON(http.StatusOK, job)
	}
}

func updateJob(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var job models.BackupJob
		if err := db.First(&job, c.Param("id")).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
			return
		}
		if err := c.ShouldBindJSON(&job); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		db.Save(&job)
		c.JSON(http.StatusOK, job)
	}
}

func deleteJob(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := db.Delete(&models.BackupJob{}, c.Param("id")).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Job deleted"})
	}
}

func runJob(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var job models.BackupJob
		if err := db.First(&job, c.Param("id")).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Job not found"})
			return
		}
		// TODO: Trigger backup job execution
		c.JSON(http.StatusAccepted, gin.H{"message": "Job execution started", "job_id": job.ID})
	}
}

// Repository handlers
func listRepositories(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var repos []models.Repository
		if err := db.Find(&repos).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, repos)
	}
}

func createRepository(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var repo models.Repository
		if err := c.ShouldBindJSON(&repo); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := db.Create(&repo).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, repo)
	}
}

func getRepository(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var repo models.Repository
		if err := db.First(&repo, c.Param("id")).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Repository not found"})
			return
		}
		c.JSON(http.StatusOK, repo)
	}
}

func deleteRepository(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := db.Delete(&models.Repository{}, c.Param("id")).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Repository deleted"})
	}
}

func initRepository(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var repo models.Repository
		if err := db.First(&repo, c.Param("id")).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Repository not found"})
			return
		}
		// TODO: Initialize restic repository
		repo.Initialized = true
		db.Save(&repo)
		c.JSON(http.StatusOK, gin.H{"message": "Repository initialized"})
	}
}

// Snapshot handlers
func listSnapshots(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var snapshots []models.Snapshot
		if err := db.Find(&snapshots).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, snapshots)
	}
}

func getSnapshot(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var snapshot models.Snapshot
		if err := db.First(&snapshot, c.Param("id")).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Snapshot not found"})
			return
		}
		c.JSON(http.StatusOK, snapshot)
	}
}

func deleteSnapshot(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Delete snapshot from restic repository
		if err := db.Delete(&models.Snapshot{}, c.Param("id")).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Snapshot deleted"})
	}
}

func restoreSnapshot(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var snapshot models.Snapshot
		if err := db.First(&snapshot, c.Param("id")).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Snapshot not found"})
			return
		}
		// TODO: Restore snapshot using restic
		c.JSON(http.StatusAccepted, gin.H{"message": "Restore started", "snapshot_id": snapshot.SnapshotID})
	}
}

// Storage backend handlers
func listStorageBackends(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var backends []models.StorageBackend
		if err := db.Find(&backends).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, backends)
	}
}

func createStorageBackend(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var backend models.StorageBackend
		if err := c.ShouldBindJSON(&backend); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := db.Create(&backend).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, backend)
	}
}

func getStorageBackend(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var backend models.StorageBackend
		if err := db.First(&backend, c.Param("id")).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Storage backend not found"})
			return
		}
		c.JSON(http.StatusOK, backend)
	}
}

func updateStorageBackend(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var backend models.StorageBackend
		if err := db.First(&backend, c.Param("id")).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Storage backend not found"})
			return
		}
		if err := c.ShouldBindJSON(&backend); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		db.Save(&backend)
		c.JSON(http.StatusOK, backend)
	}
}

func deleteStorageBackend(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := db.Delete(&models.StorageBackend{}, c.Param("id")).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Storage backend deleted"})
	}
}

// History handler
func getBackupHistory(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var history []models.BackupHistory
		if err := db.Order("created_at desc").Limit(100).Find(&history).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, history)
	}
}
