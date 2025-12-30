package api

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// SetupRouter initializes the API router with all routes
func SetupRouter(db *gorm.DB) *gin.Engine {
	router := gin.Default()

	// CORS middleware
	router.Use(corsMiddleware())

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Health check
		v1.GET("/health", healthCheck)

		// Backup jobs
		jobs := v1.Group("/jobs")
		{
			jobs.GET("", listJobs(db))
			jobs.POST("", createJob(db))
			jobs.GET("/:id", getJob(db))
			jobs.PUT("/:id", updateJob(db))
			jobs.DELETE("/:id", deleteJob(db))
			jobs.POST("/:id/run", runJob(db))
		}

		// Repositories
		repos := v1.Group("/repositories")
		{
			repos.GET("", listRepositories(db))
			repos.POST("", createRepository(db))
			repos.GET("/:id", getRepository(db))
			repos.DELETE("/:id", deleteRepository(db))
			repos.POST("/:id/init", initRepository(db))
		}

		// Snapshots
		snapshots := v1.Group("/snapshots")
		{
			snapshots.GET("", listSnapshots(db))
			snapshots.GET("/:id", getSnapshot(db))
			snapshots.DELETE("/:id", deleteSnapshot(db))
			snapshots.POST("/:id/restore", restoreSnapshot(db))
		}

		// Storage backends
		storage := v1.Group("/storage")
		{
			storage.GET("", listStorageBackends(db))
			storage.POST("", createStorageBackend(db))
			storage.GET("/:id", getStorageBackend(db))
			storage.PUT("/:id", updateStorageBackend(db))
			storage.DELETE("/:id", deleteStorageBackend(db))
		}

		// History
		v1.GET("/history", getBackupHistory(db))
	}

	return router
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}
