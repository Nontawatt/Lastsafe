package main

import (
	"log"
	"os"

	"github.com/nontawatt/lastsafe/internal/api"
	"github.com/nontawatt/lastsafe/internal/scheduler"
	"github.com/nontawatt/lastsafe/internal/storage"
)

func main() {
	log.Println("Starting Lastsafe Backup Service...")

	// Initialize storage
	db, err := storage.InitDatabase()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize scheduler
	sched := scheduler.NewScheduler(db)
	sched.Start()
	defer sched.Stop()

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Start API server
	router := api.SetupRouter(db)
	log.Printf("Server starting on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
