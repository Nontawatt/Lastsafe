package storage

import (
	"os"
	"path/filepath"

	"github.com/nontawatt/lastsafe/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// InitDatabase initializes the SQLite database
func InitDatabase() (*gorm.DB, error) {
	// Get database path from environment or use default
	dbPath := os.Getenv("DATABASE_PATH")
	if dbPath == "" {
		dbPath = "./data/lastsafe.db"
	}

	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	// Open database connection
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Auto-migrate models
	if err := db.AutoMigrate(
		&models.BackupJob{},
		&models.BackupHistory{},
		&models.StorageBackend{},
		&models.Repository{},
		&models.Snapshot{},
	); err != nil {
		return nil, err
	}

	return db, nil
}
