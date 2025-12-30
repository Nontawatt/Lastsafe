.PHONY: all build run dev stop clean test lint help

# Default target
all: build

# Build all containers
build:
	docker-compose build

# Run in production mode
run:
	docker-compose up -d

# Run in development mode with logs
dev:
	docker-compose up

# Stop all containers
stop:
	docker-compose down

# Clean up containers and volumes
clean:
	docker-compose down -v
	rm -rf data/*.db

# Run backend tests
test-backend:
	cd backend && go test ./...

# Run frontend tests
test-frontend:
	cd frontend && npm test

# Run all tests
test: test-backend test-frontend

# Lint backend code
lint-backend:
	cd backend && go vet ./...
	cd backend && golangci-lint run

# Lint frontend code
lint-frontend:
	cd frontend && npm run lint

# Lint all code
lint: lint-backend lint-frontend

# Install dependencies
deps:
	cd backend && go mod download
	cd frontend && npm install

# Build backend locally
build-backend:
	cd backend && go build -o bin/lastsafe ./cmd/lastsafe

# Build frontend locally
build-frontend:
	cd frontend && npm run build

# Run backend locally
run-backend:
	cd backend && go run ./cmd/lastsafe

# Run frontend locally
run-frontend:
	cd frontend && npm run dev

# Generate API documentation
docs:
	cd backend && swag init -g cmd/lastsafe/main.go

# Database migrations
migrate:
	@echo "Migrations are handled automatically by GORM"

# Show logs
logs:
	docker-compose logs -f

# Show backend logs
logs-backend:
	docker-compose logs -f backend

# Show frontend logs
logs-frontend:
	docker-compose logs -f frontend

# Rebuild and restart
restart: stop build run

# Help
help:
	@echo "Lastsafe - Backup & Sync Manager"
	@echo ""
	@echo "Usage:"
	@echo "  make build          Build all Docker containers"
	@echo "  make run            Run in production mode (detached)"
	@echo "  make dev            Run in development mode with logs"
	@echo "  make stop           Stop all containers"
	@echo "  make clean          Remove containers and data"
	@echo "  make test           Run all tests"
	@echo "  make lint           Run linters"
	@echo "  make deps           Install dependencies"
	@echo "  make logs           Show container logs"
	@echo "  make restart        Rebuild and restart"
	@echo "  make help           Show this help"
