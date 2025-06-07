.PHONY: build run test clean migrate-up migrate-down docker-up docker-down docker-build

build:
	go build -o bin/server cmd/server/main.go

run:
	go run cmd/server/main.go

test:
	go test -v ./...

clean:
	rm -rf bin/

migrate-up:
	migrate -path migrations -database "$(DATABASE_URL)" up

migrate-down:
	migrate -path migrations -database "$(DATABASE_URL)" down

# Debug build to troubleshoot Docker issues
docker-debug:
	docker build -f Dockerfile.debug -t oauth-backend-debug .

docker-build:
	docker build -t oauth-backend .

# Build with no cache to ensure fresh build
docker-build-fresh:
	docker build --no-cache -t oauth-backend .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

docker-restart:
	docker-compose restart app

install-deps:
	go mod tidy
	go mod verify

# Check if the project builds locally first
verify-build:
	go mod tidy
	go mod verify
	go build -v ./cmd/server
	@echo "✅ Local build successful"

# Development with just databases
dev-db:
	docker-compose up -d postgres redis
	sleep 5

# Full development with all services - but build locally first
dev: verify-build docker-up

# Production build and run
prod-build:
	docker build -t oauth-backend:latest .

prod-run:
	docker run -p 8080:8080 --env-file .env oauth-backend:latest

# Clean up Docker resources
docker-clean:
	docker-compose down -v
	docker system prune -f

# Troubleshooting commands
debug: verify-build docker-debug
	@echo "🔍 Debug build completed. Check for issues in build output above."