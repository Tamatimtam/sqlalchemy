#!/bin/bash

echo "Setting up PostgreSQL with Docker for SQLAlchemy project..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "Docker Compose is not available. Please install Docker Compose."
    exit 1
fi

# Start PostgreSQL container
echo "Starting PostgreSQL container..."
docker-compose up -d

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
sleep 10

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

echo "Setup complete!"
echo "PostgreSQL is running on localhost:5432"
echo "Database: orm_db"
echo "Username: postgres"
echo "Password: password"
echo ""
echo "To stop PostgreSQL: docker-compose down"
echo "To view logs: docker-compose logs postgres"
echo "To connect via psql: docker exec -it sqlalchemy_postgres psql -U postgres -d orm_db"
