#!/bin/bash

# VaulTLS Deployment Script
# Usage: ./deploy.sh [environment] [action]
# Environment: development, testing, production
# Action: up, down, restart, logs, backup

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_DIR="$PROJECT_ROOT/IaC/docker-compose"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
VaulTLS Deployment Script

Usage: $0 [environment] [action]

Environments:
  development  - Local development environment
  testing      - Testing environment with test runners
  production   - Production environment

Actions:
  up           - Start services
  down         - Stop and remove services
  restart      - Restart services
  logs         - Show service logs
  backup       - Create database backup (production only)
  restore      - Restore database from backup (production only)
  health       - Check service health
  update       - Pull latest images and restart

Examples:
  $0 development up
  $0 production restart
  $0 testing logs
  $0 production backup

EOF
}

# Validate environment
validate_environment() {
    local env=$1
    case $env in
        development|testing|production)
            return 0
            ;;
        *)
            log_error "Invalid environment: $env"
            show_help
            exit 1
            ;;
    esac
}

# Check prerequisites
check_prerequisites() {
    local env=$1
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check environment file for production
    if [[ $env == "production" ]]; then
        if [[ ! -f "$COMPOSE_DIR/.env.production" ]]; then
            log_error "Production environment file not found: $COMPOSE_DIR/.env.production"
            log_info "Copy .env.production.template and configure it"
            exit 1
        fi
    fi
    
    log_success "Prerequisites check passed"
}

# Get compose file path
get_compose_file() {
    local env=$1
    echo "$COMPOSE_DIR/$env.yml"
}

# Get environment file
get_env_file() {
    local env=$1
    if [[ $env == "production" ]]; then
        echo "$COMPOSE_DIR/.env.production"
    else
        echo ""
    fi
}

# Execute docker-compose command
execute_compose() {
    local env=$1
    local action=$2
    shift 2
    
    local compose_file=$(get_compose_file $env)
    local env_file=$(get_env_file $env)
    
    local cmd="docker-compose -f $compose_file"
    if [[ -n $env_file ]]; then
        cmd="$cmd --env-file $env_file"
    fi
    
    log_info "Executing: $cmd $action $*"
    $cmd $action "$@"
}

# Start services
start_services() {
    local env=$1
    log_info "Starting $env environment..."
    execute_compose $env up -d
    log_success "$env environment started"
}

# Stop services
stop_services() {
    local env=$1
    log_info "Stopping $env environment..."
    execute_compose $env down
    log_success "$env environment stopped"
}

# Restart services
restart_services() {
    local env=$1
    log_info "Restarting $env environment..."
    execute_compose $env restart
    log_success "$env environment restarted"
}

# Show logs
show_logs() {
    local env=$1
    log_info "Showing logs for $env environment..."
    execute_compose $env logs -f
}

# Check health
check_health() {
    local env=$1
    log_info "Checking health for $env environment..."
    execute_compose $env ps
}

# Create backup (production only)
create_backup() {
    local env=$1
    if [[ $env != "production" ]]; then
        log_error "Backup is only available for production environment"
        exit 1
    fi
    
    log_info "Creating database backup..."
    local backup_name="vaultls_backup_$(date +%Y%m%d_%H%M%S).sql"
    execute_compose $env exec database pg_dump -U vaultls vaultls > "backups/$backup_name"
    log_success "Backup created: backups/$backup_name"
}

# Update services
update_services() {
    local env=$1
    log_info "Updating $env environment..."
    execute_compose $env pull
    execute_compose $env up -d
    log_success "$env environment updated"
}

# Main function
main() {
    if [[ $# -lt 2 ]]; then
        show_help
        exit 1
    fi
    
    local environment=$1
    local action=$2
    
    validate_environment $environment
    check_prerequisites $environment
    
    case $action in
        up)
            start_services $environment
            ;;
        down)
            stop_services $environment
            ;;
        restart)
            restart_services $environment
            ;;
        logs)
            show_logs $environment
            ;;
        backup)
            create_backup $environment
            ;;
        health)
            check_health $environment
            ;;
        update)
            update_services $environment
            ;;
        *)
            log_error "Invalid action: $action"
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
