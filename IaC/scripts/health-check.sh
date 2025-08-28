#!/bin/bash

# VaulTLS Health Check Script
# Comprehensive health monitoring for all services

set -euo pipefail

# Configuration
FRONTEND_URL="${FRONTEND_URL:-http://localhost:3000}"
BACKEND_URL="${BACKEND_URL:-http://localhost:8000}"
DATABASE_HOST="${DATABASE_HOST:-localhost}"
DATABASE_PORT="${DATABASE_PORT:-5432}"
DATABASE_USER="${DATABASE_USER:-vaultls}"
DATABASE_NAME="${DATABASE_NAME:-vaultls}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Status tracking
OVERALL_STATUS=0
CHECKS_PASSED=0
CHECKS_TOTAL=0

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((CHECKS_PASSED++))
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
    OVERALL_STATUS=1
}

log_check() {
    ((CHECKS_TOTAL++))
}

# Health check functions
check_frontend() {
    log_info "Checking frontend health..."
    log_check
    
    if curl -f -s "$FRONTEND_URL/health" > /dev/null 2>&1; then
        log_success "Frontend is healthy"
    else
        log_error "Frontend health check failed"
    fi
}

check_backend() {
    log_info "Checking backend health..."
    log_check
    
    if curl -f -s "$BACKEND_URL/api/server/health" > /dev/null 2>&1; then
        log_success "Backend is healthy"
    else
        log_error "Backend health check failed"
    fi
}

check_backend_version() {
    log_info "Checking backend version..."
    log_check
    
    local version=$(curl -s "$BACKEND_URL/api/server/version" 2>/dev/null || echo "unknown")
    if [[ $version != "unknown" ]]; then
        log_success "Backend version: $version"
    else
        log_error "Could not retrieve backend version"
    fi
}

check_database() {
    log_info "Checking database connectivity..."
    log_check
    
    if command -v pg_isready &> /dev/null; then
        if pg_isready -h "$DATABASE_HOST" -p "$DATABASE_PORT" -U "$DATABASE_USER" -d "$DATABASE_NAME" > /dev/null 2>&1; then
            log_success "Database is accessible"
        else
            log_error "Database is not accessible"
        fi
    else
        log_warning "pg_isready not available, skipping database check"
    fi
}

check_api_authentication() {
    log_info "Checking API authentication..."
    log_check
    
    local response=$(curl -s -o /dev/null -w "%{http_code}" "$BACKEND_URL/api/certificates/search" 2>/dev/null || echo "000")
    if [[ $response == "401" ]]; then
        log_success "API authentication is working (401 Unauthorized as expected)"
    else
        log_error "API authentication check failed (expected 401, got $response)"
    fi
}

check_api_docs() {
    log_info "Checking API documentation..."
    log_check
    
    if curl -f -s "$BACKEND_URL/docs" > /dev/null 2>&1; then
        log_success "API documentation is accessible"
    else
        log_error "API documentation is not accessible"
    fi
}

check_ssl_certificates() {
    log_info "Checking SSL certificate validity..."
    log_check
    
    if [[ $FRONTEND_URL == https://* ]]; then
        local domain=$(echo "$FRONTEND_URL" | sed 's|https://||' | sed 's|/.*||')
        local expiry=$(echo | openssl s_client -servername "$domain" -connect "$domain:443" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null | grep notAfter | cut -d= -f2)
        
        if [[ -n $expiry ]]; then
            log_success "SSL certificate expires: $expiry"
        else
            log_error "Could not check SSL certificate"
        fi
    else
        log_warning "Not using HTTPS, skipping SSL check"
    fi
}

check_disk_space() {
    log_info "Checking disk space..."
    log_check
    
    local usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $usage -lt 80 ]]; then
        log_success "Disk usage: ${usage}%"
    elif [[ $usage -lt 90 ]]; then
        log_warning "Disk usage: ${usage}% (warning threshold)"
    else
        log_error "Disk usage: ${usage}% (critical threshold)"
    fi
}

check_memory_usage() {
    log_info "Checking memory usage..."
    log_check
    
    if command -v free &> /dev/null; then
        local mem_usage=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
        if [[ $mem_usage -lt 80 ]]; then
            log_success "Memory usage: ${mem_usage}%"
        elif [[ $mem_usage -lt 90 ]]; then
            log_warning "Memory usage: ${mem_usage}% (warning threshold)"
        else
            log_error "Memory usage: ${mem_usage}% (critical threshold)"
        fi
    else
        log_warning "free command not available, skipping memory check"
    fi
}

check_docker_containers() {
    log_info "Checking Docker containers..."
    log_check
    
    if command -v docker &> /dev/null; then
        local unhealthy=$(docker ps --filter "health=unhealthy" --format "table {{.Names}}" | tail -n +2)
        if [[ -z $unhealthy ]]; then
            log_success "All Docker containers are healthy"
        else
            log_error "Unhealthy containers: $unhealthy"
        fi
    else
        log_warning "Docker not available, skipping container check"
    fi
}

# Performance checks
check_response_times() {
    log_info "Checking response times..."
    log_check
    
    local frontend_time=$(curl -o /dev/null -s -w "%{time_total}" "$FRONTEND_URL/health" 2>/dev/null || echo "999")
    local backend_time=$(curl -o /dev/null -s -w "%{time_total}" "$BACKEND_URL/api/server/health" 2>/dev/null || echo "999")
    
    if (( $(echo "$frontend_time < 2.0" | bc -l) )); then
        log_success "Frontend response time: ${frontend_time}s"
    else
        log_error "Frontend response time too slow: ${frontend_time}s"
    fi
    
    if (( $(echo "$backend_time < 2.0" | bc -l) )); then
        log_success "Backend response time: ${backend_time}s"
    else
        log_error "Backend response time too slow: ${backend_time}s"
    fi
}

# Main health check function
run_health_checks() {
    log_info "Starting VaulTLS health checks..."
    echo
    
    # Core service checks
    check_frontend
    check_backend
    check_backend_version
    check_database
    
    # API functionality checks
    check_api_authentication
    check_api_docs
    
    # Security checks
    check_ssl_certificates
    
    # System resource checks
    check_disk_space
    check_memory_usage
    
    # Container checks
    check_docker_containers
    
    # Performance checks
    check_response_times
    
    echo
    log_info "Health check summary:"
    echo -e "  Checks passed: ${GREEN}$CHECKS_PASSED${NC}/$CHECKS_TOTAL"
    
    if [[ $OVERALL_STATUS -eq 0 ]]; then
        log_success "All health checks passed!"
    else
        log_error "Some health checks failed!"
    fi
    
    exit $OVERALL_STATUS
}

# Help function
show_help() {
    cat << EOF
VaulTLS Health Check Script

Usage: $0 [options]

Options:
  -h, --help           Show this help message
  --frontend-url URL   Frontend URL (default: http://localhost:3000)
  --backend-url URL    Backend URL (default: http://localhost:8000)
  --db-host HOST       Database host (default: localhost)
  --db-port PORT       Database port (default: 5432)

Environment Variables:
  FRONTEND_URL         Frontend URL
  BACKEND_URL          Backend URL
  DATABASE_HOST        Database host
  DATABASE_PORT        Database port
  DATABASE_USER        Database user
  DATABASE_NAME        Database name

Examples:
  $0
  $0 --frontend-url https://vaultls.company.com
  BACKEND_URL=https://api.vaultls.company.com $0

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        --frontend-url)
            FRONTEND_URL="$2"
            shift 2
            ;;
        --backend-url)
            BACKEND_URL="$2"
            shift 2
            ;;
        --db-host)
            DATABASE_HOST="$2"
            shift 2
            ;;
        --db-port)
            DATABASE_PORT="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Run health checks
run_health_checks
