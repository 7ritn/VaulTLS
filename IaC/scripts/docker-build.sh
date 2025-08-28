#!/bin/bash

# VaulTLS Docker Build & Publish Script
# Usage: ./docker-build.sh [options]

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOCKER_REGISTRY="${DOCKER_REGISTRY:-docker.io}"
DOCKER_NAMESPACE="${DOCKER_NAMESPACE:-vaultls}"
VERSION_FILE="$PROJECT_ROOT/VERSION"
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values
BUILD_FRONTEND=true
BUILD_BACKEND=true
BUILD_DATABASE=false
PUSH_IMAGES=false
LATEST_TAG=false
PLATFORM="linux/amd64"
VERSION=""

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
VaulTLS Docker Build & Publish Script

Usage: $0 [options]

Options:
  -h, --help              Show this help message
  -v, --version VERSION   Set version tag (default: from VERSION file or git tag)
  -p, --push              Push images to registry after building
  -l, --latest            Also tag as 'latest'
  --frontend-only         Build only frontend image
  --backend-only          Build only backend image
  --database              Also build database image
  --platform PLATFORM    Target platform (default: linux/amd64)
  --registry REGISTRY     Docker registry (default: docker.io)
  --namespace NAMESPACE   Docker namespace (default: vaultls)

Environment Variables:
  DOCKER_REGISTRY         Docker registry URL
  DOCKER_NAMESPACE        Docker namespace/organization
  DOCKER_USERNAME         Docker Hub username (for push)
  DOCKER_PASSWORD         Docker Hub password/token (for push)

Examples:
  $0                                    # Build all images locally
  $0 --push --latest                   # Build and push with latest tag
  $0 --frontend-only --version 2.1.0   # Build only frontend with specific version
  $0 --platform linux/amd64,linux/arm64 # Multi-platform build

EOF
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Buildx for multi-platform builds
    if [[ $PLATFORM == *","* ]]; then
        if ! docker buildx version &> /dev/null; then
            log_error "Docker Buildx is required for multi-platform builds"
            exit 1
        fi
    fi
    
    # Check git for version info
    if ! command -v git &> /dev/null; then
        log_warning "Git not found, using default version info"
    fi
    
    # Check if we're in the right directory
    if [[ ! -f "$PROJECT_ROOT/backend/Cargo.toml" ]] || [[ ! -f "$PROJECT_ROOT/frontend/package.json" ]]; then
        log_error "Not in VaulTLS project root directory"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Get version
get_version() {
    if [[ -n $VERSION ]]; then
        echo "$VERSION"
        return
    fi
    
    # Try VERSION file first
    if [[ -f $VERSION_FILE ]]; then
        cat "$VERSION_FILE"
        return
    fi
    
    # Try git tag
    local git_version=$(git describe --tags --exact-match 2>/dev/null || echo "")
    if [[ -n $git_version ]]; then
        echo "$git_version"
        return
    fi
    
    # Fallback to git commit
    echo "dev-$GIT_COMMIT"
}

# Docker login
docker_login() {
    if [[ $PUSH_IMAGES == true ]]; then
        log_info "Logging into Docker registry..."
        
        if [[ -n ${DOCKER_USERNAME:-} ]] && [[ -n ${DOCKER_PASSWORD:-} ]]; then
            echo "$DOCKER_PASSWORD" | docker login "$DOCKER_REGISTRY" -u "$DOCKER_USERNAME" --password-stdin
            log_success "Docker login successful"
        else
            log_warning "DOCKER_USERNAME or DOCKER_PASSWORD not set, assuming already logged in"
        fi
    fi
}

# Build image
build_image() {
    local component=$1
    local dockerfile=$2
    local context=$3
    local image_name="$DOCKER_REGISTRY/$DOCKER_NAMESPACE/vaultls-$component"
    local version=$(get_version)
    
    log_info "Building $component image..."
    log_info "Image: $image_name:$version"
    log_info "Dockerfile: $dockerfile"
    log_info "Context: $context"
    
    # Build arguments
    local build_args=(
        --build-arg "VERSION=$version"
        --build-arg "BUILD_DATE=$BUILD_DATE"
        --build-arg "GIT_COMMIT=$GIT_COMMIT"
        --build-arg "GIT_BRANCH=$GIT_BRANCH"
        --label "org.opencontainers.image.version=$version"
        --label "org.opencontainers.image.created=$BUILD_DATE"
        --label "org.opencontainers.image.revision=$GIT_COMMIT"
        --label "org.opencontainers.image.source=https://github.com/Grace-Solutions/VaulTLS"
    )
    
    # Multi-platform build
    if [[ $PLATFORM == *","* ]]; then
        docker buildx create --use --name vaultls-builder 2>/dev/null || true
        docker buildx build \
            "${build_args[@]}" \
            --platform "$PLATFORM" \
            --file "$dockerfile" \
            --tag "$image_name:$version" \
            $(if [[ $LATEST_TAG == true ]]; then echo "--tag $image_name:latest"; fi) \
            $(if [[ $PUSH_IMAGES == true ]]; then echo "--push"; else echo "--load"; fi) \
            "$context"
    else
        docker build \
            "${build_args[@]}" \
            --platform "$PLATFORM" \
            --file "$dockerfile" \
            --tag "$image_name:$version" \
            $(if [[ $LATEST_TAG == true ]]; then echo "--tag $image_name:latest"; fi) \
            "$context"
    fi
    
    log_success "$component image built successfully"
    
    # Push if requested and not multi-platform (already pushed above)
    if [[ $PUSH_IMAGES == true ]] && [[ $PLATFORM != *","* ]]; then
        log_info "Pushing $component image..."
        docker push "$image_name:$version"
        if [[ $LATEST_TAG == true ]]; then
            docker push "$image_name:latest"
        fi
        log_success "$component image pushed successfully"
    fi
}

# Build frontend
build_frontend() {
    if [[ $BUILD_FRONTEND == true ]]; then
        build_image "frontend" "$PROJECT_ROOT/IaC/docker/frontend/Dockerfile" "$PROJECT_ROOT"
    fi
}

# Build backend
build_backend() {
    if [[ $BUILD_BACKEND == true ]]; then
        build_image "backend" "$PROJECT_ROOT/IaC/docker/backend/Dockerfile" "$PROJECT_ROOT"
    fi
}

# Build database
build_database() {
    if [[ $BUILD_DATABASE == true ]]; then
        build_image "database" "$PROJECT_ROOT/IaC/docker/database/Dockerfile" "$PROJECT_ROOT"
    fi
}

# Show build summary
show_summary() {
    local version=$(get_version)
    
    log_info "Build Summary:"
    echo "  Version: $version"
    echo "  Registry: $DOCKER_REGISTRY"
    echo "  Namespace: $DOCKER_NAMESPACE"
    echo "  Platform: $PLATFORM"
    echo "  Git Commit: $GIT_COMMIT"
    echo "  Git Branch: $GIT_BRANCH"
    echo "  Build Date: $BUILD_DATE"
    echo
    echo "  Components built:"
    if [[ $BUILD_FRONTEND == true ]]; then
        echo "    ✓ Frontend: $DOCKER_REGISTRY/$DOCKER_NAMESPACE/vaultls-frontend:$version"
    fi
    if [[ $BUILD_BACKEND == true ]]; then
        echo "    ✓ Backend: $DOCKER_REGISTRY/$DOCKER_NAMESPACE/vaultls-backend:$version"
    fi
    if [[ $BUILD_DATABASE == true ]]; then
        echo "    ✓ Database: $DOCKER_REGISTRY/$DOCKER_NAMESPACE/vaultls-database:$version"
    fi
    
    if [[ $PUSH_IMAGES == true ]]; then
        echo
        log_success "All images have been pushed to the registry!"
        echo
        echo "To deploy these images:"
        echo "  docker pull $DOCKER_REGISTRY/$DOCKER_NAMESPACE/vaultls-frontend:$version"
        echo "  docker pull $DOCKER_REGISTRY/$DOCKER_NAMESPACE/vaultls-backend:$version"
        if [[ $BUILD_DATABASE == true ]]; then
            echo "  docker pull $DOCKER_REGISTRY/$DOCKER_NAMESPACE/vaultls-database:$version"
        fi
    else
        echo
        log_success "All images have been built locally!"
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -p|--push)
            PUSH_IMAGES=true
            shift
            ;;
        -l|--latest)
            LATEST_TAG=true
            shift
            ;;
        --frontend-only)
            BUILD_FRONTEND=true
            BUILD_BACKEND=false
            BUILD_DATABASE=false
            shift
            ;;
        --backend-only)
            BUILD_FRONTEND=false
            BUILD_BACKEND=true
            BUILD_DATABASE=false
            shift
            ;;
        --database)
            BUILD_DATABASE=true
            shift
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        --registry)
            DOCKER_REGISTRY="$2"
            shift 2
            ;;
        --namespace)
            DOCKER_NAMESPACE="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Main execution
main() {
    log_info "Starting VaulTLS Docker build process..."
    
    check_prerequisites
    docker_login
    
    # Build images
    build_frontend
    build_backend
    build_database
    
    show_summary
}

# Run main function
main "$@"
