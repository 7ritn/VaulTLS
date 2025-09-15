# Stage 1: Build the Vue.js frontend
FROM node:23 AS frontend-builder

COPY assets/logo.png /app/assets/logo.png

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN --mount=type=cache,target=/root/.npm npm install

COPY frontend/ ./
RUN npm run build

# Stage 2: Build the Rust backend binary
FROM rust:1.87 AS backend-builder

ARG RUN_TESTS=false
WORKDIR /app/backend
COPY backend/ ./

RUN --mount=type=cache,target=/app/backend/target \
    --mount=type=cache,target=/usr/local/cargo/git/db \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    cargo build --release \
    && cp target/release/backend backend \
    && if [ "$RUN_TESTS" = "true" ]; then \
         cargo test --features test-mode; \
       else \
         echo "Skipping tests"; \
       fi

# Stage 3 Final container with Nginx and backend binary
FROM nginx:stable

WORKDIR /app/data
COPY --from=frontend-builder /app/frontend/dist/ /usr/share/nginx/html/
COPY container/nginx.conf /etc/nginx/nginx.conf
COPY --from=backend-builder /app/backend/backend /app/bin/backend

EXPOSE 80

CMD ["/bin/sh", "-c", "nginx && /app/bin/backend"]
