# Stage 1: Build the Vue.js frontend
FROM node:26 AS frontend-builder

COPY assets/logo.png /app/assets/logo.png

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# Stage 2: Build the Rust backend binary
FROM rust:1.97 AS backend-builder

ARG RUN_TESTS=false
WORKDIR /app/backend
COPY backend/ ./

RUN cargo build --release --locked \
    && cp target/release/backend backend \
    && if [ "$RUN_TESTS" = "true" ]; then \
         cargo test --features test-mode; \
       else \
         echo "Skipping tests"; \
       fi

# Stage 3: Final container with Nginx unprivileged and backend binary
FROM nginxinc/nginx-unprivileged:stable

USER root

WORKDIR /app/data
COPY --from=frontend-builder /app/frontend/dist/ /usr/share/nginx/html/
COPY container/nginx.conf /etc/nginx/nginx.conf
COPY --from=backend-builder /app/backend/backend /app/bin/backend

RUN chown -R nginx:nginx /app/data

EXPOSE 8080

# Prepare init system
RUN apt-get update && apt-get install -y tini

COPY container/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER nginx

CMD ["/entrypoint.sh"]
