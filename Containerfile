# Stage 1: Build the Vue.js frontend
FROM node:26 AS frontend-builder

WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# Stage 2: Build the Rust backend binary
FROM rust:1.97 AS chef
RUN cargo install cargo-chef --version 0.1.78 --locked
WORKDIR /app/backend

# Derive a dependency-only recipe so the dependency layer below
# is only rebuilt when Cargo.toml or Cargo.lock change
FROM chef AS planner
COPY backend/ ./
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS backend-builder

COPY --from=planner /app/backend/recipe.json recipe.json
RUN cargo chef cook --release --locked --recipe-path recipe.json

ARG RUN_TESTS=false
COPY backend/ ./

RUN cargo build --release --locked \
    && cp target/release/backend backend \
    && if [ "$RUN_TESTS" = "true" ]; then \
         cargo test --features test-mode; \
       else \
         echo "Skipping tests"; \
       fi

# Stage 3a: Root-compatible runtime image
FROM nginx:stable AS privileged

USER root

WORKDIR /app/data
COPY --from=frontend-builder /app/frontend/dist/ /usr/share/nginx/html/
COPY container/nginx.privileged.conf /etc/nginx/nginx.conf
COPY --from=backend-builder /app/backend/backend /app/bin/backend

EXPOSE 80

# Prepare init system
RUN apt-get update && apt-get install -y tini

COPY container/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]

# Stage 3b: Non-root runtime image
FROM nginxinc/nginx-unprivileged:stable AS unprivileged

USER root

WORKDIR /app/data
COPY --from=frontend-builder /app/frontend/dist/ /usr/share/nginx/html/
COPY container/nginx.unprivileged.conf /etc/nginx/nginx.conf
COPY --from=backend-builder /app/backend/backend /app/bin/backend

RUN chown -R nginx:nginx /app/data

EXPOSE 8080

# Prepare init system
RUN apt-get update && apt-get install -y tini

COPY container/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER nginx

CMD ["/entrypoint.sh"]

# Keep an unqualified local build compatible with the privileged release image.
FROM privileged AS default
