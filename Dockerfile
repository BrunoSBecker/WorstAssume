# ─── Stage 1: Build the React frontend ───────────────────────────────────────
FROM node:22-alpine AS frontend-build

WORKDIR /app/worstassume/viz/frontend

COPY worstassume/viz/frontend/package*.json ./
RUN npm ci --prefer-offline

COPY worstassume/viz/frontend/ ./
RUN npm run build

# ─── Stage 2: Python runtime ──────────────────────────────────────────────────
FROM python:3.12-slim

# System deps (SQLite is included in Python slim; no extras needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies (use pyproject.toml)
COPY pyproject.toml ./
# Copy source before pip install -e . so editable install resolves the package
COPY worstassume/ ./worstassume/
RUN pip install --no-cache-dir -e .

# Copy built frontend into the static serving location
COPY --from=frontend-build /app/worstassume/viz/frontend/dist ./worstassume/viz/frontend/dist

# Runtime configuration
ENV WORST_DB=/data/db.sqlite

# Persist the SQLite DB in a named volume
VOLUME ["/data"]

# Default: start the viz server
EXPOSE 3000
ENTRYPOINT ["worst"]
CMD ["viz", "--host", "0.0.0.0", "--port", "3000", "--no-open-browser"]
