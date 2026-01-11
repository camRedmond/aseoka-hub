FROM python:3.12-slim

WORKDIR /app

# Install system dependencies (curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for faster dependency management
RUN pip install uv

# Copy package files
COPY pyproject.toml .
COPY aseoka_hub/ ./aseoka_hub/

# Install the package
RUN uv pip install --system -e .

# Create data directory for database and certificates
RUN mkdir -p /app/data

# Expose hub server port
EXPOSE 8000

# Run the hub server
CMD ["uvicorn", "aseoka_hub.server:app", "--host", "0.0.0.0", "--port", "8000"]
