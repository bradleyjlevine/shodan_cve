FROM python:3.11-slim

WORKDIR /app

# Install uv
RUN pip install --no-cache-dir uv

# Copy project files
COPY . /app/

# Create a virtual environment using uv
RUN uv venv

# Activate the virtual environment and install dependencies
RUN . ./.venv/bin/activate && \
    uv pip install --no-cache-dir -e . && \
    uv pip install --no-cache-dir requests fastapi uvicorn

# Expose ports for HTTP transport and health server
EXPOSE 8088 8089

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"

# Run the MCP server with HTTP transport
# Default to listening on all interfaces (0.0.0.0) to work properly in Docker
CMD ["shodan-cve", "--http", "--host", "0.0.0.0", "--port", "8088"]