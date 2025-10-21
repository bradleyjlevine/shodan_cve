# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This repository contains the `shodan-cve` project, a Python application designed to work with Shodan data and CVE (Common Vulnerabilities and Exposures) information. It provides an MCP (Messaging Control Protocol) interface to the Shodan CVEDB API, allowing users to query vulnerability information. The application is in early development (version 0.1.0).

## Project Structure

- `main.py`: Entry point for the application
- `shodan_cve/`: Main package directory
  - `__init__.py`: Package initialization
  - `models.py`: Data models for API requests and responses
  - `client.py`: Shodan CVEDB API client implementation
  - `mcp_app.py`: MCP application using FastMCP
  - `cli.py`: Command-line interface implementation
- `pyproject.toml`: Project configuration and dependencies
- `Dockerfile`: Docker container configuration
- `docker-compose.yml`: Docker Compose configuration
- `.gitignore`: Standard Python gitignore file
- `.dockerignore`: Excludes unnecessary files from Docker builds

## Development Setup

### Requirements

- Python 3.11 or newer
- `uv` package manager (recommended for dependency management)

### Installation

1. Clone the repository
2. Set up a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   uv pip install -e .
   ```

### Common Commands

#### Running the Application

```bash
# Run with stdio transport
python main.py --stdio

# Run with HTTP transport
python main.py --http --host 0.0.0.0 --port 8088
```

#### Running with Docker

```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f
```

#### Installing Dependencies

```bash
uv pip install -e .  # Install in development mode
```

#### Adding New Dependencies

```bash
uv pip install <package-name>
uv pip freeze > requirements.txt  # If tracking requirements explicitly
```

## Project Dependencies

- `fastmcp` (>=2.12.5): MCP framework implementation
- `requests` (>=2.32.5): HTTP library for making API requests

## API Features

The application provides access to the following Shodan CVEDB API endpoints:

- `get_cve`: Get information about a specific CVE by ID
- `search_cpes`: Search for CPEs by product name
- `search_cves`: Search for CVEs by product name or CPE

Additionally, a separate Health API runs alongside the MCP server, providing direct HTTP endpoints:

- `GET /health`: Health check endpoint for Docker container health monitoring
- `GET /ping`: Simple endpoint to check if the service is running

## Architecture

The application uses the FastMCP framework to implement an MCP server with support for:

- stdio transport: For command-line usage
- Streamable HTTP transport: For web service usage

A separate FastAPI server runs alongside the MCP server to provide health check endpoints.

The code follows a clean architecture pattern:
- Data models in `models.py` define the request and response structures
- API client in `client.py` handles communication with the Shodan CVEDB API
- MCP application in `mcp_app.py` implements the MCP tools
- Command-line interface in `cli.py` provides the entry point and starts both servers

## Development Notes

As this project interacts with Shodan and CVE data, it's important to:

1. Handle API credentials securely (never commit API keys to the repository)
2. Implement proper error handling for API requests
3. Consider rate limiting when making requests to external APIs
4. Follow responsible security research practices when using vulnerability data

When extending the application:
1. Use the FastMCP tool decorator pattern for new endpoints
2. Ensure proper error handling and validation
3. Follow the existing architecture pattern
4. Add tests for new functionality