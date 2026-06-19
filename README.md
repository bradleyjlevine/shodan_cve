# Shodan CVEDB MCP Application

This is an MCP (Messaging Control Protocol) application that provides an interface to the [Shodan CVEDB API](https://cvedb.shodan.io/).

## Features

- Access to Shodan CVEDB API endpoints:
  - Retrieve information about specific CVEs by ID
  - Retrieve information about specific EUVD/EUVID records by ID
  - Search for CPEs by product name
  - Search for CVEs by product name or CPE
- Support for multiple transport protocols:
  - stdio transport for command-line usage
  - Streamable HTTP transport for web service usage
- Implemented using FastMCP for efficient and stable API interactions
- Docker support for easy deployment
- No authentication required (free for non-commercial use)

## Installation

### Local Installation

```bash
# Install directly from the repository using pip
pip install -e .

# Or using uv (recommended)
uv pip install -e .
```

### Docker Installation

The application can also be run using Docker:

```bash
# Build and start the Docker container
docker-compose up -d

# View logs
docker-compose logs -f
```

## Usage

### Command-line Options

```
usage: shodan-cve [-h] (--stdio | --http) [--host HOST] [--port PORT]
                  [--path PATH] [--base-url BASE_URL]
                  [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}]

Shodan CVEDB API MCP application

options:
  -h, --help            show this help message and exit

Transport Options:
  --stdio               Use stdio transport (default)
  --http                Use streamable HTTP transport

HTTP Transport Options:
  --host HOST           Host to bind to (default: localhost)
  --port PORT           Port to bind to (default: 8088)
  --path PATH           URL path to serve the API (default: /api)

General Options:
  --base-url BASE_URL   Base URL for the Shodan CVEDB API (default:
                        https://cvedb.shodan.io)
  --log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Set the logging level (default: INFO)
```

### Examples

#### Starting with stdio Transport

```bash
shodan-cve --stdio
```

#### Starting with HTTP Transport

```bash
shodan-cve --http --host 0.0.0.0 --port 8088
```

### API Endpoints

The MCP application exposes the following methods:

#### get_cve

Get information about a specific CVE by ID.

Parameters:
- `cve_id`: The CVE ID to retrieve (e.g., "CVE-2021-44228")
- `include_cpes`: Include affected CPE identifiers in the response (optional, default: false)

Example:
```json
{
  "id": "1",
  "method": "get_cve",
  "params": {
    "cve_id": "CVE-2021-44228"
  }
}
```

#### get_euvd

Get information about a specific EUVD/EUVID by ID.

Parameters:
- `euvd_id`: The EUVD ID to retrieve (e.g., "EUVD-2024-16003")
- `include_cpes`: Include linked CVE CPE identifiers when present (optional, default: false)

Example:
```json
{
  "id": "2",
  "method": "get_euvd",
  "params": {
    "euvd_id": "EUVD-2024-16003"
  }
}
```

#### search_cpes

Search for CPEs by product name.

Parameters:
- `product`: The product name to search for (required)
- `count`: Return only the count of matching CPEs (optional, default: false)
- `skip`: Number of results to skip (optional, default: 0)
- `limit`: Maximum number of results to return (optional, default: 1000)

Example:
```json
{
  "id": "3",
  "method": "search_cpes",
  "params": {
    "product": "log4j"
  }
}
```

#### search_cves

Search for CVEs by product name or CPE.

Parameters:
- `cpe23`: CPE 2.3 identifier to search for (optional)
- `product`: Product name to search for (optional)
- `count`: Return only the count of matching CVEs (optional, default: false)
- `is_kev`: Filter for CVEs that are known exploited vulnerabilities (optional)
- `sort_by_epss`: Sort results by EPSS score (optional, default: false)
- `skip`: Number of results to skip (optional, default: 0)
- `limit`: Maximum number of results to return (optional, default: 1000)
- `start_date`: Start date for filtering (format: YYYY-MM-DDTHH:MM:SS) (optional)
- `end_date`: End date for filtering (format: YYYY-MM-DDTHH:MM:SS) (optional)

Example:
```json
{
  "id": "4",
  "method": "search_cves",
  "params": {
    "product": "log4j",
    "sort_by_epss": true,
    "limit": 10
  }
}
```

#### ping

Check if the application is running.

Example:
```json
{
  "id": "5",
  "method": "ping",
  "params": {}
}
```

# Health API

The application includes a separate Health API that runs alongside the MCP server. This API provides direct HTTP endpoints for health checks and monitoring:

- `GET /health`: Health check endpoint for Docker container health monitoring
- `GET /ping`: Simple endpoint to check if the service is running

These endpoints are accessible on port 8089 (by default).

Example:
```bash
# Health check
curl http://localhost:8089/health

# Ping check
curl http://localhost:8089/ping
```

## Implementation Details

The application is built using:

- **FastMCP**: A Python framework for building MCP applications
- **Docker**: For containerization and easy deployment
- **UV**: For Python package management

### Architecture

The application follows a clean architecture with:

- **models.py**: Data models for the API requests and responses
- **client.py**: Client for interacting with the Shodan CVEDB API
- **mcp_app.py**: MCP application implementation using FastMCP
- **cli.py**: Command-line interface for running the application

## API Documentation

For more information about the Shodan CVEDB API, visit:
- [Shodan CVEDB Documentation](https://cvedb.shodan.io/docs)
- [Shodan CVEDB Home](https://cvedb.shodan.io/)
