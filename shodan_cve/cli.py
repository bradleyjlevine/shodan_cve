# cli.py
import argparse
import logging
import sys
from typing import Optional
from threading import Thread

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from shodan_cve.mcp_app import create_app


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="Shodan CVEDB API MCP application"
    )

    # Transport selection
    transport_group = parser.add_argument_group("Transport Options")
    transport = transport_group.add_mutually_exclusive_group(required=True)
    transport.add_argument(
        "--stdio", action="store_true",
        help="Use stdio transport (default)"
    )
    transport.add_argument(
        "--http", action="store_true",
        help="Use streamable HTTP transport"
    )

    # HTTP transport options
    http_group = parser.add_argument_group("HTTP Transport Options")
    http_group.add_argument(
        "--host", default="localhost",
        help="Host to bind to (default: localhost)"
    )
    http_group.add_argument(
        "--port", type=int, default=8088,
        help="Port to bind to (default: 8088)"
    )
    http_group.add_argument(
        "--path", default="/mcp",
        help="URL path to serve the API (default: /mcp)"
    )

    # General options
    general_group = parser.add_argument_group("General Options")
    general_group.add_argument(
        "--base-url", default="https://cvedb.shodan.io",
        help="Base URL for the Shodan CVEDB API (default: https://cvedb.shodan.io)"
    )
    general_group.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO)"
    )

    return parser.parse_args()


def start_health_server(host: str = "0.0.0.0", port: int = 8089) -> None:
    """Start a separate FastAPI server for health checks"""
    app = FastAPI(
        title="Shodan CVEDB Health API",
        description="Health check endpoints for the Shodan CVEDB MCP application",
        version="0.1.0"
    )

    @app.get("/health")
    async def health_endpoint():
        """Health check endpoint for Docker healthcheck"""
        return JSONResponse({"status": "healthy"})

    @app.get("/ping")
    async def ping_endpoint():
        """Ping endpoint to check if the application is running"""
        return JSONResponse({"status": "ok", "message": "Shodan CVEDB MCP application is running"})

    # Run the FastAPI server in its own thread
    uvicorn_config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        log_level="info"
    )
    server = uvicorn.Server(uvicorn_config)

    # Start server in a thread
    thread = Thread(target=server.run, daemon=True)
    thread.start()

    logging.getLogger(__name__).info(f"Health API server started on http://{host}:{port}")


def main() -> None:
    """Main entry point for the CLI"""
    args = parse_args()

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    logger = logging.getLogger(__name__)

    try:
        # Create the MCP application
        mcp = create_app(base_url=args.base_url)

        # Start the health server
        health_port = args.port + 1 if args.http else 8089  # Use next port or default
        start_health_server(host=args.host, port=health_port)

        # Run with the selected transport
        if args.http:
            logger.info(f"Starting with HTTP transport on {args.host}:{args.port}{args.path}")
            mcp.run(
                transport="streamable-http",
                host=args.host,
                port=args.port,
                path=args.path
            )
        else:  # stdio is the default
            logger.info("Starting with stdio transport")
            mcp.run(transport="stdio")

    except KeyboardInterrupt:
        logger.info("Shutting down...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error running application: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()