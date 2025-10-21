# mcp_app.py
import json
import logging
from typing import Any, Dict, List, Optional, Union

from fastmcp import FastMCP

from shodan_cve.client import ShodanCVEDBClient
from shodan_cve.models import (
    CPEsRequest, CVERequest, CVEsRequest, ErrorResponse
)


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# Initialize the client and MCP handler
client = ShodanCVEDBClient(base_url="https://cvedb.shodan.io")
mcp = FastMCP(
    name="Shodan CVEDB API",
    instructions="Query the Shodan CVE Database API for vulnerability information"
)


def _convert_to_dict(obj: Any) -> Dict[str, Any]:
    """Convert dataclass objects to dictionaries"""
    if hasattr(obj, "__dict__"):
        result = {}
        for key, value in obj.__dict__.items():
            if isinstance(value, list):
                result[key] = [_convert_to_dict(item) for item in value]
            elif hasattr(value, "__dict__"):
                result[key] = _convert_to_dict(value)
            else:
                result[key] = value
        return result
    return obj


@mcp.tool(
    name="get_cve",
    description="Get detailed information about a specific CVE by ID",
    output_schema={"type": "object"}
)
def get_cve(cve_id: str) -> Union[Dict[str, Any], Dict[str, Any]]:
    """Get information about a specific CVE"""
    try:
        if not cve_id:
            return {"error": {"message": "Missing required parameter: cve_id", "code": 400}}

        cve_request = CVERequest(cve_id=cve_id)
        result = client.get_cve(cve_request)

        if isinstance(result, ErrorResponse):
            return {"error": {"message": result.error, "code": result.status_code}}

        return _convert_to_dict(result)
    except Exception as e:
        logger.exception("Error handling get_cve request")
        return {"error": {"message": str(e), "code": 500}}


@mcp.tool(
    name="search_cpes",
    description="Search for CPEs (Common Platform Enumeration) by product name",
    output_schema={"type": "object"}
)
def search_cpes(
    product: str,
    count: bool = False,
    skip: int = 0,
    limit: int = 1000
) -> Union[Dict[str, Any], Dict[str, Any]]:
    """Search for CPEs by product name"""
    try:
        if not product:
            return {"error": {"message": "Missing required parameter: product", "code": 400}}

        cpes_request = CPEsRequest(
            product=product,
            count=count,
            skip=skip,
            limit=limit
        )

        result = client.search_cpes(cpes_request)

        if isinstance(result, ErrorResponse):
            return {"error": {"message": result.error, "code": result.status_code}}

        return _convert_to_dict(result)
    except Exception as e:
        logger.exception("Error handling search_cpes request")
        return {"error": {"message": str(e), "code": 500}}


@mcp.tool(
    name="search_cves",
    description="Search for CVEs by product name or CPE identifier",
    output_schema={"type": "object"}
)
def search_cves(
    cpe23: Optional[str] = None,
    product: Optional[str] = None,
    count: bool = False,
    is_kev: Optional[bool] = None,
    sort_by_epss: bool = False,
    skip: int = 0,
    limit: int = 1000,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
) -> Union[Dict[str, Any], Dict[str, Any]]:
    """Search for CVEs by product name or CPE"""
    try:
        # At least one of cpe23 or product is required
        if not cpe23 and not product:
            return {
                "error": {
                    "message": "Missing required parameter: either cpe23 or product must be provided",
                    "code": 400
                }
            }

        cves_request = CVEsRequest(
            cpe23=cpe23,
            product=product,
            count=count,
            is_kev=is_kev,
            sort_by_epss=sort_by_epss,
            skip=skip,
            limit=limit,
            start_date=start_date,
            end_date=end_date
        )

        result = client.search_cves(cves_request)

        if isinstance(result, ErrorResponse):
            return {"error": {"message": result.error, "code": result.status_code}}

        return _convert_to_dict(result)
    except Exception as e:
        logger.exception("Error handling search_cves request")
        return {"error": {"message": str(e), "code": 500}}


# Health and ping endpoints are not exposed as MCP tools
# They will be implemented as direct HTTP endpoints


def create_app(base_url: str = "https://cvedb.shodan.io") -> FastMCP:
    """Create and configure the MCP application"""
    global client
    client = ShodanCVEDBClient(base_url=base_url)
    return mcp