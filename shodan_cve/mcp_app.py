# mcp_app.py
import json
import logging
from typing import Any, Dict, List, Optional, Union

from fastmcp import FastMCP

from shodan_cve.client import ShodanCVEDBClient
from shodan_cve.models import (
    CPEsRequest, CVERequest, CVEsRequest, EUVDRequest, ErrorResponse
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
    description="""Look up a specific CVE directly by its ID (e.g., CVE-2021-44228). Use this tool to get comprehensive details about a known vulnerability.

Example usage:
  get_cve(cve_id="CVE-2021-44228")                        # Looks up Log4Shell vulnerability
  get_cve(cve_id="CVE-2023-21036")                        # Looks up a specific Windows vulnerability
  get_cve(cve_id="CVE-2021-44228", include_cpes=True)     # Include full CPE list (WARNING: may be very large)

Parameters:
  cve_id (str): The CVE identifier in CVE-YYYY-NNNNN format.
  include_cpes (bool): Whether to include the list of affected CPE identifiers in the response.
    Defaults to False. WARNING: For widely-affecting CVEs (e.g. Log4Shell), the CPE list can
    contain hundreds of entries and significantly increase response size.""",
    output_schema={"type": "object"}
)
def get_cve(cve_id: str, include_cpes: bool = False) -> Union[Dict[str, Any], Dict[str, Any]]:
    """Get complete information about a specific CVE by its ID (CVE-YYYY-NNNNN format)"""
    try:
        if not cve_id:
            return {"error": {"message": "Missing required parameter: cve_id", "code": 400}}
        if cve_id.startswith("EUVD-"):
            return {
                "error": {
                    "message": f"It looks like you're trying to look up a specific EUVD ({cve_id}). "
                              f"Please use the get_euvd tool instead with: get_euvd(euvd_id=\"{cve_id}\")",
                    "code": 400,
                    "suggestion": {
                        "tool": "get_euvd",
                        "params": {"euvd_id": cve_id}
                    }
                }
            }

        cve_request = CVERequest(cve_id=cve_id)
        result = client.get_cve(cve_request)

        if isinstance(result, ErrorResponse):
            return {"error": {"message": result.error, "code": result.status_code}}

        result_dict = _convert_to_dict(result)
        if not include_cpes:
            result_dict.pop("cpes", None)
        return result_dict
    except Exception as e:
        logger.exception("Error handling get_cve request")
        return {"error": {"message": str(e), "code": 500}}


@mcp.tool(
    name="get_euvd",
    description="""Look up a specific EUVD/EUVID directly by its ID (e.g., EUVD-2024-16003). Use this tool to get European Union vulnerability details and any linked CVE record.

Example usage:
  get_euvd(euvd_id="EUVD-2024-16003")                     # Looks up a specific EUVD vulnerability
  get_euvd(euvd_id="EUVD-2024-16003", include_cpes=True)  # Include linked CVE CPE list when present

Parameters:
  euvd_id (str): The EUVD identifier in EUVD-YYYY-NNNNN format.
  include_cpes (bool): Whether to include the linked CVE CPE identifiers when a linked CVE is present.
    Defaults to False because linked CVE CPE lists can be large.""",
    output_schema={"type": "object"}
)
def get_euvd(euvd_id: str, include_cpes: bool = False) -> Union[Dict[str, Any], Dict[str, Any]]:
    """Get complete information about a specific EUVD by its ID (EUVD-YYYY-NNNNN format)"""
    try:
        if not euvd_id:
            return {"error": {"message": "Missing required parameter: euvd_id", "code": 400}}
        if euvd_id.startswith("CVE-"):
            return {
                "error": {
                    "message": f"It looks like you're trying to look up a specific CVE ({euvd_id}). "
                              f"Please use the get_cve tool instead with: get_cve(cve_id=\"{euvd_id}\")",
                    "code": 400,
                    "suggestion": {
                        "tool": "get_cve",
                        "params": {"cve_id": euvd_id}
                    }
                }
            }

        euvd_request = EUVDRequest(euvd_id=euvd_id)
        result = client.get_euvd(euvd_request)

        if isinstance(result, ErrorResponse):
            return {"error": {"message": result.error, "code": result.status_code}}

        result_dict = _convert_to_dict(result)
        if not include_cpes and isinstance(result_dict.get("cve"), dict):
            result_dict["cve"].pop("cpes", None)
        return result_dict
    except Exception as e:
        logger.exception("Error handling get_euvd request")
        return {"error": {"message": str(e), "code": 500}}


@mcp.tool(
    name="search_cpes",
    description="""Search for CPEs (Common Platform Enumeration) by product name.
Use this to find platform identifiers, not to look up specific CVEs.

Example usage:
  search_cpes(product="log4j")       # Find CPE identifiers for Log4j
  search_cpes(product="windows 10")  # Find CPE identifiers for Windows 10

Note: To look up a specific CVE by ID, use the get_cve tool instead.""",
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

        # Check if the product parameter is actually a CVE ID
        if product and product.startswith("CVE-"):
            # Return a helpful error message suggesting the correct tool
            logger.info(f"User attempted to search for CVE ID {product} using search_cpes tool")
            return {
                "error": {
                    "message": f"It looks like you're trying to look up a specific CVE ({product}). "
                              f"Please use the get_cve tool instead with: get_cve(cve_id=\"{product}\")",
                    "code": 400,
                    "suggestion": {
                        "tool": "get_cve",
                        "params": {"cve_id": product}
                    }
                }
            }
        if product and product.startswith("EUVD-"):
            logger.info(f"User attempted to search for EUVD ID {product} using search_cpes tool")
            return {
                "error": {
                    "message": f"It looks like you're trying to look up a specific EUVD ({product}). "
                              f"Please use the get_euvd tool instead with: get_euvd(euvd_id=\"{product}\")",
                    "code": 400,
                    "suggestion": {
                        "tool": "get_euvd",
                        "params": {"euvd_id": product}
                    }
                }
            }

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
    description="""Search for CVEs by product name or CPE identifier.
Use this to find vulnerabilities related to a product, not to look up a specific CVE.

Example usage:
  search_cves(product="log4j")             # Find all vulnerabilities for Log4j
  search_cves(cpe23="cpe:2.3:a:apache:log4j:2.0")  # Find vulnerabilities for a specific version
  search_cves(product="windows", is_kev=True)  # Find only known exploited vulnerabilities

Note: To look up a specific CVE by ID, use the get_cve tool instead.""",
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
        # Check if the product parameter is actually a CVE ID
        if product and product.startswith("CVE-"):
            # Return a helpful error message suggesting the correct tool
            logger.info(f"User attempted to search for CVE ID {product} using search_cves tool")
            return {
                "error": {
                    "message": f"It looks like you're trying to look up a specific CVE ({product}). "
                              f"Please use the get_cve tool instead with: get_cve(cve_id=\"{product}\")",
                    "code": 400,
                    "suggestion": {
                        "tool": "get_cve",
                        "params": {"cve_id": product}
                    }
                }
            }
        if product and product.startswith("EUVD-"):
            logger.info(f"User attempted to search for EUVD ID {product} using search_cves tool")
            return {
                "error": {
                    "message": f"It looks like you're trying to look up a specific EUVD ({product}). "
                              f"Please use the get_euvd tool instead with: get_euvd(euvd_id=\"{product}\")",
                    "code": 400,
                    "suggestion": {
                        "tool": "get_euvd",
                        "params": {"euvd_id": product}
                    }
                }
            }

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
