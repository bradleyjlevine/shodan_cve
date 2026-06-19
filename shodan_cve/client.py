# client.py
import json
import logging
from typing import Dict, List, Optional, Union, Any, Type, TypeVar, cast
from urllib.parse import urljoin, quote

import requests

from shodan_cve.models import (
    CPE, CPEsRequest, CPEsResponse, CVE, CVERequest, CVEsRequest,
    CVESummary, CVEsResponse, EUVD, EUVDRequest, EUVDSummary, ErrorResponse
)


T = TypeVar("T")
logger = logging.getLogger(__name__)


class ShodanCVEDBClient:
    """Client for the Shodan CVEDB API"""

    def __init__(self, base_url: str = "https://cvedb.shodan.io"):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        response_type: Optional[Type[T]] = None
    ) -> Union[T, Dict[str, Any]]:
        """Make a request to the API and parse the response"""
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))

        try:
            response = self.session.request(method, url, params=params)
            response.raise_for_status()

            data = response.json()
            if response_type:
                return self._parse_response(data, response_type)
            return data

        except requests.RequestException as e:
            logger.error(f"Request failed: {e}")
            status_code = e.response.status_code if hasattr(e, 'response') else 500
            error_msg = str(e)

            if hasattr(e, 'response') and e.response.content:
                try:
                    error_data = e.response.json()
                    if isinstance(error_data, dict) and 'error' in error_data:
                        error_msg = error_data['error']
                except:
                    pass

            return ErrorResponse(error=error_msg, status_code=status_code)

    def _parse_response(self, data: Dict[str, Any], response_type: Type[T]) -> T:
        """Parse API response into the appropriate dataclass"""
        if response_type == CVE:
            return CVE(
                cve_id=data.get("cve_id", ""),
                summary=data.get("summary", ""),
                published_time=data.get("published_time", ""),
                cvss_v2=data.get("cvss_v2"),
                cvss_v3=data.get("cvss_v3"),
                cvss_v4=data.get("cvss_v4"),
                cvss=data.get("cvss"),
                cvss_version=data.get("cvss_version"),
                epss=data.get("epss"),
                ranking_epss=data.get("ranking_epss"),
                kev=data.get("kev", False),
                propose_action=data.get("propose_action"),
                ransomware_campaign=data.get("ransomware_campaign"),
                cpes=[self._parse_cpe(cpe) for cpe in data.get("cpes", [])],
                references=data.get("references", []),
                euvd=self._parse_euvd_summary(data.get("euvd"))
            )

        elif response_type == EUVD:
            return EUVD(
                euvd_id=data.get("euvd_id", ""),
                description=data.get("description", ""),
                published_time=data.get("published_time", ""),
                cvss=data.get("cvss"),
                cvss_version=data.get("cvss_version"),
                epss=data.get("epss"),
                assigner=data.get("assigner"),
                references=data.get("references", []),
                products=data.get("products", []),
                vendors=data.get("vendors", []),
                cve=self._parse_cve_summary(data.get("cve"))
            )

        elif response_type == CVEsResponse:
            return CVEsResponse(
                total=data.get("total", 0),
                cves=[self._parse_response(cve, CVE) for cve in data.get("cves", [])]
            )

        elif response_type == CPEsResponse:
            return CPEsResponse(
                total=data.get("total", 0),
                cpes=[self._parse_cpe(cpe) for cpe in data.get("cpes", [])]
            )

        # Fallback to returning the raw data
        return data  # type: ignore

    # _parse_cvss method removed as we're now handling CVSS scores as direct float values

    def _parse_euvd_summary(self, data: Any) -> Optional[EUVDSummary]:
        """Parse embedded EUVD data from a CVE response"""
        if not isinstance(data, dict):
            return None

        return EUVDSummary(
            id=data.get("id", ""),
            description=data.get("description", ""),
            published_time=data.get("published_time", ""),
            cvss=data.get("cvss"),
            cvss_version=data.get("cvss_version"),
            epss=data.get("epss"),
            assigner=data.get("assigner"),
            references=data.get("references", []),
            products=data.get("products", []),
            vendors=data.get("vendors", [])
        )

    def _parse_cve_summary(self, data: Any) -> Optional[CVESummary]:
        """Parse embedded CVE data from an EUVD response"""
        if not isinstance(data, dict):
            return None

        return CVESummary(
            id=data.get("id", ""),
            summary=data.get("summary", ""),
            published_time=data.get("published_time", ""),
            cvss_v2=data.get("cvss_v2"),
            cvss_v3=data.get("cvss_v3"),
            cvss_v4=data.get("cvss_v4"),
            cvss=data.get("cvss"),
            cvss_version=data.get("cvss_version"),
            epss=data.get("epss"),
            ranking_epss=data.get("ranking_epss"),
            kev=data.get("kev", False),
            propose_action=data.get("propose_action"),
            ransomware_campaign=data.get("ransomware_campaign"),
            cpes=[self._parse_cpe(cpe) for cpe in data.get("cpes", [])],
            references=data.get("references", [])
        )

    def _parse_cpe(self, data: Any) -> CPE:
        """Parse CPE data from the API response"""
        # Handle case where data is a string (direct CPE)
        if isinstance(data, str):
            # Parse CPE string to extract vendor, product, version
            # CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
            try:
                parts = data.split(":")
                if len(parts) >= 5 and parts[0] == "cpe":
                    return CPE(
                        cpe23=data,
                        vendor=parts[3] if parts[3] != "*" else None,
                        product=parts[4] if parts[4] != "*" else None,
                        version=parts[5] if len(parts) > 5 and parts[5] != "*" else None
                    )
            except Exception as e:
                logger.warning(f"Failed to parse CPE string {data}: {e}")

            # Return with just the CPE string if parsing failed
            return CPE(
                cpe23=data,
                vendor=None,
                product=None,
                version=None
            )

        # Normal case - data is a dictionary
        if isinstance(data, dict):
            return CPE(
                cpe23=data.get("cpe23", ""),
                vendor=data.get("vendor"),
                product=data.get("product"),
                version=data.get("version")
            )

        # Unexpected data type
        logger.warning(f"Unexpected CPE data type: {type(data)}")
        return CPE(
            cpe23="",
            vendor=None,
            product=None,
            version=None
        )

    def get_cve(self, request: CVERequest) -> Union[CVE, ErrorResponse]:
        """Get information about a specific CVE"""
        endpoint = f"/cve/{quote(request.cve_id)}"
        return self._make_request("GET", endpoint, response_type=CVE)

    def get_euvd(self, request: EUVDRequest) -> Union[EUVD, ErrorResponse]:
        """Get information about a specific EUVD"""
        endpoint = f"/euvd/{quote(request.euvd_id)}"
        return self._make_request("GET", endpoint, response_type=EUVD)

    def search_cpes(self, request: CPEsRequest) -> Union[CPEsResponse, ErrorResponse]:
        """Search for CPEs by product name"""
        params = {
            "product": request.product,
            "count": request.count,
            "skip": request.skip,
            "limit": request.limit
        }
        return self._make_request("GET", "/cpes", params=params, response_type=CPEsResponse)

    def search_cves(self, request: CVEsRequest) -> Union[CVEsResponse, ErrorResponse]:
        """Search for CVEs by product name or CPE"""
        params = {
            "count": request.count,
            "skip": request.skip,
            "limit": request.limit,
        }

        if request.cpe23:
            params["cpe23"] = request.cpe23
        if request.product:
            params["product"] = request.product
        if request.is_kev is not None:
            params["is_kev"] = request.is_kev
        if request.sort_by_epss:
            params["sort_by_epss"] = request.sort_by_epss
        if request.start_date:
            params["start_date"] = request.start_date
        if request.end_date:
            params["end_date"] = request.end_date

        return self._make_request("GET", "/cves", params=params, response_type=CVEsResponse)
