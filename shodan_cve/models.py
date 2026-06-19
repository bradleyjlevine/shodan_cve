# models.py
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Union


class SortType(str, Enum):
    EPSS = "epss"
    CVSS = "cvss"
    DATE = "date"


@dataclass
class CVERequest:
    """Request to fetch a specific CVE by ID"""
    cve_id: str


@dataclass
class EUVDRequest:
    """Request to fetch a specific EUVD by ID"""
    euvd_id: str


@dataclass
class CPEsRequest:
    """Request to search for CPEs by product name"""
    product: str
    count: bool = False
    skip: int = 0
    limit: int = 1000


@dataclass
class CVEsRequest:
    """Request to search for CVEs by product or CPE"""
    cpe23: Optional[str] = None
    product: Optional[str] = None
    count: bool = False
    is_kev: Optional[bool] = None
    sort_by_epss: bool = False
    skip: int = 0
    limit: int = 1000
    start_date: Optional[str] = None
    end_date: Optional[str] = None


# CVSS class removed as we're now handling CVSS scores as direct float values


@dataclass
class CPE:
    """CPE identifier with metadata"""
    cpe23: str
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


@dataclass
class EUVDSummary:
    """EUVD reference embedded in a CVE response"""
    id: str
    description: str
    published_time: str
    cvss: Optional[float] = None
    cvss_version: Optional[str] = None
    epss: Optional[float] = None
    assigner: Optional[str] = None
    references: List[str] = field(default_factory=list)
    products: List[str] = field(default_factory=list)
    vendors: List[str] = field(default_factory=list)


@dataclass
class CVESummary:
    """CVE reference embedded in an EUVD response"""
    id: str
    summary: str
    published_time: str
    cvss_v2: Optional[float] = None
    cvss_v3: Optional[float] = None
    cvss_v4: Optional[float] = None
    cvss: Optional[float] = None
    cvss_version: Optional[Union[str, int]] = None
    epss: Optional[float] = None
    ranking_epss: Optional[float] = None
    kev: bool = False
    propose_action: Optional[str] = None
    ransomware_campaign: Optional[str] = None
    cpes: List[CPE] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


@dataclass
class CVE:
    """CVE vulnerability information"""
    cve_id: str
    summary: str
    published_time: str
    cvss_v2: Optional[float] = None
    cvss_v3: Optional[float] = None
    cvss_v4: Optional[float] = None
    cvss: Optional[float] = None
    cvss_version: Optional[Union[str, int]] = None
    epss: Optional[float] = None
    ranking_epss: Optional[float] = None
    kev: bool = False
    propose_action: Optional[str] = None
    ransomware_campaign: Optional[str] = None
    cpes: List[CPE] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    euvd: Optional[EUVDSummary] = None


@dataclass
class EUVD:
    """EUVD vulnerability information"""
    euvd_id: str
    description: str
    published_time: str
    cvss: Optional[float] = None
    cvss_version: Optional[str] = None
    epss: Optional[float] = None
    assigner: Optional[str] = None
    references: List[str] = field(default_factory=list)
    products: List[str] = field(default_factory=list)
    vendors: List[str] = field(default_factory=list)
    cve: Optional[CVESummary] = None


@dataclass
class CVEsResponse:
    """Response containing multiple CVEs"""
    total: int
    cves: List[CVE] = field(default_factory=list)


@dataclass
class CPEsResponse:
    """Response containing multiple CPEs"""
    total: int
    cpes: List[CPE] = field(default_factory=list)


@dataclass
class ErrorResponse:
    """Error response from the API"""
    error: str
    status_code: int
