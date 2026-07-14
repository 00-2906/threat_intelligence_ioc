from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class IOCType(str, Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    hash = "hash"


class ScanRequest(BaseModel):
    ioc_type: IOCType = Field(..., description="Type of IOC: ip, domain, url, or hash")
    value: str = Field(..., description="The actual IOC value, e.g. an IP or hash string")


class ScanResponse(BaseModel):
    ioc_type: IOCType
    value: str
    risk_score: Optional[float] = None
    risk_label: Optional[str] = None
    virustotal: Optional[dict[str, Any]] = None
    abuseipdb: Optional[dict[str, Any]] = None
    errors: list[str] = []
