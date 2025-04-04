from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class VulnerabilityDetail(BaseModel):
    name: str
    severity: str
    description: str
    recommendation: str

class PortDetail(BaseModel):
    port: int
    service: str
    state: str
    version: Optional[str] = None

class ScanResult(BaseModel):
    id: str
    scan_id: str
    target: str
    scan_type: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: str  # "running", "completed", "failed"
    summary: str
    vulnerabilities: Optional[List[VulnerabilityDetail]] = None
    open_ports: Optional[List[PortDetail]] = None
    risk_score: Optional[int] = None 