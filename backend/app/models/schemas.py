from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class AttackType(str, Enum):
    BRUTE_FORCE = "brute_force"
    PORT_SCAN = "port_scan"
    MALWARE = "malware"
    DDoS = "ddos"
    PHISHING = "phishing"
    EXPLOIT = "exploit"
    OTHER = "other"

class HoneypotType(str, Enum):
    T_POT = "t-pot"
    COWRIE = "cowrie"
    DIONAEA = "dionaea"
    GLUTTON = "glutton"
    CUSTOM = "custom"

class LogUploadRequest(BaseModel):
    filename: str
    honeypot_type: HoneypotType
    description: Optional[str] = None

class HoneypotConnection(BaseModel):
    name: str
    honeypot_type: HoneypotType
    api_url: str
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

class AttackPattern(BaseModel):
    timestamp: datetime
    source_ip: str
    destination_ip: str
    port: int
    protocol: str
    attack_type: AttackType
    payload: Optional[Dict[str, Any]] = None
    severity: int = Field(ge=1, le=10)
    country: Optional[str] = None
    city: Optional[str] = None

class STIXIndicator(BaseModel):
    pattern: str
    pattern_type: str = "stix"
    valid_from: datetime
    valid_until: Optional[datetime] = None
    description: str
    mitre_attack_id: Optional[str] = None

class AnalysisRequest(BaseModel):
    start_date: datetime
    end_date: datetime
    attack_types: Optional[List[AttackType]] = None
    min_severity: int = 1

class AnalysisResponse(BaseModel):
    total_attacks: int
    unique_attackers: int
    attack_distribution: Dict[str, int]
    timeline_data: List[Dict[str, Any]]
    top_countries: List[Dict[str, Any]]
    mitre_coverage: Dict[str, int]

class APIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None

class STIXGenerationRequest(BaseModel):
    attack_ids: Optional[List[str]] = None
    file_id: Optional[int] = None
    all_attacks: Optional[bool] = False