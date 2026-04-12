from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
class SeverityLevel(str, Enum):
    """Severity levels for findings"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class StatusEnum(str, Enum):
    """Status of a finding"""
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    REMEDIATED = "REMEDIATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    WONT_FIX = "WONT_FIX"

class RemediationStatus(str, Enum):
    """Status of remediation"""
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"

class NormalizedFinding(BaseModel):
    """Normalized finding schema"""
    
    # Identifiers
    finding_id: str = Field(..., description="Unique finding identifier")
    finding_code: str = Field(..., description="Scanner-specific finding code")
    
    # Core details
    scanner: str = Field(..., description="Scanner name (scoutsuite, cloudsploit, checkov)")
    provider: str = Field(..., description="Cloud provider (aws, azure, gcp, openstack)")
    severity: SeverityLevel = Field(..., description="Finding severity")
    title: str = Field(..., description="Finding title/name")
    description: str = Field(..., description="Detailed description")
    
    # Resource details
    resource_type: str = Field(..., description="Type of resource (s3, iam, sg, etc)")
    resource_id: str = Field(..., description="Unique resource identifier")
    resource_name: Optional[str] = Field(None, description="Human-readable resource name")
    region: Optional[str] = Field(None, description="AWS region or Azure region")
    
    # Classification
    cis_controls: List[str] = Field(default_factory=list, description="Mapped CIS controls")
    risk_category: Optional[str] = Field(None, description="Risk category")
    
    # Remediation
    remediation_available: bool = Field(False, description="Whether automated remediation is available")
    remediation_type: Optional[str] = Field(None, description="Type of remediation (auto_fix, pr, manual)")
    
    # Timeline
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    last_seen_at: datetime = Field(default_factory=datetime.utcnow)
    remediated_at: Optional[datetime] = Field(None)
    
    # Status
    status: StatusEnum = Field(default=StatusEnum.OPEN)
    remediation_status: Optional[RemediationStatus] = Field(None)
    
    # Additional metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)
    tags: Dict[str, str] = Field(default_factory=dict)
    
    class Config:
        use_enum_values = True

class TriageDecision(BaseModel):
    """Triage decision for a finding"""
    
    finding_id: str
    recommendation: str  # 'auto_remediate', 'manual_review', 'ignore'
    confidence_score: float  # 0.0 to 1.0
    reasoning: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    created_at: datetime = Field(default_factory=datetime.utcnow)