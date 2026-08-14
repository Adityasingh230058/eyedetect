"""Data models and schema definitions for detection rules."""

from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleStatus(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    EXPERIMENTAL = "experimental"


class Condition(BaseModel):
    field: str
    operator: str
    value: Any
    case_sensitive: bool = False


class LogicNode(BaseModel):
    all: Optional[List[Union[Condition, "LogicNode"]]] = None
    any: Optional[List[Union[Condition, "LogicNode"]]] = None
    none: Optional[List[Union[Condition, "LogicNode"]]] = None


# Allow recursive definitions
LogicNode.update_forward_refs()


class MitreMapping(BaseModel):
    tactic: Optional[str] = None
    technique: Optional[str] = None
    name: Optional[str] = None


class Rule(BaseModel):
    id: str
    name: str
    description: str = ""
    version: int = 1
    status: RuleStatus = RuleStatus.ENABLED
    event_type: str
    logic: LogicNode
    severity: SeverityLevel = SeverityLevel.MEDIUM
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence: List[str] = Field(default_factory=list)
    mitre: Optional[MitreMapping] = None
    tags: List[str] = Field(default_factory=list)

    class Config:
        use_enum_values = True
