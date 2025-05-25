"""Data models for ATT&CK framework objects and detection rules."""

from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class ExternalReference(BaseModel):
    """External reference model."""
    source_name: str
    url: Optional[str] = None
    external_id: Optional[str] = None
    description: Optional[str] = None


class KillChainPhase(BaseModel):
    """Kill chain phase model."""
    kill_chain_name: str
    phase_name: str


class Technique(BaseModel):
    """ATT&CK Technique model."""
    id: str
    name: str
    description: str
    tactic: Optional[str] = None
    technique_id: str = ""
    platforms: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    kill_chain_phases: List[KillChainPhase] = Field(default_factory=list)
    external_references: List[ExternalReference] = Field(default_factory=list)
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    version: Optional[str] = None
    is_subtechnique: bool = False
    parent_technique: Optional[str] = None
    
    @property
    def mitre_id(self) -> str:
        """Get the MITRE technique ID (e.g., T1059.003)."""
        for ref in self.external_references:
            if ref.source_name == "mitre-attack" and ref.external_id:
                return ref.external_id
        return self.technique_id


class Tactic(BaseModel):
    """ATT&CK Tactic model."""
    id: str
    name: str
    description: str
    shortname: str
    external_references: List[ExternalReference] = Field(default_factory=list)
    
    @property
    def mitre_id(self) -> str:
        """Get the MITRE tactic ID."""
        for ref in self.external_references:
            if ref.source_name == "mitre-attack" and ref.external_id:
                return ref.external_id
        return self.id


class Group(BaseModel):
    """ATT&CK Group model."""
    id: str
    name: str
    description: str
    aliases: List[str] = Field(default_factory=list)
    external_references: List[ExternalReference] = Field(default_factory=list)


class Software(BaseModel):
    """ATT&CK Software (malware/tool) model."""
    id: str
    name: str
    description: str
    labels: List[str] = Field(default_factory=list)
    platforms: List[str] = Field(default_factory=list)
    external_references: List[ExternalReference] = Field(default_factory=list)


class Mitigation(BaseModel):
    """ATT&CK Mitigation model."""
    id: str
    name: str
    description: str
    external_references: List[ExternalReference] = Field(default_factory=list)


class DataSource(BaseModel):
    """ATT&CK Data Source model."""
    id: str
    name: str
    description: str
    data_components: List[str] = Field(default_factory=list)
    external_references: List[ExternalReference] = Field(default_factory=list)


class AttackBundle(BaseModel):
    """Complete ATT&CK data bundle."""
    techniques: List[Technique] = Field(default_factory=list)
    tactics: List[Tactic] = Field(default_factory=list)
    groups: List[Group] = Field(default_factory=list)
    software: List[Software] = Field(default_factory=list)
    mitigations: List[Mitigation] = Field(default_factory=list)
    data_sources: List[DataSource] = Field(default_factory=list)
    version: str = "unknown"
    last_updated: Optional[datetime] = None
    
    def get_technique_by_id(self, technique_id: str) -> Optional[Technique]:
        """Get technique by MITRE ID (e.g., T1059.003)."""
        for technique in self.techniques:
            if technique.mitre_id == technique_id:
                return technique
        return None
    
    def search_techniques(self, query: str) -> List[Technique]:
        """Search techniques by name or description."""
        query_lower = query.lower()
        results = []
        
        for technique in self.techniques:
            if (query_lower in technique.name.lower() or 
                query_lower in technique.description.lower()):
                results.append(technique)
        
        return results


# Detection Rule Models

class RuleStatus(str, Enum):
    """Sigma rule status levels."""
    STABLE = "stable"
    TEST = "test"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    UNSUPPORTED = "unsupported"


class RuleLevel(str, Enum):
    """Sigma rule severity levels."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LogSource(BaseModel):
    """Sigma rule log source definition."""
    product: Optional[str] = None
    service: Optional[str] = None
    category: Optional[str] = None
    definition: Optional[str] = None


class DetectionItem(BaseModel):
    """Detection logic item (selection, keyword, etc.)."""
    name: str
    conditions: Dict[str, Any]


class SigmaRule(BaseModel):
    """Sigma detection rule model."""
    title: str
    id: Optional[str] = None
    status: RuleStatus = RuleStatus.EXPERIMENTAL
    description: str
    author: Optional[str] = None
    date: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    logsource: LogSource
    detection: Dict[str, Any] = Field(default_factory=dict)
    condition: str = ""
    falsepositives: List[str] = Field(default_factory=list)
    level: RuleLevel = RuleLevel.MEDIUM
    
    @property
    def attack_techniques(self) -> List[str]:
        """Extract ATT&CK technique IDs from tags."""
        techniques = []
        for tag in self.tags:
            if tag.startswith("attack.t") and not tag.startswith("attack.ta"):
                # Extract technique ID (e.g., "attack.t1059.003" -> "T1059.003")
                technique_id = tag.replace("attack.t", "T").upper()
                techniques.append(technique_id)
        return techniques
    
    @property
    def attack_tactics(self) -> List[str]:
        """Extract ATT&CK tactic names from tags."""
        tactics = []
        for tag in self.tags:
            if tag.startswith("attack.") and not tag.startswith("attack.t"):
                # Extract tactic name (e.g., "attack.credential_access" -> "credential-access")
                tactic = tag.replace("attack.", "").replace("_", "-")
                tactics.append(tactic)
        return tactics


class RuleTemplate(BaseModel):
    """Template for generating detection rules."""
    technique_id: str
    name: str
    description: str
    platforms: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    tactics: List[str] = Field(default_factory=list)
    template_type: str = "sigma"  # sigma, splunk, elastic, etc.
    base_template: str = ""  # Template content with placeholders


class DetectionCoverage(BaseModel):
    """Detection coverage analysis model."""
    technique_id: str
    technique_name: str
    has_detection: bool = False
    rule_count: int = 0
    rule_files: List[str] = Field(default_factory=list)
    platforms_covered: List[str] = Field(default_factory=list)
    data_sources_covered: List[str] = Field(default_factory=list)
    coverage_score: float = 0.0  # 0-1 score based on completeness
    
    def calculate_coverage_score(self, technique: 'Technique') -> float:
        """Calculate coverage score based on platforms and data sources."""
        if not self.has_detection:
            return 0.0
        
        platform_coverage = 0.0
        if technique.platforms:
            covered_platforms = len(set(self.platforms_covered) & set(technique.platforms))
            platform_coverage = covered_platforms / len(technique.platforms)
        
        data_source_coverage = 0.0
        if technique.data_sources:
            covered_sources = len(set(self.data_sources_covered) & set(technique.data_sources))
            data_source_coverage = covered_sources / len(technique.data_sources)
        
        # Weighted average: 60% platform coverage, 40% data source coverage
        self.coverage_score = (platform_coverage * 0.6) + (data_source_coverage * 0.4)
        return self.coverage_score