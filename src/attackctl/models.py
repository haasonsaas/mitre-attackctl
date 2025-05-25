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
# These models support Sigma rule generation and coverage analysis functionality

class RuleStatus(str, Enum):
    """
    Sigma rule status levels indicating operational readiness.
    
    - STABLE: Production-ready rules with low false positive rates
    - TEST: Rules being validated, may have higher false positives  
    - EXPERIMENTAL: New rules requiring validation and tuning
    - DEPRECATED: Outdated rules that should be removed
    - UNSUPPORTED: Rules that may not work with current systems
    """
    STABLE = "stable"
    TEST = "test"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    UNSUPPORTED = "unsupported"


class RuleLevel(str, Enum):
    """
    Sigma rule severity levels for alert prioritization.
    
    Follows standard security severity classification:
    - CRITICAL: Immediate response required (active compromise)
    - HIGH: Urgent investigation (likely malicious activity)
    - MEDIUM: Standard investigation (suspicious activity)
    - LOW: Informational (potential reconnaissance)
    - INFORMATIONAL: Logging only (baseline activity)
    """
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LogSource(BaseModel):
    """
    Sigma rule log source definition specifying which logs to analyze.
    
    Attributes:
        product: Log source product (e.g., "windows", "linux", "aws")
        service: Specific service within product (e.g., "security", "system")
        category: Event category (e.g., "process_creation", "file_event")
        definition: Additional requirements for log source configuration
    """
    product: Optional[str] = None
    service: Optional[str] = None
    category: Optional[str] = None
    definition: Optional[str] = None


class DetectionItem(BaseModel):
    """
    Detection logic item representing a selection or condition block.
    
    Used internally for building complex detection logic with multiple
    selection criteria, keywords, filters, and conditions.
    """
    name: str
    conditions: Dict[str, Any]


class SigmaRule(BaseModel):
    """
    Complete Sigma detection rule model following official Sigma specification.
    
    Represents a structured detection rule that can be converted to various
    SIEM formats. Includes all standard Sigma fields plus helper methods
    for extracting ATT&CK framework mappings.
    
    Attributes:
        title: Short, descriptive rule name (< 50 chars recommended)
        id: Unique identifier (UUID) for rule management and relationships
        status: Operational status indicating rule maturity level
        description: Detailed explanation of what the rule detects
        author: Rule creator(s) for attribution and contact
        date: Creation date in YYYY/MM/DD format
        references: External URLs providing context or documentation
        tags: Framework mappings (ATT&CK, CAR, etc.) and categorization
        logsource: Specification of which logs to analyze
        detection: Core detection logic with selections and conditions
        condition: Boolean logic combining detection selections
        falsepositives: Known scenarios that may trigger false alerts
        level: Severity classification for alert prioritization
    """
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
        """
        Extract ATT&CK technique IDs from tags.
        
        Parses tags following the format "attack.t####.###" and converts
        them to standard MITRE technique format "T####.###".
        
        Returns:
            List of technique IDs (e.g., ["T1059.003", "T1003.001"])
        
        Example:
            tags = ["attack.t1059.003", "attack.credential_access"]
            rule.attack_techniques -> ["T1059.003"]
        """
        techniques = []
        for tag in self.tags:
            if tag.startswith("attack.t") and not tag.startswith("attack.ta"):
                # Extract technique ID (e.g., "attack.t1059.003" -> "T1059.003")
                technique_id = tag.replace("attack.t", "T").upper()
                techniques.append(technique_id)
        return techniques
    
    @property
    def attack_tactics(self) -> List[str]:
        """
        Extract ATT&CK tactic names from tags.
        
        Parses tactic tags and normalizes them to ATT&CK tactic naming
        convention (lowercase with hyphens).
        
        Returns:
            List of tactic names (e.g., ["credential-access", "execution"])
            
        Example:
            tags = ["attack.credential_access", "attack.t1059.003"]
            rule.attack_tactics -> ["credential-access"]
        """
        tactics = []
        for tag in self.tags:
            if tag.startswith("attack.") and not tag.startswith("attack.t"):
                # Extract tactic name (e.g., "attack.credential_access" -> "credential-access")
                tactic = tag.replace("attack.", "").replace("_", "-")
                tactics.append(tactic)
        return tactics


class RuleTemplate(BaseModel):
    """
    Template definition for generating detection rules from ATT&CK techniques.
    
    Stores metadata and template content for generating platform-specific
    detection rules. Templates use placeholder substitution to customize
    rules based on technique characteristics.
    
    Attributes:
        technique_id: ATT&CK technique ID this template applies to
        name: Human-readable template name
        description: Template purpose and usage notes
        platforms: Supported platforms (windows, linux, macos, etc.)
        data_sources: Required data sources for effective detection
        tactics: ATT&CK tactics this template addresses
        template_type: Target format (sigma, splunk, elastic, etc.)
        base_template: Template content with {placeholder} variables
    """
    technique_id: str
    name: str
    description: str
    platforms: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    tactics: List[str] = Field(default_factory=list)
    template_type: str = "sigma"  # sigma, splunk, elastic, etc.
    base_template: str = ""  # Template content with placeholders


class DetectionCoverage(BaseModel):
    """
    Analysis model for ATT&CK technique detection coverage assessment.
    
    Tracks detection capability for individual techniques across rule
    repositories, calculating coverage scores based on platform and
    data source completeness.
    
    Attributes:
        technique_id: ATT&CK technique identifier (e.g., "T1003.001")
        technique_name: Human-readable technique name
        has_detection: Whether any detection rules exist for this technique
        rule_count: Number of rules that detect this technique
        rule_files: File paths containing detection rules
        platforms_covered: Platforms with detection coverage
        data_sources_covered: Data sources with detection coverage  
        coverage_score: Calculated completeness score (0.0-1.0)
    """
    technique_id: str
    technique_name: str
    has_detection: bool = False
    rule_count: int = 0
    rule_files: List[str] = Field(default_factory=list)
    platforms_covered: List[str] = Field(default_factory=list)
    data_sources_covered: List[str] = Field(default_factory=list)
    coverage_score: float = 0.0  # 0-1 score based on completeness
    
    def calculate_coverage_score(self, technique: 'Technique') -> float:
        """
        Calculate detection coverage score based on platform and data source coverage.
        
        Uses weighted scoring to assess how comprehensively a technique is detected
        across its applicable platforms and required data sources.
        
        Args:
            technique: ATT&CK technique object with platform and data source info
            
        Returns:
            Coverage score from 0.0 (no coverage) to 1.0 (complete coverage)
            
        Scoring Algorithm:
            - Platform coverage: (covered platforms / total platforms) * 0.6
            - Data source coverage: (covered sources / total sources) * 0.4
            - Final score: weighted average of platform and data source coverage
            
        Example:
            Technique supports 3 platforms, 2 data sources
            Rules cover 2 platforms, 1 data source
            Score = (2/3 * 0.6) + (1/2 * 0.4) = 0.4 + 0.2 = 0.6
        """
        if not self.has_detection:
            return 0.0
        
        # Calculate platform coverage percentage
        platform_coverage = 0.0
        if technique.platforms:
            covered_platforms = len(set(self.platforms_covered) & set(technique.platforms))
            platform_coverage = covered_platforms / len(technique.platforms)
        
        # Calculate data source coverage percentage  
        data_source_coverage = 0.0
        if technique.data_sources:
            covered_sources = len(set(self.data_sources_covered) & set(technique.data_sources))
            data_source_coverage = covered_sources / len(technique.data_sources)
        
        # Weighted average: 60% platform coverage, 40% data source coverage
        # Platform coverage weighted higher as it's often more critical for detection
        self.coverage_score = (platform_coverage * 0.6) + (data_source_coverage * 0.4)
        return self.coverage_score