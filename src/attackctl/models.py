"""Data models for ATT&CK framework objects."""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime


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