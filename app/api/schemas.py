"""
Pydantic API Schemas
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class LogAnalysisRequest(BaseModel):
    raw_content: str = Field(..., description="Raw log text to parse and analyze")
    rules_config: Optional[List[Dict[str, Any]]] = None


class AiInvestigateRequest(BaseModel):
    title: str
    severity: str = "Medium"
    category: str = "General"
    evidence: List[str] = []
    rule_explanation: Optional[str] = ""
    log_excerpts: Optional[List[str]] = []


class ExportReportRequest(BaseModel):
    format: str = "json"  # json, csv, html
    analysis_data: Dict[str, Any]
    analyst_notes: Optional[str] = ""


class BenchmarkRequest(BaseModel):
    line_count: int = 10000
