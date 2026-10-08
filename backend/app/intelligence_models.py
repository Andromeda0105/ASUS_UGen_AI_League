"""Scan-local graph and investigation contracts; no external graph database."""
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


class GraphNode(BaseModel):
    id: str
    node_type: Literal["incident", "alert", "event", "ip", "user", "endpoint"]
    label: str
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relation: str
    edge_type: Literal["observed", "inferred"]
    evidence_ids: list[str] = Field(min_length=1)
    confidence: float | None = Field(default=None, ge=0, le=1)
    reasons: list[str] = Field(default_factory=list)


class EvidenceGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    scope: str = "current_scan_only"
    confidence_note: str = "推論邊的分數是規則對關係的支持程度，未經統計校準，並非入侵機率。"

    @model_validator(mode="after")
    def integrity(self):
        ids = {node.id for node in self.nodes}
        if len(ids) != len(self.nodes) or len({edge.id for edge in self.edges}) != len(self.edges):
            raise ValueError("Graph IDs must be unique")
        if any(edge.source not in ids or edge.target not in ids for edge in self.edges):
            raise ValueError("Graph edge references a missing node")
        return self


HypothesisStatus = Literal["plausible", "supported", "weak", "contradicted", "insufficient_evidence"]


class InvestigationHypothesis(BaseModel):
    id: str
    incident_id: str
    template: str
    title: str
    description: str
    status: HypothesisStatus
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    neutral_evidence_ids: list[str] = Field(default_factory=list)
    supporting_edge_ids: list[str] = Field(default_factory=list)
    contradicting_edge_ids: list[str] = Field(default_factory=list)
    neutral_edge_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    confidence_origin: Literal["rule", "ai_bounded"] = "rule"
    inference: str = "尚未進行 AI 比較；這是未驗證假說。"
    inference_evidence_ids: list[str] = Field(default_factory=list)


class InvestigationQuestion(BaseModel):
    id: str
    hypothesis_ids: list[str]
    question: str
    evidence_type: str
    answerable: bool
    suggested_tool: str | None = None
    tool_arguments: dict[str, Any] = Field(default_factory=dict)
    status: Literal["pending", "answered", "unavailable", "error"] = "pending"
    answer: str | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    truncated: bool = False


class ObservedFact(BaseModel):
    text: str
    evidence_ids: list[str] = Field(min_length=1)


class HypothesisReport(BaseModel):
    incident_id: str
    hypotheses: list[InvestigationHypothesis]
    observed_facts: list[ObservedFact]
    questions: list[InvestigationQuestion]
    missing_evidence: list[str]
    uncertainty: str
    stop_reason: Literal["not_run", "all_answerable_checked", "tool_budget_exhausted", "unavailable_telemetry", "no_new_distinguishing_evidence", "iteration_limit"] = "not_run"
    stop_explanation: str = "尚未進行唯讀調查；假說與觀察事實由規則建立。"
    tool_calls: int = 0
    tool_budget: int = 4
    iteration_count: int = 0
    confidence_note: str = "各分數表示證據對假說的支持程度，未經校準、不必合計為 1，並非入侵機率。"


class HypothesisEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hypothesis_id: str
    status: HypothesisStatus
    confidence: float = Field(ge=0, le=1)
    inference: str = Field(min_length=1, max_length=600)
    evidence_ids: list[str] = Field(min_length=1, max_length=8)
    graph_edge_ids: list[str] = Field(default_factory=list, max_length=8)


class InvestigationPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question_ids: list[str] = Field(max_length=12)


class InvestigationRequest(BaseModel):
    with_ai: bool = False
    tool_budget: int = Field(default=4, ge=0, le=12)
    question_ids: list[str] | None = Field(default=None, max_length=12)
