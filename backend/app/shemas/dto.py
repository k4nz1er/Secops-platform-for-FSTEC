from datetime import date, datetime
from typing import Any, List, Optional
from pydantic import BaseModel, ConfigDict
from app.models.domain import TaskStatus, VulnStatus


class UserDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    role: str


class VulnerabilityBase(BaseModel):
    bdu: Optional[str] = None
    cve: Optional[str] = None
    source_document: Optional[str] = None
    affected_software: Optional[str] = None
    recommendations: Optional[str] = None
    description: str = ""
    action_taken: str = ""
    status: VulnStatus = VulnStatus.IN_PROGRESS


class VulnerabilityUpdateDTO(BaseModel):
    bdu: Optional[str] = None
    cve: Optional[str] = None
    source_document: Optional[str] = None
    affected_software: Optional[str] = None
    recommendations: Optional[str] = None
    description: Optional[str] = None
    action_taken: Optional[str] = None
    status: Optional[VulnStatus] = None


class VulnerabilityDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    bdu: Optional[str]
    cve: Optional[str]
    source_document: Optional[str]
    affected_software: Optional[str]
    recommendations: Optional[str]
    description: str
    action_taken: str
    status: str
    created_at: datetime


class TaskUpdateDTO(BaseModel):
    status: Optional[TaskStatus] = None
    action_taken: Optional[str] = None
    assignee: Optional[int] = None


class KanbanCardDTO(BaseModel):
    task_id: int
    vulnerability_id: int
    source_document: Optional[str]
    bdu: Optional[str]
    cve: Optional[str]
    description: str
    action_taken: str
    assignee_id: int
    assignee_name: str
    deadline: date
    status: str


class DashboardMetricsDTO(BaseModel):
    total_tasks: int
    total_vulnerabilities: int
    total_iocs: int
    completion_percentage: float


class KanbanColumnsDTO(BaseModel):
    in_progress: List[KanbanCardDTO]
    closed: List[KanbanCardDTO]


class DashboardStateDTO(BaseModel):
    metrics: DashboardMetricsDTO
    columns: KanbanColumnsDTO


class IocUpdateDTO(BaseModel):
    status: Optional[str] = None
    reputation: Optional[str] = None


class IocDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    type: str
    value: str
    source: str
    reputation: str
    status: str
    created_at: datetime


class ActionHistoryDTO(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    object_type: str
    object_id: int
    action: str
    user: str
    timestamp: datetime


class DocumentUploadResponseDTO(BaseModel):
    status: str
    task_id: str
    filename: str


class TaskProcessingStatusDTO(BaseModel):
    task_id: str
    state: str
    result: Optional[Any] = None
