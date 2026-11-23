import io
import csv
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.domain import IOC, Vulnerability, Task, User, ActionHistory, VulnStatus

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])

# ==============================================================================
# НАСТРОЙКИ ОТЧЁТА (РЕДАКТИРОВАТЬ ЗДЕСЬ)
# ==============================================================================

# Ответственный по умолчанию для строк БДУ (если в задаче не назначен вручную)
DEFAULT_BDU_ASSIGNEE = ""

# 4 стандартных пункта, которые добавляются в отчёт для каждого письма с IOC
IOC_REPORT_ITEMS = [
    {
        "bdu": "IOC",
        "description": "1",
        "action_taken": "1",
        "assignee": "Ответственный 1",
    },
    {
        "bdu": "IOC",
        "description": "2",
        "action_taken": "2",
        "assignee": "Ответственный 2",
    },
    {
        "bdu": "IOC",
        "description": "3",
        "action_taken": "3",
        "assignee": "Ответственный 3",
    },
    {
        "bdu": "IOC",
        "description": "4",
        "action_taken": "4",
        "assignee": "Ответственный 4",
    },
]

# ==============================================================================


class VulnerabilityUpdateRequest(BaseModel):
    bdu: Optional[str] = None
    cve: Optional[str] = None
    source_document: Optional[str] = None
    description: Optional[str] = None
    action_taken: Optional[str] = None
    status: Optional[VulnStatus] = None


class VulnerabilityResponse(BaseModel):
    id: int
    bdu: Optional[str]
    cve: Optional[str]
    source_document: Optional[str]
    affected_software: Optional[str]
    recommendations: Optional[str]
    description: str
    action_taken: str
    status: str

    class Config:
        from_attributes = True


@router.get("/", response_model=List[VulnerabilityResponse])
def list_vulnerabilities(
    vuln_status: Optional[str] = Query(None, alias="status"),
    bdu: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = db.query(Vulnerability)

    if vuln_status:
        query = query.filter(Vulnerability.status == vuln_status)
    if bdu:
        query = query.filter(Vulnerability.bdu.ilike(f"%{bdu}%"))
    if source:
        query = query.filter(Vulnerability.source_document.ilike(f"%{source}%"))
    if q:
        search = f"%{q}%"
        query = query.filter(
            Vulnerability.description.ilike(search)
            | Vulnerability.action_taken.ilike(search)
            | Vulnerability.bdu.ilike(search)
            | Vulnerability.cve.ilike(search)
        )

    return query.order_by(Vulnerability.id.asc()).offset(skip).limit(limit).all()


@router.get("/export")
def export_vulnerabilities_report(
    only_ready: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = (
        db.query(Vulnerability, User.name)
        .outerjoin(Task, Task.vulnerability_id == Vulnerability.id)
        .outerjoin(User, Task.assignee == User.id)
        .order_by(Vulnerability.id.asc())
    )

    if only_ready:
        query = query.filter(
            Vulnerability.status.in_([VulnStatus.COMPLETED.value, VulnStatus.CLOSED.value])
        )

    rows = query.all()

    # Уникальные письма из реестра IOC
    if only_ready:
        active_ioc_sources = {
            row[0]
            for row in db.query(IOC.source)
            .filter(
                IOC.source.isnot(None),
                IOC.source != "",
                IOC.status.in_(["В работе", "Активен"]),
            )
            .distinct()
            .all()
        }
        ioc_rows = (
            db.query(IOC.source)
            .filter(
                IOC.source.isnot(None),
                IOC.source != "",
                IOC.status.in_(["Выполнено", "Заблокирован"]),
            )
            .group_by(IOC.source)
            .order_by(func.min(IOC.id).asc())
            .all()
        )
        ioc_sources = [row[0] for row in ioc_rows if row[0] not in active_ioc_sources]
    else:
        ioc_rows = (
            db.query(IOC.source)
            .filter(IOC.source.isnot(None), IOC.source != "")
            .group_by(IOC.source)
            .order_by(func.min(IOC.id).asc())
            .all()
        )
        ioc_sources = [row[0] for row in ioc_rows]

    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")
    writer.writerow([
        "Номер письма",
        "№ п/п",
        "БДУ",
        "Описание",
        "Что сделано",
        "Кто ответственный",
    ])

    idx = 1
    for vuln, assignee_name in rows:
        writer.writerow([
            vuln.source_document or "",
            idx,
            vuln.bdu or "—",
            vuln.description or "",
            vuln.action_taken or "",
            assignee_name or DEFAULT_BDU_ASSIGNEE,
        ])
        idx += 1

    for source_doc in ioc_sources:
        for item in IOC_REPORT_ITEMS:
            writer.writerow([
                source_doc,
                idx,
                item["bdu"],
                item["description"],
                item["action_taken"],
                item["assignee"],
            ])
            idx += 1

    csv_bytes = output.getvalue().encode("utf-8-sig")
    headers = {
        "Content-Disposition": 'attachment; filename="fstec_report.csv"'
    }
    return StreamingResponse(
        io.BytesIO(csv_bytes),
        media_type="text/csv; charset=utf-8-sig",
        headers=headers,
    )


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
def get_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Запись об уязвимости не найдена",
        )
    return vuln


@router.patch("/{vuln_id}", response_model=VulnerabilityResponse)
def update_vulnerability(
    vuln_id: int,
    payload: VulnerabilityUpdateRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Запись об уязвимости не найдена",
        )

    changes = []

    if payload.bdu is not None and payload.bdu != vuln.bdu:
        changes.append(f"БДУ: '{vuln.bdu}' -> '{payload.bdu}'")
        vuln.bdu = payload.bdu
    if payload.cve is not None and payload.cve != vuln.cve:
        changes.append(f"CVE: '{vuln.cve}' -> '{payload.cve}'")
        vuln.cve = payload.cve
    if payload.source_document is not None and payload.source_document != vuln.source_document:
        changes.append(f"письмо: '{vuln.source_document}' -> '{payload.source_document}'")
        vuln.source_document = payload.source_document
    if payload.description is not None and payload.description != vuln.description:
        changes.append("обновлено описание")
        vuln.description = payload.description
    if payload.action_taken is not None and payload.action_taken != vuln.action_taken:
        changes.append("обновлено поле 'что сделано'")
        vuln.action_taken = payload.action_taken
    if payload.status is not None and payload.status.value != vuln.status:
        changes.append(f"статус: '{vuln.status}' -> '{payload.status.value}'")
        vuln.status = payload.status.value
        for task in vuln.tasks:
            task.status = payload.status.value

    if changes:
        actor = current_user.get("preferred_username") or current_user.get("name", "ИБ-Специалист")
        db.add(
            ActionHistory(
                object_type="vulnerability",
                object_id=vuln.id,
                action="Обновлена уязвимость: " + ", ".join(changes),
                user=actor,
            )
        )
        db.commit()
        db.refresh(vuln)

    return vuln


@router.delete("/{vuln_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Запись об уязвимости не найдена",
        )

    actor = current_user.get("preferred_username") or current_user.get("name", "ИБ-Специалист")
    db.add(
        ActionHistory(
            object_type="vulnerability",
            object_id=vuln.id,
            action=f"Удалена запись (БДУ: {vuln.bdu}, письмо: {vuln.source_document})",
            user=actor,
        )
    )
    db.delete(vuln)
    db.commit()
