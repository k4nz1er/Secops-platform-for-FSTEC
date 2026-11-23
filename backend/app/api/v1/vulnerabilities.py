import io
import csv
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.domain import Vulnerability, Task, User, ActionHistory, VulnStatus

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["Vulnerabilities"])


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

    for idx, (vuln, assignee_name) in enumerate(rows, start=1):
        writer.writerow([
            vuln.source_document or "",
            idx,
            vuln.bdu or "—",
            vuln.description or "",
            vuln.action_taken or "",
            assignee_name or "",
        ])

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
