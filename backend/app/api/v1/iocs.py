from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.domain import IOC, ActionHistory

router = APIRouter(prefix="/api/v1/iocs", tags=["IOCs"])


class IocUpdateRequest(BaseModel):
    status: Optional[str] = None
    reputation: Optional[str] = None


class IocResponse(BaseModel):
    id: int
    type: str
    value: str
    source: str
    reputation: str
    status: str

    class Config:
        from_attributes = True


@router.get("/", response_model=List[IocResponse])
def list_iocs(
    ioc_type: Optional[str] = Query(None),
    ioc_status: Optional[str] = Query(None, alias="status"),
    source: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = db.query(IOC)

    if ioc_type:
        query = query.filter(IOC.type == ioc_type)
    if ioc_status:
        query = query.filter(IOC.status == ioc_status)
    if source:
        query = query.filter(IOC.source.ilike(f"%{source}%"))
    if q:
        query = query.filter(IOC.value.ilike(f"%{q}%"))

    return query.order_by(IOC.id.desc()).offset(skip).limit(limit).all()


@router.get("/export", response_class=PlainTextResponse)
def export_iocs_blocklist(
    ioc_type: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    ioc_status: Optional[str] = Query(None, alias="status"),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = db.query(IOC.value)

    if ioc_type:
        query = query.filter(IOC.type == ioc_type)
    if source:
        query = query.filter(IOC.source.ilike(f"%{source}%"))
    if ioc_status:
        query = query.filter(IOC.status == ioc_status)

    values = sorted({row[0] for row in query.all() if row[0]})
    content = "\n".join(values)

    headers = {
        "Content-Disposition": 'attachment; filename="iocs_blocklist.txt"'
    }
    return PlainTextResponse(content=content, headers=headers)


@router.get("/{ioc_id}", response_model=IocResponse)
def get_ioc(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Индикатор компрометации не найден",
        )
    return ioc


@router.patch("/{ioc_id}", response_model=IocResponse)
def update_ioc(
    ioc_id: int,
    payload: IocUpdateRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Индикатор компрометации не найден",
        )

    changes = []
    if payload.status is not None and payload.status != ioc.status:
        changes.append(f"статус: '{ioc.status}' -> '{payload.status}'")
        ioc.status = payload.status
    if payload.reputation is not None and payload.reputation != ioc.reputation:
        changes.append(f"репутация: '{ioc.reputation}' -> '{payload.reputation}'")
        ioc.reputation = payload.reputation

    if changes:
        actor = current_user.get("preferred_username") or current_user.get("name", "ИБ-Специалист")
        db.add(ActionHistory(
            object_type="ioc",
            object_id=ioc.id,
            action=f"Обновлен IOC ({ioc.value}): " + ", ".join(changes),
            user=actor,
        ))
        db.commit()
        db.refresh(ioc)

    return ioc


@router.delete("/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_ioc(
    ioc_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Индикатор компрометации не найден",
        )

    actor = current_user.get("preferred_username") or current_user.get("name", "ИБ-Специалист")
    db.add(ActionHistory(
        object_type="ioc",
        object_id=ioc.id,
        action=f"Удален IOC ({ioc.type}): {ioc.value}",
        user=actor,
    ))
    db.delete(ioc)
    db.commit()
