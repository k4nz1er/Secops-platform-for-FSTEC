from datetime import datetime, timezone
import io
from typing import Dict, List, Optional, Tuple
import uuid
import xml.etree.ElementTree as ET
import zipfile

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.domain import IOC, ActionHistory

router = APIRouter(prefix="/api/v1/iocs", tags=["IOCs"])

ACTIVE_WORK_STATUSES = ("В работе", "Активен")
DONE_STATUS = "Выполнено"

# Маппинг типов IOC в OpenIOC 1.0 термы KATA:
# (группа_файла, document, search, content_type, condition)
# При необходимости под конкретный модуль KATA легко поменять search
# (например, DnsEntryItem/Host -> Network/DNS или UrlHistoryItem/URL -> Network/URI)
KATA_OPENIOC_MAP: Dict[str, Tuple[str, str, str, str, str]] = {
    "MD5": ("hashes", "FileItem", "FileItem/Md5sum", "md5", "is"),
    "SHA1": ("hashes", "FileItem", "FileItem/Sha1sum", "sha1", "is"),
    "SHA256": ("hashes", "FileItem", "FileItem/Sha256sum", "sha256", "is"),
    "IP": ("ip", "PortItem", "PortItem/remoteIP", "IP", "is"),
    "Domain": ("domains", "DnsEntryItem", "DnsEntryItem/Host", "string", "is"),
    "URL": ("urls", "UrlHistoryItem", "UrlHistoryItem/URL", "string", "contains"),
}

KATA_GROUP_TITLES: Dict[str, str] = {
    "hashes": "File Hashes (MD5/SHA1/SHA256)",
    "ip": "IP Addresses",
    "domains": "Domains",
    "urls": "URLs",
}


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
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


def _build_openioc_xml(
    group_key: str,
    items: List[IOC],
    timestamp_iso: str,
    date_label: str,
) -> bytes:
    root = ET.Element(
        "ioc",
        {
            "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
            "xmlns:xsd": "http://www.w3.org/2001/XMLSchema",
            "id": str(uuid.uuid4()),
            "last-modified": timestamp_iso,
            "xmlns": "http://schemas.mandiant.com/2010/ioc",
        },
    )

    title = KATA_GROUP_TITLES.get(group_key, group_key)
    sources = sorted({i.source for i in items if i.source})
    sources_preview = ", ".join(sources[:10])
    if len(sources) > 10:
        sources_preview += f" (+ ещё {len(sources) - 10})"

    short_desc = ET.SubElement(root, "short_description")
    short_desc.text = f"SecOps KATA {title} ({date_label})"

    desc = ET.SubElement(root, "description")
    desc.text = f"Автоматическая выгрузка IOC ({len(items)} шт.). Источники: {sources_preview}"

    authored_by = ET.SubElement(root, "authored_by")
    authored_by.text = "SecOps Platform"

    authored_date = ET.SubElement(root, "authored_date")
    authored_date.text = timestamp_iso

    ET.SubElement(root, "links")

    definition = ET.SubElement(root, "definition")
    root_indicator = ET.SubElement(
        definition,
        "Indicator",
        {"operator": "OR", "id": str(uuid.uuid4())},
    )

    seen_values = set()
    for ioc in items:
        mapping = KATA_OPENIOC_MAP.get(ioc.type)
        if not mapping:
            continue
        dedup_key = (ioc.type, ioc.value)
        if dedup_key in seen_values:
            continue
        seen_values.add(dedup_key)

        _, document, search, content_type, condition = mapping
        ind_item = ET.SubElement(
            root_indicator,
            "IndicatorItem",
            {"id": str(uuid.uuid4()), "condition": condition},
        )
        ET.SubElement(
            ind_item,
            "Context",
            {"document": document, "search": search, "type": "mir"},
        )
        content = ET.SubElement(ind_item, "Content", {"type": content_type})
        content.text = ioc.value.strip()

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


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
        pattern = f"%{q}%"
        query = query.filter(
            or_(IOC.value.ilike(pattern), IOC.source.ilike(pattern))
        )

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


@router.post("/export/kata")
def export_iocs_for_kata(
    ioc_type: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    query = db.query(IOC).filter(IOC.status.in_(ACTIVE_WORK_STATUSES))

    if ioc_type:
        query = query.filter(IOC.type == ioc_type)
    if source:
        query = query.filter(IOC.source.ilike(f"%{source}%"))

    records = query.order_by(IOC.id.asc()).all()
    if not records:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Нет индикаторов в статусе «В работе» для выгрузки в KATA",
        )

    grouped: Dict[str, List[IOC]] = {}
    exported_records: List[IOC] = []

    for rec in records:
        mapping = KATA_OPENIOC_MAP.get(rec.type)
        if not mapping:
            continue
        group_key = mapping[0]
        grouped.setdefault(group_key, []).append(rec)
        exported_records.append(rec)

    if not exported_records:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Среди активных индикаторов нет поддерживаемых KATA типов",
        )

    now = datetime.now(timezone.utc)
    timestamp_iso = now.strftime("%Y-%m-%dT%H:%M:%S")
    file_stamp = now.strftime("%Y%m%d_%H%M%S")
    date_label = now.strftime("%d.%m.%Y")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for group_key, group_items in grouped.items():
            xml_bytes = _build_openioc_xml(
                group_key=group_key,
                items=group_items,
                timestamp_iso=timestamp_iso,
                date_label=date_label,
            )
            zf.writestr(f"kata_{group_key}_{file_stamp}.ioc", xml_bytes)

    actor = current_user.get("preferred_username") or current_user.get("name", "ИБ-Специалист")
    for rec in exported_records:
        old_status = rec.status
        rec.status = DONE_STATUS
        db.add(
            ActionHistory(
                object_type="ioc",
                object_id=rec.id,
                action=(
                    f"Выгружен в KATA (OpenIOC): статус '{old_status}' -> '{DONE_STATUS}' "
                    f"({rec.type}: {rec.value})"
                ),
                user=actor,
            )
        )

    db.commit()

    filename = f"kata_iocs_{file_stamp}.zip"
    return Response(
        content=zip_buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Exported-Count": str(len(exported_records)),
            "Access-Control-Expose-Headers": "Content-Disposition, X-Exported-Count",
        },
    )


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
        db.add(
            ActionHistory(
                object_type="ioc",
                object_id=ioc.id,
                action=f"Обновлен IOC ({ioc.value}): " + ", ".join(changes),
                user=actor,
            )
        )
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
    db.add(
        ActionHistory(
            object_type="ioc",
            object_id=ioc.id,
            action=f"Удален IOC ({ioc.type}): {ioc.value}",
            user=actor,
        )
    )
    db.delete(ioc)
    db.commit()
