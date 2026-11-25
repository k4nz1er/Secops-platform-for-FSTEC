import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.domain import (
    ActionHistory,
    IOC,
    Task,
    TaskStatus,
    User,
    Vulnerability,
    VulnStatus,
)

router = APIRouter(prefix="/api/v1/kanban", tags=["Kanban & Dashboard"])

NOT_RELEVANT_RE = re.compile(
    r"(не\s*актуал|не\s*примен|не\s*использует|не\s*установл|отсутств|нет\s+по|(?:^|\s)н/а(?:$|\s|[.,;]))",
    re.IGNORECASE,
)

DONE_STATUSES = {"выполнена", "выполнено", "закрыта", "закрыто", "заблокирован"}
CLOSED_ONLY_STATUSES = {"закрыта", "закрыто"}


def _is_not_relevant(action_taken: Optional[str]) -> bool:
    return bool(action_taken and NOT_RELEVANT_RE.search(action_taken))


def _norm_status(value: Optional[str]) -> str:
    return (value or "").strip().lower()


def _is_done_status(value: Optional[str]) -> bool:
    return _norm_status(value) in DONE_STATUSES


def _is_closed_status(value: Optional[str]) -> bool:
    return _norm_status(value) in CLOSED_ONLY_STATUSES


class TaskUpdateRequest(BaseModel):
    status: Optional[TaskStatus] = None
    action_taken: Optional[str] = None
    assignee: Optional[int] = None


class LetterStatusUpdateRequest(BaseModel):
    source_document: str
    status: str  # "В работе" | "Выполнено" | "Закрыто"


@router.get("/dashboard")
def get_dashboard_state(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    vulns: List[Vulnerability] = db.query(Vulnerability).order_by(Vulnerability.id.desc()).all()
    iocs: List[IOC] = db.query(IOC).order_by(IOC.id.desc()).all()

    # 1. Статистика по БДУ для круговой диаграммы
    bdu_closed = 0
    bdu_in_progress = 0
    bdu_not_relevant = 0

    for v in vulns:
        bdu_val = (v.bdu or "").strip()
        if not bdu_val or bdu_val == "—":
            continue
        if _is_not_relevant(v.action_taken):
            bdu_not_relevant += 1
        elif _is_done_status(v.status):
            bdu_closed += 1
        else:
            bdu_in_progress += 1

    bdu_total = bdu_closed + bdu_in_progress + bdu_not_relevant
    bdu_done_total = bdu_closed + bdu_not_relevant

    # 2. Статистика по индикаторам (IOC)
    iocs_total = len(iocs)
    iocs_done = sum(1 for ioc in iocs if _is_done_status(ioc.status))
    iocs_in_progress = iocs_total - iocs_done

    # 3. Агрегация всех писем (БДУ + IOC)
    letters_map: Dict[str, Dict[str, Any]] = {}

    def get_letter_bucket(raw_name: Optional[str]) -> Dict[str, Any]:
        doc_name = (raw_name or "").strip() or "Без номера письма"
        if doc_name not in letters_map:
            letters_map[doc_name] = {
                "source_document": doc_name,
                "bdu_total": 0,
                "bdu_closed": 0,
                "bdu_not_relevant": 0,
                "bdu_in_progress": 0,
                "ioc_total": 0,
                "ioc_done": 0,
                "ioc_in_progress": 0,
                "has_vulns": False,
                "has_iocs": False,
                "all_statuses": [],
                "latest_created_at": None,
            }
        return letters_map[doc_name]

    for v in vulns:
        bucket = get_letter_bucket(v.source_document)
        bucket["has_vulns"] = True
        bdu_val = (v.bdu or "").strip()
        is_not_rel = _is_not_relevant(v.action_taken)
        is_done = _is_done_status(v.status) or is_not_rel

        if bdu_val and bdu_val != "—":
            bucket["bdu_total"] += 1
            if is_not_rel:
                bucket["bdu_not_relevant"] += 1
            elif _is_done_status(v.status):
                bucket["bdu_closed"] += 1
            else:
                bucket["bdu_in_progress"] += 1

        effective_status = v.status
        if is_not_rel and not _is_done_status(v.status):
            effective_status = VulnStatus.COMPLETED.value
        bucket["all_statuses"].append(effective_status)

        if v.created_at and (
            bucket["latest_created_at"] is None or v.created_at > bucket["latest_created_at"]
        ):
            bucket["latest_created_at"] = v.created_at

    for ioc in iocs:
        bucket = get_letter_bucket(ioc.source)
        bucket["has_iocs"] = True
        bucket["ioc_total"] += 1
        if _is_done_status(ioc.status):
            bucket["ioc_done"] += 1
        else:
            bucket["ioc_in_progress"] += 1
        bucket["all_statuses"].append(ioc.status)

        if ioc.created_at and (
            bucket["latest_created_at"] is None or ioc.created_at > bucket["latest_created_at"]
        ):
            bucket["latest_created_at"] = ioc.created_at

    letters_in_progress: List[Dict[str, Any]] = []
    letters_completed_or_closed: List[Dict[str, Any]] = []
    letters_completed_count = 0
    letters_closed_count = 0

    for bucket in letters_map.values():
        statuses = bucket["all_statuses"]
        has_active = any(not _is_done_status(st) for st in statuses)
        all_closed = bool(statuses) and all(_is_closed_status(st) for st in statuses)

        if has_active:
            letter_status = "В работе"
        elif all_closed:
            letter_status = "Закрыто"
            letters_closed_count += 1
        else:
            letter_status = "Выполнено"
            letters_completed_count += 1

        total_items = len(statuses)
        done_items = sum(1 for st in statuses if _is_done_status(st))
        progress_pct = round((done_items / total_items) * 100) if total_items > 0 else 0

        categories: List[str] = []
        if bucket["has_vulns"]:
            categories.append("БДУ")
        if bucket["has_iocs"]:
            categories.append("IOC")

        letter_card = {
            "source_document": bucket["source_document"],
            "status": letter_status,
            "categories": categories,
            "bdu_total": bucket["bdu_total"],
            "bdu_closed": bucket["bdu_closed"],
            "bdu_not_relevant": bucket["bdu_not_relevant"],
            "bdu_in_progress": bucket["bdu_in_progress"],
            "ioc_total": bucket["ioc_total"],
            "ioc_done": bucket["ioc_done"],
            "ioc_in_progress": bucket["ioc_in_progress"],
            "total_items": total_items,
            "done_items": done_items,
            "progress_percentage": progress_pct,
            "updated_at": bucket["latest_created_at"].isoformat() if bucket["latest_created_at"] else None,
        }

        if letter_status == "В работе":
            letters_in_progress.append(letter_card)
        else:
            letters_completed_or_closed.append(letter_card)

    letters_in_progress.sort(key=lambda x: x["updated_at"] or "", reverse=True)
    letters_completed_or_closed.sort(key=lambda x: x["updated_at"] or "", reverse=True)

    total_entities = bdu_total + iocs_total
    done_entities = bdu_done_total + iocs_done
    overall_completion = round((done_entities / total_entities) * 100, 1) if total_entities > 0 else 0.0
    bdu_completion = round((bdu_done_total / bdu_total) * 100, 1) if bdu_total > 0 else 0.0
    ioc_completion = round((iocs_done / iocs_total) * 100, 1) if iocs_total > 0 else 0.0

    letters_total = len(letters_map)
    letters_done_total = letters_completed_count + letters_closed_count
    letters_completion = (
        round((letters_done_total / letters_total) * 100, 1) if letters_total > 0 else 0.0
    )

    return {
        "bdu_stats": {
            "total": bdu_total,
            "closed": bdu_closed,
            "in_progress": bdu_in_progress,
            "not_relevant": bdu_not_relevant,
            "completion_percentage": bdu_completion,
        },
        "ioc_stats": {
            "total": iocs_total,
            "done": iocs_done,
            "in_progress": iocs_in_progress,
            "completion_percentage": ioc_completion,
        },
        "progress": {
            "overall_percentage": overall_completion,
            "done_entities": done_entities,
            "total_entities": total_entities,
            "letters_total": letters_total,
            "letters_in_progress": len(letters_in_progress),
            "letters_completed": letters_completed_count,
            "letters_closed": letters_closed_count,
            "letters_completion_percentage": letters_completion,
        },
        "letters": {
            "in_progress": letters_in_progress,
            "completed_or_closed": letters_completed_or_closed,
        },
    }


@router.patch("/letters/status")
def update_letter_status(
    payload: LetterStatusUpdateRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    target = (payload.status or "").strip()
    if target not in ("В работе", "Выполнено", "Закрыто"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Допустимые статусы письма: 'В работе', 'Выполнено', 'Закрыто'",
        )

    vuln_status_map = {
        "В работе": VulnStatus.IN_PROGRESS.value,
        "Выполнено": VulnStatus.COMPLETED.value,
        "Закрыто": VulnStatus.CLOSED.value,
    }
    ioc_status_map = {
        "В работе": "В работе",
        "Выполнено": "Выполнено",
        "Закрыто": "Закрыто",
    }

    doc_name = payload.source_document.strip()
    if doc_name == "Без номера письма":
        vulns = db.query(Vulnerability).filter(
            (Vulnerability.source_document.is_(None)) | (Vulnerability.source_document == "")
        ).all()
        iocs = db.query(IOC).filter(
            (IOC.source.is_(None)) | (IOC.source == "")
        ).all()
    else:
        vulns = db.query(Vulnerability).filter(Vulnerability.source_document == doc_name).all()
        iocs = db.query(IOC).filter(IOC.source == doc_name).all()

    if not vulns and not iocs:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Записи по указанному письму не найдены",
        )

    new_vuln_status = vuln_status_map[target]
    new_ioc_status = ioc_status_map[target]

    vuln_ids = [v.id for v in vulns]
    for v in vulns:
        v.status = new_vuln_status

    if vuln_ids:
        db.query(Task).filter(Task.vulnerability_id.in_(vuln_ids)).update(
            {Task.status: new_vuln_status},
            synchronize_session=False,
        )

    for ioc in iocs:
        ioc.status = new_ioc_status

    actor = current_user.get("preferred_username") or current_user.get("name", "ИБ-Специалист")
    db.add(
        ActionHistory(
            object_type="letter",
            object_id=vuln_ids[0] if vuln_ids else (iocs[0].id if iocs else 0),
            action=f"Статус письма '{doc_name}' изменён на '{target}' (БДУ: {len(vulns)}, IOC: {len(iocs)})",
            user=actor,
        )
    )
    db.commit()

    return {
        "status": "ok",
        "source_document": doc_name,
        "new_status": target,
        "updated_vulns": len(vulns),
        "updated_iocs": len(iocs),
    }


@router.patch("/tasks/{task_id}/status")
def update_task_status(
    task_id: int,
    payload: TaskUpdateRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Задача не найдена",
        )

    changes = []

    if payload.status is not None and payload.status.value != task.status:
        changes.append(f"статус: '{task.status}' -> '{payload.status.value}'")
        task.status = payload.status.value
        if task.vulnerability:
            task.vulnerability.status = payload.status.value

    if payload.action_taken is not None and task.vulnerability:
        if payload.action_taken != task.vulnerability.action_taken:
            changes.append("обновлено поле 'что сделано'")
            task.vulnerability.action_taken = payload.action_taken

    if payload.assignee is not None and payload.assignee != task.assignee:
        new_user = db.query(User).filter(User.id == payload.assignee).first()
        if not new_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Указанный исполнитель не найден",
            )
        changes.append(f"исполнитель изменен на '{new_user.name}'")
        task.assignee = new_user.id

    if changes:
        actor = current_user.get("preferred_username") or current_user.get("name", "ИБ-Специалист")
        db.add(
            ActionHistory(
                object_type="task",
                object_id=task.id,
                action="Обновлена задача: " + ", ".join(changes),
                user=actor,
            )
        )
        db.commit()

    return {
        "status": "ok",
        "task_id": task.id,
        "new_status": task.status,
    }
