from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.domain import Task, Vulnerability, IOC, User, ActionHistory, TaskStatus

router = APIRouter(prefix="/api/v1/kanban", tags=["Kanban & Dashboard"])


class TaskUpdateRequest(BaseModel):
    status: Optional[TaskStatus] = None
    action_taken: Optional[str] = None
    assignee: Optional[int] = None


@router.get("/dashboard")
def get_dashboard_state(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    total_tasks = db.query(func.count(Task.id)).scalar() or 0
    closed_tasks = (
        db.query(func.count(Task.id))
        .filter(Task.status.in_([TaskStatus.COMPLETED.value, TaskStatus.CLOSED.value]))
        .scalar()
        or 0
    )

    total_vulns = (
        db.query(func.count(Vulnerability.id))
        .filter(Vulnerability.bdu != "—")
        .scalar()
        or 0
    )
    total_iocs = db.query(func.count(IOC.id)).scalar() or 0
    completion_rate = round((closed_tasks / total_tasks) * 100, 1) if total_tasks > 0 else 0.0

    tasks_query = (
        db.query(Task, Vulnerability, User)
        .join(Vulnerability, Task.vulnerability_id == Vulnerability.id)
        .join(User, Task.assignee == User.id)
        .order_by(Task.id.asc())
        .all()
    )

    columns = {
        "in_progress": [],
        "closed": [],
    }

    for task, vuln, user in tasks_query:
        card = {
            "task_id": task.id,
            "vulnerability_id": vuln.id,
            "source_document": vuln.source_document,
            "bdu": vuln.bdu,
            "cve": vuln.cve,
            "description": vuln.description,
            "action_taken": vuln.action_taken,
            "assignee_id": user.id,
            "assignee_name": user.name,
            "deadline": task.deadline.isoformat(),
            "status": task.status,
        }
        if task.status == TaskStatus.IN_PROGRESS.value:
            columns["in_progress"].append(card)
        else:
            columns["closed"].append(card)

    return {
        "metrics": {
            "total_tasks": total_tasks,
            "total_vulnerabilities": total_vulns,
            "total_iocs": total_iocs,
            "completion_percentage": completion_rate,
        },
        "columns": columns,
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
