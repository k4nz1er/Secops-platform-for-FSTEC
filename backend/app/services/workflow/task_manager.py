from datetime import date, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from app.models.domain import Task, User, Vulnerability, TaskStatus
from app.services.workflow.audit_logger import audit_logger


class TaskManager:
    DEFAULT_DEADLINE_DAYS = 5

    def get_default_assignee(self, db: Session, role: str = "specialist") -> User:
        user = db.query(User).filter(User.role == role).first()
        if not user:
            user = db.query(User).first()
        if not user:
            raise ValueError("В таблице users нет ни одного ответственного сотрудника")
        return user

    def create_task_for_vulnerability(
        self,
        db: Session,
        vulnerability: Vulnerability,
        actor: str = "System",
        assignee_id: Optional[int] = None,
        deadline_days: Optional[int] = None,
    ) -> Task:
        if assignee_id is not None:
            assignee = db.query(User).filter(User.id == assignee_id).first()
            if not assignee:
                raise ValueError(f"Исполнитель с id={assignee_id} не найден")
        else:
            assignee = self.get_default_assignee(db, role="specialist")

        days = deadline_days if deadline_days is not None else self.DEFAULT_DEADLINE_DAYS
        deadline = date.today() + timedelta(days=days)

        task = Task(
            vulnerability_id=vulnerability.id,
            assignee=assignee.id,
            deadline=deadline,
            status=TaskStatus.IN_PROGRESS.value,
        )
        db.add(task)
        db.flush()

        audit_logger.log(
            db=db,
            object_type="task",
            object_id=task.id,
            action=(
                f"Создана задача по уязвимости ({vulnerability.bdu or '—'}) "
                f"из документа '{vulnerability.source_document}', "
                f"исполнитель: {assignee.name}, срок: {deadline.isoformat()}"
            ),
            user=actor,
        )
        return task

    def transition_status(
        self,
        db: Session,
        task: Task,
        new_status: TaskStatus,
        actor: str,
        action_taken: Optional[str] = None,
    ) -> Task:
        changes = []

        if task.status != new_status.value:
            changes.append(f"статус: '{task.status}' -> '{new_status.value}'")
            task.status = new_status.value
            if task.vulnerability:
                task.vulnerability.status = new_status.value

        if action_taken is not None and task.vulnerability:
            if task.vulnerability.action_taken != action_taken:
                changes.append("обновлено поле 'что сделано'")
                task.vulnerability.action_taken = action_taken

        if changes:
            audit_logger.log(
                db=db,
                object_type="task",
                object_id=task.id,
                action="Обновлена задача: " + ", ".join(changes),
                user=actor,
            )

        return task

    def reassign_task(
        self,
        db: Session,
        task: Task,
        new_assignee_id: int,
        actor: str,
    ) -> Task:
        new_user = db.query(User).filter(User.id == new_assignee_id).first()
        if not new_user:
            raise ValueError(f"Исполнитель с id={new_assignee_id} не найден")

        if task.assignee != new_user.id:
            task.assignee = new_user.id
            audit_logger.log(
                db=db,
                object_type="task",
                object_id=task.id,
                action=f"Исполнитель изменен на '{new_user.name}'",
                user=actor,
            )

        return task


task_manager = TaskManager()
