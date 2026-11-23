from typing import List, Optional
from sqlalchemy.orm import Session
from app.models.domain import ActionHistory


class AuditLogger:
    def log(
        self,
        db: Session,
        object_type: str,
        object_id: int,
        action: str,
        user: str,
        commit: bool = False,
    ) -> ActionHistory:
        entry = ActionHistory(
            object_type=object_type,
            object_id=object_id,
            action=action,
            user=user,
        )
        db.add(entry)
        if commit:
            db.commit()
            db.refresh(entry)
        return entry

    def get_history(
        self,
        db: Session,
        object_type: Optional[str] = None,
        object_id: Optional[int] = None,
        user: Optional[str] = None,
        limit: int = 100,
    ) -> List[ActionHistory]:
        query = db.query(ActionHistory)

        if object_type:
            query = query.filter(ActionHistory.object_type == object_type)
        if object_id is not None:
            query = query.filter(ActionHistory.object_id == object_id)
        if user:
            query = query.filter(ActionHistory.user.ilike(f"%{user}%"))

        return query.order_by(ActionHistory.timestamp.desc()).limit(limit).all()


audit_logger = AuditLogger()
