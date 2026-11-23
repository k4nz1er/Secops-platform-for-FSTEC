from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from celery.result import AsyncResult
from app.core.security import get_current_user
from app.worker.tasks import celery_app, process_incoming_document

router = APIRouter(prefix="/api/v1/documents", tags=["Documents"])

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx", "rtf", "txt", "msg", "eml"}
VALID_DOC_TYPES = {"bdu", "ioc", "auto"}
MAX_FILE_SIZE = 50 * 1024 * 1024


@router.post("/upload", status_code=status.HTTP_202_ACCEPTED)
async def upload_document(
    file: UploadFile = File(...),
    doc_type: str = Form("auto"),
    current_user: dict = Depends(get_current_user),
):
    if not file.filename or "." not in file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Некорректное имя файла",
        )

    normalized_doc_type = (doc_type or "auto").strip().lower()
    if normalized_doc_type not in VALID_DOC_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Некорректный тип письма '{doc_type}'. Допустимые: bdu, ioc, auto",
        )

    ext = file.filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"Формат .{ext} не поддерживается. Допустимые: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )

    content = await file.read()
    if not content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Загруженный файл пуст",
        )

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Размер файла превышает допустимый лимит (50 МБ)",
        )

    actor_name = current_user.get("preferred_username") or current_user.get("name", "ИБ-Специалист")
    task = process_incoming_document.delay(
        file.filename,
        content.hex(),
        actor_name,
        normalized_doc_type,
    )

    return {
        "status": "queued",
        "task_id": task.id,
        "filename": file.filename,
        "doc_type": normalized_doc_type,
    }


@router.get("/status/{task_id}")
def get_processing_status(
    task_id: str,
    current_user: dict = Depends(get_current_user),
):
    result = AsyncResult(task_id, app=celery_app)
    response = {
        "task_id": task_id,
        "state": result.state,
    }
    if result.ready():
        response["result"] = result.result if result.successful() else str(result.result)
    return response
