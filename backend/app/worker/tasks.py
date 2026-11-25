from typing import Any, Dict
from app.core.broker import celery_app
from app.core.database import SessionLocal
from app.models.domain import IOC, Vulnerability, VulnStatus
from app.services.enrichment.fstec_client import fstec_client
from app.services.ingestion.dispatcher import document_dispatcher
from app.services.ingestion.entity_parser import entity_parser
from app.services.workflow.audit_logger import audit_logger
from app.services.workflow.task_manager import task_manager


@celery_app.task(name="app.worker.tasks.process_incoming_document", bind=True)
def process_incoming_document(
    self,
    filename: str,
    content_hex: str,
    actor_name: str = "System",
    doc_type: str = "auto",
) -> Dict[str, Any]:
    mode = (doc_type or "auto").strip().lower()
    content = bytes.fromhex(content_hex)
    raw_text = document_dispatcher.extract_text(filename, content)
    parsed = entity_parser.parse(raw_text, filename, doc_type=mode)

    source_doc = parsed["source_document"]
    bdu_list = parsed["bdu_list"]
    bdu_contexts = parsed.get("bdu_contexts", {})
    cve_list = parsed["cve_list"]
    iocs_list = parsed["iocs"]

    db = SessionLocal()
    vulns_created = 0
    iocs_created = 0

    try:
        # Уязвимости сохраняем только в режимах "bdu" и "auto"
        if mode != "ioc":
            if bdu_list:
                for bdu_id in bdu_list:
                    exists = (
                        db.query(Vulnerability)
                        .filter(
                            Vulnerability.bdu == bdu_id,
                            Vulnerability.source_document == source_doc,
                        )
                        .first()
                    )
                    if exists:
                        continue

                    bdu_info = fstec_client.fetch_bdu_info(bdu_id)
                    local_context = bdu_contexts.get(bdu_id) or ""
                    local_cves = entity_parser.extract_cve(local_context) if local_context else []
                    cve_value = (
                        bdu_info.get("cve")
                        or (", ".join(local_cves) if local_cves else None)
                        or (", ".join(cve_list) if len(bdu_list) == 1 and cve_list else None)
                    )

                    vuln = Vulnerability(
                        bdu=bdu_id,
                        cve=cve_value,
                        source_document=source_doc,
                        description=bdu_info.get("description") or "",
                        action_taken="",
                        status=VulnStatus.IN_PROGRESS.value,
                    )
                    db.add(vuln)
                    db.flush()

                    audit_logger.log(
                        db=db,
                        object_type="vulnerability",
                        object_id=vuln.id,
                        action=f"Автоматически добавлена уязвимость {bdu_id} из файла '{filename}'",
                        user=actor_name,
                    )
                    task_manager.create_task_for_vulnerability(
                        db=db,
                        vulnerability=vuln,
                        actor=actor_name,
                    )
                    vulns_created += 1
            elif mode == "bdu" or not iocs_list:
                vuln = Vulnerability(
                    bdu="-",
                    cve=", ".join(cve_list) if cve_list else None,
                    source_document=source_doc,
                    description="",
                    action_taken="",
                    status=VulnStatus.IN_PROGRESS.value,
                )
                db.add(vuln)
                db.flush()

                audit_logger.log(
                    db=db,
                    object_type="vulnerability",
                    object_id=vuln.id,
                    action=f"Создана запись по документу без БДУ ('{filename}')",
                    user=actor_name,
                )
                task_manager.create_task_for_vulnerability(
                    db=db,
                    vulnerability=vuln,
                    actor=actor_name,
                )
                vulns_created += 1

        # Индикаторы сохраняем только в режимах "ioc" и "auto"
        if mode != "bdu":
            for item in iocs_list:
                ioc_exists = (
                    db.query(IOC)
                    .filter(
                        IOC.type == item["type"],
                        IOC.value == item["value"],
                        IOC.source == source_doc,
                    )
                    .first()
                )
                if ioc_exists:
                    continue

                ioc = IOC(
                    type=item["type"],
                    value=item["value"],
                    source=source_doc,
                    reputation="Вредоносный",
                    status="В работе",
                )
                db.add(ioc)
                iocs_created += 1

        db.commit()

        return {
            "status": "completed",
            "doc_type": mode,
            "filename": filename,
            "source_document": source_doc,
            "vulnerabilities_created": vulns_created,
            "iocs_created": iocs_created,
            "bdu_found": bdu_list,
        }
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
