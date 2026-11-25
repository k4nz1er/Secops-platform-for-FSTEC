import logging
import os
from typing import Dict

import httpx

logger = logging.getLogger(__name__)


class FstecClient:
    def __init__(self) -> None:
        self.crawler_url = os.getenv("BDU_CRAWLER_URL", "http://bdu_crawler:8001").rstrip("/")

    def fetch_bdu_info(self, bdu_id: str) -> Dict[str, str]:
        if not bdu_id:
            return {}

        code = bdu_id.replace("BDU:", "").replace("БДУ:", "").strip()
        url = f"{self.crawler_url}/bdu/{code}"

        try:
            with httpx.Client(timeout=25.0) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "description": (data.get("description") or "").strip(),
                        "cve": data.get("cve"),
                        "affected_software": data.get("affected_software"),
                        "recommendations": data.get("recommendations"),
                    }
                logger.warning("bdu_crawler вернул HTTP %s для %s", resp.status_code, bdu_id)
        except Exception as exc:
            logger.warning("Ошибка обращения к bdu_crawler для %s: %s", bdu_id, exc)

        return {}


fstec_client = FstecClient()
