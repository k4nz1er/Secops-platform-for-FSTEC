import html
import re
from typing import Dict, Optional
import httpx
from app.core.redis import get_cache, set_cache


class FstecClient:
    BASE_URL = "https://bdu.fstec.ru/vul/"
    CACHE_TTL = 604800

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        }

    def _normalize_bdu_code(self, bdu_id: str) -> str:
        cleaned = bdu_id.strip().upper()
        cleaned = re.sub(r"^(BDU|БДУ)[:\-\s]*", "", cleaned)
        return cleaned

    def _clean_html(self, raw: str) -> str:
        text = re.sub(r"<[^>]+>", " ", raw)
        text = html.unescape(text)
        return re.sub(r"\s+", " ", text).strip()

    def _extract_table_field(self, page_html: str, label: str) -> Optional[str]:
        pattern = rf"<td[^>]*>\s*{re.escape(label)}[^<]*</td>\s*<td[^>]*>(.*?)</td>"
        match = re.search(pattern, page_html, flags=re.IGNORECASE | re.DOTALL)
        if not match:
            return None
        value = self._clean_html(match.group(1))
        return value if value else None

    def _extract_cve(self, page_html: str) -> Optional[str]:
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", page_html, flags=re.IGNORECASE)))
        if not cves:
            return None
        return ", ".join(c.upper() for c in cves)

    def fetch_bdu_info(self, bdu_id: str) -> Dict[str, Optional[str]]:
        code = self._normalize_bdu_code(bdu_id)
        cache_key = f"bdu:{code}"

        cached = get_cache(cache_key)
        if isinstance(cached, dict):
            return cached

        result: Dict[str, Optional[str]] = {
            "bdu": f"BDU:{code}",
            "cve": None,
            "description": None,
            "affected_software": None,
            "recommendations": None,
        }

        url = f"{self.BASE_URL}{code}"
        try:
            with httpx.Client(
                timeout=self.timeout,
                verify=False,
                follow_redirects=True,
                headers=self.headers,
            ) as client:
                response = client.get(url)
                if response.status_code != 200:
                    return result
                page_html = response.text
        except httpx.HTTPError:
            return result

        result["cve"] = self._extract_cve(page_html)
        result["description"] = self._extract_table_field(page_html, "Описание уязвимости")
        result["affected_software"] = self._extract_table_field(page_html, "Наименование ПО")
        result["recommendations"] = self._extract_table_field(page_html, "Возможные меры по устранению")

        if any(result[k] for k in ("cve", "description", "affected_software", "recommendations")):
            set_cache(cache_key, result, ttl=self.CACHE_TTL)

        return result


fstec_client = FstecClient()
