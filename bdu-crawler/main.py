import asyncio
import json
import re
import time
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException

app = FastAPI(title="FSTEC BDU Crawler", version="1.0.0")

BDU_URL_TEMPLATE = "https://bdu.fstec.ru/vul/{bdu_num}"
BDU_NUM_RE = re.compile(r"(\d{4}-\d{4,6})")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
MODEL_MARKER_RE = re.compile(r"const\s+v_model\s*=\s*reactive\s*\(\s*")

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8",
    "Referer": "https://bdu.fstec.ru/vul",
}

# Ограничиваем частоту запросов к bdu.fstec.ru, чтобы не ловить WAF 403/429
_rate_lock = asyncio.Lock()
_last_request_ts = 0.0
MIN_DELAY_SEC = 0.4


def _normalize_bdu_num(raw_id: str) -> str:
    match = BDU_NUM_RE.search(raw_id or "")
    if not match:
        raise HTTPException(status_code=400, detail=f"Некорректный формат БДУ: {raw_id}")
    return match.group(1)


def _extract_v_model(html: str) -> Optional[Dict[str, Any]]:
    marker = MODEL_MARKER_RE.search(html)
    if not marker:
        return None
    start_idx = html.find("{", marker.end())
    if start_idx == -1:
        return None
    try:
        decoder = json.JSONDecoder()
        obj, _ = decoder.raw_decode(html, start_idx)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def _extract_cves(idvals: Any) -> Optional[str]:
    if not isinstance(idvals, list):
        return None
    found = set()
    for entry in idvals:
        if isinstance(entry, str):
            for cve in CVE_RE.findall(entry):
                found.add(cve.upper())
    return ", ".join(sorted(found)) if found else None


def _extract_software(model: Dict[str, Any]) -> Optional[str]:
    vendors: List[str] = [v for v in (model.get("vendors") or []) if isinstance(v, str)]
    softs: List[str] = [s for s in (model.get("softs") or []) if isinstance(s, str)]
    parts: List[str] = []
    if vendors:
        parts.append(", ".join(dict.fromkeys(vendors)))
    if softs:
        parts.append(", ".join(dict.fromkeys(softs)))
    return " / ".join(parts) if parts else None


async def _fetch_html(url: str) -> str:
    global _last_request_ts
    last_error = ""

    async with httpx.AsyncClient(
        verify=False,
        timeout=20.0,
        follow_redirects=True,
        headers=BROWSER_HEADERS,
    ) as client:
        for attempt in range(3):
            async with _rate_lock:
                elapsed = time.monotonic() - _last_request_ts
                if elapsed < MIN_DELAY_SEC:
                    await asyncio.sleep(MIN_DELAY_SEC - elapsed)
                _last_request_ts = time.monotonic()

            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return resp.text
                if resp.status_code == 404:
                    raise HTTPException(status_code=404, detail="Карточка БДУ не найдена")
                last_error = f"HTTP {resp.status_code}"
            except HTTPException:
                raise
            except httpx.HTTPError as exc:
                last_error = str(exc)

            await asyncio.sleep(1.0 * (attempt + 1))

    raise HTTPException(status_code=502, detail=f"Не удалось получить данные с ФСТЭК: {last_error}")


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/bdu/{bdu_id}")
async def get_bdu(bdu_id: str):
    bdu_num = _normalize_bdu_num(bdu_id)
    url = BDU_URL_TEMPLATE.format(bdu_num=bdu_num)
    html = await _fetch_html(url)

    model = _extract_v_model(html)
    if not model:
        raise HTTPException(status_code=404, detail=f"Данные v_model не найдены для BDU:{bdu_num}")

    description = (model.get("vul_desc") or model.get("vul_name") or "").strip()
    recommendations = (model.get("vul_vmer") or "").strip() or None

    return {
        "bdu": f"BDU:{bdu_num}",
        "url": url,
        "description": description,
        "cve": _extract_cves(model.get("idvals")),
        "affected_software": _extract_software(model),
        "recommendations": recommendations,
    }
