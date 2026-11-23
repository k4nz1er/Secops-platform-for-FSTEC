import ipaddress
import re
from typing import Any, Dict, List, Optional, Set


class EntityParser:
    BDU_PATTERN = re.compile(r"\b(?:BDU|БДУ)[:\-\s]*(\d{4}-\d{4,6})\b", re.IGNORECASE)
    CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    RU_MONTHS: Dict[str, str] = {
        "января": "01",
        "февраля": "02",
        "марта": "03",
        "апреля": "04",
        "мая": "05",
        "июня": "06",
        "июля": "07",
        "августа": "08",
        "сентября": "09",
        "октября": "10",
        "ноября": "11",
        "декабря": "12",
    }

    NUMERIC_DATE_PATTERN = re.compile(r"\b(\d{1,2}[.\-/]\d{1,2}[.\-/]\d{2,4})\b")
    TEXT_DATE_PATTERN = re.compile(
        r"[«\"„']?\s*(\d{1,2})\s*[»\"“']?\s+"
        r"(января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+"
        r"(\d{4})",
        re.IGNORECASE,
    )

    SLASH_NUM_PATTERN = re.compile(
        r"\b(\d{1,5}\s*/\s*\d{1,5}\s*/\s*[А-ЯA-Z0-9\-]{1,12})\b",
        re.IGNORECASE,
    )

    DATE_THEN_SLASH_WITH_SIGN = re.compile(
        r"(?:от\s*)?"
        r"(\d{1,2}[.\-/]\d{1,2}[.\-/]\d{2,4})"
        r"(?:\s*(?:г\.?|года))?"
        r"[\s,;:\-_]*"
        r"(?:№|N[oо°]?\.?)[\s_:\-]*"
        r"([А-ЯA-Z0-9]+\s*/\s*[А-ЯA-Z0-9/\-]{2,25})",
        re.IGNORECASE,
    )

    TEXT_DATE_THEN_SLASH_WITH_SIGN = re.compile(
        r"(?:от\s*)?"
        r"[«\"„']?\s*(\d{1,2})\s*[»\"“']?\s+"
        r"(января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+"
        r"(\d{4})(?:\s*(?:г\.?|года))?"
        r"[\s,;:\-_]*"
        r"(?:№|N[oо°]?\.?)[\s_:\-]*"
        r"([А-ЯA-Z0-9]+\s*/\s*[А-ЯA-Z0-9/\-]{2,25})",
        re.IGNORECASE,
    )

    SLASH_THEN_DATE = re.compile(
        r"(?<!На\s)(?:№|N[oо°]?\.?)[\s_:\-]*"
        r"([А-ЯA-Z0-9]+\s*/\s*[А-ЯA-Z0-9/\-]{2,25})"
        r"[\s,;\-_]*от\s*"
        r"(\d{1,2}[.\-/]\d{1,2}[.\-/]\d{2,4})",
        re.IGNORECASE,
    )

    DATE_THEN_PLAIN_NUM = re.compile(
        r"(?:от\s*)?"
        r"(\d{1,2}[.\-/]\d{1,2}[.\-/]\d{2,4})"
        r"(?:\s*(?:г\.?|года))?"
        r"[\s,;:\-_]*"
        r"(?:№|N[oо°]?\.?)[\s_:\-]*"
        r"((?=[А-ЯA-Z0-9/\-]*\d)[А-ЯA-Z0-9][А-ЯA-Z0-9/\-]{1,30})",
        re.IGNORECASE,
    )

    NUM_THEN_DATE_PLAIN = re.compile(
        r"(?<!На\s)(?:№|N[oо°]?\.?)[\s_:\-]*"
        r"((?=[А-ЯA-Z0-9/\-]*\d)[А-ЯA-Z0-9][А-ЯA-Z0-9/\-]{1,30})"
        r"[\s,;\-_]*от\s*"
        r"(\d{1,2}[.\-/]\d{1,2}[.\-/]\d{2,4})",
        re.IGNORECASE,
    )

    DOC_NUMBER_PATTERN = re.compile(
        r"(?<!На\s)(?:(?:исх\.|вх\.|письм[оа]|бюллетен[ья])\s*)?"
        r"(?:№|\bN[oо°]\.?)[\s_:\-]*"
        r"((?=[А-ЯA-Z0-9/\-]*\d)[А-ЯA-Z0-9][А-ЯA-Z0-9/\-]{2,35})",
        re.IGNORECASE,
    )

    LEGAL_ACT_CONTEXT = re.compile(
        r"(?:указ\w*|приказ\w*|закон\w*|постановлен\w*|распоряжен\w*|\bфз\b|протокол\w*|на\s+№)",
        re.IGNORECASE,
    )

    SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
    SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
    MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")

    URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"'\]\)}{,;]+", re.IGNORECASE)
    DEFANGED_URL_PATTERN = re.compile(
        r"\b(?:hxxps?(?:\[:\]|:)//|https?://[^\s]*?(?:\[\.\]|\(\.\)|\{\.\}))[^\s<>\"'\]\)}{,;]+",
        re.IGNORECASE,
    )
    DEFANGED_DOMAIN_PATTERN = re.compile(
        r"\b(?:[a-zA-Z0-9\-]+(?:\[\.\]|\(\.\)|\{\.\}))+[a-zA-Z]{2,24}\b",
        re.IGNORECASE,
    )
    EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24}\b")
    IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    DOMAIN_PATTERN = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,12})\b"
    )

    VALID_TLDS: Set[str] = {
        "ru", "su", "com", "net", "org", "info", "biz", "io", "me", "co", "ai",
        "xyz", "top", "club", "online", "site", "pro", "dev", "app", "gov",
        "edu", "mil", "int", "eu", "us", "uk", "de", "fr", "nl", "cn", "jp",
        "kr", "ua", "by", "kz", "pl", "cz", "ch", "se", "no", "fi", "it", "es",
        "ca", "au", "br", "in", "cc", "tv", "pw", "ws", "to", "sh", "gg", "ly",
        "tk", "ml", "ga", "cf", "gq", "cloud", "host", "space", "tech", "store",
        "live", "link", "click", "work", "fun", "icu", "vip", "win", "bid",
        "support", "news", "today", "world", "zone", "systems", "network",
        "security", "solutions", "services", "center", "agency", "email", "group",
    }

    BENIGN_DOMAINS: Set[str] = {
        "fstec.ru", "astralinux.ru", "omp.ru", "altsp.su", "altlinux.org",
        "basealt.ru", "red-soft.ru", "kaspersky.ru", "kaspersky.com",
        "ptsecurity.com", "bi.zone", "safe-surf.ru", "cert.gov.ru", "gov.ru",
        "gosuslugi.ru", "nist.gov", "mitre.org", "cve.org", "cvedetails.com",
        "cisa.gov", "github.com", "gitlab.com", "debian.org", "ubuntu.com",
        "redhat.com", "centos.org", "fedoraproject.org", "suse.com", "kernel.org",
        "openssl.org", "python.org", "djangoproject.com", "microsoft.com",
        "apple.com", "google.com", "mozilla.org", "apache.org", "nginx.org",
        "postgresql.org", "mysql.com", "oracle.com", "cisco.com", "fortinet.com",
        "checkpoint.com", "paloaltonetworks.com", "vmware.com", "docker.com",
        "kubernetes.io", "wikipedia.org", "w3.org", "ietf.org", "rfc-editor.org",
        "launchpad.net", "bugzilla.org", "sourceforge.net", "gnu.org",
    }

    def _refang(self, text: str) -> str:
        text = re.sub(
            r"hxxps?://",
            lambda m: re.sub(r"xx", "tt", m.group(0), flags=re.IGNORECASE),
            text,
            flags=re.IGNORECASE,
        )
        text = text.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
        text = text.replace("[:]", ":").replace("[:/]", ":/")
        return text

    def _is_benign_host(self, host: str) -> bool:
        h = host.lower().strip(".")
        return any(h == b or h.endswith(f".{b}") for b in self.BENIGN_DOMAINS)

    def _extract_host_from_url(self, url: str) -> str:
        match = re.match(r"^https?://([^/:?#]+)", url, flags=re.IGNORECASE)
        return match.group(1).lower() if match else ""

    def _normalize_numeric_date(self, raw_date: str) -> Optional[str]:
        parts = re.split(r"[.\-/]", raw_date.strip())
        if len(parts) != 3:
            return None
        try:
            day, month = int(parts[0]), int(parts[1])
            year = int(parts[2]) if len(parts[2]) == 4 else 2000 + int(parts[2])
        except ValueError:
            return None
        if not (1 <= day <= 31 and 1 <= month <= 12 and 2000 <= year <= 2100):
            return None
        return f"{day:02d}.{month:02d}.{year}"

    def _extract_first_date(self, snippet: str) -> Optional[str]:
        for m in self.NUMERIC_DATE_PATTERN.finditer(snippet):
            norm = self._normalize_numeric_date(m.group(1))
            if norm:
                return norm
        for m in self.TEXT_DATE_PATTERN.finditer(snippet):
            day_str, month_word, year_str = m.groups()
            month_num = self.RU_MONTHS.get(month_word.lower())
            day = int(day_str)
            if month_num and 1 <= day <= 31:
                return f"{day:02d}.{month_num}.{year_str}"
        return None

    def _clean_doc_number(self, raw_num: str) -> Optional[str]:
        cleaned = re.sub(r"\s*/\s*", "/", raw_num).strip(".,;:-_ ")
        if not cleaned or not re.search(r"\d", cleaned):
            return None
        return cleaned

    def _looks_like_slash_date(self, value: str) -> bool:
        parts = value.split("/")
        if len(parts) != 3:
            return False
        try:
            p1, p2, p3 = int(parts[0]), int(parts[1]), int(parts[2])
            return 1 <= p1 <= 31 and 1 <= p2 <= 12 and 1990 <= p3 <= 2100
        except ValueError:
            return False

    def _is_legal_act_reference(self, text: str, start_pos: int) -> bool:
        prefix = text[max(0, start_pos - 80):start_pos]
        return bool(self.LEGAL_ACT_CONTEXT.search(prefix))

    def _extract_from_snippet(self, snippet: str) -> Optional[str]:
        header = (snippet or "")[:2500]
        letterhead = header[:900]

        for m in self.DATE_THEN_SLASH_WITH_SIGN.finditer(header):
            norm_date = self._normalize_numeric_date(m.group(1))
            clean_num = self._clean_doc_number(m.group(2))
            if norm_date and clean_num and not self._looks_like_slash_date(clean_num):
                return f"№ {clean_num} от {norm_date}"

        for m in self.TEXT_DATE_THEN_SLASH_WITH_SIGN.finditer(header):
            day_str, month_word, year_str, raw_num = m.groups()
            month_num = self.RU_MONTHS.get(month_word.lower())
            clean_num = self._clean_doc_number(raw_num)
            day = int(day_str)
            if month_num and clean_num and 1 <= day <= 31 and not self._looks_like_slash_date(clean_num):
                return f"№ {clean_num} от {day:02d}.{month_num}.{year_str}"

        for m in self.SLASH_NUM_PATTERN.finditer(letterhead):
            clean_num = self._clean_doc_number(m.group(1))
            if clean_num and not self._looks_like_slash_date(clean_num):
                found_date = self._extract_first_date(letterhead)
                if found_date:
                    return f"№ {clean_num} от {found_date}"
                return f"№ {clean_num}"

        for m in self.SLASH_THEN_DATE.finditer(header):
            clean_num = self._clean_doc_number(m.group(1))
            norm_date = self._normalize_numeric_date(m.group(2))
            if norm_date and clean_num and not self._looks_like_slash_date(clean_num):
                return f"№ {clean_num} от {norm_date}"

        for m in self.DATE_THEN_PLAIN_NUM.finditer(header):
            if self._is_legal_act_reference(header, m.start()):
                continue
            norm_date = self._normalize_numeric_date(m.group(1))
            clean_num = self._clean_doc_number(m.group(2))
            if norm_date and clean_num:
                return f"№ {clean_num} от {norm_date}"

        for m in self.NUM_THEN_DATE_PLAIN.finditer(header):
            if self._is_legal_act_reference(header, m.start()):
                continue
            clean_num = self._clean_doc_number(m.group(1))
            norm_date = self._normalize_numeric_date(m.group(2))
            if norm_date and clean_num:
                return f"№ {clean_num} от {norm_date}"

        for m in self.DOC_NUMBER_PATTERN.finditer(letterhead):
            if self._is_legal_act_reference(letterhead, m.start()):
                continue
            cleaned = self._clean_doc_number(m.group(1))
            if cleaned:
                return f"№ {cleaned}"

        return None

    def extract_document_number(self, text: str, fallback_filename: str) -> str:
        from_text = self._extract_from_snippet(text)
        if from_text:
            return from_text

        filename_stem = re.sub(r"\.[a-zA-Z0-9]{2,5}$", "", fallback_filename or "").strip()
        from_filename = self._extract_from_snippet(filename_stem)
        if from_filename:
            return from_filename

        return fallback_filename

    def extract_bdu(self, text: str) -> List[str]:
        codes = {f"BDU:{m.group(1)}" for m in self.BDU_PATTERN.finditer(text)}
        return sorted(codes)

    def extract_cve(self, text: str) -> List[str]:
        cves = {m.group(0).upper() for m in self.CVE_PATTERN.finditer(text)}
        return sorted(cves)

    def extract_bdu_context(self, text: str, bdu_id: str) -> Optional[str]:
        code = bdu_id.replace("BDU:", "")
        match = re.search(rf"(?:BDU|БДУ)[:\-\s]*{re.escape(code)}", text, flags=re.IGNORECASE)
        if not match:
            return None
        start = max(0, match.start() - 60)
        end = min(len(text), match.end() + 420)
        snippet = re.sub(r"\s+", " ", text[start:end]).strip()
        return snippet if len(snippet) > 25 else None

    def _is_valid_public_ip(self, value: str) -> bool:
        try:
            ip = ipaddress.IPv4Address(value)
            return not (
                ip.is_private
                or ip.is_loopback
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_link_local
            )
        except ValueError:
            return False

    def extract_iocs(self, text: str, strict_mode: bool = False) -> List[Dict[str, str]]:
        normalized = self._refang(text)
        iocs: List[Dict[str, str]] = []
        seen: Set[tuple] = set()

        def add_ioc(ioc_type: str, value: str):
            key = (ioc_type, value)
            if key not in seen:
                seen.add(key)
                iocs.append({"type": ioc_type, "value": value})

        sha256_matches = {m.group(0).lower() for m in self.SHA256_PATTERN.finditer(normalized)}
        for h in sorted(sha256_matches):
            add_ioc("SHA256", h)

        sha1_matches = {m.group(0).lower() for m in self.SHA1_PATTERN.finditer(normalized)}
        for h in sorted(sha1_matches):
            if not any(h in s for s in sha256_matches):
                add_ioc("SHA1", h)

        md5_matches = {m.group(0).lower() for m in self.MD5_PATTERN.finditer(normalized)}
        for h in sorted(md5_matches):
            if not any(h in s for s in sha256_matches) and not any(h in s for s in sha1_matches):
                add_ioc("MD5", h)

        ip_matches = sorted(
            {
                m.group(0)
                for m in self.IPV4_PATTERN.finditer(normalized)
                if self._is_valid_public_ip(m.group(0))
            }
        )
        for ip in ip_matches:
            add_ioc("IP", ip)

        if strict_mode:
            for m in self.DEFANGED_URL_PATTERN.finditer(text):
                u = self._refang(m.group(0)).rstrip(".,;:)")
                host = self._extract_host_from_url(u)
                if host and not self._is_benign_host(host):
                    add_ioc("URL", u)

            for m in self.DEFANGED_DOMAIN_PATTERN.finditer(text):
                d = self._refang(m.group(0)).lower().rstrip(".")
                tld = d.rsplit(".", 1)[-1]
                if tld in self.VALID_TLDS and not self._is_benign_host(d):
                    add_ioc("Domain", d)
        else:
            url_matches = sorted(
                {m.group(0).rstrip(".,;:)") for m in self.URL_PATTERN.finditer(normalized)}
            )
            for u in url_matches:
                host = self._extract_host_from_url(u)
                if host and not self._is_benign_host(host):
                    add_ioc("URL", u)

            clean_text = self.URL_PATTERN.sub(" ", normalized)
            clean_text = self.EMAIL_PATTERN.sub(" ", clean_text)
            domain_matches = sorted(
                {m.group(0).lower().rstrip(".") for m in self.DOMAIN_PATTERN.finditer(clean_text)}
            )
            for domain in domain_matches:
                if "_" in domain or domain.count(".") > 4:
                    continue
                tld = domain.rsplit(".", 1)[-1]
                if tld not in self.VALID_TLDS or self._is_benign_host(domain):
                    continue
                add_ioc("Domain", domain)

        return iocs

    def parse(self, text: str, filename: str, doc_type: str = "auto") -> Dict[str, Any]:
        safe_text = text or ""
        mode = (doc_type or "auto").strip().lower()
        source_document = self.extract_document_number(safe_text, filename)

        if mode == "bdu":
            bdu_list = self.extract_bdu(safe_text)
            bdu_contexts = {
                bdu_id: self.extract_bdu_context(safe_text, bdu_id)
                for bdu_id in bdu_list
            }
            return {
                "source_document": source_document,
                "bdu_list": bdu_list,
                "bdu_contexts": bdu_contexts,
                "cve_list": self.extract_cve(safe_text),
                "iocs": [],
            }

        if mode == "ioc":
            return {
                "source_document": source_document,
                "bdu_list": [],
                "bdu_contexts": {},
                "cve_list": [],
                "iocs": self.extract_iocs(safe_text, strict_mode=False),
            }

        bdu_list = self.extract_bdu(safe_text)
        bdu_contexts = {
            bdu_id: self.extract_bdu_context(safe_text, bdu_id)
            for bdu_id in bdu_list
        }
        return {
            "source_document": source_document,
            "bdu_list": bdu_list,
            "bdu_contexts": bdu_contexts,
            "cve_list": self.extract_cve(safe_text),
            "iocs": self.extract_iocs(safe_text, strict_mode=bool(bdu_list)),
        }


entity_parser = EntityParser()
