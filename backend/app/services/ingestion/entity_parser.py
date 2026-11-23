import ipaddress
import re
from typing import Any, Dict, List, Optional, Set


class EntityParser:
    BDU_PATTERN = re.compile(r"\b(?:BDU|БДУ)[:\-\s]*(\d{4}-\d{4,6})\b", re.IGNORECASE)
    CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

    DOC_NUMBER_PATTERN = re.compile(
        r"(?:(?:исх\.|вх\.|письм[оа]|бюллетен[ья])\s*)?"
        r"(?:№|\bN[oо°]\.?)\s*"
        r"((?=[А-ЯA-Z0-9/\-\.]*\d)[А-ЯA-Z0-9][А-ЯA-Z0-9/\-]{2,35})",
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

    def extract_document_number(self, text: str, fallback_filename: str) -> str:
        match = self.DOC_NUMBER_PATTERN.search(text[:2500])
        if match:
            cleaned = match.group(1).strip(".,;:-")
            if cleaned:
                return f"№ {cleaned}"
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
