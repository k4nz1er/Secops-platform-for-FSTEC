import email
from email import policy
import io
import os
import subprocess
import tempfile
from typing import List
import docx
import extract_msg
import pdfplumber
from pdf2image import convert_from_bytes
import pytesseract
from striprtf.striprtf import rtf_to_text


class DocumentDispatcher:
    MIN_PDF_TEXT_LENGTH = 50

    def extract_text(self, filename: str, content: bytes) -> str:
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

        handlers = {
            "pdf": self._extract_pdf,
            "docx": self._extract_docx,
            "doc": self._extract_doc,
            "rtf": self._extract_rtf,
            "txt": self._extract_txt,
            "eml": self._extract_eml,
            "msg": self._extract_msg,
        }

        handler = handlers.get(ext)
        if not handler:
            raise ValueError(f"Неподдерживаемый формат файла: .{ext}")

        return handler(content).strip()

    def _extract_pdf(self, content: bytes) -> str:
        pages_text: List[str] = []
        with pdfplumber.open(io.BytesIO(content)) as pdf:
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    pages_text.append(text)

        full_text = "\n".join(pages_text).strip()
        if len(full_text) >= self.MIN_PDF_TEXT_LENGTH:
            return full_text

        return self._ocr_pdf(content)

    def _ocr_pdf(self, content: bytes) -> str:
        images = convert_from_bytes(content, dpi=300)
        ocr_pages: List[str] = []
        for img in images:
            page_text = pytesseract.image_to_string(img, lang="rus+eng")
            if page_text:
                ocr_pages.append(page_text)
        return "\n".join(ocr_pages)

    def _extract_docx(self, content: bytes) -> str:
        document = docx.Document(io.BytesIO(content))
        parts: List[str] = [p.text for p in document.paragraphs if p.text.strip()]

        for table in document.tables:
            for row in table.rows:
                row_text = " | ".join(cell.text.strip() for cell in row.cells if cell.text.strip())
                if row_text:
                    parts.append(row_text)

        return "\n".join(parts)

    def _extract_doc(self, content: bytes) -> str:
        with tempfile.NamedTemporaryFile(suffix=".doc", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            result = subprocess.run(
                ["antiword", tmp_path],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            return result.stdout
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def _extract_rtf(self, content: bytes) -> str:
        raw_text = content.decode("cp1251", errors="ignore")
        return rtf_to_text(raw_text)

    def _extract_txt(self, content: bytes) -> str:
        for encoding in ("utf-8", "cp1251", "latin-1"):
            try:
                return content.decode(encoding)
            except UnicodeDecodeError:
                continue
        return content.decode("utf-8", errors="ignore")

    def _extract_eml(self, content: bytes) -> str:
        msg = email.message_from_bytes(content, policy=policy.default)
        parts: List[str] = []

        if msg.get("Subject"):
            parts.append(f"Subject: {msg['Subject']}")

        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition") or "")

            if "attachment" in disposition:
                att_filename = part.get_filename()
                att_payload = part.get_payload(decode=True)
                if att_filename and att_payload:
                    try:
                        parts.append(self.extract_text(att_filename, att_payload))
                    except ValueError:
                        pass
            elif content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    parts.append(self._extract_txt(payload))

        return "\n".join(parts)

    def _extract_msg(self, content: bytes) -> str:
        with tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        try:
            msg = extract_msg.Message(tmp_path)
            parts: List[str] = []
            if msg.subject:
                parts.append(f"Subject: {msg.subject}")
            if msg.body:
                parts.append(msg.body)

            for att in msg.attachments:
                att_name = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None)
                att_data = getattr(att, "data", None)
                if att_name and isinstance(att_data, bytes):
                    try:
                        parts.append(self.extract_text(att_name, att_data))
                    except ValueError:
                        pass

            msg.close()
            return "\n".join(parts)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


document_dispatcher = DocumentDispatcher()
