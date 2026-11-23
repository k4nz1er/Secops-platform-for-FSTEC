import io
from typing import List, Optional
import numpy as np
from PIL import Image
from pdf2image import convert_from_bytes
import pytesseract


class OCREngine:
    MIN_CONFIDENT_LENGTH = 30

    def __init__(self, languages: Optional[List[str]] = None):
        self.languages = languages or ["ru", "en"]
        self._easyocr_reader = None

    def _get_easyocr_reader(self):
        if self._easyocr_reader is None:
            import easyocr
            self._easyocr_reader = easyocr.Reader(self.languages, gpu=False)
        return self._easyocr_reader

    def _preprocess_image(self, image: Image.Image) -> Image.Image:
        return image.convert("L")

    def _run_tesseract(self, image: Image.Image) -> str:
        processed = self._preprocess_image(image)
        return pytesseract.image_to_string(
            processed,
            lang="rus+eng",
            config="--oem 3 --psm 6",
        ).strip()

    def _run_easyocr(self, image: Image.Image) -> str:
        reader = self._get_easyocr_reader()
        img_array = np.array(image.convert("RGB"))
        results = reader.readtext(img_array, detail=0, paragraph=True)
        return "\n".join(results).strip()

    def recognize_image(self, image: Image.Image, use_fallback: bool = True) -> str:
        text = self._run_tesseract(image)
        if len(text) >= self.MIN_CONFIDENT_LENGTH or not use_fallback:
            return text

        fallback_text = self._run_easyocr(image)
        return fallback_text if len(fallback_text) > len(text) else text

    def recognize_image_bytes(self, content: bytes, use_fallback: bool = True) -> str:
        image = Image.open(io.BytesIO(content))
        return self.recognize_image(image, use_fallback=use_fallback)

    def recognize_pdf_bytes(self, content: bytes, dpi: int = 300, use_fallback: bool = True) -> str:
        images = convert_from_bytes(content, dpi=dpi)
        pages_text: List[str] = []
        for img in images:
            page_text = self.recognize_image(img, use_fallback=use_fallback)
            if page_text:
                pages_text.append(page_text)
        return "\n".join(pages_text).strip()


ocr_engine = OCREngine()
