import io
from email.message import EmailMessage

import pytest
from PIL import Image, ImageDraw, ImageFont

from antiphish.analyzer import Analyzer
from antiphish.models import Verdict
from antiphish.ocr import status


def image_bytes(text):
    image = Image.new("RGB", (1100, 350), "white")
    from pathlib import Path
    candidates = [Path('C:/Windows/Fonts/arial.ttf'), Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'), Path('/mnt/c/Windows/Fonts/arial.ttf')]
    font = next((path for path in candidates if path.is_file()), None)
    if font is None:
        pytest.skip('Cyrillic test font not installed')
    ImageDraw.Draw(image).text((25, 30), text, font=ImageFont.truetype(str(font), 38), fill="black", spacing=12)
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


@pytest.mark.skipif(not status()["ready"], reason="Optional downloaded Cyrillic OCR")
@pytest.mark.parametrize("malicious", [False, True])
def test_russian_image_mail_and_official_negative(empty_kb, malicious):
    message = EmailMessage()
    message["From"] = "notifications@example.org"
    message["Subject"] = "Уведомление"
    message.set_content("Подробности в изображении")
    host = "fake-reward.example" if malicious else "sberbank.ru"
    message.add_alternative(f'<a href="https://{host}/gift">Получить подарок</a>', subtype="html")
    message.add_attachment(image_bytes("СберБанк\nВы выиграли 5000 рублей\nПолучить подарок"), maintype="image", subtype="png", filename="notice.png")
    report = Analyzer(empty_kb).analyze(message.as_bytes(), name="notice.eml")
    assert any("Сбер" in page.text for page in report.pages)
    assert "OCR_TEXT_EXTRACTED" in {e.code for e in report.reason_codes}
    assert report.verdict == (Verdict.SUSPICIOUS if malicious else Verdict.NOT_DETECTED)
    assert all(page.identity_source == "ocr" for page in report.pages if page.id.startswith("image:"))


@pytest.mark.skipif(not status()["ready"], reason="Optional downloaded Cyrillic OCR")
def test_scanned_pdf_russian_text_and_tiny_image(empty_kb):
    import fitz
    doc = fitz.open()
    page = doc.new_page(width=800, height=280)
    page.insert_image(page.rect, stream=image_bytes("Госуслуги\nПодтвердите доступ к аккаунту"))
    report = Analyzer(empty_kb).analyze(doc.tobytes(), name="scan.pdf")
    doc.close()
    assert any("Госуслуги" in page.text for page in report.pages)
    assert report.verdict != Verdict.PHISHING  # OCR invents neither form nor collector
    tiny = Image.new("RGB", (1, 1), "white")
    stream = io.BytesIO()
    tiny.save(stream, "PNG")
    report = Analyzer(empty_kb).analyze(stream.getvalue(), name="pixel.png")
    assert not report.pages
    assert report.verdict == Verdict.NOT_DETECTED


def test_absent_ocr_never_triggers_download(monkeypatch):
    from antiphish import ocr
    monkeypatch.setattr(ocr, "status", lambda: {"ready": False})
    monkeypatch.setattr(ocr.urllib.request, "urlopen", lambda *a, **k: pytest.fail("Unexpected runtime download"))
    assert ocr.recognize(Image.new("RGB", (500, 200)))[1] == "UNAVAILABLE"
