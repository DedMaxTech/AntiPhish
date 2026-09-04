from __future__ import annotations

import io
import zipfile

from antiphish.config import Limits
from antiphish.extractors import extract_eml, extract_office, extract_pdf


def test_zip_bomb_ratio_is_stopped():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", "A" * 2_000_000)
    result = extract_office(stream.getvalue(), "bomb.docx", Limits(max_compression_ratio=5.0))
    assert any("unsafe archive" in warning for warning in result.warnings)


def test_xxe_is_never_resolved():
    stream = io.BytesIO()
    payload = b'<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///C:/Windows/win.ini">]><x>&secret;</x>'
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("word/document.xml", payload)
    result = extract_office(stream.getvalue(), "xxe.docx", Limits())
    assert any("Unsafe XML" in warning for warning in result.warnings)
    assert "extensions" not in result.text.lower()


def test_malformed_mime_and_pdf_do_not_crash():
    assert extract_eml(b"\x00\xffbroken MIME", Limits()).kind == "eml"
    result = extract_pdf(b"%PDF broken", Limits())
    assert result.kind == "pdf"
    assert result.warnings


def test_html_with_wrong_declared_encoding_does_not_fail():
    from antiphish.extractors import extract_html
    body = b'<meta charset="utf-8"><body>\xa9 password expires <a href="https://example.test">keep password</a>'
    result = extract_html(body, Limits())
    assert result.kind == "html"
    assert result.fingerprints["sha256"]


def test_huge_base64_part_is_bounded():
    eml = b"From: x@y.test\nMIME-Version: 1.0\nContent-Type: application/octet-stream\nContent-Transfer-Encoding: base64\nContent-Disposition: attachment; filename=x.bin\n\n" + b"A" * 50_000
    result = extract_eml(eml, Limits(max_attachment_bytes=1024))
    assert result.warnings


def test_qr_url_is_extracted_end_to_end():
    import cv2
    from antiphish.extractors import extract_image
    encoder = cv2.QRCodeEncoder_create()
    matrix = encoder.encode("https://qr.bad.example/login")
    matrix = cv2.copyMakeBorder(matrix, 4, 4, 4, 4, cv2.BORDER_CONSTANT, value=255)
    matrix = cv2.resize(matrix, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    ok, encoded = cv2.imencode(".png", matrix)
    assert ok
    result = extract_image(bytes(encoded), Limits())
    assert [u.original for u in result.urls] == ["https://qr.bad.example/login"]
    assert "QR_EXTERNAL_DESTINATION" in {e.code for e in result.evidence}


def test_ooxml_external_relationship_is_extracted():
    stream = io.BytesIO()
    relationship = b'<Relationships><Relationship TargetMode="External" Target="https://outside.example/payload"/></Relationships>'
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("word/_rels/document.xml.rels", relationship)
        archive.writestr("word/document.xml", b"<document><t>Quarterly report</t></document>")
    result = extract_office(stream.getvalue(), "report.docx", Limits())
    assert "OFFICE_EXTERNAL_RELATIONSHIP" in {e.code for e in result.evidence}
    assert any(u.host == "outside.example" for u in result.urls)


def test_pdf_text_and_link_parse_end_to_end():
    import fitz
    document = fitz.open()
    page = document.new_page()
    page.insert_text((72, 72), "Quarterly document")
    page.insert_link({"kind": fitz.LINK_URI, "from": fitz.Rect(72, 80, 200, 100), "uri": "https://documents.example/view"})
    data = document.tobytes()
    document.close()
    result = extract_pdf(data, Limits())
    assert "Quarterly document" in result.text
    assert any(u.host == "documents.example" for u in result.urls)
