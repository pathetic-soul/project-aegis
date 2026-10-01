from __future__ import annotations

import re

import pymupdf as fitz

from .crypto import sha256


PREFIX = "AEGIS-WM:"
TOKEN_PATTERN = re.compile(r"AEGIS-WM:([a-f0-9]{32}):([a-f0-9]{12})")


def marker_for(token: str) -> str:
    checksum = sha256(("aegis-proof:" + token).encode())[:12]
    return f"{PREFIX}{token}:{checksum}"


def embed(pdf_bytes: bytes, token: str) -> bytes:
    marker = marker_for(token)
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    if doc.page_count == 0:
        raise ValueError("PDF contains no pages")
    for index, page in enumerate(doc):
        # PDF render mode 3 stores glyphs in the content stream without painting them.
        # Multiple placements add modest resilience to simple object removal.
        page.insert_text((7, 7), marker, fontsize=1, render_mode=3, overlay=True)
        page.insert_text(
            (max(7, page.rect.width - 9), max(7, page.rect.height - 9)),
            marker[::-1], fontsize=1, render_mode=3, rotate=180, overlay=True,
        )
    result = doc.tobytes(garbage=3, deflate=True)
    doc.close()
    return result


def extract(pdf_bytes: bytes) -> str | None:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        for page in doc:
            match = TOKEN_PATTERN.search(page.get_text("text"))
            if match:
                token, checksum = match.groups()
                if marker_for(token).endswith(checksum):
                    return token
    finally:
        doc.close()
    return None
