from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

import pymupdf as fitz


ROOT = Path(__file__).resolve().parent.parent
FONT_REGULAR = ROOT / "static" / "fonts" / "NotoSans-Regular.ttf"
FONT_BOLD = ROOT / "static" / "fonts" / "NotoSans-Bold.ttf"
FONT_MONO = ROOT / "static" / "fonts" / "DejaVuSansMono.ttf"


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def build_forensic_report(block: dict[str, Any], verification: dict[str, Any]) -> bytes:
    """Create a printable evidence receipt from a ledger block and fresh verification."""
    event = block["event"]
    certificate_count = len(block.get("certificate", []))
    quorum_ok = bool(verification.get("block_certificate_valid"))
    signature_ok = bool(verification.get("recipient_signature_valid"))
    ledger_ok = bool(verification.get("ledger_valid"))
    identity_binding_ok = bool(verification.get("identity_binding_temporal_valid"))

    document = fitz.open()
    page = document.new_page(width=595, height=842)
    page.insert_font(fontname="aegis", fontfile=str(FONT_REGULAR))
    page.insert_font(fontname="aegis-bold", fontfile=str(FONT_BOLD))
    page.insert_font(fontname="aegis-mono", fontfile=str(FONT_MONO))

    navy = (0.027, 0.067, 0.122)
    slate = (0.075, 0.133, 0.208)
    cobalt = (0.243, 0.471, 1.0)
    green = (0.055, 0.443, 0.333)
    green_soft = (0.91, 0.973, 0.953)
    amber = (0.72, 0.38, 0.09)
    amber_soft = (1.0, 0.956, 0.902)
    ink = (0.06, 0.11, 0.17)
    muted = (0.34, 0.4, 0.47)
    line = (0.82, 0.85, 0.88)

    page.draw_rect(page.rect, color=(0.95, 0.965, 0.976), fill=(0.95, 0.965, 0.976))
    page.draw_rect(fitz.Rect(0, 0, 595, 118), color=navy, fill=navy)
    page.draw_rect(fitz.Rect(42, 38, 68, 68), color=cobalt, fill=cobalt)
    page.insert_text((50, 60), "A", fontsize=14, fontname="aegis-bold", color=(1, 1, 1))
    page.insert_text((82, 48), "PROJECT AEGIS", fontsize=10, fontname="aegis-bold", color=(0.65, 0.76, 1.0))
    page.insert_text((82, 73), "Forensic Evidence Report", fontsize=23, fontname="aegis-bold", color=(1, 1, 1))
    page.insert_text((42, 101), f"Report generated {_timestamp()}  |  Evidence schema aegis.decryption.v1", fontsize=8, fontname="aegis", color=(0.66, 0.72, 0.79))

    verified = signature_ok and quorum_ok and ledger_ok and identity_binding_ok
    status_color = green if verified else amber
    status_fill = green_soft if verified else amber_soft
    page.draw_rect(fitz.Rect(42, 139, 553, 205), color=status_color, fill=status_fill, width=0.8)
    page.insert_text((58, 160), "EVIDENCE STATUS", fontsize=8, fontname="aegis-bold", color=status_color)
    page.insert_text((58, 184), "CRYPTOGRAPHICALLY VERIFIED" if verified else "IDENTITY BINDING REQUIRES REVIEW", fontsize=17, fontname="aegis-bold", color=status_color)
    page.insert_text((390, 160), "LEDGER HEIGHT", fontsize=8, fontname="aegis-bold", color=muted)
    page.insert_text((390, 185), f"#{block['height']}", fontsize=20, fontname="aegis-bold", color=ink)

    def section_title(y: float, title: str) -> None:
        page.insert_text((42, y), title.upper(), fontsize=8, fontname="aegis-bold", color=cobalt)
        page.draw_line(fitz.Point(42, y + 8), fitz.Point(553, y + 8), color=line, width=0.7)

    def field(x: float, y: float, width: float, label: str, value: Any, mono: bool = False) -> None:
        page.insert_text((x, y), label.upper(), fontsize=7.5, fontname="aegis-bold", color=muted)
        page.insert_textbox(
            fitz.Rect(x, y + 7, x + width, y + 33), str(value),
            fontsize=9 if mono else 10, fontname="aegis-mono" if mono else "aegis",
            color=ink, lineheight=1.15,
        )

    section_title(234, "Identity and release session")
    field(42, 258, 244, "Recipient identity", f"{event.get('recipient_name')} (@{event.get('recipient_id')})")
    field(309, 258, 244, "Decryption timestamp", event.get("decrypted_at"), mono=True)
    field(42, 307, 244, "Document ID", event.get("document_id"), mono=True)
    field(309, 307, 244, "Session ID", event.get("session_id"), mono=True)
    field(42, 356, 511, "Watermark token", event.get("watermark_token"), mono=True)

    section_title(423, "Cryptographic verification")
    field(42, 447, 244, "Recipient ML-DSA signature", "VALID - ML-DSA-65" if signature_ok else "INVALID")
    field(309, 447, 244, "Validator quorum", f"VALID - {certificate_count}/4 signatures (3 required)" if quorum_ok else f"INVALID - {certificate_count}/4 signatures")
    field(42, 496, 244, "Ledger and identity binding", "VERIFIED" if ledger_ok and identity_binding_ok else "LEGACY OR FAILED")
    field(309, 496, 244, "Package ID", event.get("package_id"), mono=True)

    section_title(563, "Ledger binding")
    field(42, 587, 511, "Ledger block hash", block.get("block_hash"), mono=True)
    field(42, 636, 511, "Signed output SHA-256", event.get("output_hash"), mono=True)
    field(42, 685, 511, "Recipient signing key fingerprint", event.get("recipient_signing_key_id"), mono=True)

    page.draw_rect(fitz.Rect(42, 748, 553, 790), color=slate, fill=slate)
    note = "This report verifies the recipient key, signed decryption event, and local validator quorum. It attributes the exact signed digital copy; it does not establish intent or survive every document transformation."
    page.insert_textbox(fitz.Rect(55, 760, 540, 782), note, fontsize=7.6, fontname="aegis", color=(0.88, 0.91, 0.95), lineheight=1.2)
    page.insert_text((42, 818), f"Event {event.get('event_id')}", fontsize=7, fontname="aegis-mono", color=muted)
    page.insert_text((508, 818), "PAGE 1 / 1", fontsize=7, fontname="aegis-bold", color=muted)

    output = BytesIO()
    document.save(output, deflate=True, garbage=4)
    document.close()
    return output.getvalue()
