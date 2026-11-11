"""detect-document-text-corrupt-image-rejected."""
from __future__ import annotations

import io

from behavioral_harness import tags

CHECK = "detect-document-text-corrupt-image-rejected"
GROUP = "overly-permissive"
SERVICES = ["textract"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PNG-signature-bearing but truncated/corrupt image blob is rejected with
    UnsupportedDocumentException, and the same image, uncorrupted (positive control), succeeds."""
    good_png = _render_text_png(["FINE DOCUMENT"])
    # Keep the PNG magic header but chop off the rest of the stream (no IDAT/IEND), producing a
    # blob that is unambiguously PNG-formatted yet unreadable.
    corrupt_png = good_png[:64]

    textract = ctx.client("textract")
    err = _client_error(lambda: textract.detect_document_text(Document={"Bytes": corrupt_png}))
    assert err["Code"] == "UnsupportedDocumentException", f"unexpected code: {err['Code']!r}"
    expected_message = "Request has unsupported document format"
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Positive control: the uncorrupted image succeeds and produces the expected text.
    resp = textract.detect_document_text(Document={"Bytes": good_png})
    line_texts = " ".join(b["Text"].upper() for b in resp["Blocks"] if b["BlockType"] == "LINE")
    assert "FINE" in line_texts and "DOCUMENT" in line_texts, (
        f"expected 'FINE' and 'DOCUMENT' in recognized text, got {line_texts!r}"
    )


def _client_error(fn):
    """Call fn(); return the botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _render_text_png(lines, scale: int = 6) -> bytes:
    from PIL import Image, ImageDraw

    width = 420
    height = 40 * max(len(lines), 1) + 20
    img = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(img)
    y = 10
    for line in lines:
        draw.text((10, y), line, fill="black")
        y += 40
    img = img.resize((width * scale, height * scale), Image.LANCZOS)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
