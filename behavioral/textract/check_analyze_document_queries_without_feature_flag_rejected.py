"""analyze-document-queries-without-feature-flag-rejected."""
from __future__ import annotations

import io

from behavioral_harness import tags

CHECK = "analyze-document-queries-without-feature-flag-rejected"
GROUP = "overly-permissive"
SERVICES = ["textract"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Supplying QueriesConfig without including QUERIES in FeatureTypes is rejected with
    InvalidParameterException, no QUERY block is produced, and the same request WITH the QUERIES
    feature enabled (positive control) succeeds and returns a QUERY block."""
    png_bytes = _render_text_png(["Invoice Number: INV-12345"])
    textract = ctx.client("textract")
    queries_config = {
        "Queries": [{"Text": "What is the invoice number?", "Alias": "INVOICE_NUMBER"}]
    }

    err = _client_error(
        lambda: textract.analyze_document(
            Document={"Bytes": png_bytes},
            FeatureTypes=["FORMS"],
            QueriesConfig=queries_config,
        )
    )
    assert err["Code"] == "InvalidParameterException", (
        f"expected InvalidParameterException for QueriesConfig without QUERIES in "
        f"FeatureTypes, got {err['Code']!r}"
    )
    expected_message = "QueriesConfig must be used with QUERIES FeatureType."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Positive control: the identical QueriesConfig succeeds once QUERIES is in FeatureTypes.
    resp = textract.analyze_document(
        Document={"Bytes": png_bytes},
        FeatureTypes=["QUERIES"],
        QueriesConfig=queries_config,
    )
    query_blocks = [b for b in resp["Blocks"] if b["BlockType"] == "QUERY"]
    assert len(query_blocks) == 1, (
        f"expected exactly one QUERY block once QUERIES is enabled, got {len(query_blocks)}"
    )
    actual_alias = query_blocks[0]["Query"]["Alias"]
    assert actual_alias == "INVOICE_NUMBER", (
        f"expected QUERY block alias 'INVOICE_NUMBER', got {actual_alias!r}"
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
