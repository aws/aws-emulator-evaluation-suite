"""sprites-returns-valid-png-blob."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "sprites-returns-valid-png-blob"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSprites with FileName="sprites.png" must return a real PNG image (correct magic
    bytes and Content-Type), matching the requested file extension."""
    client = ctx.client("geo-maps")
    resp = client.get_sprites(
        FileName="sprites.png", Style="Standard", ColorScheme="Light", Variant="Default"
    )
    blob = resp["Blob"].read()
    assert len(blob) > 0, "expected a non-empty sprite blob"
    assert blob[:8] == b"\x89PNG\r\n\x1a\n", f"expected PNG magic bytes, got {blob[:8]!r}"
    content_type = resp["ContentType"].lower()
    # Real AWS serves sprite files generically rather than "image/png"; the format is
    # verified above via the PNG magic-byte signature, not the header. Pinned to the
    # observed value (not just non-empty) since this is a fixed API contract, not a
    # per-account variable.
    assert content_type == "binary/octet-stream", (
        f"expected Content-Type 'binary/octet-stream' for a sprite PNG blob, got {content_type!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
