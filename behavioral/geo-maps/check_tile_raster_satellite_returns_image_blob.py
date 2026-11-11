"""tile-raster-satellite-returns-image-blob."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tile-raster-satellite-returns-image-blob"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTile against the raster.satellite tileset must return an actual raster image
    (PNG/JPEG magic bytes), distinct in kind from the protobuf vector.basemap tiles."""
    client = ctx.client("geo-maps")
    resp = client.get_tile(Tileset="raster.satellite", Z="0", X="0", Y="0")
    blob = resp["Blob"].read()
    assert len(blob) > 0
    assert _looks_like_image(blob), f"expected image magic bytes, got {blob[:8]!r}"
    assert resp["ContentType"].startswith("image/"), (
        f"expected an image/* Content-Type for a raster tileset, got {resp['ContentType']!r}"
    )
    assert resp["PricingBucket"], "expected a non-empty pricing bucket header"


def _looks_like_image(blob: bytes) -> bool:
    return blob[:8] == b"\x89PNG\r\n\x1a\n" or blob[:2] == b"\xff\xd8"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
