"""static-map-satellite-style-returns-image."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "static-map-satellite-style-returns-image"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetStaticMap with Style Satellite and with Style Standard each return a decodable image of the same
    area, and the two images differ.
    """
    client = ctx.client("geo-maps")
    common = dict(FileName="map", Width=200, Height=200, Center="24.9460,60.1690", Zoom=11.5)

    resp_sat = client.get_static_map(Style="Satellite", **common)
    resp_std = client.get_static_map(Style="Standard", **common)

    blob_sat = resp_sat["Blob"].read()
    blob_std = resp_std["Blob"].read()
    assert len(blob_sat) > 0, "Satellite style returned an empty blob"
    assert len(blob_std) > 0, "Standard style returned an empty blob"
    assert resp_sat["ContentType"].startswith("image/"), (
        f"Satellite style ContentType={resp_sat['ContentType']!r}, expected image/*"
    )
    assert resp_std["ContentType"].startswith("image/"), (
        f"Standard style ContentType={resp_std['ContentType']!r}, expected image/*"
    )
    assert _looks_like_image(blob_sat), f"Satellite blob is not a decodable image, magic={blob_sat[:8]!r}"
    assert _looks_like_image(blob_std), f"Standard blob is not a decodable image, magic={blob_std[:8]!r}"
    assert blob_sat != blob_std, (
        "Satellite and Standard styles rendered byte-identical images for the same geography"
    )


def _looks_like_image(blob: bytes) -> bool:
    return blob[:8] == b"\x89PNG\r\n\x1a\n" or blob[:2] == b"\xff\xd8"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
