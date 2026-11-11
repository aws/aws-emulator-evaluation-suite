"""tile-zoom-level-changes-tile-content."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tile-zoom-level-changes-tile-content"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The vector.basemap tile at X/Y 0/0 differs between zoom 0 and zoom 1, and each zoom returns the same
    bytes on a repeated fetch, so the difference comes from Z.
    """
    client = ctx.client("geo-maps")

    def fetch(z: str) -> bytes:
        resp = client.get_tile(Tileset="vector.basemap", Z=z, X="0", Y="0")
        return resp["Blob"].read()

    blob_z0 = fetch("0")
    blob_z1 = fetch("1")

    assert len(blob_z0) > 0, "zoom-0 tile returned an empty blob"
    assert len(blob_z1) > 0, "zoom-1 tile returned an empty blob"
    assert blob_z0 != blob_z1, "tiles at zoom 0 and zoom 1 have identical content"

    blob_z0_repeat = fetch("0")
    blob_z1_repeat = fetch("1")
    assert blob_z0_repeat == blob_z0, (
        "repeated zoom-0 fetch returned different content -- Z-0/0/0 is not deterministic"
    )
    assert blob_z1_repeat == blob_z1, (
        "repeated zoom-1 fetch returned different content -- Z-1/0/0 is not deterministic"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
