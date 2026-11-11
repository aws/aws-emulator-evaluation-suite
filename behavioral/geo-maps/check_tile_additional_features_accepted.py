"""tile-additional-features-accepted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tile-additional-features-accepted"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTile with AdditionalFeatures Transit returns tile data that differs from the same tile without it."""
    client = ctx.client("geo-maps")
    # Zoom 14 tile over midtown Manhattan, a real subway network -- picked so a
    # Transit-specific layer has something to render (the zoom-0 whole-world tile
    # does not: real AWS returns byte-identical content with or without the feature).
    tile_kwargs = dict(Tileset="vector.basemap", Z="14", X="4824", Y="6157")
    resp_plain = client.get_tile(**tile_kwargs)
    resp_transit = client.get_tile(**tile_kwargs, AdditionalFeatures=["Transit"])

    blob_plain = resp_plain["Blob"].read()
    blob_transit = resp_transit["Blob"].read()

    assert len(blob_plain) > 0, f"expected non-empty plain tile blob, got {len(blob_plain)} bytes"
    assert len(blob_transit) > 0, (
        f"expected non-empty AdditionalFeatures=[Transit] tile blob, got {len(blob_transit)} bytes"
    )
    assert resp_transit["ContentType"], "expected a non-empty ContentType on the transit response"
    assert blob_transit != blob_plain, (
        "AdditionalFeatures=[Transit] returned byte-identical content to the plain tile -- "
        "the feature was accepted but not honored"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
