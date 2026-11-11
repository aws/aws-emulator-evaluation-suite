"""static-map-response-deterministic-across-repeated-requests."""
from __future__ import annotations

import hashlib

from behavioral_harness import tags

CHECK = "static-map-response-deterministic-across-repeated-requests"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two identical GetStaticMap requests for the same immutable map view must yield the
    same ETag and byte-identical image content (deterministic rendering / cache validity),
    not a fresh render with different bytes each time."""
    client = ctx.client("geo-maps")
    params = dict(
        FileName="map",
        Width=256,
        Height=256,
        Style="Satellite",
        Center="-123.108,49.295",
        Zoom=9.0,
    )
    resp_a = client.get_static_map(**params)
    resp_b = client.get_static_map(**params)

    blob_a = resp_a["Blob"].read()
    blob_b = resp_b["Blob"].read()
    assert len(blob_a) > 0, "first GetStaticMap response had an empty body"
    assert len(blob_b) > 0, "second GetStaticMap response had an empty body"

    # ETag is documented but not consistently populated by the live service; compare it
    # only when both responses actually carry the header, and always compare bytes below.
    if "ETag" in resp_a and "ETag" in resp_b:
        assert resp_a["ETag"] == resp_b["ETag"], (
            "identical requests produced different ETags"
        )
    assert hashlib.sha256(blob_a).hexdigest() == hashlib.sha256(blob_b).hexdigest(), (
        "identical requests produced different image bytes"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
