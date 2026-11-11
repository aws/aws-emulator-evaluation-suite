"""concurrent-tile-requests-return-isolated-content."""
from __future__ import annotations

import concurrent.futures

from behavioral_harness import tags

CHECK = "concurrent-tile-requests-return-isolated-content"
GROUP = "concurrency"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent GetTile calls for distinct (Z, X, Y) coordinates each return exactly the bytes a sequential
    fetch of that coordinate returns, and the coordinates' tiles all differ.
    """
    client = ctx.client("geo-maps")
    tileset = "vector.basemap"
    coords = [("0", "0", "0"), ("1", "0", "0"), ("1", "1", "0"), ("1", "0", "1")]

    def fetch(z: str, x: str, y: str) -> bytes:
        resp = client.get_tile(Tileset=tileset, Z=z, X=x, Y=y)
        return resp["Blob"].read()

    reference = {c: fetch(*c) for c in coords}
    for c, blob in reference.items():
        assert len(blob) > 0, f"reference fetch for {c} was empty"

    distinct_blobs = {blob for blob in reference.values()}
    assert len(distinct_blobs) == len(coords), (
        f"expected {len(coords)} distinct tile payloads across coordinates "
        f"{list(reference)}, got only {len(distinct_blobs)} distinct blobs -- "
        "GetTile is not varying content by coordinate, so cross-request isolation "
        "cannot be meaningfully tested"
    )

    mismatches = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(coords)) as pool:
        for _ in range(3):
            futures = {pool.submit(fetch, *c): c for c in coords}
            for fut in concurrent.futures.as_completed(futures):
                c = futures[fut]
                blob = fut.result()
                if blob != reference[c]:
                    mismatches.append(c)

    assert not mismatches, f"concurrent GetTile returned mismatched content for: {mismatches}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
