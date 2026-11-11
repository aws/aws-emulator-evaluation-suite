"""sprites-returns-valid-json-offsets."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "sprites-returns-valid-json-offsets"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSprites with FileName="sprites.json" must return a parseable JSON offset map
    where each named sprite entry carries positive pixel width/height, not an opaque or
    empty stub payload."""
    client = ctx.client("geo-maps")
    resp = client.get_sprites(
        FileName="sprites.json", Style="Standard", ColorScheme="Light", Variant="Default"
    )
    blob = resp["Blob"].read()
    content_type = resp["ContentType"].lower()
    # Real AWS serves sprite files generically (observed: "binary/octet-stream") rather
    # than a format-specific MIME type; the actual format is verified below via the JSON
    # payload itself, not the header.
    assert content_type, "expected a non-empty ContentType header"

    offsets = json.loads(blob)
    assert isinstance(offsets, dict), f"expected a JSON object, got {type(offsets).__name__}"
    assert len(offsets) > 0, "expected a non-empty sprite offset map"

    for name, entry in offsets.items():
        assert isinstance(entry, dict), f"entry {name!r} is not an object: {entry!r}"
        assert entry["width"] > 0, f"entry {name!r} has non-positive width: {entry['width']!r}"
        assert entry["height"] > 0, f"entry {name!r} has non-positive height: {entry['height']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
