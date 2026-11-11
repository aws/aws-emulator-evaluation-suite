"""sprites-2x-variant-larger-icon-dimensions."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "sprites-2x-variant-larger-icon-dimensions"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The sprites@2x.json offset file describes the retina sprite sheet: for an icon
    present in both the 1x and 2x offset maps, the 2x entry's pixel width/height must be
    strictly larger than the 1x entry's, not identical or smaller."""
    client = ctx.client("geo-maps")
    common = dict(Style="Standard", ColorScheme="Light", Variant="Default")

    resp_1x = client.get_sprites(FileName="sprites.json", **common)
    resp_2x = client.get_sprites(FileName="sprites@2x.json", **common)

    offsets_1x = json.loads(resp_1x["Blob"].read())
    offsets_2x = json.loads(resp_2x["Blob"].read())

    shared_keys = sorted(set(offsets_1x) & set(offsets_2x))
    assert shared_keys, "1x and 2x sprite offset maps share no icon keys"

    violations = []
    for icon in shared_keys:
        entry_1x = offsets_1x[icon]
        entry_2x = offsets_2x[icon]
        if not entry_2x["width"] > entry_1x["width"]:
            violations.append(
                f"{icon!r}: 2x width {entry_2x['width']} not greater than 1x width {entry_1x['width']}"
            )
        if not entry_2x["height"] > entry_1x["height"]:
            violations.append(
                f"{icon!r}: 2x height {entry_2x['height']} not greater than 1x height {entry_1x['height']}"
            )
    assert not violations, "icons failing 2x > 1x dimension check: " + "; ".join(violations)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
