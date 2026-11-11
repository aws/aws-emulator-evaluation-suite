"""style-descriptor-standard-returns-valid-style-json."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "style-descriptor-standard-returns-valid-style-json"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetStyleDescriptor(Standard) returns a version 8 style JSON with https sprite and glyphs URLs, vector
    sources with {z}/{x}/{y} tile templates, and layers that each carry an id and a type.
    """
    client = ctx.client("geo-maps")
    resp = client.get_style_descriptor(Style="Standard")
    blob = resp["Blob"].read()
    assert resp["ContentType"], "expected a non-empty ContentType on the style response"

    style = json.loads(blob)
    assert isinstance(style, dict), f"expected a JSON object style document, got {type(style).__name__}"
    assert style.get("version") == 8, f"expected MapLibre/Mapbox GL style-spec version 8, got {style.get('version')!r}"

    for key in ("sprite", "glyphs"):
        url = style.get(key)
        assert isinstance(url, str) and url.startswith("https://"), (
            f"expected a non-empty https {key} URL template, got {url!r}"
        )

    sources = style["sources"]
    assert isinstance(sources, dict), f"expected sources to be a JSON object, got {type(sources).__name__}"
    assert len(sources) > 0, f"expected at least one source, got {sources!r}"
    for name, source in sources.items():
        assert source.get("type") == "vector", f"source {name!r} expected type=vector, got {source.get('type')!r}"
        tiles = source.get("tiles")
        assert (
            isinstance(tiles, list)
            and len(tiles) > 0
            and all(tok in tiles[0] for tok in ("{z}", "{x}", "{y}"))
        ), f"source {name!r} expected a tiles list with a {{z}}/{{x}}/{{y}} URL template, got {tiles!r}"

    layers = style["layers"]
    assert isinstance(layers, list), f"expected layers to be a JSON array, got {type(layers).__name__}"
    assert len(layers) > 0, f"expected a non-empty layer list, got {layers!r}"
    for layer in layers:
        assert isinstance(layer, dict) and "id" in layer and "type" in layer, (
            f"expected every layer to carry an id and a type, got {layer!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
