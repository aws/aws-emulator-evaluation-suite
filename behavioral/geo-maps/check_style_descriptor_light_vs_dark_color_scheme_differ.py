"""style-descriptor-light-vs-dark-color-scheme-differ."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "style-descriptor-light-vs-dark-color-scheme-differ"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The same Standard style requested with ColorScheme=Light vs ColorScheme=Dark must
    produce genuinely different style descriptor JSON (e.g. different background/paint
    colors) -- the ColorScheme parameter must actually change rendering, not be a no-op."""
    client = ctx.client("geo-maps")
    resp_light = client.get_style_descriptor(Style="Standard", ColorScheme="Light")
    resp_dark = client.get_style_descriptor(Style="Standard", ColorScheme="Dark")

    blob_light = resp_light["Blob"].read()
    blob_dark = resp_dark["Blob"].read()

    style_light = json.loads(blob_light)
    style_dark = json.loads(blob_dark)
    assert isinstance(style_light, dict) and isinstance(style_dark, dict), (
        f"expected two JSON object style documents, got {type(style_light).__name__}/{type(style_dark).__name__}"
    )
    assert len(style_light["layers"]) > 0 and len(style_dark["layers"]) > 0, (
        "expected a non-empty layer list for both color schemes"
    )
    assert blob_light != blob_dark, "Light and Dark color schemes produced identical style JSON"

    # An incidental per-request field (e.g. a generation timestamp) would make the raw
    # blobs differ with no real rendering change, so pin the difference to the thing the
    # docstring actually claims: most layers' own paint colors.
    paints_light = {layer["id"]: layer.get("paint", {}) for layer in style_light["layers"] if "id" in layer}
    paints_dark = {layer["id"]: layer.get("paint", {}) for layer in style_dark["layers"] if "id" in layer}
    assert set(paints_light) == set(paints_dark), (
        f"expected Light and Dark to render the same layer set, "
        f"got {len(paints_light)} vs {len(paints_dark)} ids "
        f"(only-light={set(paints_light) - set(paints_dark)}, only-dark={set(paints_dark) - set(paints_light)})"
    )
    differing = [lid for lid, paint in paints_light.items() if paint != paints_dark[lid]]
    assert len(differing) > len(paints_light) // 2, (
        f"expected a majority of layers' paint (background/fill/line color) to differ between "
        f"Light and Dark, got only {len(differing)}/{len(paints_light)} differing"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
