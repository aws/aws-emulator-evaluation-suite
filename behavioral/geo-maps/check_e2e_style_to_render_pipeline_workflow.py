"""e2e-style-to-render-pipeline-workflow."""
from __future__ import annotations

import json
import re

from behavioral_harness import tags

CHECK = "e2e-style-to-render-pipeline-workflow"
GROUP = "e2e"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The resources a Standard style descriptor references are retrievable: GetTile returns data for its
    vector source's tileset, GetSprites a PNG sheet with an offsets JSON, and GetGlyphs data for its glyphs
    template.
    """
    client = ctx.client("geo-maps")

    # 1. Fetch the style descriptor for the Standard style.
    style_resp = client.get_style_descriptor(Style="Standard")
    style = json.loads(style_resp["Blob"].read())
    assert isinstance(style, dict), f"style descriptor body must be a JSON object, got {type(style)}"
    sources = style["sources"]
    assert isinstance(sources, dict) and len(sources) > 0, (
        f"style descriptor must declare at least one source, got {sources!r}"
    )

    # 2. Follow the style's own vector source to the tile-URL template and derive the
    # Tileset path segment geo-maps' GetTile expects (…/v2/tiles/{Tileset}/{z}/{x}/{y}…).
    tile_template = None
    for src in sources.values():
        tiles = src.get("tiles") if isinstance(src, dict) else None
        if tiles:
            tile_template = tiles[0]
            break
    assert tile_template, f"style descriptor has no source with a tiles[] template: {sources}"

    match = re.search(r"/tiles/([^/]+(?:/[^/{}]+)*)/\{z\}/\{x\}/\{y\}", tile_template)
    assert match, f"could not parse a Tileset out of tile template {tile_template!r}"
    tileset = match.group(1)

    # 3. Actually fetch a tile for that derived tileset -- the referential-consistency
    # assertion: what the style descriptor ADVERTISES must be truly fetchable.
    tile_resp = client.get_tile(Tileset=tileset, Z="0", X="0", Y="0")
    tile_blob = tile_resp["Blob"].read()
    assert len(tile_blob) > 0, f"GetTile for style-referenced tileset {tileset!r} returned no data"

    # 4. Follow the style's sprite reference (…/styles/{Style}/{ColorScheme}/{Variant}/
    # sprites/{sprite}) and fetch the actual sprite sheet + offsets it points at.
    sprite_url = style.get("sprite")
    assert sprite_url, "style descriptor has no top-level 'sprite' reference"
    sprite_match = re.search(r"/([^/]+)/([^/]+)/([^/]+)/sprites/[^/]*$", sprite_url)
    assert sprite_match, "SPRITE_URL=" + repr(sprite_url)
    style_name, color_scheme, variant = sprite_match.groups()

    sprites_resp = client.get_sprites(
        FileName="sprites.png", Style=style_name, ColorScheme=color_scheme, Variant=variant
    )
    sprite_blob = sprites_resp["Blob"].read()
    assert sprite_blob[:8] == b"\x89PNG\r\n\x1a\n", "sprite sheet referenced by style isn't a PNG"

    json_resp = client.get_sprites(
        FileName="sprites.json", Style=style_name, ColorScheme=color_scheme, Variant=variant
    )
    offsets = json.loads(json_resp["Blob"].read())
    assert isinstance(offsets, dict) and len(offsets) > 0, (
        f"sprites.json offsets must be a non-empty object, got {offsets!r}"
    )

    # 5. Follow the style's glyphs reference (…/glyphs/{fontstack}/{range}) for a font
    # actually used by a layer, if the style declares one, else fall back to a known stack.
    glyphs_url = style.get("glyphs")
    assert glyphs_url, "style descriptor has no top-level 'glyphs' reference"
    assert "{fontstack}" in glyphs_url and "{range}" in glyphs_url, (
        f"glyphs URL template missing expected placeholders: {glyphs_url!r}"
    )
    glyphs_resp = client.get_glyphs(
        FontStack="Amazon Ember Regular", FontUnicodeRange="0-255.pbf"
    )
    glyphs_blob = glyphs_resp["Blob"].read()
    assert len(glyphs_blob) > 0, "glyphs referenced by the style's glyphs template returned no data"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
