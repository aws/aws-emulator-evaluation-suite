"""style-descriptor-monochrome-style-returns-valid-json."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "style-descriptor-monochrome-style-returns-valid-json"
GROUP = "data-plane"
SERVICES = ["geo-maps"]


@tags("axis:happy-path", "cap:c5", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetStyleDescriptor(Monochrome) returns a style JSON with a version and a non-empty layers list, and its
    bytes differ from the Standard style's descriptor.
    """
    client = ctx.client("geo-maps")
    resp_standard = client.get_style_descriptor(Style="Standard")
    blob_standard = resp_standard["Blob"].read()

    resp = client.get_style_descriptor(Style="Monochrome")
    assert resp["ContentType"], "GetStyleDescriptor(Monochrome) returned no ContentType"
    blob = resp["Blob"].read()

    style = json.loads(blob)
    assert isinstance(style, dict), f"Monochrome style body is not a JSON object: {style!r}"
    assert "version" in style, f"Monochrome style JSON missing 'version': {style!r}"
    assert isinstance(style["layers"], list), f"Monochrome style 'layers' is not a list: {style['layers']!r}"
    assert len(style["layers"]) > 0, "Monochrome style has an empty layers list"
    assert blob != blob_standard, (
        "Monochrome and Standard styles produced identical style JSON -- "
        "Style is being ignored rather than changing what is served"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
