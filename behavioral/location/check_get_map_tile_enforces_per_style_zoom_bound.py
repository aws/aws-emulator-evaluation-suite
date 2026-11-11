"""get-map-tile-enforces-per-style-zoom-bound."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-map-tile-enforces-per-style-zoom-bound"
GROUP = 'maps'
SERVICES = ['location']

_MAX_ZOOM_RE = re.compile(r"maximum zoom of style \S+ \((\d+)\)")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "plane:data", "dp:api")
def run(ctx) -> None:
    """GetMapTile enforces a per-style maximum zoom tighter than the model's generic
    label pattern: the declared bound rejects one above it and accepts it exactly.

    Reference: https://docs.aws.amazon.com/location/previous/APIReference/API_GetMapTile.html
    """
    loc = ctx.client("location")
    map_name = ctx.unique_name("sim2real-behav-location-map-")
    loc.create_map(MapName=map_name, Configuration={"Style": "VectorEsriStreets"})
    ctx.on_cleanup(_teardown(lambda: loc.delete_map(MapName=map_name), "ResourceNotFoundException"))

    try:
        loc.get_map_tile(MapName=map_name, Z="30", X="0", Y="0")
        raise AssertionError("expected Z=30 to be rejected as beyond the style's maximum zoom")
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
        match = _MAX_ZOOM_RE.search(err["Message"])
        assert match, f"could not find a declared maximum zoom in {err['Message']!r}"
        max_zoom = int(match.group(1))

    tile = loc.get_map_tile(MapName=map_name, Z=str(max_zoom), X="0", Y="0")
    assert tile["Blob"].read(), f"expected tile bytes at the declared maximum zoom {max_zoom}"

    over = max_zoom + 1
    try:
        loc.get_map_tile(MapName=map_name, Z=str(over), X="0", Y="0")
        raise AssertionError(f"expected Z={over} to be rejected, one past the declared maximum")
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
        expected = f"'Z' must not be greater than maximum zoom of style VectorEsriStreets ({max_zoom})."
        assert err["Message"] == expected, f"unexpected message {err['Message']!r}"

    try:
        loc.get_map_tile(MapName=map_name, Z="3", X="8", Y="0")
        raise AssertionError("expected X=8 at Z=3 to be rejected (valid range is 0..7)")
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']!r}"
        expected = "'X' must be an integer in the range 0..2^Zoom-1 (0..7)."
        assert err["Message"] == expected, f"unexpected message {err['Message']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
