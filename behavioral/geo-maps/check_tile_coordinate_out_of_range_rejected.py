"""tile-coordinate-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tile-coordinate-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-maps"]


@tags("axis:rejection", "cap:c5", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTile with an 8-digit X, beyond the modeled 7-digit length, is rejected with ValidationException and
    its exact message, while tile 1/0/0 of the same tileset returns data.
    """
    client = ctx.client("geo-maps")

    def bad_call():
        client.get_tile(Tileset="vector.basemap", Z="1", X="99999999", Y="0")

    code, message = _error_code(bad_call)
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = "'X' must have length at most 7"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    control = client.get_tile(Tileset="vector.basemap", Z="1", X="0", Y="0")
    control_blob = control["Blob"].read()
    assert len(control_blob) > 0, f"expected non-empty tile blob for in-range coordinate, got {len(control_blob)} bytes"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
