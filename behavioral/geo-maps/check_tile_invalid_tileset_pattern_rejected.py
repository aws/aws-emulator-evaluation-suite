"""tile-invalid-tileset-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tile-invalid-tileset-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-maps"]


@tags("axis:rejection", "cap:c5", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTile with a Tileset containing a space and '!' is rejected with ValidationException and its exact
    message, while a valid Tileset for the same coordinate returns data.
    """
    client = ctx.client("geo-maps")

    def bad_call():
        client.get_tile(Tileset="bad tileset!", Z="0", X="0", Y="0")

    code, message = _error_code(bad_call)
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_message = r"'Tileset' must match regex ^[-.\w]+$"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    control = client.get_tile(Tileset="vector.basemap", Z="0", X="0", Y="0")
    control_blob = control["Blob"].read()
    assert len(control_blob) > 0


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
