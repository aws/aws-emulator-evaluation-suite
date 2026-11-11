"""list-public-keys-invalid-marker-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-public-keys-invalid-marker-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListPublicKeys with a malformed pagination Marker is rejected with
    InvalidArgument -- an emulator that just treats Marker as an opaque string
    and returns an (empty) page instead of validating it is overly permissive."""
    cf = ctx.client("cloudfront")

    # Positive control: an ordinary call with no marker must succeed.
    control = cf.list_public_keys()
    assert "PublicKeyList" in control

    code, message = _error(lambda: cf.list_public_keys(Marker="not a valid marker !! ###"))
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    expected = "Marker must be a valid CF public key Id"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises: an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
