"""list-origin-access-controls-invalid-argument-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-origin-access-controls-invalid-argument-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListOriginAccessControls with an invalid MaxItems (-1, below the minimum
    of 1) is rejected with InvalidArgument rather than being clamped silently
    to some default page size."""
    cf = ctx.client("cloudfront")

    # Positive control: a valid MaxItems must succeed.
    control = cf.list_origin_access_controls(MaxItems="1")
    assert "OriginAccessControlList" in control, f"expected a page, got={control!r}"

    code, message = _error(lambda: cf.list_origin_access_controls(MaxItems="-1"))
    assert code == "InvalidArgument", f"expected InvalidArgument got={code!r}"
    expected = "MaxItems must be a non-zero positive integer."
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
