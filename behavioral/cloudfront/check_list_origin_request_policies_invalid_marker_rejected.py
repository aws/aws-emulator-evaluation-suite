"""list-origin-request-policies-invalid-marker-rejected."""
from __future__ import annotations

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so an
    emulator accepting input real AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


CHECK = "list-origin-request-policies-invalid-marker-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListOriginRequestPolicies with a malformed pagination Marker is rejected with
    NoSuchOriginRequestPolicy instead of being silently accepted as an opaque cursor."""
    cf = ctx.client("cloudfront")

    # Positive control: an ordinary call with no marker must succeed.
    control = cf.list_origin_request_policies()
    assert "OriginRequestPolicyList" in control, (
        f"expected OriginRequestPolicyList in response, got keys={list(control)!r}"
    )

    code, message = _error(
        lambda: cf.list_origin_request_policies(Marker="not a valid marker !! ###")
    )
    assert code == "NoSuchOriginRequestPolicy", f"expected NoSuchOriginRequestPolicy, got {code!r}: {message!r}"
    expected = "The request contains an invalid origin request policy marker."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
