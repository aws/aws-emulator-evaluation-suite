"""list-anycast-ip-lists-invalid-argument-malformed-marker-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-anycast-ip-lists-invalid-argument-malformed-marker-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAnycastIpLists with MaxItems -1 is refused with InvalidArgument and "MaxItems must be a
    non-zero positive integer.", while MaxItems 5 succeeds. The model leaves Marker unconstrained, so
    the negative MaxItems is the rejected input."""
    cf = ctx.client("cloudfront")

    code, message = _error_code_and_message(lambda: cf.list_anycast_ip_lists(MaxItems=-1))
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    assert message == "MaxItems must be a non-zero positive integer.", f"unexpected message {message!r}"

    control = cf.list_anycast_ip_lists(MaxItems=5)
    assert "AnycastIpLists" in control, f"expected AnycastIpLists in response, got keys {list(control)!r}"


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
