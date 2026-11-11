"""list-streaming-distributions-pagination-invalid-marker-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-streaming-distributions-pagination-invalid-marker-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListStreamingDistributions with a non-numeric MaxItems is refused with InvalidArgument and "MaxItems
    must be a non-zero positive integer.", while MaxItems "5" returns a StreamingDistributionList."""
    cf = ctx.client("cloudfront")

    code, message = _error(lambda: cf.list_streaming_distributions(MaxItems="not-a-number"))
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    expected = "MaxItems must be a non-zero positive integer."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    control = cf.list_streaming_distributions(MaxItems="5")
    assert "StreamingDistributionList" in control, f"expected a StreamingDistributionList, got {control!r}"


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises: an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
