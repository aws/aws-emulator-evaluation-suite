"""describe-canaries-max-results-out-of-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-canaries-max-results-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["synthetics"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeCanaries accepts MaxResults 1000 and 21, above the model's documented 1-20 range, and refuses
    1001 with ValidationException and its exact message."""
    synth = ctx.client("synthetics")

    # Positive control: the boundary value 1000 is accepted, and so is 21, above the
    # documented maximum of 20 that AWS does not enforce.
    resp = synth.describe_canaries(MaxResults=1000)
    assert "Canaries" in resp, f"MaxResults=1000 (the real ceiling) was not accepted: {resp!r}"

    resp = synth.describe_canaries(MaxResults=21)
    assert "Canaries" in resp, (
        f"MaxResults=21 was rejected, but real AWS accepts it despite the service model's "
        f"1-20 smithy.api#range trait: {resp!r}"
    )

    error = _client_error(lambda: synth.describe_canaries(MaxResults=1001))
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException for MaxResults=1001 (one past the real ceiling), "
        f"got {error!r}"
    )
    expected_message = (
        "1 validation error detected: Value '1001' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 1000"
    )
    assert error["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {error['Message']!r}"
    )


def _client_error(fn) -> dict:
    """Call fn() and return the botocore Error dict (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
