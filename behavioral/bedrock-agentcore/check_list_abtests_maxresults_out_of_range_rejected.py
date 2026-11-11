"""list-abtests-maxresults-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-abtests-maxresults-out-of-range-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListABTests sent without client-side validation refuses maxResults=0 and
    maxResults=101 with ValidationException and the exact range message for each bound,
    while a valid maxResults succeeds.
    """
    client = ctx.client("bedrock-agentcore")
    raw = ctx.client("bedrock-agentcore", config=Config(parameter_validation=False))

    # Positive control: a valid maxResults succeeds.
    ok = client.list_ab_tests(maxResults=5)
    assert "abTests" in ok, f"expected an abTests key in the response, got {sorted(ok)}"

    # Negative: maxResults below the documented minimum of 1.
    code_low, message_low = _error(lambda: raw.list_ab_tests(maxResults=0))
    assert code_low == "ValidationException", (
        f"maxResults=0: expected ValidationException, got {code_low}"
    )
    expected_low = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert message_low == expected_low, (
        f"maxResults=0: expected message {expected_low!r}, got {message_low!r}"
    )

    # Negative (distinct boundary edge): maxResults above the documented maximum of 100.
    code_high, message_high = _error(lambda: raw.list_ab_tests(maxResults=101))
    assert code_high == "ValidationException", (
        f"maxResults=101: expected ValidationException, got {code_high}"
    )
    expected_high = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    )
    assert message_high == expected_high, (
        f"maxResults=101: expected message {expected_high!r}, got {message_high!r}"
    )


def _error(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
