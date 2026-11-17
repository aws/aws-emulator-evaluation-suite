"""list-harnesses-max-results-above-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-harnesses-max-results-above-range-rejected"
GROUP = "validation"
SERVICES = ["bedrock-agentcore-control"]


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; AssertionError if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListHarnesses refuses maxResults=101 with ValidationException and the exact range message,
    while maxResults=100, the top of the allowed range, is accepted."""
    bac = ctx.client("bedrock-agentcore-control")

    code, message = _error(lambda: bac.list_harnesses(maxResults=101))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value '101' at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    ok = bac.list_harnesses(maxResults=100)
    assert "harnesses" in ok, f"the in-range positive control was not accepted: {ok!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
