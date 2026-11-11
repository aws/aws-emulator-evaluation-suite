"""list-streams-limit-over-100-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-streams-limit-over-100-rejected"
GROUP = "rejection"
SERVICES = ["dynamodbstreams"]

_OVER_LIMIT = (
    "ValidationException",
    "One or more parameter values were invalid: Limit cannot be greater than the "
    "maximum allowed size: 100",
)


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """ListStreams rejects a Limit above the maximum of 100 with ValidationException, and the same
    call at the boundary, Limit=100, succeeds.
    """
    streams = ctx.client("dynamodbstreams")

    expect_error(lambda: streams.list_streams(Limit=101), *_OVER_LIMIT)

    # Positive control: the same call at the maximum is accepted (it raises otherwise).
    streams.list_streams(Limit=100)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
