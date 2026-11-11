"""describe-events-invalid-duration-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-events-invalid-duration-rejected"
GROUP = "error-semantics"
SERVICES = ["dax"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeEvents with a Duration exceeding the documented 14-day (20160 minute)
    maximum is rejected with InvalidParameterCombinationException, while a Duration
    within range (the positive control) succeeds."""
    dax = ctx.client("dax")

    code, message = _error_code(lambda: dax.describe_events(Duration=20161))
    assert code == "InvalidParameterCombinationException", (
        f"expected InvalidParameterCombinationException, got {code!r}"
    )
    assert message == "Events occurring more than 14 days in the past are not available.", (
        f"unexpected message: {message!r}"
    )

    # Positive control: same operation, a valid Duration, succeeds.
    resp = dax.describe_events(Duration=60)
    assert "Events" in resp, f"expected an Events key in the response, got {resp!r}"


def _error_code(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting an out-of-range Duration real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this Duration, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
