"""get-trace-summaries-malformed-filter-expression-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-trace-summaries-malformed-filter-expression-rejected"
GROUP = "error-semantics"
SERVICES = ["xray"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A syntactically invalid FilterExpression (unbalanced parens / bad operator) is rejected
    with InvalidRequestException -- distinct from the end-before-start time-range case -- while
    an otherwise-identical call with a valid FilterExpression still succeeds (positive control)."""
    xray = ctx.client("xray")
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=30)

    unbalanced, unbalanced_message = _error(
        lambda: xray.get_trace_summaries(
            StartTime=start, EndTime=now, FilterExpression='((service("x")'
        )
    )
    assert unbalanced == "InvalidRequestException", (
        f"expected InvalidRequestException for unbalanced parens, got {unbalanced}"
    )
    assert unbalanced_message == (
        "Error Location: line 1, position 15 : Invalid input symbol: '((service(\"x\")'"
    ), f"unexpected message: {unbalanced_message!r}"

    bad_operator, bad_operator_message = _error(
        lambda: xray.get_trace_summaries(
            StartTime=start, EndTime=now, FilterExpression='annotation.foo ==> "bar"'
        )
    )
    assert bad_operator == "InvalidRequestException", (
        f"expected InvalidRequestException for bad operator, got {bad_operator}"
    )
    assert bad_operator_message == (
        "Error Location: line 1, position 17 : Invalid input symbol: '='"
    ), f"unexpected message: {bad_operator_message!r}"

    # positive control: a syntactically valid FilterExpression on the same time range succeeds
    resp = xray.get_trace_summaries(
        StartTime=start, EndTime=now, FilterExpression='service("does-not-exist")'
    )
    assert "TraceSummaries" in resp, (
        f"a syntactically valid FilterExpression must still be accepted (positive control), "
        f"got response with no TraceSummaries key: {resp!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
