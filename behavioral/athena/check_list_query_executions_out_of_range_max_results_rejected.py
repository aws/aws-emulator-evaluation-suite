"""list-query-executions-out-of-range-max-results-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-query-executions-out-of-range-max-results-rejected"
GROUP = "error-semantics"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListQueryExecutions rejects MaxResults above the documented maximum of 50 with
    InvalidRequestException instead of clamping it, and accepts MaxResults=50."""
    # Client-side parameter validation would otherwise short-circuit this before it
    # ever reaches the wire (MaxResults carries a min:0/max:50 range constraint in
    # the model), so use a client with validation disabled to actually exercise the
    # server-side rejection.
    athena = _unvalidated_client(ctx, "athena")

    code, message = _error(lambda: athena.list_query_executions(MaxResults=51))
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for MaxResults=51 (above the documented "
        f"max of 50), got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 50"
    ), f"unexpected ListQueryExecutions message: {message!r}"

    # Positive control: the documented maximum (50) is accepted, not rejected.
    resp = athena.list_query_executions(MaxResults=50)
    assert "QueryExecutionIds" in resp, (
        f"expected QueryExecutionIds in the response for MaxResults=50 (the "
        f"documented boundary), got keys={sorted(resp)!r}"
    )


def _unvalidated_client(ctx, service: str):
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    instead: accepting a call AWS refuses is a distinct failure, not an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
