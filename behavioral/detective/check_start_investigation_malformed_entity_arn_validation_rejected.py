"""start-investigation-malformed-entity-arn-validation-rejected."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-investigation-malformed-entity-arn-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["detective"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """StartInvestigation with an EntityArn outside the '^arn:' pattern fails on the service side with
    ValidationException and its exact message and creates no investigation, while tagging the graph succeeds."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # An account administers at most one behavior graph per Region; CreateGraph returns that
    # graph, so it is left in place.

    scope_end = datetime.now(timezone.utc)
    scope_start = scope_end - timedelta(hours=4)

    code, message = _error(
        lambda: d.start_investigation(
            GraphArn=arn,
            EntityArn="not-an-arn-at-all",
            ScopeStartTime=scope_start,
            ScopeEndTime=scope_end,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "1 validation error detected: Value 'not-an-arn-at-all' at 'entityArn' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: ^arn:.*"
    ), f"unexpected message: {message!r}"

    investigations = d.list_investigations(GraphArn=arn).get("InvestigationDetails", [])
    assert investigations == [], f"expected no investigation created, got {investigations!r}"

    # Positive control: the graph itself is otherwise fully usable.
    d.tag_resource(ResourceArn=arn, Tags={"sim2real-detective-entity-arn-control": "ok"})
    ctx.on_cleanup(lambda: _untag_quietly(d, arn, ["sim2real-detective-entity-arn-control"]))
    tags = _poll_until(
        probe=lambda: d.list_tags_for_resource(ResourceArn=arn)["Tags"],
        predicate=lambda t: t.get("sim2real-detective-entity-arn-control") == "ok",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert tags.get("sim2real-detective-entity-arn-control") == "ok", f"expected control tag to stick, got {tags!r}"


def _create_graph_with_retry(d, retries: int = 8, base_delay: float = 5.0) -> str:
    import time

    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            return d.create_graph()["GraphArn"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < retries - 1:
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise AssertionError("create_graph did not succeed after retries")


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _untag_quietly(d, graph_arn: str, keys: list[str]) -> None:
    from botocore.exceptions import ClientError

    try:
        d.untag_resource(ResourceArn=graph_arn, TagKeys=keys)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
