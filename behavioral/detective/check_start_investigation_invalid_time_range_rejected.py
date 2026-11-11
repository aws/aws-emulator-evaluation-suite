"""start-investigation-invalid-time-range-rejected."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-investigation-invalid-time-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["detective"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """StartInvestigation rejects a ScopeEndTime before ScopeStartTime; no investigation is
    created. A positive control with the identical EntityArn and a correctly-ordered scope
    proves the rejection is specific to the broken time range, not every call to this entity."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_entity_arn = f"arn:aws:iam::{account_id}:role/sim2real-detective-bad-time-range-role"

    now = datetime.now(timezone.utc)

    # positive control: the identical EntityArn succeeds when the scope is correctly ordered --
    # isolates ScopeEndTime < ScopeStartTime as the one broken input, rather than every
    # StartInvestigation call against this entity being rejected regardless of the time range.
    control_resp = d.start_investigation(
        GraphArn=arn,
        EntityArn=fake_entity_arn,
        ScopeStartTime=now - timedelta(hours=6),
        ScopeEndTime=now,
    )
    control_id = control_resp["InvestigationId"]
    entity_ids_before = _investigation_ids_for_entity(d, arn, fake_entity_arn)
    assert control_id in entity_ids_before, (
        f"expected control investigation {control_id!r} to be listed, got {entity_ids_before!r}"
    )

    code, message = _error(lambda: d.start_investigation(
        GraphArn=arn,
        EntityArn=fake_entity_arn,
        ScopeStartTime=now,
        ScopeEndTime=now - timedelta(hours=6),  # end before start
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Invalid investigation window: End time is before or equal to start time.", (
        f"unexpected message: {message!r}"
    )

    entity_ids_after = _investigation_ids_for_entity(d, arn, fake_entity_arn)
    assert entity_ids_after == entity_ids_before, (
        f"expected no new investigation for {fake_entity_arn!r}, "
        f"before={entity_ids_before!r} after={entity_ids_after!r}"
    )

    # positive control: the graph itself is otherwise fully usable
    d.tag_resource(ResourceArn=arn, Tags={"sim2real-detective-time-range-control": "ok"})
    ctx.on_cleanup(lambda: _untag_quietly(d, arn, ["sim2real-detective-time-range-control"]))
    tags = _poll_until(
        probe=lambda: d.list_tags_for_resource(ResourceArn=arn)["Tags"],
        predicate=lambda t: t.get("sim2real-detective-time-range-control") == "ok",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert tags.get("sim2real-detective-time-range-control") == "ok"


def _create_graph_with_retry(d, retries: int = 8, base_delay: float = 5.0) -> str:
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


def _investigation_ids_for_entity(d, graph_arn: str, entity_arn: str) -> list[str]:
    return sorted(
        i["InvestigationId"]
        for i in d.list_investigations(GraphArn=graph_arn).get("InvestigationDetails", [])
        if i.get("EntityArn") == entity_arn
    )


def _untag_quietly(d, graph_arn: str, keys: list[str]) -> None:
    from botocore.exceptions import ClientError

    try:
        d.untag_resource(ResourceArn=graph_arn, TagKeys=keys)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
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
