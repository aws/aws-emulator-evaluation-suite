"""investigation-lifecycle-state-transitions."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "investigation-lifecycle-state-transitions"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """StartInvestigation on an observed entity starts RUNNING/ACTIVE with that EntityArn and GraphArn, and
    UpdateInvestigationState moves it to ARCHIVED and back to ACTIVE, with ListInvestigations' State filter
    following each change."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # An account administers at most one behavior graph per Region; CreateGraph returns that
    # graph, so it is left in place.

    entity_arn = _resolve_iam_entity_arn(ctx)
    scope_end = datetime.now(timezone.utc)
    scope_start = scope_end - timedelta(hours=4)

    # StartInvestigation succeeds only once the graph has ingested history for the entity
    # (documented in the Detective user guide, "Running investigations"), so it is retried.
    investigation_id = _poll_until(
        probe=lambda: _try_start_investigation(d, arn, entity_arn, scope_start, scope_end),
        predicate=lambda result: result is not None,
        timeout_s=180.0,
        interval_s=5.0,
    )

    initial = d.get_investigation(GraphArn=arn, InvestigationId=investigation_id)
    assert initial["Status"] == "RUNNING", f"unexpected initial Status: {initial!r}"
    assert initial["State"] == "ACTIVE", f"unexpected initial State: {initial!r}"
    assert initial["EntityArn"] == entity_arn, (
        f"expected EntityArn {entity_arn!r}, got {initial['EntityArn']!r}"
    )
    assert initial["GraphArn"] == arn, f"expected GraphArn {arn!r}, got {initial['GraphArn']!r}"

    d.update_investigation_state(
        GraphArn=arn, InvestigationId=investigation_id, State="ARCHIVED"
    )
    archived = _poll_until(
        probe=lambda: d.get_investigation(GraphArn=arn, InvestigationId=investigation_id),
        predicate=lambda resp: resp["State"] == "ARCHIVED",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert archived["State"] == "ARCHIVED", f"expected State ARCHIVED, got {archived['State']!r}"

    archived_ids = _list_investigation_ids(d, arn, state="ARCHIVED")
    active_ids = _list_investigation_ids(d, arn, state="ACTIVE")
    assert investigation_id in archived_ids, f"{investigation_id} missing from {archived_ids!r}"
    assert investigation_id not in active_ids, f"{investigation_id} unexpectedly in {active_ids!r}"

    d.update_investigation_state(
        GraphArn=arn, InvestigationId=investigation_id, State="ACTIVE"
    )
    reactivated = _poll_until(
        probe=lambda: d.get_investigation(GraphArn=arn, InvestigationId=investigation_id),
        predicate=lambda resp: resp["State"] == "ACTIVE",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert reactivated["State"] == "ACTIVE", f"expected State ACTIVE, got {reactivated['State']!r}"


def _resolve_iam_entity_arn(ctx) -> str:
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    arn = identity["Arn"]
    if ":assumed-role/" in arn:
        after = arn.split(":assumed-role/", 1)[1]
        role_name = after.split("/", 1)[0]
        return f"arn:aws:iam::{identity['Account']}:role/{role_name}"
    return arn


def _try_start_investigation(d, graph_arn, entity_arn, scope_start, scope_end):
    from botocore.exceptions import ClientError

    try:
        resp = d.start_investigation(
            GraphArn=graph_arn,
            EntityArn=entity_arn,
            ScopeStartTime=scope_start,
            ScopeEndTime=scope_end,
        )
        return resp["InvestigationId"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _list_investigation_ids(d, graph_arn, state: str) -> list[str]:
    ids: list[str] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = d.list_investigations(
            GraphArn=graph_arn,
            FilterCriteria={"State": {"Value": state}},
            **kwargs,
        )
        ids.extend(i["InvestigationId"] for i in resp.get("InvestigationDetails", []))
        token = resp.get("NextToken")
        if not token:
            break
    return ids


def _delete_graph_quietly(d, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        d.delete_graph(GraphArn=arn)
    except ClientError:
        pass


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


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
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
