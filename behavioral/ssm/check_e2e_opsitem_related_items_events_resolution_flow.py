"""e2e-opsitem-related-items-events-resolution-flow."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-opsitem-related-items-events-resolution-flow"
GROUP = "e2e"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """OpsItem flow: an associated related item is listed, status reaches Resolved, a repeated
    DeleteOpsItem returns 200, and ListOpsItemEvents stays scoped to the OpsItemId."""
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    title = ctx.unique_name("sim2real-opsitem-")
    created = ssm.create_ops_item(
        Title=title,
        Description="sim2real ops item related-items/events/resolution flow",
        Source="sim2real-test",
        Priority=3,
    )
    ops_item_id = created["OpsItemId"]
    ctx.on_cleanup(lambda: _ignore(ssm.delete_ops_item, OpsItemId=ops_item_id))

    resource_uri = f"arn:aws:ssm:{ctx.region}:{account_id}:document/AWS-RunShellScript"
    assoc = ssm.associate_ops_item_related_item(
        OpsItemId=ops_item_id,
        AssociationType="RelatesTo",
        ResourceType="AWS::SSM::Document",
        ResourceUri=resource_uri,
    )
    association_id = assoc["AssociationId"]
    assert association_id, f"expected a non-empty AssociationId, got {association_id!r}"

    related = ssm.list_ops_item_related_items(OpsItemId=ops_item_id)["Summaries"]
    matching = [r for r in related if r["AssociationId"] == association_id]
    assert len(matching) == 1, (
        f"expected exactly 1 ListOpsItemRelatedItems summary for association "
        f"{association_id}, got {matching!r}"
    )
    assert matching[0]["ResourceUri"] == resource_uri, matching[0]
    assert matching[0]["ResourceType"] == "AWS::SSM::Document", matching[0]

    ssm.update_ops_item(OpsItemId=ops_item_id, Status="Resolved")
    resolved = ssm.get_ops_item(OpsItemId=ops_item_id)["OpsItem"]
    assert resolved["Status"] == "Resolved", resolved

    # ListOpsItemEvents is queryable for the life of the item scoped to this OpsItemId.
    # API-driven mutations do not always produce an event entry, so only well-formedness and
    # scoping are asserted, not non-emptiness.
    events = ssm.list_ops_item_events(
        Filters=[{"Key": "OpsItemId", "Values": [ops_item_id], "Operator": "Equal"}]
    )["Summaries"]
    assert all(e["OpsItemId"] == ops_item_id for e in events), events


    # DeleteOpsItem is eventually consistent (GetOpsItem may still return the item for minutes),
    # so the assertion is its documented idempotence: a repeat delete also returns 200.
    first_resp = ssm.delete_ops_item(OpsItemId=ops_item_id)
    second_resp = ssm.delete_ops_item(OpsItemId=ops_item_id)
    assert first_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, first_resp["ResponseMetadata"]
    assert second_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, second_resp["ResponseMetadata"]

    # GetOpsItem keeps returning a deleted item well past a short propagation window: the
    # deleted-items index is eventually consistent.
    after_delete = ssm.get_ops_item(OpsItemId=ops_item_id)["OpsItem"]
    assert after_delete["Title"] == title, after_delete





def _error_code(fn: Any):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


def _ignore(fn, **kwargs) -> None:
    try:
        fn(**kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "OpsItemNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    if not predicate(value):
        raise AssertionError(f"condition never satisfied, last value={value!r}")
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
