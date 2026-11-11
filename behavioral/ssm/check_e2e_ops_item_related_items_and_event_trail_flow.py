"""e2e-ops-item-related-items-and-event-trail-flow."""
from __future__ import annotations

import re
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-ops-item-related-items-and-event-trail-flow"
GROUP = "state-machine"
SERVICES = ["ssm"]


# AWS appends the request id of the inner service call to this message; it is the only part
# that varies per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")


def _stable(message):
    if message is None:
        return None
    return _REQUEST_ID.sub("Request ID: <request-id>", message)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating a related item, transitioning status and listing events each have an
    observable effect on the OpsItem; DeleteOpsItem is idempotent, and a later
    UpdateOpsItem on the deleted id raises OpsItemConflictException."""
    ssm = ctx.client("ssm")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    title = ctx.unique_name("sim2real-opsitem-")

    # AssociateOpsItemRelatedItem's ResourceUri validation requires an SSM::Document that
    # actually exists (and is owned/accessible) in this account -- a public AWS-owned document
    # ARN (no account segment) is rejected as an invalid resourceUri. Create our own.
    doc_name = ctx.unique_name("sim2real-opsitem-doc-")
    ssm.create_document(
        Name=doc_name,
        DocumentType="Command",
        Content=json.dumps(
            {
                "schemaVersion": "2.2",
                "description": "sim2real related-item target document",
                "mainSteps": [
                    {
                        "action": "aws:runShellScript",
                        "name": "runShellScript",
                        "inputs": {"runCommand": ["echo sim2real"]},
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real", "Value": "e2e-ops-item-related-items-and-event-trail-flow"}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: ssm.delete_document(Name=doc_name, Force=True)))
    related_arn = f"arn:aws:ssm:{ctx.region}:{account_id}:document/{doc_name}"

    ops_item_id = ssm.create_ops_item(
        Title=title,
        Description="sim2real behavioral test ops item",
        Source="sim2real-behav",
        Tags=[{"Key": "sim2real", "Value": "e2e-ops-item-related-items-and-event-trail-flow"}],
    )["OpsItemId"]
    ctx.on_cleanup(lambda: _safe(lambda: ssm.delete_ops_item(OpsItemId=ops_item_id)))

    got = ssm.get_ops_item(OpsItemId=ops_item_id)["OpsItem"]
    assert got["Status"] == "Open", f"expected Status Open, got {got['Status']!r}"

    ssm.associate_ops_item_related_item(
        OpsItemId=ops_item_id,
        AssociationType="RelatesTo",
        ResourceType="AWS::SSM::Document",
        ResourceUri=related_arn,
    )

    # Real consequence of the association call: it shows up in ListOpsItemRelatedItems.
    related = _poll_until(
        lambda: ssm.list_ops_item_related_items(OpsItemId=ops_item_id)["Summaries"],
        lambda items: any(i["ResourceUri"] == related_arn for i in items),
        timeout_s=30,
        interval_s=3,
    )
    matching = [i for i in related if i["ResourceUri"] == related_arn]
    assert len(matching) == 1, f"expected exactly one related-item summary for {related_arn}, got {matching!r}"
    assert matching[0]["ResourceType"] == "AWS::SSM::Document", (
        f"expected ResourceType AWS::SSM::Document, got {matching[0]['ResourceType']!r}"
    )

    baseline_events = _events_count(ssm, ops_item_id)

    ssm.update_ops_item(OpsItemId=ops_item_id, Status="Resolved")
    resolved = ssm.get_ops_item(OpsItemId=ops_item_id)["OpsItem"]
    assert resolved["Status"] == "Resolved", f"expected Status Resolved, got {resolved['Status']!r}"

    # ListOpsItemEvents is populated by AWS-internal event sources (e.g. Incident Manager
    # actions on related items), not by direct API status updates in this account -- confirm
    # the call itself is well-formed and scoped to this OpsItem (no cross-item leakage) rather
    # than asserting a specific growth in count.
    events_after = ssm.list_ops_item_events(
        Filters=[{"Key": "OpsItemId", "Values": [ops_item_id], "Operator": "Equal"}]
    )["Summaries"]
    assert all(e["OpsItemId"] == ops_item_id for e in events_after), (
        f"list_ops_item_events leaked an event for a different OpsItemId: {events_after!r}"
    )
    assert len(events_after) >= baseline_events, (
        f"event count must not shrink: baseline={baseline_events}, after={len(events_after)}"
    )

    first_delete = ssm.delete_ops_item(OpsItemId=ops_item_id)
    assert first_delete["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 on first delete, got {first_delete['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    # DeleteOpsItem is documented as eventually consistent (an immediate GetOpsItem may still
    # return the deleted item for a few minutes) AND idempotent (repeated deletes of the same
    # ID must not raise). Assert the idempotency guarantee directly rather than racing the
    # undefined consistency window.
    second_delete = ssm.delete_ops_item(OpsItemId=ops_item_id)
    assert second_delete["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200 on repeated delete of an already-deleted OpsItemId, "
        f"got {second_delete['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # UpdateOpsItem, unlike GetOpsItem, does not ride the eventual-consistency window:
    # a mutation on an OpsItem mid-deletion raises OpsItemConflictException (not
    # OpsItemNotFoundException, since deletion is still settling).
    try:
        ssm.update_ops_item(OpsItemId=ops_item_id, Status="Resolved")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "OpsItemConflictException", (
            f"expected OpsItemConflictException mutating a deleted OpsItem, got {code!r}"
        )
        # AWS embeds a per-call backend request id; it is the only varying part.
        expected = (
            "Deletion of the provided OpsItem is already in progress (Service: AmazonSSM; "
            "Status Code: 409; Error Code: OpsItemConflictException; Request ID: <request-id>; "
            "Proxy: null)"
        )
        message = e.response["Error"].get("Message")
        assert _stable(message) == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError(
            "update_ops_item on an already-deleted OpsItemId unexpectedly succeeded"
        )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidDocument", "OpsItemNotFoundException"):
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={value!r}")


def _events_count(ssm, ops_item_id: str) -> int:
    resp = ssm.list_ops_item_events(
        Filters=[{"Key": "OpsItemId", "Values": [ops_item_id], "Operator": "Equal"}]
    )
    return len(resp["Summaries"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
