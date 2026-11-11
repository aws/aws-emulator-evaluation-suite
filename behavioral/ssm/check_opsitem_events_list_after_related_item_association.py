"""opsitem-events-list-after-related-item-association."""
from __future__ import annotations

import re
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "opsitem-events-list-after-related-item-association"
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
    """An OpsItem related-item association is listed, then dropped by disassociation.

    A repeat disassociate fails OpsItemRelatedItemAssociationNotFoundException with the exact
    message."""
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    doc_name = ctx.unique_name("sim2real-opsitem-doc-")
    content = json.dumps(
        {
            "schemaVersion": "2.2",
            "description": "sim2real behavioral check document",
            "mainSteps": [
                {
                    "action": "aws:runShellScript",
                    "name": "example",
                    "inputs": {"runCommand": ["echo hello"]},
                }
            ],
        }
    )
    ssm.create_document(
        Content=content,
        Name=doc_name,
        DocumentType="Command",
        Tags=[{"Key": "sim2real", "Value": "behavioral-check"}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name))
    doc_arn = f"arn:aws:ssm:{ctx.region}:{account_id}:document/{doc_name}"

    ops_item_id = ssm.create_ops_item(
        Title=ctx.unique_name("sim2real-opsitem-"),
        Description="sim2real behavioral check ops item",
        Source="sim2real-behavioral",
        Tags=[{"Key": "sim2real", "Value": "behavioral-check"}],
    )["OpsItemId"]
    ctx.on_cleanup(lambda: ssm.delete_ops_item(OpsItemId=ops_item_id))

    association_id = ssm.associate_ops_item_related_item(
        OpsItemId=ops_item_id,
        AssociationType="RelatesTo",
        ResourceType="AWS::SSM::Document",
        ResourceUri=doc_arn,
    )["AssociationId"]

    related = _list_related_items(ssm, ops_item_id)
    assert any(
        r["AssociationId"] == association_id and r["ResourceUri"] == doc_arn
        for r in related
    ), f"expected association {association_id} for {doc_arn} in {related!r}"

    ssm.disassociate_ops_item_related_item(
        OpsItemId=ops_item_id, AssociationId=association_id
    )

    related_after = _poll_until(
        lambda: _list_related_items(ssm, ops_item_id),
        lambda items: not any(r["AssociationId"] == association_id for r in items),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert not any(
        r["AssociationId"] == association_id for r in related_after
    ), f"expected association {association_id} gone, still in {related_after!r}"

    dup_code, dup_message = _error_code(
        lambda: ssm.disassociate_ops_item_related_item(
            OpsItemId=ops_item_id, AssociationId=association_id
        )
    )
    assert dup_code == "OpsItemRelatedItemAssociationNotFoundException", (
        f"expected OpsItemRelatedItemAssociationNotFoundException re-disassociating "
        f"{association_id}, got {dup_code!r}"
    )
    expected = (
        "Related Item to be disassociated not found. (Service: AmazonSSM; Status Code: 400; "
        "Error Code: OpsItemRelatedItemAssociationNotFoundException; Request ID: <request-id>; "
        "Proxy: null)"
    )
    assert _stable(dup_message) == expected, f"expected message {expected!r}, got {dup_message!r}"


def _list_related_items(ssm, ops_item_id):
    items = []
    next_token = None
    for _ in range(50):
        kwargs = {"OpsItemId": ops_item_id}
        if next_token:
            kwargs["NextToken"] = next_token
        page = ssm.list_ops_item_related_items(**kwargs)
        items.extend(page.get("Summaries", []))
        next_token = page.get("NextToken")
        if not next_token:
            break
    return items


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected a ClientError, call succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


