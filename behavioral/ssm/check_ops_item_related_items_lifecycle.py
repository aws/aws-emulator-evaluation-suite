"""ops-item-related-items-lifecycle."""
from __future__ import annotations

import re
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ops-item-related-items-lifecycle"
GROUP = "state-machine"
SERVICES = ["ssm"]


# AWS appends the request id of the inner service call to this message; it is the only part
# that varies per call.
_REQUEST_ID = re.compile(r"Request ID: [0-9A-Za-z-]+")


def _stable(message):
    if message is None:
        return None
    return _REQUEST_ID.sub("Request ID: <request-id>", message)


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """AssociateOpsItemRelatedItem links a related item visible via
    ListOpsItemRelatedItems until DisassociateOpsItemRelatedItem removes it."""
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    ops_item_id = _create_ops_item(ctx)

    # AssociateOpsItemRelatedItem's AWS::SSM::Document resourceUri validation
    # rejects public/AWS-owned document ARNs (e.g. AWS-RunShellScript, which has
    # an empty account segment); it requires a document owned by the caller's
    # own account, so create one to use as the related item.
    doc_name = ctx.unique_name("sim2real-relitem-doc-")
    ssm.create_document(
        Content=json.dumps(
            {
                "schemaVersion": "2.2",
                "description": "sim2real behavioral test document",
                "mainSteps": [
                    {
                        "action": "aws:runShellScript",
                        "name": "echoStep",
                        "inputs": {"runCommand": ["echo sim2real"]},
                    }
                ],
            }
        ),
        Name=doc_name,
        DocumentType="Command",
        DocumentFormat="JSON",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name, Force=True))
    doc_arn = f"arn:aws:ssm:{ctx.region}:{account_id}:document/{doc_name}"

    associated = ssm.associate_ops_item_related_item(
        OpsItemId=ops_item_id,
        AssociationType="RelatesTo",
        ResourceType="AWS::SSM::Document",
        ResourceUri=doc_arn,
    )
    association_id = associated["AssociationId"]

    summaries = ssm.list_ops_item_related_items(OpsItemId=ops_item_id)["Summaries"]
    assert len(summaries) == 1, f"expected exactly 1 related item, got {summaries}"
    assert summaries[0]["ResourceType"] == "AWS::SSM::Document", (
        f"expected ResourceType AWS::SSM::Document, got {summaries[0]}"
    )
    assert summaries[0]["AssociationType"] == "RelatesTo", (
        f"expected AssociationType RelatesTo, got {summaries[0]}"
    )
    assert summaries[0]["ResourceUri"] == doc_arn, (
        f"expected ResourceUri {doc_arn}, got {summaries[0]}"
    )
    assert summaries[0]["AssociationId"] == association_id, (
        f"expected AssociationId {association_id}, got {summaries[0]}"
    )

    ssm.disassociate_ops_item_related_item(OpsItemId=ops_item_id, AssociationId=association_id)

    summaries = ssm.list_ops_item_related_items(OpsItemId=ops_item_id)["Summaries"]
    assert summaries == [], f"expected no related items after disassociate, got {summaries}"

    # The association is now gone, not just listed as absent: a second
    # disassociate on the same (dead) AssociationId must be rejected with the
    # specific not-found error, not silently accepted.
    redisassoc_code, redisassoc_message = _error_code(
        lambda: ssm.disassociate_ops_item_related_item(
            OpsItemId=ops_item_id, AssociationId=association_id
        )
    )
    assert redisassoc_code == "OpsItemRelatedItemAssociationNotFoundException", (
        f"expected OpsItemRelatedItemAssociationNotFoundException, got {redisassoc_code}"
    )
    expected = (
        "Related Item to be disassociated not found. (Service: AmazonSSM; Status Code: 400; "
        "Error Code: OpsItemRelatedItemAssociationNotFoundException; Request ID: <request-id>; "
        "Proxy: null)"
    )
    assert _stable(redisassoc_message) == expected, (
        f"expected message {expected!r}, got {redisassoc_message!r}"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


def _create_ops_item(ctx) -> str:
    ssm = ctx.client("ssm")
    ops_item_id = ssm.create_ops_item(
        Title=ctx.unique_name("sim2real-opsitem-"),
        Description="sim2real behavioral test ops item",
        Source="sim2real",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["OpsItemId"]
    ctx.on_cleanup(lambda: ssm.delete_ops_item(OpsItemId=ops_item_id))
    return ops_item_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
