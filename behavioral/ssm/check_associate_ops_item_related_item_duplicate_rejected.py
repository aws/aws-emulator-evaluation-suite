"""associate-ops-item-related-item-duplicate-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-ops-item-related-item-duplicate-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Associating the exact same related item to an OpsItem twice is rejected with
    OpsItemRelatedItemAlreadyExistsException, and only one association is recorded."""
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    ops_item_id = ssm.create_ops_item(
        Title=ctx.unique_name("sim2real-opsitem-"),
        Description="sim2real behavioral test ops item",
        Source="sim2real",
    )["OpsItemId"]
    ctx.on_cleanup(lambda: ssm.delete_ops_item(OpsItemId=ops_item_id))

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
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name, Force=True))
    doc_arn = f"arn:aws:ssm:{ctx.region}:{account_id}:document/{doc_name}"

    first = ssm.associate_ops_item_related_item(
        OpsItemId=ops_item_id,
        AssociationType="RelatesTo",
        ResourceType="AWS::SSM::Document",
        ResourceUri=doc_arn,
    )
    association_id = first["AssociationId"]

    code, message, request_id = _error_code(
        lambda: ssm.associate_ops_item_related_item(
            OpsItemId=ops_item_id,
            AssociationType="RelatesTo",
            ResourceType="AWS::SSM::Document",
            ResourceUri=doc_arn,
        )
    )
    assert code == "OpsItemRelatedItemAlreadyExistsException", code
    # AWS embeds the response's own request id in this message.
    expected = (
        "ResourceUri (Service: AmazonSSM; Status Code: 400; Error Code: "
        f"OpsItemRelatedItemAlreadyExistsException; Request ID: {request_id}; Proxy: null)"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: exactly one related-item association is recorded.
    summaries = ssm.list_ops_item_related_items(OpsItemId=ops_item_id)["Summaries"]
    assert len(summaries) == 1, summaries
    assert summaries[0]["AssociationId"] == association_id

    # Restore leg: the rejection is state-forbids (the resourceUri is already
    # associated), not an always-invalid input, so it must be reversible —
    # remove the association and prove the identical call now succeeds.
    ssm.disassociate_ops_item_related_item(OpsItemId=ops_item_id, AssociationId=association_id)
    removed = ssm.list_ops_item_related_items(OpsItemId=ops_item_id)["Summaries"]
    assert removed == [], removed

    restored = ssm.associate_ops_item_related_item(
        OpsItemId=ops_item_id,
        AssociationType="RelatesTo",
        ResourceType="AWS::SSM::Document",
        ResourceUri=doc_arn,
    )
    restored_association_id = restored["AssociationId"]

    summaries_after_restore = ssm.list_ops_item_related_items(OpsItemId=ops_item_id)["Summaries"]
    assert len(summaries_after_restore) == 1, summaries_after_restore
    assert summaries_after_restore[0]["AssociationId"] == restored_association_id


def _error_code(fn):
    """Call fn(); return the ClientError (code, message, request id). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return (
            exc.response["Error"]["Code"],
            exc.response["Error"].get("Message"),
            exc.response.get("ResponseMetadata", {}).get("RequestId"),
        )
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
