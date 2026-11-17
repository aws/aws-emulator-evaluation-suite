"""associate-ops-item-related-item-rejects-unknown-ops-item."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-ops-item-related-item-rejects-unknown-ops-item"
GROUP = "state-machine"
SERVICES = ["ssm"]


def _error_code(fn):
    """(Error.Code, Error.Message, RequestId) of the ClientError fn() raises; an unexpected
    success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        request_id = exc.response.get("ResponseMetadata", {}).get("RequestId")
        return err.get("Code"), err.get("Message"), request_id
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateOpsItemRelatedItem rejects a well-formed but nonexistent OpsItemId with
    OpsItemNotFoundException, though the identical association on a real OpsItem succeeds."""
    ssm = ctx.client("ssm")

    ops_item_id = ssm.create_ops_item(
        Title=ctx.unique_name("sim2real-opsitem-notfound-"),
        Description="sim2real behavioral test ops item",
        Source="sim2real",
    )["OpsItemId"]
    ctx.on_cleanup(lambda: ssm.delete_ops_item(OpsItemId=ops_item_id))

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
    doc_arn = f"arn:aws:ssm:{ctx.region}:{ctx.account}:document/{doc_name}"

    # Positive control: the association succeeds against the real OpsItem.
    association_id = ssm.associate_ops_item_related_item(
        OpsItemId=ops_item_id,
        AssociationType="RelatesTo",
        ResourceType="AWS::SSM::Document",
        ResourceUri=doc_arn,
    )["AssociationId"]
    ctx.on_cleanup(
        lambda: ssm.disassociate_ops_item_related_item(
            OpsItemId=ops_item_id, AssociationId=association_id
        )
    )

    fake_ops_item_id = "oi-" + ("0" if ops_item_id[3] != "0" else "1") + ops_item_id[4:]
    assert fake_ops_item_id != ops_item_id, "fabricated id must differ from the real one"

    code, message, request_id = _error_code(
        lambda: ssm.associate_ops_item_related_item(
            OpsItemId=fake_ops_item_id,
            AssociationType="RelatesTo",
            ResourceType="AWS::SSM::Document",
            ResourceUri=doc_arn,
        )
    )
    assert code == "OpsItemNotFoundException", code
    expected = (
        "OpsItem not found. (Service: AmazonSSM; Status Code: 400; Error Code: "
        f"OpsItemNotFoundException; Request ID: {request_id}; Proxy: null)"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The rejected call attached no association to the fabricated OpsItemId.
    summaries = ssm.list_ops_item_related_items(OpsItemId=ops_item_id)["Summaries"]
    assert len(summaries) == 1, summaries
    assert summaries[0]["AssociationId"] == association_id, summaries


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
