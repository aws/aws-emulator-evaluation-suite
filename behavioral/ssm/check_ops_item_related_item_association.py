"""ops-item-related-item-association."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ops-item-related-item-association"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateOpsItemRelatedItem adds a RelatesTo item to ListOpsItemRelatedItems, a duplicate fails
    with OpsItemRelatedItemAlreadyExistsException and adds nothing, and after disassociation a second
    disassociate fails with OpsItemRelatedItemAssociationNotFoundException."""

    ssm = ctx.client("ssm")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    def _run_shell_doc_content(command="echo hello"):
        return json.dumps(
            {
                "schemaVersion": "2.2",
                "description": "behavioral-fidelity-probe document",
                "mainSteps": [
                    {
                        "action": "aws:runShellScript",
                        "name": "runShellScript",
                        "inputs": {"runCommand": [command]},
                    }
                ],
            }
        )

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"condition not met within {timeout_s}s. Last: {last!r}")

    def _error_code(fn):
        """Call fn(); return its (error code, message). An unexpected SUCCESS raises."""
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")

    def _create_command_document(command="echo hello"):
        name = ctx.unique_name("sim2real-behav-probe-doc-")
        ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
        ssm.create_document(
            Content=_run_shell_doc_content(command),
            Name=name,
            DocumentType="Command",
            DocumentFormat="JSON",
        )
        status = _poll_until(
            lambda: ssm.describe_document(Name=name)["Document"]["Status"],
            lambda s: s in ("Active", "Failed"),
            timeout_s=60,
            interval_s=1,
        )
        assert status == "Active", f"expected document {name} to become Active, got {status}"
        return name

    def _document_arn(name):
        return f"arn:aws:ssm:{ctx.region}:{account_id}:document/{name}"

    doc_name = _create_command_document()
    title = ctx.unique_name("sim2real-behav-opsitem-")
    create_resp = ssm.create_ops_item(
        Description="behavioral-fidelity-probe",
        Source="EmulatorProbe",
        Title=title,
    )
    ops_item_id = create_resp["OpsItemId"]

    resource_uri = _document_arn(doc_name)
    assoc_resp = ssm.associate_ops_item_related_item(
        OpsItemId=ops_item_id,
        AssociationType="RelatesTo",
        ResourceType="AWS::SSM::Document",
        ResourceUri=resource_uri,
    )
    association_id = assoc_resp["AssociationId"]

    related = ssm.list_ops_item_related_items(OpsItemId=ops_item_id)["Summaries"]
    match = next(r for r in related if r["AssociationId"] == association_id)
    assert match["ResourceUri"] == resource_uri, match
    assert match["AssociationType"] == "RelatesTo", match

    # Re-associating the same ARN must be rejected, not silently duplicated.
    dup_code, dup_message = _error_code(
        lambda: ssm.associate_ops_item_related_item(
            OpsItemId=ops_item_id,
            AssociationType="RelatesTo",
            ResourceType="AWS::SSM::Document",
            ResourceUri=resource_uri,
        )
    )
    assert dup_code == "OpsItemRelatedItemAlreadyExistsException", dup_code
    # The message embeds a backend request id the check never sees, so match around it.
    assert dup_message.startswith(
        "ResourceUri (Service: AmazonSSM; Status Code: 400; "
        "Error Code: OpsItemRelatedItemAlreadyExistsException; Request ID: "
    ) and dup_message.endswith("; Proxy: null)"), dup_message

    # The rejected duplicate must be a no-op: still exactly the one association, unchanged.
    related_after_dup = ssm.list_ops_item_related_items(OpsItemId=ops_item_id)["Summaries"]
    assert len(related_after_dup) == 1, related_after_dup
    assert related_after_dup[0]["AssociationId"] == association_id, related_after_dup

    ssm.disassociate_ops_item_related_item(
        OpsItemId=ops_item_id, AssociationId=association_id
    )
    related_after = ssm.list_ops_item_related_items(OpsItemId=ops_item_id)["Summaries"]
    assert all(r["AssociationId"] != association_id for r in related_after), related_after

    # The dead association id is not just absent from the list; acting on it must also fail.
    redisassociate_code, redisassociate_message = _error_code(
        lambda: ssm.disassociate_ops_item_related_item(
            OpsItemId=ops_item_id, AssociationId=association_id
        )
    )
    assert redisassociate_code == "OpsItemRelatedItemAssociationNotFoundException", redisassociate_code
    assert redisassociate_message.startswith(
        "Related Item to be disassociated not found. (Service: AmazonSSM; Status Code: 400; "
        "Error Code: OpsItemRelatedItemAssociationNotFoundException; Request ID: "
    ) and redisassociate_message.endswith("; Proxy: null)"), redisassociate_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
