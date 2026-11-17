"""create-association-batch-malformed-document-name-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-association-batch-malformed-document-name-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


def _error(fn) -> tuple:
    """(Error.Code, Error.Message) raised by ``fn``; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAssociationBatch rejects an entry whose Name is shorter than a document name can
    be, and creates one association from a single valid entry."""
    ssm = ctx.client("ssm")

    malformed_name = "ab"
    expected = ("ValidationException", f"Invalid document name: {malformed_name}")
    got = _error(lambda: ssm.create_association_batch(Entries=[{"Name": malformed_name}]))
    assert got == expected, f"expected {expected!r}, got {got!r}"

    doc_name = ctx.unique_name("sim2real-ssm-doc-")
    ssm.create_document(
        Name=doc_name,
        DocumentType="Command",
        DocumentFormat="JSON",
        Content=json.dumps(
            {
                "schemaVersion": "2.2",
                "description": "a document the sole batch entry targets",
                "mainSteps": [
                    {"action": "aws:runShellScript", "name": "echoStep", "inputs": {"runCommand": ["echo sim2real"]}}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name, Force=True))

    # A run-unique tag no managed node carries: the association never runs on an instance.
    no_node = [{"Key": "tag:sim2real-target", "Values": [ctx.unique_name("sim2real-no-node-")]}]
    resp = ssm.create_association_batch(Entries=[{"Name": doc_name, "Targets": no_node}])
    assert resp["Failed"] == [], resp["Failed"]
    successful = resp["Successful"]
    assert len(successful) == 1, successful
    assoc_id = successful[0]["AssociationId"]
    ctx.on_cleanup(lambda: ssm.delete_association(AssociationId=assoc_id))

    described = ssm.describe_association(AssociationId=assoc_id)["AssociationDescription"]
    assert described["Name"] == doc_name, described


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
