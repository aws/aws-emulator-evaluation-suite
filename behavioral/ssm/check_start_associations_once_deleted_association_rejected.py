"""start-associations-once-deleted-association-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-associations-once-deleted-association-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


def _delete_association_if_present(ssm, assoc_id: str) -> None:
    try:
        ssm.delete_association(AssociationId=assoc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AssociationDoesNotExist":
            raise


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
    """StartAssociationsOnce runs on a live association it created, and rejects the identical
    call once that association is deleted."""
    ssm = ctx.client("ssm")

    doc_name = ctx.unique_name("sim2real-ssm-doc-")
    ssm.create_document(
        Name=doc_name,
        DocumentType="Command",
        DocumentFormat="JSON",
        Content=json.dumps(
            {
                "schemaVersion": "2.2",
                "description": "a document an association can target",
                "mainSteps": [
                    {"action": "aws:runShellScript", "name": "echoStep", "inputs": {"runCommand": ["echo sim2real"]}}
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name, Force=True))

    # A run-unique tag no managed node carries: the association never runs on an instance.
    no_node = [{"Key": "tag:sim2real-target", "Values": [ctx.unique_name("sim2real-no-node-")]}]
    assoc_id = ssm.create_association(Name=doc_name, Targets=no_node)["AssociationDescription"]["AssociationId"]
    ctx.on_cleanup(lambda: _delete_association_if_present(ssm, assoc_id))

    # Positive control: StartAssociationsOnce on the live association succeeds.
    ssm.start_associations_once(AssociationIds=[assoc_id])

    ssm.delete_association(AssociationId=assoc_id)
    gone = _error(lambda: ssm.describe_association(AssociationId=assoc_id))
    assert gone[0] == "AssociationDoesNotExist", f"expected AssociationDoesNotExist, got {gone!r}"

    expected = ("AssociationDoesNotExist", f"Association id {assoc_id} does not exist")
    got = _error(lambda: ssm.start_associations_once(AssociationIds=[assoc_id]))
    assert got == expected, f"expected {expected!r}, got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
