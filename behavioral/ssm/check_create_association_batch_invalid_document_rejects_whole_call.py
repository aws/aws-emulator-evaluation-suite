"""create-association-batch-invalid-document-rejects-whole-call."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-association-batch-invalid-document-rejects-whole-call"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_command_document(ctx, ssm) -> str:
    name = ctx.unique_name("sim2real-behav-batch-doc-")
    content = json.dumps(
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
    )
    ssm.create_document(
        Content=content,
        Name=name,
        DocumentType="Command",
        DocumentFormat="JSON",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
    return name


def _delete_association_if_exists(ssm, assoc_id: str) -> None:
    try:
        ssm.delete_association(AssociationId=assoc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AssociationDoesNotExist":
            raise


def _list_all_associations(ssm) -> list:
    associations = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        page = ssm.list_associations(**kwargs)
        associations.extend(page.get("Associations", []))
        next_token = page.get("NextToken")
        if not next_token:
            return associations


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAssociationBatch rejects the whole call with InvalidDocument when one entry names a
    document that does not exist, creating no association for the entry that was otherwise valid;
    the same valid entry alone succeeds."""
    ssm = ctx.client("ssm")
    good_doc = _create_command_document(ctx, ssm)
    bad_doc = ctx.unique_name("sim2real-behav-batch-missing-doc-")

    # A run-unique tag no managed node carries: the association targets no instance.
    no_node = [{"Key": "tag:sim2real-target", "Values": [ctx.unique_name("sim2real-no-node-")]}]

    code, message = _error(
        lambda: ssm.create_association_batch(
            Entries=[
                {"Name": good_doc, "Targets": no_node},
                {"Name": bad_doc, "Targets": no_node},
            ]
        )
    )
    assert code == "InvalidDocument", f"expected InvalidDocument, got {code!r}: {message!r}"
    assert message == f"Document does not exist: {bad_doc}", (
        f"CreateAssociationBatch message: {message!r}"
    )

    # Effect absent: the entry for the valid document must not have been created either, even
    # though it named a real document -- the whole call is one unit, not entry-by-entry.
    listed_after_rejection = _list_all_associations(ssm)
    assert all(a["Name"] != good_doc for a in listed_after_rejection), (
        f"a rejected CreateAssociationBatch must not create an association for {good_doc!r}: "
        f"{listed_after_rejection!r}"
    )

    # Positive control: the same valid entry alone succeeds.
    resp = ssm.create_association_batch(Entries=[{"Name": good_doc, "Targets": no_node}])
    assert resp["Failed"] == [], f"expected no Failed entries, got {resp['Failed']!r}"
    successful = resp["Successful"]
    assert len(successful) == 1, f"expected exactly one successful entry, got {successful!r}"
    assert successful[0]["Name"] == good_doc, (
        f"the successful entry should name {good_doc!r}, got {successful[0]!r}"
    )
    good_assoc_id = successful[0]["AssociationId"]
    ctx.on_cleanup(lambda: _delete_association_if_exists(ssm, good_assoc_id))

    described = ssm.describe_association(AssociationId=good_assoc_id)["AssociationDescription"]
    assert described["Name"] == good_doc, (
        f"DescribeAssociation returned Name={described['Name']!r}, expected {good_doc!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
