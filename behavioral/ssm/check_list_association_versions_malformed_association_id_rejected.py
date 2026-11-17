"""list-association-versions-malformed-association-id-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-association-versions-malformed-association-id-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_MALFORMED_ID = (
    "ValidationException",
    "1 validation error detected: Value 'not-a-uuid' at 'associationId' failed to satisfy "
    "constraint: Member must satisfy regular expression pattern: "
    "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
)


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
    """ListAssociationVersions rejects an AssociationId that is not a UUID, and lists the sole
    version of an association this check creates."""
    ssm = ctx.client("ssm")

    got = _error(lambda: ssm.list_association_versions(AssociationId="not-a-uuid"))
    assert got == _MALFORMED_ID, f"expected {_MALFORMED_ID!r}, got {got!r}"

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
    created = ssm.create_association(Name=doc_name, Targets=no_node)["AssociationDescription"]
    assoc_id = created["AssociationId"]
    ctx.on_cleanup(lambda: ssm.delete_association(AssociationId=assoc_id))
    assert created["AssociationVersion"] == "1", created

    versions = ssm.list_association_versions(AssociationId=assoc_id)["AssociationVersions"]
    assert [v["AssociationVersion"] for v in versions] == ["1"], versions


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
