"""update-association-status-invalid-document-rejected."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-association-status-invalid-document-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAssociationStatus for a real document and an instance with no association fails with
    AssociationDoesNotExist (empty message), and DescribeAssociation for that pair fails with the
    exact not-found message."""
    ssm = ctx.client("ssm")
    doc_name = ctx.unique_name("sim2real-ssm-doc-")
    content = json.dumps(
        {
            "schemaVersion": "2.2",
            "description": "no-op command document",
            "mainSteps": [
                {
                    "action": "aws:runShellScript",
                    "name": "noop",
                    "inputs": {"runCommand": ["echo hi"]},
                }
            ],
        }
    )
    ssm.create_document(
        Content=content,
        Name=doc_name,
        DocumentType="Command",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name))

    # Positive control: the document itself is real and resolvable.
    described = ssm.get_document(Name=doc_name)
    assert described["Status"] == "Active", (
        f"expected newly-created document {doc_name!r} to be Active, "
        f"got {described['Status']!r}"
    )

    # Well-formed managed-node ID that was never associated with this doc.
    fake_instance_id = "i-" + uuid.uuid4().hex[:17]
    status = {
        "Date": datetime.now(timezone.utc),
        "Name": "Success",
        "Message": "attempted status update with no association on record",
    }

    def _call():
        return ssm.update_association_status(
            Name=doc_name, InstanceId=fake_instance_id, AssociationStatus=status
        )

    code, message = _error(_call)
    assert code == "AssociationDoesNotExist", f"expected AssociationDoesNotExist, got {code}"
    assert message == "", message

    # Independent terminal read at the destination: the rejected call must not have a side
    # effect. describe_association on the same (Name, InstanceId) pair must report the same
    # absence, through a different operation than the one that was rejected.
    describe_code, describe_message = _error(
        lambda: ssm.describe_association(Name=doc_name, InstanceId=fake_instance_id)
    )
    assert describe_code == "AssociationDoesNotExist", (
        f"expected no association to exist for ({doc_name}, {fake_instance_id}) after the "
        f"rejected update, got error {describe_code!r}"
    )
    assert describe_message == (
        f"Association not found for documentName {doc_name} and instanceId {fake_instance_id}. "
        "Try using the association-id parameter if you are looking for an association created "
        "using targets."
    ), describe_message


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

