"""delete-association-nonexistent-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-association-nonexistent-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]

_DOC_CONTENT = json.dumps(
    {
        "schemaVersion": "2.2",
        "description": "sim2real behavioral test document",
        "mainSteps": [
            {"action": "aws:runShellScript", "name": "run", "inputs": {"runCommand": ["echo hi"]}}
        ],
    }
)


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAssociation rejects a bogus AssociationId with
    AssociationDoesNotExist and leaves no association behind, whereas the same
    call against a real association (positive control) succeeds and removes it."""
    ssm = ctx.client("ssm")

    bogus_id = "00000000-0000-0000-0000-000000000000"
    code, message = _error(lambda: ssm.delete_association(AssociationId=bogus_id))
    assert code == "AssociationDoesNotExist", code
    assert message == f"Association {bogus_id} does not exist.", message

    # Positive control: a real association can be deleted successfully.
    doc_name = ctx.unique_name("sim2real-delassocdoc-")
    tag_value = ctx.unique_name("sim2real-delassoc-tag-")
    ssm.create_document(
        Name=doc_name,
        Content=_DOC_CONTENT,
        DocumentType="Command",
        DocumentFormat="JSON",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name))

    assoc_id = ssm.create_association(
        Name=doc_name,
        Targets=[{"Key": "tag:sim2real-delassoc", "Values": [tag_value]}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["AssociationDescription"]["AssociationId"]

    def _delete_if_present():
        try:
            ssm.delete_association(AssociationId=assoc_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "AssociationDoesNotExist":
                raise

    ctx.on_cleanup(_delete_if_present)

    ssm.delete_association(AssociationId=assoc_id)

    # DescribeAssociation is backed by an eventually-consistent index; immediately
    # after DeleteAssociation it may briefly still report the (now-deleted)
    # association instead of AssociationDoesNotExist. Poll for the deletion to
    # become visible.
    gone = f"Association {assoc_id} does not exist."
    code_after, message_after = _poll_error(
        lambda: ssm.describe_association(AssociationId=assoc_id), "AssociationDoesNotExist"
    )
    assert code_after == "AssociationDoesNotExist", code_after
    assert message_after == gone, message_after

    # Deleting it a second time is now itself rejected as not-found. The same
    # eventually-consistent index can briefly let a second DeleteAssociation
    # succeed as a no-op, so poll here too.
    code_second_delete, message_second_delete = _poll_error(
        lambda: ssm.delete_association(AssociationId=assoc_id), "AssociationDoesNotExist"
    )
    assert code_second_delete == "AssociationDoesNotExist", code_second_delete
    assert message_second_delete == gone, message_second_delete


def _poll_error(fn, expected_code: str, attempts: int = 15, delay: float = 2.0):
    """Retry fn() until it raises expected_code; return (code, message). A call that keeps
    succeeding, or keeps raising another code, past the attempts raises AssertionError."""
    last = None
    for _ in range(attempts + 1):
        try:
            result = fn()
        except ClientError as exc:
            last = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            if last[0] == expected_code:
                return last
        else:
            last = ("<success>", repr(result))
        time.sleep(delay)
    raise AssertionError(f"expected {expected_code} within {attempts} retries, last: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
