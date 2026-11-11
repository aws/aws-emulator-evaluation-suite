"""create-association-lifecycle-and-versions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-association-lifecycle-and-versions"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAssociation returns version 1, UpdateAssociation version 2 with the new schedule,
    ListAssociationVersions both schedules, and after DeleteAssociation both describe and update fail with
    AssociationDoesNotExist and the exact message."""
    ssm = ctx.client("ssm")
    doc_name = _create_command_document(ctx)

    # A run-unique tag no managed node carries: the association targets no instance.
    no_node = [{"Key": "tag:sim2real-target", "Values": [ctx.unique_name("sim2real-no-node-")]}]
    created = ssm.create_association(
        Name=doc_name,
        Targets=no_node,
        ScheduleExpression="rate(30 days)",
        Tags=[{"Key": "sim2real-behav-probe", "Value": CHECK}],
    )["AssociationDescription"]
    assoc_id = created["AssociationId"]
    assert created["AssociationVersion"] == "1", f"expected version 1 on create, got {created['AssociationVersion']!r}"
    ctx.on_cleanup(lambda: _delete_association_if_exists(ssm, assoc_id))

    described = ssm.describe_association(AssociationId=assoc_id)["AssociationDescription"]
    assert described["Name"] == doc_name, f"expected document {doc_name!r}, got {described['Name']!r}"
    assert described["AssociationVersion"] == "1", f"expected version 1 on describe, got {described['AssociationVersion']!r}"
    assert described["ScheduleExpression"] == "rate(30 days)", f"expected 'rate(30 days)', got {described['ScheduleExpression']!r}"

    updated = ssm.update_association(
        AssociationId=assoc_id, ScheduleExpression="rate(15 days)"
    )["AssociationDescription"]
    assert updated["AssociationVersion"] == "2", f"expected version 2 after update, got {updated['AssociationVersion']!r}"
    assert updated["ScheduleExpression"] == "rate(15 days)", f"expected 'rate(15 days)', got {updated['ScheduleExpression']!r}"

    versions = ssm.list_association_versions(AssociationId=assoc_id)["AssociationVersions"]
    version_numbers = sorted(v["AssociationVersion"] for v in versions)
    assert version_numbers == ["1", "2"], version_numbers
    v2 = next(v for v in versions if v["AssociationVersion"] == "2")
    assert v2["ScheduleExpression"] == "rate(15 days)", f"version 2 should carry 'rate(15 days)', got {v2['ScheduleExpression']!r}"
    v1 = next(v for v in versions if v["AssociationVersion"] == "1")
    assert v1["ScheduleExpression"] == "rate(30 days)", f"version 1 should still carry 'rate(30 days)', got {v1['ScheduleExpression']!r}"

    ssm.delete_association(AssociationId=assoc_id)

    # DescribeAssociation is backed by an eventually-consistent index; immediately
    # after DeleteAssociation it may briefly still report the (deleted)
    # association rather than AssociationDoesNotExist. Poll for the deletion to
    # become visible.
    gone = f"Association {assoc_id} does not exist."
    code, message = _poll_error(
        lambda: ssm.describe_association(AssociationId=assoc_id), "AssociationDoesNotExist"
    )
    assert code == "AssociationDoesNotExist", f"expected AssociationDoesNotExist from describe after delete, got {code!r}"
    assert message == gone, f"DescribeAssociation message: {message!r}"

    # The dead id must also be unusable, not just unreadable: a mutation against
    # it fails with the same not-found code rather than resurrecting the record.
    mutate_code, mutate_message = _error(
        lambda: ssm.update_association(AssociationId=assoc_id, ScheduleExpression="rate(1 days)")
    )
    assert mutate_code == "AssociationDoesNotExist", f"expected AssociationDoesNotExist from update on deleted id, got {mutate_code!r}"
    assert mutate_message == gone, f"UpdateAssociation message: {mutate_message!r}"


def _create_command_document(ctx) -> str:
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-ssm-doc-")
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
        Tags=[{"Key": "sim2real-behav-probe", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
    return name


def _delete_association_if_exists(ssm, assoc_id: str) -> None:
    try:
        ssm.delete_association(AssociationId=assoc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "AssociationDoesNotExist":
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded: {result!r}")


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
