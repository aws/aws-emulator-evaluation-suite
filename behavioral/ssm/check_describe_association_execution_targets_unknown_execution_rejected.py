"""describe-association-execution-targets-unknown-execution-rejected."""
from __future__ import annotations

import json
import time
import uuid


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-association-execution-targets-unknown-execution-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]

# A well-formed instance id that no node registers: the association runs on no instance.
_UNREGISTERED_INSTANCE_ID = "i-" + "0" * 17


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAssociationExecutionTargets with the check's AssociationId and an unknown ExecutionId
    returns an empty AssociationExecutionTargets list, while an unknown AssociationId fails with
    AssociationDoesNotExist with the exact message "Association <id> does not exist." for that id."""
    ssm = ctx.client("ssm")
    doc_name = ctx.unique_name("sim2real-ssm-doc-")
    content = json.dumps(
        {
            "schemaVersion": "2.2",
            "description": "no-op command document for association targeting",
            "mainSteps": [
                {
                    "action": "aws:runShellScript",
                    "name": "noop",
                    "inputs": {"runCommand": ["echo hi"]},
                }
            ],
        }
    )
    ssm.create_document(Content=content, Name=doc_name, DocumentType="Command")
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name))

    association_id = ssm.create_association(
        Name=doc_name, Targets=[{"Key": "InstanceIds", "Values": [_UNREGISTERED_INSTANCE_ID]}]
    )["AssociationDescription"]["AssociationId"]
    ctx.on_cleanup(lambda: ssm.delete_association(AssociationId=association_id))

    # Positive control: the real association resolves fine.
    described = ssm.describe_association(AssociationId=association_id)
    assert described["AssociationDescription"]["AssociationId"] == association_id

    # Force a real execution to exist so the association has genuine execution
    # history (an association with zero executions ever recorded returns an empty
    # target list for any ExecutionId rather than raising).
    ssm.start_associations_once(AssociationIds=[association_id])

    def _list_executions():
        return ssm.describe_association_executions(AssociationId=association_id).get(
            "AssociationExecutions", []
        )

    executions = _poll_until(
        _list_executions,
        lambda execs: len(execs) > 0,
        timeout_s=90.0,
        description="a real association execution",
    )
    real_execution_id = executions[0]["ExecutionId"]

    # Positive control: the real execution ID resolves fine.
    real_targets = ssm.describe_association_execution_targets(
        AssociationId=association_id, ExecutionId=real_execution_id
    )
    assert "AssociationExecutionTargets" in real_targets

    # A well-formed but nonexistent ExecutionId against a VALID association does not
    # raise -- it resolves to an empty target list (AssociationExecutionDoesNotExist
    # is reserved for AssociationId-level validation problems, not per-execution
    # lookups within a known-good association).
    fake_execution_id = str(uuid.uuid4())
    unknown_execution_result = ssm.describe_association_execution_targets(
        AssociationId=association_id, ExecutionId=fake_execution_id
    )
    assert unknown_execution_result["AssociationExecutionTargets"] == [], (
        "expected an unknown ExecutionId against a valid association to resolve to "
        f"an empty target list, got {unknown_execution_result['AssociationExecutionTargets']}"
    )

    fake_association_id = str(uuid.uuid4())

    def _unknown_association():
        ssm.describe_association_execution_targets(
            AssociationId=fake_association_id, ExecutionId=fake_execution_id
        )

    assoc_code, assoc_message = _error(_unknown_association)
    assert assoc_code == "AssociationDoesNotExist", (
        f"expected AssociationDoesNotExist, got {assoc_code}"
    )
    assert assoc_message == f"Association {fake_association_id} does not exist.", assoc_message


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(
        f"expected a ClientError, but the call succeeded and returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not observed within {timeout_s}s; last saw {value!r}"
            )
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

