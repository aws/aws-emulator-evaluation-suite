"""describe-association-execution-targets-nonexistent-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-association-execution-targets-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, so an
    emulator that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAssociationExecutionTargets for a never-created AssociationId fails with
    AssociationDoesNotExist "Association <id> does not exist.", while the same ExecutionId on the
    check's real association returns an empty target list."""
    ssm = ctx.client("ssm")
    fake_instance_id = "i-" + "0" * 17

    created = ssm.create_association(
        Name="AWS-UpdateSSMAgent",
        Targets=[{"Key": "InstanceIds", "Values": [fake_instance_id]}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["AssociationDescription"]
    association_id = created["AssociationId"]
    ctx.on_cleanup(lambda: ssm.delete_association(AssociationId=association_id))

    execution_id = _wait_for_execution_id(ssm, association_id)
    assert execution_id is not None, "no execution landed for the association within timeout"

    bogus_association_id = str(uuid.uuid4())
    assert bogus_association_id != association_id, "fabricated id collided with the real one"
    code, message = _error(
        lambda: ssm.describe_association_execution_targets(
            AssociationId=bogus_association_id, ExecutionId=execution_id
        )
    )
    assert code == "AssociationDoesNotExist", code
    assert message == f"Association {bogus_association_id} does not exist.", message

    # Positive control: the exact same ExecutionId, queried against the real, existing
    # association it actually belongs to, is accepted by the identical call shape rather
    # than raising -- a never-registered instance id
    # produces no delivered execution target (the target never resolves), so the
    # discriminator from the negative case above is raise-vs-no-raise plus the specific
    # error code, not the payload content.
    resp = ssm.describe_association_execution_targets(
        AssociationId=association_id, ExecutionId=execution_id
    )
    assert resp["AssociationExecutionTargets"] == [], (
        "expected a never-registered instance id to leave the execution with no delivered "
        f"targets, got {resp['AssociationExecutionTargets']!r}"
    )


def _wait_for_execution_id(ssm, association_id, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        executions = ssm.describe_association_executions(AssociationId=association_id)[
            "AssociationExecutions"
        ]
        if executions:
            return executions[0]["ExecutionId"]
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
