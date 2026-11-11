"""stack-rollback-after-create-failed-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-rollback-after-create-failed-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """RollbackStack takes a CREATE_FAILED stack (DisableRollback, a SecureString AWS::SSM::Parameter, which
    CloudFormation cannot create) to ROLLBACK_COMPLETE, after which DescribeStackResource fails with
    ValidationError "Resource BadParam does not exist for stack <name>"."""
    cfn = ctx.client("cloudformation")

    stack_name = ctx.unique_name("sim2real-rollbackstack-")
    template = {
        "Resources": {
            "BadParam": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Type": "SecureString", "Value": "unsupported-by-cfn"},
            }
        }
    }
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        DisableRollback=True,
    )
    ctx.on_cleanup(lambda: _safe(lambda: cfn.delete_stack(StackName=stack_name)))

    failed_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("CREATE_FAILED", "CREATE_COMPLETE"),
        timeout_s=120.0,
        interval_s=4.0,
    )
    assert failed_status == "CREATE_FAILED", (
        f"expected CREATE_FAILED (DisableRollback=True), got {failed_status}"
    )

    cfn.rollback_stack(StackName=stack_name)

    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("ROLLBACK_COMPLETE", "ROLLBACK_FAILED"),
        timeout_s=120.0,
        interval_s=4.0,
    )
    assert final_status == "ROLLBACK_COMPLETE", (
        f"RollbackStack ended in {final_status}, expected ROLLBACK_COMPLETE"
    )

    # DescribeStackResource is an independent read at a different operation than the
    # rollback itself; CloudFormation rejects SecureString up front (no resource-level
    # CREATE_IN_PROGRESS event is ever emitted for BadParam), so a target that instead
    # let BadParam reach CREATE_COMPLETE would answer this call, not raise on it.
    try:
        cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId="BadParam")
    except ClientError as exc:
        error = exc.response["Error"]
        assert error["Code"] == "ValidationError", (
            f"expected a ValidationError naming BadParam as not existing on the rolled-back stack, got {error}"
        )
        assert error["Message"] == f"Resource BadParam does not exist for stack {stack_name}", error
    else:
        raise AssertionError(
            "BadParam should never exist: SecureString creation was rejected before rollback"
        )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
