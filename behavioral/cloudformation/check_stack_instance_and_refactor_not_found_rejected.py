"""stack-instance-and-refactor-not-found-rejected."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-instance-and-refactor-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStackInstance fails with StackSetNotFoundException for an absent stack set and
    StackInstanceNotFoundException for an absent instance of a real one; ListStackInstanceResourceDrifts
    and DescribeStackRefactor fail with OperationNotFoundException and StackRefactorNotFoundException."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    stack_set_name = ctx.unique_name("sim2real-ss-instnf-")
    template = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})
    cfn.create_stack_set(
        StackSetName=stack_set_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_stack_set(cfn, stack_set_name))

    # Differential control: a stack set that was never created is reported as the stack
    # set being absent, not the instance, so the two not-found answers are told apart.
    missing_stack_set = ctx.unique_name("sim2real-ss-absent-")
    code0, msg0 = _error_code(
        lambda: cfn.describe_stack_instance(
            StackSetName=missing_stack_set, StackInstanceAccount=account_id, StackInstanceRegion=ctx.region
        )
    )
    assert code0 == "StackSetNotFoundException", (
        f"DescribeStackInstance on a never-created stack set: expected StackSetNotFoundException, got {code0!r}"
    )
    assert msg0 == f"StackSet {missing_stack_set} not found", msg0

    # No stack instances have ever been created for this (real, existing) stack set.
    code1, msg1 = _error_code(
        lambda: cfn.describe_stack_instance(
            StackSetName=stack_set_name, StackInstanceAccount=account_id, StackInstanceRegion=ctx.region
        )
    )
    assert code1 == "StackInstanceNotFoundException", (
        f"DescribeStackInstance on a real stack set with no instances: expected "
        f"StackInstanceNotFoundException, got {code1!r}"
    )
    assert msg1 == "StackInstance not found", msg1

    # ListStackInstanceResourceDrifts needs OperationId to name a real drift-detection
    # operation; CloudFormation checks that before the stack instance, so a never-issued
    # id surfaces OperationNotFoundException.
    bogus_op_id = str(uuid.uuid4())
    code2, msg2 = _error_code(
        lambda: cfn.list_stack_instance_resource_drifts(
            StackSetName=stack_set_name,
            StackInstanceAccount=account_id,
            StackInstanceRegion=ctx.region,
            OperationId=bogus_op_id,
        )
    )
    assert code2 == "OperationNotFoundException", (
        f"ListStackInstanceResourceDrifts with a never-issued OperationId: expected "
        f"OperationNotFoundException, got {code2!r}"
    )
    assert msg2 == "Detect Drift Operation not found", msg2

    bogus_refactor_id = str(uuid.uuid4())
    code3, msg3 = _error_code(lambda: cfn.describe_stack_refactor(StackRefactorId=bogus_refactor_id))
    assert code3 == "StackRefactorNotFoundException", (
        f"DescribeStackRefactor with a never-created StackRefactorId: expected "
        f"StackRefactorNotFoundException, got {code3!r}"
    )
    assert msg3 == f"Stack refactor [{bogus_refactor_id}] does not exist", msg3


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) from a raised ClientError. An
    unexpected success raises, so a target that accepts input AWS rejects fails as an
    acceptance rather than as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _safe_delete_stack_set(cfn, stack_set_name):
    try:
        cfn.delete_stack_set(StackSetName=stack_set_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
