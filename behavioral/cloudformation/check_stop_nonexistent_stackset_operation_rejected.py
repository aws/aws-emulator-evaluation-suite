"""stop-nonexistent-stackset-operation-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-nonexistent-stackset-operation-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopStackSetOperation and DescribeStackSetOperation for a never-issued OperationId fail with
    OperationNotFoundException "Operation not found", while StopStackSetOperation on a real
    OperationId of the same stack set never answers OperationNotFoundException."""
    cfn = ctx.client("cloudformation")
    stackset_name = ctx.unique_name("sim2real-behav-stopop-")
    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}}}),
        Tags=[{"Key": "sim2real-behav", "Value": "stop-nonexistent-stackset-operation-rejected"}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack_set(StackSetName=stackset_name))

    real_operation_id = cfn.update_stack_set(
        StackSetName=stackset_name,
        TemplateBody=json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": "positive-control"}}}}),
    )["OperationId"]
    try:
        cfn.stop_stack_set_operation(StackSetName=stackset_name, OperationId=real_operation_id)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] != "OperationNotFoundException", (
            f"stop_stack_set_operation on a real, existing OperationId {real_operation_id!r} "
            f"returned OperationNotFoundException -- this call cannot tell a real operation "
            f"from a bogus one"
        )

    bogus_operation_id = ctx.unique_name("nonexistent-op-")
    expected = ("OperationNotFoundException", "Operation not found")
    stop_error = _error(lambda: cfn.stop_stack_set_operation(
        StackSetName=stackset_name, OperationId=bogus_operation_id,
    ))
    assert stop_error == expected, f"expected {expected!r}, got {stop_error!r}"

    describe_error = _error(lambda: cfn.describe_stack_set_operation(
        StackSetName=stackset_name, OperationId=bogus_operation_id,
    ))
    assert describe_error == expected, (
        f"DescribeStackSetOperation on the same bogus id: expected {expected!r}, "
        f"got {describe_error!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the rejection fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
