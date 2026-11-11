"""stackset-operation-not-found-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stackset-operation-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopStackSetOperation, DescribeStackSetOperation and ListStackSetOperationResults with a never-issued
    OperationId on an existing stack set fail with OperationNotFoundException "Operation not found", while
    the id of a real UpdateStackSet operation on it is not answered with that code."""
    cfn = ctx.client("cloudformation")
    stack_set_name = ctx.unique_name("sim2real-ss-opnf-")
    template = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})
    cfn.create_stack_set(StackSetName=stack_set_name, TemplateBody=template)
    ctx.on_cleanup(lambda: _safe_delete_stack_set(cfn, stack_set_name))

    real_op_id = cfn.update_stack_set(
        StackSetName=stack_set_name,
        TemplateBody=template,
        Description="sim2real-opnf-real-op",
    )["OperationId"]

    real_describe = cfn.describe_stack_set_operation(
        StackSetName=stack_set_name, OperationId=real_op_id
    )["StackSetOperation"]
    assert real_describe["OperationId"] == real_op_id, (
        f"DescribeStackSetOperation(OperationId=<real>) returned operation "
        f"{real_describe.get('OperationId')!r}, expected {real_op_id!r}"
    )

    real_results = cfn.list_stack_set_operation_results(
        StackSetName=stack_set_name, OperationId=real_op_id
    )
    assert "Summaries" in real_results, f"ListStackSetOperationResults(OperationId=<real>) missing Summaries: {real_results}"

    try:
        cfn.stop_stack_set_operation(StackSetName=stack_set_name, OperationId=real_op_id)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] != "OperationNotFoundException", (
            f"StopStackSetOperation(OperationId=<real>) returned OperationNotFoundException; "
            f"cannot distinguish 'unknown id rejected' from 'every id rejected'"
        )

    bogus_op_id = str(uuid.uuid4())

    checks = [
        ("StopStackSetOperation", lambda: cfn.stop_stack_set_operation(StackSetName=stack_set_name, OperationId=bogus_op_id)),
        (
            "DescribeStackSetOperation",
            lambda: cfn.describe_stack_set_operation(StackSetName=stack_set_name, OperationId=bogus_op_id),
        ),
        (
            "ListStackSetOperationResults",
            lambda: cfn.list_stack_set_operation_results(StackSetName=stack_set_name, OperationId=bogus_op_id),
        ),
    ]
    expected = ("OperationNotFoundException", "Operation not found")
    for label, fn in checks:
        error = _error(fn)
        assert error == expected, f"{label} returned {error!r}, expected {expected!r}"


def _error(fn):
    """(Error.Code, Error.Message) of the rejection fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe_delete_stack_set(cfn, stack_set_name, timeout_s=900.0):
    """DeleteStackSet is refused with OperationInProgressException while the stopped update
    settles; retry that refusal every 2 s to a deadline. A missing stack set is gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cfn.delete_stack_set(StackSetName=stack_set_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "StackSetNotFoundException":
                return
            if code != "OperationInProgressException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
