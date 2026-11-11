"""operation-not-found-error."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "operation-not-found-error"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A random OperationId fails with OperationNotFoundException and its exact message on four
    stack-set operation calls (Describe, Stop, ListResults, ListStackInstanceResourceDrifts),
    while a completed operation's id is SUCCEEDED with no results."""
    cfn = ctx.client("cloudformation")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]
    stackset_name = ctx.unique_name("sim2real-opnotfound-")
    template = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})

    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": stackset_name}],
    )
    ctx.on_cleanup(lambda: _swallow(lambda: cfn.delete_stack_set(StackSetName=stackset_name)))

    # Positive control: a real, completed operation on this stack set, so "rejects an
    # unknown OperationId" is told apart from "rejects every OperationId".
    real_template = json.dumps(
        {
            "Resources": {
                "Topic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"DisplayName": stackset_name[:100]},
                }
            }
        }
    )
    real_op = cfn.update_stack_set(StackSetName=stackset_name, TemplateBody=real_template)[
        "OperationId"
    ]
    real_status = _wait_terminal(cfn, stackset_name, real_op)
    assert real_status == "SUCCEEDED", (
        f"positive-control UpdateStackSet ended as {real_status!r}, expected SUCCEEDED"
    )

    real_describe = cfn.describe_stack_set_operation(
        StackSetName=stackset_name, OperationId=real_op
    )["StackSetOperation"]
    assert real_describe["Status"] == "SUCCEEDED", (
        f"DescribeStackSetOperation(OperationId=<real>) returned {real_describe!r}"
    )

    real_results = cfn.list_stack_set_operation_results(
        StackSetName=stackset_name, OperationId=real_op
    )["Summaries"]
    assert real_results == [], (
        f"ListStackSetOperationResults(OperationId=<real>) on an instance-less stack "
        f"set returned {real_results!r}, expected an empty list"
    )

    bogus_op = str(uuid.uuid4())
    checks = [
        (
            "DescribeStackSetOperation",
            "Operation not found",
            lambda: cfn.describe_stack_set_operation(
                StackSetName=stackset_name, OperationId=bogus_op
            ),
        ),
        (
            "ListStackSetOperationResults",
            "Operation not found",
            lambda: cfn.list_stack_set_operation_results(
                StackSetName=stackset_name, OperationId=bogus_op
            ),
        ),
        (
            "StopStackSetOperation",
            "Operation not found",
            lambda: cfn.stop_stack_set_operation(
                StackSetName=stackset_name, OperationId=bogus_op
            ),
        ),
        (
            "ListStackInstanceResourceDrifts",
            "Detect Drift Operation not found",
            lambda: cfn.list_stack_instance_resource_drifts(
                StackSetName=stackset_name,
                StackInstanceAccount=account,
                StackInstanceRegion=ctx.region,
                OperationId=bogus_op,
            ),
        ),
    ]
    for label, expected, fn in checks:
        code, message = _error(fn)
        assert code == "OperationNotFoundException", (
            f"{label}(OperationId=<unknown>): expected OperationNotFoundException, got {code!r}"
        )
        assert message == expected, (
            f"{label}(OperationId=<unknown>): expected message {expected!r}, got {message!r}"
        )


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises; raise on success."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected a ClientError for an unknown OperationId, call succeeded")


def _wait_terminal(cfn, stackset_name, op_id, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stack_set_operation(
            StackSetName=stackset_name, OperationId=op_id
        )["StackSetOperation"]["Status"]
        if status in ("SUCCEEDED", "FAILED", "STOPPED"):
            return status
        time.sleep(5)
    raise AssertionError(
        f"stack set operation {op_id} did not reach a terminal state within {timeout_s}s "
        f"(last={status!r})"
    )


def _swallow(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackSetNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
