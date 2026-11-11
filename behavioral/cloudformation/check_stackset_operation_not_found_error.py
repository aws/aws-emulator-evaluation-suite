"""stackset-operation-not-found-error."""
from __future__ import annotations

import json
import uuid

from behavioral_harness import tags

CHECK = "stackset-operation-not-found-error"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps(
    {
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {}},
        }
    }
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeStackSetOperation with a random operation id on an existing stack set fails with
    OperationNotFoundException "Operation not found", while a real operation on it is SUCCEEDED and
    listed by ListStackSetOperations, which never lists the random id."""
    cfn = ctx.client("cloudformation")
    stackset_name = ctx.unique_name("sim2real-behav-ss-")
    cfn.create_stack_set(
        StackSetName=stackset_name,
        TemplateBody=_TEMPLATE,
        PermissionModel="SELF_MANAGED",
    )
    ctx.on_cleanup(lambda: cfn.delete_stack_set(StackSetName=stackset_name))

    real_operation_id = cfn.update_stack_set(
        StackSetName=stackset_name, TemplateBody=_TEMPLATE
    )["OperationId"]
    real_status = _wait_operation(cfn, stackset_name, real_operation_id)
    assert real_status == "SUCCEEDED", (
        f"positive control: expected real OperationId {real_operation_id} to settle "
        f"SUCCEEDED, got {real_status}"
    )

    bogus_operation_id = str(uuid.uuid4())
    error = _error(
        lambda: cfn.describe_stack_set_operation(
            StackSetName=stackset_name, OperationId=bogus_operation_id
        )
    )
    expected = ("OperationNotFoundException", "Operation not found")
    assert error == expected, f"expected {expected!r}, got {error!r}"

    operation_ids = {
        op["OperationId"]
        for op in cfn.list_stack_set_operations(StackSetName=stackset_name)["Summaries"]
    }
    assert real_operation_id in operation_ids, (
        f"expected real OperationId {real_operation_id} to be enumerable, got {operation_ids}"
    )
    assert bogus_operation_id not in operation_ids, (
        f"unknown OperationId {bogus_operation_id} must never appear in ListStackSetOperations, "
        f"got {operation_ids}"
    )


def _error(fn):
    """(Error.Code, Error.Message) of the rejection fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_operation(cfn, stackset_name, operation_id, timeout_s=120.0, interval_s=3.0):
    import time

    def _status():
        return cfn.describe_stack_set_operation(
            StackSetName=stackset_name, OperationId=operation_id
        )["StackSetOperation"]["Status"]

    deadline = time.monotonic() + timeout_s
    result = _status()
    while result not in ("SUCCEEDED", "FAILED", "STOPPED"):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"OperationId {operation_id} did not settle within {timeout_s}s; last status={result}"
            )
        time.sleep(interval_s)
        result = _status()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
