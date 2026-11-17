"""execute-stack-refactor-rejects-re-execution-once-complete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execute-stack-refactor-rejects-re-execution-once-complete"
GROUP = "stack-refactoring"
SERVICES = ["cloudformation"]


def _template(topic_logical_id: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {topic_logical_id: {"Type": "AWS::SNS::Topic", "Properties": {}}},
    })


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_stack(cfn, stack_name, terminal, timeout_s=240.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name!r} did not reach {terminal} in {timeout_s}s (last={last!r})")


def _wait_refactor(cfn, refactor_id, key, terminal, timeout_s=300.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stack_refactor(StackRefactorId=refactor_id)[key]
        if last in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack refactor {refactor_id!r} did not reach {key}={terminal} in {timeout_s}s (last={last!r})"
    )


def _delete_stack(cfn, stack_name, *, timeout_s=120.0, interval_s=3.0):
    """DeleteStack, retrying while the stack is still settling from its refactor."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cfn.delete_stack(StackName=stack_name)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            message = err.get("Message", "")
            if err["Code"] == "ValidationError" and "does not exist" in message:
                return
            if err["Code"] == "ValidationError" and "in-progress stack refactor" in message:
                if time.monotonic() > deadline:
                    raise
                time.sleep(interval_s)
                continue
            raise
    _wait_deleted(cfn, stack_name, timeout_s=240.0)


def _wait_deleted(cfn, stack_name, *, timeout_s=240.0, interval_s=3.0):
    """Poll until the stack is DELETE_COMPLETE or no longer resolvable by name at all."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "does not exist" in err.get("Message", ""):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_name!r} still {status!r} {timeout_s}s after DeleteStack")
        time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A stack refactor already EXECUTE_COMPLETE rejects a second ExecuteStackRefactor call;
    the renamed resource is unaffected and the refactor's execution status stays unchanged."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-refactor-reexec-")
    old_id, new_id = "TopicOld", "TopicNew"

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(old_id),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    created = _wait_stack(cfn, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})
    assert created == "CREATE_COMPLETE", f"prerequisite stack {stack_name!r} reached {created!r}"

    old_arn = cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId=old_id
    )["StackResourceDetail"]["PhysicalResourceId"]

    refactor_id = cfn.create_stack_refactor(
        StackDefinitions=[{"StackName": stack_name, "TemplateBody": _template(new_id)}],
        ResourceMappings=[{
            "Source": {"StackName": stack_name, "LogicalResourceId": old_id},
            "Destination": {"StackName": stack_name, "LogicalResourceId": new_id},
        }],
    )["StackRefactorId"]
    status = _wait_refactor(cfn, refactor_id, "Status", {"CREATE_COMPLETE", "CREATE_FAILED"})
    assert status == "CREATE_COMPLETE", f"stack refactor {refactor_id!r} ended {status!r} before execution"

    # POSITIVE CONTROL: the first ExecuteStackRefactor succeeds and the rename takes effect.
    cfn.execute_stack_refactor(StackRefactorId=refactor_id)
    exec_status = _wait_refactor(
        cfn, refactor_id, "ExecutionStatus", {"EXECUTE_COMPLETE", "EXECUTE_FAILED"}
    )
    assert exec_status == "EXECUTE_COMPLETE", f"first execution ended {exec_status!r}"

    renamed_arn = cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId=new_id
    )["StackResourceDetail"]["PhysicalResourceId"]
    assert renamed_arn == old_arn, (
        f"the renamed logical id's physical resource {renamed_arn!r} must still be the original "
        f"topic {old_arn!r}"
    )
    gone_code, _ = _error(
        lambda: cfn.describe_stack_resource(StackName=stack_name, LogicalResourceId=old_id)
    )
    assert gone_code == "ValidationError", (
        f"the old logical id must no longer resolve after the rename, got {gone_code!r}"
    )

    # ONE thing broken: executing the SAME refactor a second time, after it is already complete.
    code, message = _error(lambda: cfn.execute_stack_refactor(StackRefactorId=refactor_id))
    assert code == "ValidationError", (
        f"expected ValidationError re-executing a completed stack refactor, got {code}: {message!r}"
    )
    assert message == (
        f"Cannot execute stack refactor [{refactor_id}] as its execution status is [EXECUTE_COMPLETE]"
    ), f"unexpected message for a re-executed stack refactor: {message!r}"

    # The effect of the re-execution attempt is absent: status and physical resource unchanged.
    still_complete = cfn.describe_stack_refactor(StackRefactorId=refactor_id)["ExecutionStatus"]
    assert still_complete == "EXECUTE_COMPLETE", (
        f"ExecutionStatus must stay EXECUTE_COMPLETE after the rejected re-execution, got {still_complete!r}"
    )
    unaffected_arn = cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId=new_id
    )["StackResourceDetail"]["PhysicalResourceId"]
    assert unaffected_arn == old_arn, (
        f"the rejected re-execution must not touch the resource; got {unaffected_arn!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
