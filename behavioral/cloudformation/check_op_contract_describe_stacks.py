"""op-contract-describeStacks."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-describeStacks"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_BUCKET_TEMPLATE = json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}})


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStacks(StackName=...) reports a created stack CREATE_COMPLETE and the unfiltered listing
    includes it; for a name that never existed, and for the stack once deleted, it fails with
    ValidationError "Stack with id <name> does not exist"."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-describestacks-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_BUCKET_TEMPLATE,
        Tags=[{"Key": "sim2real-check", "Value": "op-contract-describeStacks"}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackName"] == stack_name, f"expected StackName {stack_name}, got {stack['StackName']}"
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {stack['StackStatus']}"

    found = False
    token = None
    for _ in range(50):
        kwargs = {"NextToken": token} if token else {}
        page = cfn.describe_stacks(**kwargs)
        if any(s["StackName"] == stack_name for s in page["Stacks"]):
            found = True
            break
        token = page.get("NextToken")
        if not token:
            break
    assert found, f"stack {stack_name} not visible in unfiltered DescribeStacks listing"

    missing = ctx.unique_name("sim2real-cfn-missing-")
    code, message = _error(lambda: cfn.describe_stacks(StackName=missing))
    assert code == "ValidationError", f"expected ValidationError for unknown stack, got {code}"
    assert message == f"Stack with id {missing} does not exist", (
        f"unexpected ValidationError message {message!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    _wait_deleted(cfn, stack_name)
    code_after_delete, message_after_delete = _error(lambda: cfn.describe_stacks(StackName=stack_name))
    assert code_after_delete == "ValidationError", (
        f"expected ValidationError for deleted stack {stack_name}, got {code_after_delete}"
    )
    assert message_after_delete == f"Stack with id {stack_name} does not exist", (
        f"unexpected ValidationError message {message_after_delete!r}"
    )


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected success raises, so a target
    that accepts input AWS refuses fails as an acceptance rather than as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_for_stack_status(ctx, stack_name, terminal_statuses, timeout_s=180.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        last = resp["Stacks"][0]["StackStatus"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name} did not reach {terminal_statuses} in {timeout_s}s (last={last})"
    )


def _wait_deleted(cfn, stack_name, timeout_s=180.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
            if last == "DELETE_COMPLETE":
                return
            if last == "DELETE_FAILED":
                raise AssertionError(f"stack {stack_name} reached DELETE_FAILED")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ValidationError":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} not deleted within {timeout_s}s (last={last})")


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
