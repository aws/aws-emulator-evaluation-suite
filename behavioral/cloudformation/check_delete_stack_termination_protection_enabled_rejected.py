"""delete-stack-termination-protection-enabled-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-stack-termination-protection-enabled-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudformation"]

_TEMPLATE = json.dumps({"Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStack on a stack with termination protection enabled is rejected -- the
    protection can't be bypassed by simply calling delete -- while disabling protection first
    (UpdateTerminationProtection) lets the identical DeleteStack call succeed."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-cfn-termprot-")

    created = cfn.create_stack(StackName=name, TemplateBody=_TEMPLATE, EnableTerminationProtection=True)
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _safe_disable_and_delete(ctx, stack_id))
    _wait_stack_status(ctx, stack_id, {"CREATE_COMPLETE"})

    got = _expect_error(lambda: cfn.delete_stack(StackName=name))
    expected = ("ValidationError", f"Stack [{name}] cannot be deleted while TerminationProtection is enabled")
    assert got == expected, f"deleting a protected stack: expected {expected!r}, got {got!r}"

    # (b) effect absent: stack is untouched and still protected
    stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {stack['StackStatus']}"
    )
    assert stack["EnableTerminationProtection"] is True, (
        "expected termination protection to remain enabled after the rejected delete"
    )

    # (c) positive control: disable protection, then the identical delete call succeeds
    cfn.update_termination_protection(StackName=name, EnableTerminationProtection=False)
    cfn.delete_stack(StackName=name)
    _wait_stack_status(ctx, stack_id, {"DELETE_COMPLETE"})


def _expect_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _safe_disable_and_delete(ctx, stack_id):
    cfn = ctx.client("cloudformation")
    try:
        cfn.update_termination_protection(StackName=stack_id, EnableTerminationProtection=False)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
    try:
        cfn.delete_stack(StackName=stack_id)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _wait_stack_status(ctx, stack_id, terminal_statuses, timeout_s=180.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_id)["Stacks"]
        last = stacks[0]["StackStatus"]
        if last in terminal_statuses:
            return last
        if last not in terminal_statuses and (last.endswith("FAILED") or "ROLLBACK" in last):
            raise AssertionError(f"stack {stack_id} entered unexpected status {last}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_id} never reached {terminal_statuses}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
