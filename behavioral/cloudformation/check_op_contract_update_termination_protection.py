"""op-contract-updateTerminationProtection."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-updateTerminationProtection"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]

_BUCKET_TEMPLATE = json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}})


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With termination protection enabled (DescribeStacks reports it), DeleteStack fails with ValidationError
    "...cannot be deleted while TerminationProtection is enabled" and the stack stays CREATE_COMPLETE; once
    disabled, DeleteStack removes it and UpdateTerminationProtection reports it does not exist."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-termprotect-")

    created = cfn.create_stack(StackName=stack_name, TemplateBody=_BUCKET_TEMPLATE)
    ctx.on_cleanup(lambda: _disable_and_delete(ctx, stack_name))
    _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})

    resp = cfn.update_termination_protection(StackName=stack_name, EnableTerminationProtection=True)
    assert resp["StackId"] == created["StackId"], (
        f"expected UpdateTerminationProtection to echo the stack id {created['StackId']!r}, got {resp['StackId']!r}"
    )

    described = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert described["EnableTerminationProtection"] is True, (
        f"expected EnableTerminationProtection True after enabling, got {described['EnableTerminationProtection']!r}"
    )

    code, message = _error(lambda: cfn.delete_stack(StackName=stack_name))
    assert code == "ValidationError", (
        f"expected DeleteStack to be rejected with ValidationError while protection is enabled, got {code}"
    )
    expected = f"Stack [{stack_name}] cannot be deleted while TerminationProtection is enabled"
    assert message == expected, f"expected DeleteStack refusal message {expected!r}, got {message!r}"

    still_there = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert still_there["StackStatus"] == "CREATE_COMPLETE", (
        f"stack should be untouched after the blocked delete, got {still_there['StackStatus']}"
    )

    cfn.update_termination_protection(StackName=stack_name, EnableTerminationProtection=False)
    described2 = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert described2["EnableTerminationProtection"] is False, (
        f"expected EnableTerminationProtection False after disabling, got {described2['EnableTerminationProtection']!r}"
    )

    # Positive control: the identical DeleteStack call now succeeds once protection is
    # off, proving the earlier rejection was the protection and not a broken DeleteStack
    # path. The terminal read is independent (DescribeStacks) and proves the stack gone.
    cfn.delete_stack(StackName=stack_name)
    final_status, final_code = _wait_for_deletion(ctx, stack_name)
    assert final_status == "DELETE_COMPLETE" or final_code == "ValidationError", (
        "expected the now-unprotected stack to actually delete: either DescribeStacks "
        f"reports DELETE_COMPLETE or a by-name lookup reports ValidationError once gone, "
        f"got status={final_status!r} code={final_code!r}"
    )

    dead_code, dead_message = _error(
        lambda: cfn.update_termination_protection(StackName=stack_name, EnableTerminationProtection=True)
    )
    assert dead_code == "ValidationError", (
        f"expected UpdateTerminationProtection on the deleted stack to fail with ValidationError, got {dead_code}"
    )
    expected_dead = f"Stack [{stack_name}] does not exist"
    assert dead_message == expected_dead, (
        f"expected UpdateTerminationProtection refusal message {expected_dead!r}, got {dead_message!r}"
    )


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator accepting a call real AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


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


def _wait_for_deletion(ctx, stack_name, timeout_s=180.0, interval_s=3.0):
    """Poll DescribeStacks-by-name until the stack reaches DELETE_COMPLETE or the
    name lookup itself starts failing (both are how CFN expresses "gone"); return
    (last_status, last_error_code)."""
    from botocore.exceptions import ClientError

    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as e:
            return last_status, e.response["Error"]["Code"]
        if last_status == "DELETE_COMPLETE":
            return last_status, None
        if last_status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} reached DELETE_FAILED while deleting")
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name} did not disappear from DescribeStacks within {timeout_s}s (last={last_status})"
    )


def _disable_and_delete(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    try:
        cfn.update_termination_protection(StackName=stack_name, EnableTerminationProtection=False)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
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
