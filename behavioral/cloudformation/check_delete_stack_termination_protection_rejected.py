"""delete-stack-termination-protection-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-stack-termination-protection-rejected"
GROUP = "termination_protection"
SERVICES = ["cloudformation"]

_TEMPLATE = """{
  "Resources": {
    "Handle": {
      "Type": "AWS::CloudFormation::WaitConditionHandle"
    }
  }
}"""


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStack on a stack with termination protection enabled is rejected with
    ValidationError, the stack is left completely untouched, and disabling
    protection then lets the identical DeleteStack call succeed (positive control)."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-cfn-termprot-")

    create = cfn.create_stack(StackName=name, TemplateBody=_TEMPLATE)
    stack_id = create["StackId"]
    ctx.on_cleanup(lambda: _ensure_deletable_and_delete(cfn, name))

    _wait_for_status(cfn, name, {"CREATE_COMPLETE"}, timeout_s=120)

    cfn.update_termination_protection(StackName=name, EnableTerminationProtection=True)

    got = _expect_error(lambda: cfn.delete_stack(StackName=name))
    expected = ("ValidationError", f"Stack [{name}] cannot be deleted while TerminationProtection is enabled")
    assert got == expected, f"deleting a protected stack: expected {expected!r}, got {got!r}"

    # Effect is absent: the stack is still there, unchanged, still protected.
    stacks = cfn.describe_stacks(StackName=name)["Stacks"]
    assert len(stacks) == 1, f"expected exactly one stack named {name!r}, got {len(stacks)}"
    assert stacks[0]["StackId"] == stack_id, f"expected StackId {stack_id!r}, got {stacks[0]['StackId']!r}"
    assert stacks[0]["StackStatus"] == "CREATE_COMPLETE", (
        f"expected status CREATE_COMPLETE (untouched by the rejected delete), got {stacks[0]['StackStatus']!r}"
    )
    assert stacks[0]["EnableTerminationProtection"] is True, (
        "expected EnableTerminationProtection to remain True after the rejected delete, "
        f"got {stacks[0]['EnableTerminationProtection']!r}"
    )

    # Positive control: the identical DeleteStack call succeeds once protection is off.
    cfn.update_termination_protection(StackName=name, EnableTerminationProtection=False)
    cfn.delete_stack(StackName=name)
    _wait_for_status(cfn, name, {"DELETE_COMPLETE"}, timeout_s=180, allow_missing=True)


def _expect_error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_status(cfn, name, ok_statuses, timeout_s=120.0, allow_missing=False):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=name)["Stacks"]
        except ClientError:
            if allow_missing:
                return
            time.sleep(2)
            continue
        if stacks:
            last = stacks[0]["StackStatus"]
            if last in ok_statuses:
                return
        time.sleep(2)
    raise AssertionError(f"stack {name} never reached {ok_statuses}, last status={last}")


def _ensure_deletable_and_delete(cfn, name) -> None:
    try:
        cfn.update_termination_protection(StackName=name, EnableTerminationProtection=False)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
