"""deleted-stack-id-still-reports-delete-complete-after-name-reused."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleted-stack-id-still-reports-delete-complete-after-name-reused"
GROUP = "negative-classes"
SERVICES = ["cloudformation"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  Label:
    Type: String
Resources:
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: !Ref Label
"""

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


def _wait_terminal(cfn, stack_id, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_id} did not reach a terminal status within {timeout_s}s (last={status!r})"
    )


def _delete_and_wait(cfn, stack_id) -> None:
    cfn.delete_stack(StackName=stack_id)
    status = _wait_terminal(cfn, stack_id)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}, expected DELETE_COMPLETE")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A deleted stack's StackId refuses UpdateStack and CreateChangeSet(UPDATE) with the same
    ValidationError before and after its NAME is reused, while DescribeStacks by that id keeps
    reporting DELETE_COMPLETE; the identical UpdateStack against the reused name succeeds.
    """
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-cfn-genid-")

    first = cfn.create_stack(
        StackName=name, TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "Label", "ParameterValue": "first-gen"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    dead_id = first["StackId"]
    ctx.on_cleanup(lambda: _delete_and_wait(cfn, dead_id))
    status = _wait_terminal(cfn, dead_id)
    assert status == "CREATE_COMPLETE", f"first stack ended {status!r}, expected CREATE_COMPLETE"

    _delete_and_wait(cfn, dead_id)
    refusal = (
        "ValidationError",
        f"Stack:{dead_id} is in DELETE_COMPLETE state and can not be updated.",
    )

    # Refused before the name is reused.
    expect_error(
        lambda: cfn.update_stack(
            StackName=dead_id, TemplateBody=_TEMPLATE,
            Parameters=[{"ParameterKey": "Label", "ParameterValue": "after-delete"}],
        ),
        *refusal,
    )
    expect_error(
        lambda: cfn.create_change_set(
            StackName=dead_id, ChangeSetName=ctx.unique_name("sim2real-behav-cfn-genid-cs1-"),
            ChangeSetType="UPDATE", TemplateBody=_TEMPLATE,
            Parameters=[{"ParameterKey": "Label", "ParameterValue": "after-delete"}],
        ),
        *refusal,
        undo=lambda created: ctx.on_cleanup(
            lambda: cfn.delete_change_set(ChangeSetName=created["Id"])
        ),
    )
    before_reuse = cfn.describe_stacks(StackName=dead_id)["Stacks"][0]["StackStatus"]
    assert before_reuse == "DELETE_COMPLETE", (
        f"DescribeStacks(stale id) reported {before_reuse!r} before the name was reused, "
        f"expected DELETE_COMPLETE"
    )

    # The name is reused by a brand-new, live stack.
    second = cfn.create_stack(
        StackName=name, TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "Label", "ParameterValue": "second-gen"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    live_id = second["StackId"]
    assert live_id != dead_id, "the stack created under the reused name must mint a fresh StackId"
    ctx.on_cleanup(lambda: _delete_and_wait(cfn, live_id))
    status = _wait_terminal(cfn, live_id)
    assert status == "CREATE_COMPLETE", f"second stack ended {status!r}, expected CREATE_COMPLETE"

    # Refused identically after the name is reused.
    expect_error(
        lambda: cfn.update_stack(
            StackName=dead_id, TemplateBody=_TEMPLATE,
            Parameters=[{"ParameterKey": "Label", "ParameterValue": "after-reuse"}],
        ),
        *refusal,
    )
    expect_error(
        lambda: cfn.create_change_set(
            StackName=dead_id, ChangeSetName=ctx.unique_name("sim2real-behav-cfn-genid-cs2-"),
            ChangeSetType="UPDATE", TemplateBody=_TEMPLATE,
            Parameters=[{"ParameterKey": "Label", "ParameterValue": "after-reuse"}],
        ),
        *refusal,
        undo=lambda created: ctx.on_cleanup(
            lambda: cfn.delete_change_set(ChangeSetName=created["Id"])
        ),
    )

    # DescribeStacks by the deleted id still answers DELETE_COMPLETE while a live stack holds
    # its name.
    after_reuse = cfn.describe_stacks(StackName=dead_id)["Stacks"][0]["StackStatus"]
    assert after_reuse == "DELETE_COMPLETE", (
        f"DescribeStacks(stale id) reported {after_reuse!r} after the name was reused, "
        f"expected DELETE_COMPLETE"
    )

    # Positive control: the identical UpdateStack call, against the reused NAME, succeeds and
    # reports the live generation's StackId.
    update_resp = cfn.update_stack(
        StackName=name, TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "Label", "ParameterValue": "updated"}],
    )
    assert update_resp["StackId"] == live_id, (
        f"UpdateStack(reused name) reported StackId {update_resp['StackId']!r}, expected the "
        f"live generation's {live_id!r}"
    )
    status = _wait_terminal(cfn, live_id)
    assert status == "UPDATE_COMPLETE", f"positive control update ended {status!r}, expected UPDATE_COMPLETE"

    live_stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    assert live_stack["StackId"] == live_id, "DescribeStacks(reused name) diverged from the live id"
    assert live_stack["StackStatus"] == "UPDATE_COMPLETE"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
