"""update-stack-duplicate-token-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-stack-duplicate-token-rejected"
GROUP = "concurrency"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a ClientRequestToken on a concurrent, differently-shaped UpdateStack while the
    first is UPDATE_IN_PROGRESS returns TokenAlreadyExistsException for the second call."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-updrej-")
    ctx.on_cleanup(lambda: _cleanup_stack(cfn, stack_name))

    base_template = json.dumps({
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
    })
    cfn.create_stack(StackName=stack_name, TemplateBody=base_template)
    _wait_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=180)

    slow_template = json.dumps({
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {}},
            "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Wait": {
                "Type": "AWS::CloudFormation::WaitCondition",
                "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "60", "Count": 1},
            },
        },
    })
    token = ctx.unique_name("tok-")
    cfn.update_stack(StackName=stack_name, TemplateBody=slow_template, ClientRequestToken=token)
    _wait_stack_status(cfn, stack_name, {"UPDATE_IN_PROGRESS"}, timeout_s=30)

    other_template = json.dumps({
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {}},
            "Topic2": {"Type": "AWS::SNS::Topic", "Properties": {}},
        },
    })
    stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    code, msg = _error_code_and_message(lambda: cfn.update_stack(
        StackName=stack_name, TemplateBody=other_template, ClientRequestToken=token,
    ))
    assert code == "TokenAlreadyExistsException", f"expected TokenAlreadyExistsException, got {code!r} ({msg!r})"
    expected_msg = (
        f"The client request token {token} has already been used for this stack. "
        "Retry the request with a different client request token"
    )
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Positive control: a THIRD concurrent UpdateStack, using a token that was never seen
    # before, is rejected too -- but for a different, state-based reason (the stack is busy),
    # not a token collision. Without this, "rejects the reused token" is indistinguishable
    # from "rejects any second UpdateStack while one is in flight, token or not".
    fresh_token = ctx.unique_name("tok-fresh-")
    control_code, control_msg = _error_code_and_message(lambda: cfn.update_stack(
        StackName=stack_name, TemplateBody=other_template, ClientRequestToken=fresh_token,
    ))
    assert control_code == "ValidationError", (
        f"a fresh (never-reused) token must be rejected as a busy-stack ValidationError, "
        f"not folded into the token-collision path: got {control_code!r} ({control_msg!r})"
    )
    expected_control = f"Stack:{stack_id} is in UPDATE_IN_PROGRESS state and can not be updated."
    assert control_msg == expected_control, (
        f"expected the busy-stack message {expected_control!r}, got {control_msg!r}"
    )

    # Independent read: neither rejected call actually mutated the stack -- Topic2 (only
    # present in other_template) must not exist.
    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    logical_ids = {r["LogicalResourceId"] for r in resources}
    assert "Topic2" not in logical_ids, f"a rejected UpdateStack must not apply: {logical_ids!r}"
    assert "Topic" in logical_ids, f"expected the original Topic resource, got {logical_ids!r}"


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, call succeeded with: {result!r}")


def _wait_stack_status(cfn, stack_name, ok_statuses, timeout_s=180, interval_s=3):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        if not stacks:
            raise AssertionError(f"stack {stack_name} disappeared while waiting for {ok_statuses}")
        status = stacks[0]["StackStatus"]
        if status in ok_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {ok_statuses}, last status={status}")


def _cleanup_stack(cfn, stack_name):
    try:
        cfn.cancel_update_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if not stacks:
            return
        if not stacks[0]["StackStatus"].endswith("IN_PROGRESS"):
            break
        time.sleep(3)
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if not stacks or stacks[0]["StackStatus"] == "DELETE_COMPLETE":
            return
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
