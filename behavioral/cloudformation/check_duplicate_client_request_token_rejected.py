"""duplicate-client-request-token-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-client-request-token-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """While CreateStack is in flight, UpdateStack reusing its ClientRequestToken fails with
    TokenAlreadyExistsException and its exact message, while UpdateStack with a fresh token fails with the
    state ValidationError instead; the rejected update adds no resource."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-token-")
    ctx.on_cleanup(lambda: _cleanup_stack(cfn, stack_name))

    # An unsignaled AWS::CloudFormation::WaitCondition keeps the stack in CREATE_IN_PROGRESS
    # for its Timeout, so the ClientRequestToken is reused against a still-running CreateStack.
    template = json.dumps(
        {
            "Resources": {
                "WaitHandle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
                "Wait": {
                    "Type": "AWS::CloudFormation::WaitCondition",
                    "Properties": {"Handle": {"Ref": "WaitHandle"}, "Timeout": "180"},
                },
            }
        }
    )
    control_template = json.dumps(
        {
            "Resources": {
                "WaitHandle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
                "Wait": {
                    "Type": "AWS::CloudFormation::WaitCondition",
                    "Properties": {"Handle": {"Ref": "WaitHandle"}, "Timeout": "180"},
                },
                "ControlTopic": {"Type": "AWS::SNS::Topic"},
            }
        }
    )
    update_template = json.dumps(
        {
            "Resources": {
                "WaitHandle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
                "Wait": {
                    "Type": "AWS::CloudFormation::WaitCondition",
                    "Properties": {"Handle": {"Ref": "WaitHandle"}, "Timeout": "180"},
                },
                "Topic2": {"Type": "AWS::SNS::Topic"},
            }
        }
    )

    token = str(uuid.uuid4())
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        ClientRequestToken=token,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]

    # Control: UpdateStack on the same in-flight stack with a fresh token gets the stack-state
    # error, not the token-collision error, so the collision below is caused by the token.
    control_code, control_msg = _client_error(
        lambda: cfn.update_stack(
            StackName=stack_name, TemplateBody=control_template, ClientRequestToken=str(uuid.uuid4())
        ),
        "UpdateStack with a fresh token while the create is in flight",
    )
    assert control_code == "ValidationError", (
        f"a FRESH token must hit the stack-state refusal, not a token collision, got {control_code!r}"
    )
    assert control_msg == (
        f"Stack:{stack_id} is in CREATE_IN_PROGRESS state and can not be updated."
    ), control_msg

    # The create accepted the token and is now progressing asynchronously (blocked on
    # the WaitCondition). Reusing that same token for a DIFFERENT operation type
    # (UpdateStack) on the same stack while the create is still running must be
    # rejected -- the token is bound to the in-flight CreateStack operation.
    code, msg = _client_error(
        lambda: cfn.update_stack(StackName=stack_name, TemplateBody=update_template, ClientRequestToken=token),
        "UpdateStack reusing the in-flight CreateStack token",
    )
    assert code == "TokenAlreadyExistsException", f"expected TokenAlreadyExistsException, got {code!r}"
    assert msg == (
        f"The client request token {token} has already been used for this stack. "
        "Retry the request with a different client request token"
    ), msg

    # Independent read at the destination: the rejected update must not have applied.
    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    logical_ids = {r["LogicalResourceId"] for r in resources}
    assert "Topic2" not in logical_ids, f"rejected UpdateStack must not have applied, resources={logical_ids}"


def _client_error(fn, what):
    """Return (code, message) of the ClientError `fn` raises; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"].get("Code"), exc.response["Error"].get("Message")
    raise AssertionError(f"expected {what} to be rejected, but the call succeeded")


def _wait_for_stack_status(cfn, stack_name, target_statuses, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return None
        if not stacks:
            return None
        last = stacks[0]["StackStatus"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach {target_statuses} in {timeout_s}s (last={last})")


def _cleanup_stack(cfn, stack_name):
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
    status = stacks[0]["StackStatus"]
    if status in ("UPDATE_IN_PROGRESS", "UPDATE_ROLLBACK_IN_PROGRESS"):
        try:
            cfn.cancel_update_stack(StackName=stack_name)
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
        try:
            _wait_for_stack_status(
                cfn,
                stack_name,
                {"UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "UPDATE_COMPLETE"},
                timeout_s=200,
            )
        except AssertionError:
            pass
    # DeleteStack is a valid, supported way to cancel a CREATE_IN_PROGRESS stack (no
    # separate "cancel-create" API exists), so it's called unconditionally below.
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
    status = _wait_for_stack_status(cfn, stack_name, {"DELETE_COMPLETE", "DELETE_FAILED"}, timeout_s=200)
    if status == "DELETE_FAILED":
        raise AssertionError(f"stack {stack_name} ended DELETE_FAILED")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

