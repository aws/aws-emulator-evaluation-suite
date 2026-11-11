"""token-already-exists-rejects-duplicate-request-token."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "token-already-exists-rejects-duplicate-request-token"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Reusing a ClientRequestToken for another op on an in-flight stack returns
    TokenAlreadyExistsException with no effect on the create; the same DeleteStack with a fresh
    token succeeds right away, so the conflict is scoped to the token."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-token-")
    token = ctx.unique_name("sim2real-tok-")

    # AWS::CloudFormation::WaitCondition with no signal keeps the stack in
    # CREATE_IN_PROGRESS for the full Timeout window, giving us a deterministic
    # race-free window to reuse the ClientRequestToken against the in-flight op.
    template = json.dumps(
        {
            "Resources": {
                "WaitHandle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
                "Wait": {
                    "Type": "AWS::CloudFormation::WaitCondition",
                    "Properties": {"Handle": {"Ref": "WaitHandle"}, "Timeout": "60"},
                },
            }
        }
    )

    def _cleanup() -> None:
        try:
            cfn.delete_stack(StackName=stack_name)
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup)

    cfn.create_stack(StackName=stack_name, TemplateBody=template, ClientRequestToken=token)

    # Positive control: an independent read confirms the create actually took hold
    # (not the mutating call's own response) before we lean on it being in-flight.
    status = _poll_until(
        lambda: _describe_status(cfn, stack_name),
        lambda s: s is not None,
        timeout_s=15,
        description=f"stack {stack_name} to appear after CreateStack",
    )
    assert status == "CREATE_IN_PROGRESS", f"expected CREATE_IN_PROGRESS after CreateStack, got {status!r}"

    code, msg = _error_code_and_message(
        lambda: cfn.delete_stack(StackName=stack_name, ClientRequestToken=token)
    )
    assert code == "TokenAlreadyExistsException", (
        f"reusing ClientRequestToken={token!r} for DeleteStack while CreateStack is still "
        f"in progress: expected TokenAlreadyExistsException, got {code!r} ({msg!r})"
    )
    expected_msg = (
        f"The client request token {token} has already been used for this stack. "
        "Retry the request with a different client request token"
    )
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Effect absent, via an independent read: the rejected DeleteStack must not have
    # nudged the stack at all.
    status = _describe_status(cfn, stack_name)
    assert status == "CREATE_IN_PROGRESS", f"rejected DeleteStack must have no effect, but stack is {status!r}"

    # DeleteStack is AWS's documented way to cancel a running CreateStack, so the identical
    # call with a fresh token must succeed without waiting for the create to finish.
    fresh_token = ctx.unique_name("sim2real-tok2-")
    cfn.delete_stack(StackName=stack_name, ClientRequestToken=fresh_token)

    # Terminal, independent read at the destination: the delete actually took.
    # Describing by name stops resolving once the delete completes, so None is terminal.
    final = _poll_until(
        lambda: _describe_status(cfn, stack_name),
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED", None),
        timeout_s=240,
        description=f"stack {stack_name} deleted after the fresh token was accepted",
    )
    assert final in ("DELETE_COMPLETE", None), (
        f"expected the fresh-token DeleteStack to complete, got {final!r}"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, call succeeded with: {result!r}")


def _describe_status(cfn, stack_name):
    try:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ValidationError":
            return None
        raise
    return stacks[0]["StackStatus"] if stacks else None


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
