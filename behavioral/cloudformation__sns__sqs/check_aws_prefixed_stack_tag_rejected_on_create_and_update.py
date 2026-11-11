"""aws-prefixed-stack-tag-rejected-on-create-and-update."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "aws-prefixed-stack-tag-rejected-on-create-and-update"
GROUP = "tags"
SERVICES = ["cloudformation", "sns", "sqs"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _template() -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic"},
            "Queue": {"Type": "AWS::SQS::Queue"},
        },
    })


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An aws:-prefixed stack Tag key is refused on both CreateStack and UpdateStack with
    ValidationError, before any resource is touched; a legitimate tag in the same shape succeeds.

    The aws:cloudformation:* tags are CloudFormation's to mint, never a caller's to set.
    """
    cfn = ctx.client("cloudformation")
    template = _template()
    stack = ctx.unique_name("sim2real-xsvc-tagrej-")

    # --- break #1: CreateStack with a reserved tag key must never create the stack ------------
    create_err = _error(
        lambda: cfn.create_stack(
            StackName=stack, TemplateBody=template,
            Tags=[{"Key": "aws:hostile", "Value": "x"}],
        )
    )
    want = ("ValidationError", "aws: prefixed tag key names are not allowed for external use.")
    assert create_err == want, (
        f"CreateStack with an aws:-prefixed tag key must be refused with {want!r}, got "
        f"{create_err!r}"
    )
    missing_err = _error(lambda: cfn.describe_stacks(StackName=stack))
    want = ("ValidationError", f"Stack with id {stack} does not exist")
    assert missing_err == want, (
        f"a stack refused at CreateStack must never exist; DescribeStacks({stack!r}) was "
        f"expected to fail with {want!r}, got {missing_err!r}"
    )

    # --- positive control: the SAME template, a legitimate tag, must succeed ------------------
    cfn.create_stack(
        StackName=stack, TemplateBody=template,
        Tags=[{"Key": "sim2real-env", "Value": "before"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack))
    status = _wait_terminal(cfn, stack)
    assert status == "CREATE_COMPLETE", f"positive control: stack ended in {status!r}, expected CREATE_COMPLETE"
    before_tags = _tag_map(cfn, stack)
    assert before_tags == {"sim2real-env": "before"}, before_tags

    # --- break #2: UpdateStack with a reserved tag key must leave the stack's tags untouched --
    update_err = _error(
        lambda: cfn.update_stack(
            StackName=stack, TemplateBody=template,
            Tags=[{"Key": "aws:cloudformation:stack-name", "Value": "hacked"}],
        )
    )
    want = ("ValidationError", "aws: prefixed tag key names are not allowed for external use.")
    assert update_err == want, (
        f"UpdateStack with an aws:-prefixed tag key must be refused with {want!r}, got "
        f"{update_err!r}"
    )
    after_tags = _tag_map(cfn, stack)
    assert after_tags == {"sim2real-env": "before"}, (
        f"a refused UpdateStack must leave the stack's tags unchanged; expected "
        f"{{'sim2real-env': 'before'}}, got {after_tags!r}"
    )
    status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", (
        f"a Tags-only UpdateStack refused up front must not move the stack out of "
        f"CREATE_COMPLETE, got {status!r}"
    )

    # --- a legitimate UpdateStack still works afterward (the refusal is not sticky) -----------
    cfn.update_stack(
        StackName=stack, TemplateBody=template,
        Tags=[{"Key": "sim2real-env", "Value": "after"}],
    )
    status = _wait_terminal(cfn, stack)
    assert status == "UPDATE_COMPLETE", f"legitimate update ended in {status!r}, expected UPDATE_COMPLETE"
    assert _tag_map(cfn, stack) == {"sim2real-env": "after"}, _tag_map(cfn, stack)


def _error(fn) -> tuple[str, str]:
    """The botocore (Error.Code, Error.Message) raised by fn(); RAISES if fn() unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("expected the call to be refused, but it succeeded")


def _tag_map(cfn, stack_name: str) -> dict:
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {t["Key"]: t["Value"] for t in stack.get("Tags", [])}


def _wait_terminal(cfn, stack_name: str, *, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name!r} did not reach a terminal status within {timeout_s}s (last={last!r})")


def _delete_stack_and_wait(cfn, stack_name: str, *, timeout_s: float = 300.0) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise RuntimeError(f"stack {stack_name} DELETE_FAILED")
        time.sleep(5.0)
    raise RuntimeError(f"stack {stack_name} still deleting after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
