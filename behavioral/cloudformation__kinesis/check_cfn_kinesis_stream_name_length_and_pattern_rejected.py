"""cfn-kinesis-stream-name-length-and-pattern-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-kinesis-stream-name-length-and-pattern-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "kinesis"]

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}
_NAME_PATH = "/Resources/R/Properties/Name"
_NAME_PATTERN = "^[a-zA-Z0-9_.-]+$"


def _template(name: str) -> str:
    return json.dumps({
        "Resources": {
            "R": {"Type": "AWS::Kinesis::Stream", "Properties": {"Name": name, "ShardCount": 1}},
        },
    })


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 180.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within "
                          f"{timeout_s}s (last={last!r})")


def _validation_reasons(cfn, stack_name: str, path: str) -> list[str]:
    """Every VALIDATION_ERROR reason CloudFormation recorded for one property path."""
    out: list[str] = []
    kwargs = {"StackName": stack_name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(
            e["ValidationStatusReason"] for e in page["OperationEvents"]
            if e.get("EventType") == "VALIDATION_ERROR" and e.get("ValidationPath") == path
        )
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _delete_stack(cfn, stack_name: str, timeout_s: float = 180.0) -> None:
    """Delete the stack; a stack that never provisioned anything can vanish (not just reach
    DELETE_COMPLETE) before the first poll, which DescribeStacks reports as a ValidationError."""
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                return
            raise
        if status in _TERMINAL_STATES:
            break
        time.sleep(2)
    assert status == "DELETE_COMPLETE", f"stack {stack_name} failed to delete: {status!r}"


def _stack_resources(cfn, stack_name: str) -> list[dict]:
    pages = cfn.get_paginator("list_stack_resources").paginate(StackName=stack_name)
    return [r for page in pages for r in page["StackResourceSummaries"]]


def _error(fn) -> tuple:
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Kinesis::Stream Name violating minLength, maxLength or pattern is refused before any
    stream is provisioned, each with CloudFormation's own property-validation reason; the same
    template under a legal name reaches CREATE_COMPLETE and the stream is readable by that name.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-kinesis-stream.html
    """
    cfn = ctx.client("cloudformation")
    kinesis = ctx.client("kinesis")
    valid_name = ctx.unique_name("sim2real-behav-kds-")

    # --- positive control: a legal name deploys and the stream exists under it -----------------
    stack_ok = ctx.unique_name("sim2real-behav-kds-ok-stack-")
    cfn.create_stack(StackName=stack_ok, TemplateBody=_template(valid_name))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_ok))
    status = _wait_terminal(cfn, stack_ok)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    desc = kinesis.describe_stream(StreamName=valid_name)["StreamDescription"]
    assert desc["StreamName"] == valid_name, f"control stream: {desc!r}"

    # --- pattern violation: a colon is not in the allowed character class -----------------------
    pattern_name = f"{valid_name}:invalid"
    stack_pattern = ctx.unique_name("sim2real-behav-kds-pat-stack-")
    cfn.create_stack(StackName=stack_pattern, TemplateBody=_template(pattern_name))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_pattern))
    status = _wait_terminal(cfn, stack_pattern)
    assert status == "ROLLBACK_COMPLETE", f"pattern violation: expected ROLLBACK_COMPLETE, got {status!r}"
    reasons = _validation_reasons(cfn, stack_pattern, _NAME_PATH)
    assert reasons == [f"Property value [{pattern_name}] does not match pattern: {_NAME_PATTERN}"], (
        f"pattern violation reasons: {reasons!r}"
    )

    # --- maxLength violation: one character past the 128-character ceiling ---------------------
    maxlen_name = valid_name + "a" * (129 - len(valid_name))
    assert len(maxlen_name) == 129, maxlen_name
    stack_maxlen = ctx.unique_name("sim2real-behav-kds-maxlen-stack-")
    cfn.create_stack(StackName=stack_maxlen, TemplateBody=_template(maxlen_name))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_maxlen))
    status = _wait_terminal(cfn, stack_maxlen)
    assert status == "ROLLBACK_COMPLETE", f"maxLength violation: expected ROLLBACK_COMPLETE, got {status!r}"
    reasons = _validation_reasons(cfn, stack_maxlen, _NAME_PATH)
    assert reasons == ["#/Name: expected maxLength: 128, actual: 129"], (
        f"maxLength violation reasons: {reasons!r}"
    )

    # --- minLength violation: the empty string satisfies no character class either --------------
    stack_minlen = ctx.unique_name("sim2real-behav-kds-minlen-stack-")
    cfn.create_stack(StackName=stack_minlen, TemplateBody=_template(""))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_minlen))
    status = _wait_terminal(cfn, stack_minlen)
    assert status == "ROLLBACK_COMPLETE", f"minLength violation: expected ROLLBACK_COMPLETE, got {status!r}"
    reasons = sorted(_validation_reasons(cfn, stack_minlen, _NAME_PATH))
    want = sorted([
        "#/Name: expected minLength: 1, actual: 0",
        f"Property value [] does not match pattern: {_NAME_PATTERN}",
    ])
    assert reasons == want, f"minLength violation reasons: {reasons!r}"

    # --- effect absent: each refused stack provisioned nothing, and the over-long name is not a
    # stream Kinesis can hold at all ----------------------------------------------------------
    for label, refused_stack in (("pattern", stack_pattern), ("maxLength", stack_maxlen),
                                 ("minLength", stack_minlen)):
        resources = _stack_resources(cfn, refused_stack)
        assert resources == [], (
            f"{label} violation: a stack refused before provisioning lists resources {resources!r}"
        )
    got = _error(lambda: kinesis.describe_stream_summary(StreamName=maxlen_name))
    want = (
        "ValidationException",
        f"1 validation error detected: Value '{maxlen_name}' at 'streamName' failed to satisfy "
        "constraint: Member must have length less than or equal to 128",
    )
    assert got == want, f"DescribeStreamSummary on the 129-character name: expected {want!r}, got {got!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
