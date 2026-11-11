"""stack-tags-roundtrip."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-tags-roundtrip"
GROUP = 'tags'
SERVICES = ['cloudformation']


_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}

def _wait_terminal(cf, name, timeout_s=180):
    """Poll DescribeStacks until the stack reaches a terminal state; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "UNKNOWN"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")

def _create_and_wait(ctx, cf, template, *, parameters=None, tags=None, capabilities=None):
    """CreateStack (registered for teardown) and wait for CREATE_COMPLETE; return the name."""
    name = ctx.unique_name("sim2real-behav-stk-")
    kwargs = {"StackName": name, "TemplateBody": template}
    if parameters:
        kwargs["Parameters"] = parameters
    if tags:
        kwargs["Tags"] = tags
    if capabilities:
        kwargs["Capabilities"] = capabilities
    cf.create_stack(**kwargs)
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))
    status = _wait_terminal(cf, name)
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {status}, expected CREATE_COMPLETE")
    return name

def _handle_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    })


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags passed to CreateStack are visible in DescribeStacks."""
    cf = ctx.client("cloudformation")
    tags = [
        {"Key": "sim2real-test", "Value": "behavioral"},
        {"Key": "env", "Value": "test"},
    ]
    name = _create_and_wait(ctx, cf, _handle_template(), tags=tags)
    stack = cf.describe_stacks(StackName=name)["Stacks"][0]
    stack_tags = {t["Key"]: t["Value"] for t in stack.get("Tags", [])}
    assert stack_tags.get("sim2real-test") == "behavioral", (
        f"expected tag sim2real-test=behavioral, got stack tags {stack_tags!r}"
    )
    assert stack_tags.get("env") == "test", (
        f"expected tag env=test, got stack tags {stack_tags!r}"
    )
    expected = {t["Key"]: t["Value"] for t in tags}
    assert stack_tags == expected, (
        f"DescribeStacks tags {stack_tags!r} did not exactly match the tags passed to "
        f"CreateStack {expected!r} (no extra or missing tags expected)"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
