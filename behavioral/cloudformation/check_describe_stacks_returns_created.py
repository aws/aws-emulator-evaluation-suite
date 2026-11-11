"""describe-stacks-returns-created."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-stacks-returns-created"
GROUP = 'stack_lifecycle'
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStacks returns the stack we just created with correct fields."""
    cf = ctx.client("cloudformation")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    before = datetime.now(timezone.utc)
    name = _create_and_wait(
        ctx, cf, _handle_template(),
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack = cf.describe_stacks(StackName=name)["Stacks"][0]
    after = datetime.now(timezone.utc)
    assert stack["StackName"] == name, f"expected StackName {name!r}, got {stack['StackName']!r}"
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {stack['StackStatus']!r}"
    )
    expected_id_prefix = f"arn:aws:cloudformation:{ctx.region}:{account_id}:stack/{name}/"
    assert stack["StackId"].startswith(expected_id_prefix), (
        f"expected StackId to start with {expected_id_prefix!r}, got {stack['StackId']!r}"
    )
    creation_time = stack["CreationTime"]
    skew = timedelta(seconds=10)
    assert before - skew <= creation_time <= after + skew, (
        f"expected CreationTime in [{before!r}, {after!r}] (+/-{skew}), got {creation_time!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
