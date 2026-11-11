"""stack-rollback-cleans-up."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-rollback-cleans-up"
GROUP = 'e2e_workflows'
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A stack whose WaitCondition times out rolls back, and the Topic that DID get
    created is torn down to DELETE_COMPLETE rather than left behind."""
    cf = ctx.client("cloudformation")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Topic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": ctx.unique_name("sim2real-behav-topic-"),
                    },
                },
                "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
                "Wait": {
                    "Type": "AWS::CloudFormation::WaitCondition",
                    "DependsOn": "Handle",
                    "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "10", "Count": 1},
                },
            },
        }
    )
    name = ctx.unique_name("sim2real-behav-stk-")
    stack_id = cf.create_stack(
        StackName=name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cf, stack_id))
    status = _wait_terminal(cf, name)
    assert status == "ROLLBACK_COMPLETE", f"Expected ROLLBACK_COMPLETE, got {status}"
    resp = cf.list_stack_resources(StackName=name)
    summaries = resp.get("StackResourceSummaries", [])
    assert summaries, f"stack {name} reported no StackResourceSummaries to inspect"
    statuses = {r["LogicalResourceId"]: r["ResourceStatus"] for r in summaries}
    expected = {"Topic": "DELETE_COMPLETE", "Handle": "DELETE_COMPLETE", "Wait": "DELETE_COMPLETE"}
    assert statuses == expected, (
        f"resource statuses after rollback {statuses!r}, expected {expected!r}; the Topic created "
        f"before the WaitCondition timed out must be rolled back to DELETE_COMPLETE"
    )


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
