"""get-stack-policy-defaults-empty-when-unset."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-stack-policy-defaults-empty-when-unset"
GROUP = "data-plane"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetStackPolicy on a stack that never had SetStackPolicy called returns a null/empty
    policy body rather than an error or some stale value -- and once a real policy is set on
    that same stack, GetStackPolicy reflects exactly that policy instead of staying empty."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-gsp-")
    template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": {}}},
        }
    )
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    _wait_stack_create_complete(cfn, stack_name)

    unset_policy = cfn.get_stack_policy(StackName=stack_name)
    assert not unset_policy.get("StackPolicyBody"), (
        f"expected no stack policy before SetStackPolicy, got {unset_policy!r}"
    )

    policy = {
        "Statement": [
            {"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "*"}
        ]
    }
    cfn.set_stack_policy(StackName=stack_name, StackPolicyBody=json.dumps(policy))

    set_policy = cfn.get_stack_policy(StackName=stack_name)
    got_policy = json.loads(set_policy["StackPolicyBody"])
    assert got_policy == policy, f"expected GetStackPolicy to round-trip {policy}, got {got_policy}"


def _wait_stack_create_complete(cfn, stack_name, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        status = stacks[0]["StackStatus"]
        if not status.endswith("IN_PROGRESS"):
            assert status == "CREATE_COMPLETE", f"stack {stack_name} ended in {status}: {stacks[0]}"
            return
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
