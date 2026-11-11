"""disable-rollback."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disable-rollback"
GROUP = 'rollback'
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """With DisableRollback=True, a failed stack stays in CREATE_FAILED (not ROLLBACK)."""
    cf = ctx.client("cloudformation")
    # The template must VALIDATE and then fail while provisioning, which is the only way the flag is
    # exercised at all: the second SSM parameter has a name SSM rejects.
    good = ctx.unique_name("/sim2real-behav/ok-")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Ok": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": good, "Type": "String", "Value": "v"},
                },
                "Bad": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": "///invalid-name///", "Type": "String", "Value": "v"},
                },
            },
        }
    )
    name = ctx.unique_name("sim2real-behav-stk-")
    cf.create_stack(StackName=name, TemplateBody=template, DisableRollback=True)
    # Not wrapped: a CreateStack that is refused outright is a FAIL, not something to return past.
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=name))

    status = _wait_terminal(cf, name)
    # ROLLBACK_COMPLETE is the exact outcome `DisableRollback=True` exists to PREVENT. On AWS the
    # terminal status for the template above is CREATE_FAILED.
    assert status == "CREATE_FAILED", (
        f"DisableRollback=True must leave the stack CREATE_FAILED, not roll back; got {status}"
    )
    # ...and the flag's actual effect: the resource that DID succeed is still there. Without this the
    # status alone is satisfied by a target that rolled back and then merely reported CREATE_FAILED.
    resources = {
        r["LogicalResourceId"]: r["ResourceStatus"]
        for r in cf.describe_stack_resources(StackName=name)["StackResources"]
    }
    assert resources.get("Ok") == "CREATE_COMPLETE", (
        f"DisableRollback=True must leave the successful resource in place, got {resources}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
