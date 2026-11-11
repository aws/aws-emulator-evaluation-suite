"""stack-name-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "stack-name-conflict-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Topic:
    Type: AWS::SNS::Topic
"""


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack with the name of a live stack fails with AlreadyExistsException "Stack [<name>] already
    exists" and leaves one stack with one Topic; once that stack is deleted, the same CreateStack creates a
    new StackId that reaches CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-dup-")
    stack_tags = [{"Key": "owner", "Value": "fidelity"}]

    create_resp = cfn.create_stack(StackName=stack_name, TemplateBody=_TEMPLATE, Tags=stack_tags)
    original_stack_id = create_resp["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    status = _wait_stack_terminal(ctx, stack_name, timeout_s=180)
    assert status == "CREATE_COMPLETE", f"positive control did not reach CREATE_COMPLETE (got {status})"

    code, msg = _client_error(lambda: cfn.create_stack(StackName=stack_name, TemplateBody=_TEMPLATE, Tags=stack_tags))
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException, got {code!r}"
    assert msg == f"Stack [{stack_name}] already exists", msg

    # Effect absent: still exactly one stack with this name, same StackId, still CREATE_COMPLETE.
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    assert len(stacks) == 1, f"expected exactly one stack named {stack_name!r}, got {len(stacks)}"
    assert stacks[0]["StackId"] == original_stack_id, (
        f"expected StackId to remain {original_stack_id!r}, got {stacks[0]['StackId']!r}"
    )
    assert stacks[0]["StackStatus"] == "CREATE_COMPLETE", (
        f"expected StackStatus to remain CREATE_COMPLETE, got {stacks[0]['StackStatus']!r}"
    )

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    topic_resources = [r for r in resources if r["LogicalResourceId"] == "Topic"]
    assert len(topic_resources) == 1, f"expected exactly one Topic resource, got {len(topic_resources)}"

    # Restore: free the name by deleting the original stack. Once DELETE_COMPLETE, DescribeStacks
    # by StackNAME raises ValidationError ("does not exist") — only the StackId still resolves it.
    cfn.delete_stack(StackName=stack_name)
    delete_status = _wait_stack_terminal(ctx, original_stack_id, timeout_s=180)
    assert delete_status == "DELETE_COMPLETE", f"restore delete did not reach DELETE_COMPLETE (got {delete_status})"

    # The identical call now succeeds: the live stack was the obstacle, not the name.
    restored_resp = cfn.create_stack(StackName=stack_name, TemplateBody=_TEMPLATE, Tags=stack_tags)
    restored_stack_id = restored_resp["StackId"]
    assert restored_stack_id != original_stack_id, "restored stack must be a new StackId, not the deleted one"

    restored_status = _wait_stack_terminal(ctx, stack_name, timeout_s=180)
    assert restored_status == "CREATE_COMPLETE", (
        f"restored CreateStack did not reach CREATE_COMPLETE (got {restored_status})"
    )

    restored_stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    assert len(restored_stacks) == 1, f"expected exactly one stack named {stack_name!r}, got {len(restored_stacks)}"
    assert restored_stacks[0]["StackId"] == restored_stack_id, (
        f"expected StackId {restored_stack_id!r}, got {restored_stacks[0]['StackId']!r}"
    )


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
    "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
}


def _wait_stack_terminal(ctx, stack_name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    cfn = ctx.client("cloudformation")
    status = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL_STACK_STATUSES:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status within {timeout_s}s (last={status})")


def _client_error(fn):
    """Return (code, message) of the ClientError fn() raises; raise AssertionError if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("expected the duplicate CreateStack to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
