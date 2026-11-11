"""stack-cancel-update-rollback-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stack-cancel-update-rollback-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """CancelUpdateStack on an update held in UPDATE_IN_PROGRESS by an unsignaled WaitCondition ends the stack
    in UPDATE_ROLLBACK_COMPLETE with only its original Anchor resource."""
    cfn = ctx.client("cloudformation")

    stack_name = ctx.unique_name("sim2real-cancelupdate-")
    base_template = {"Resources": {"Anchor": {"Type": "AWS::SSM::Parameter", "Properties": {"Type": "String", "Value": "1"}}}}
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(base_template))
    ctx.on_cleanup(lambda: _safe(lambda: cfn.delete_stack(StackName=stack_name)))

    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=120.0,
        interval_s=4.0,
    )

    update_template = {
        "Resources": {
            "Anchor": {"Type": "AWS::SSM::Parameter", "Properties": {"Type": "String", "Value": "1"}},
            "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Blocker": {
                "Type": "AWS::CloudFormation::WaitCondition",
                "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "300", "Count": 1},
            },
        }
    }
    cfn.update_stack(StackName=stack_name, TemplateBody=json.dumps(update_template))

    in_progress = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s != "CREATE_COMPLETE",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert in_progress == "UPDATE_IN_PROGRESS", f"expected UPDATE_IN_PROGRESS mid-flight, got {in_progress}"

    cfn.cancel_update_stack(StackName=stack_name)

    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in ("UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "UPDATE_COMPLETE"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final_status == "UPDATE_ROLLBACK_COMPLETE", (
        f"CancelUpdateStack ended in {final_status}, expected UPDATE_ROLLBACK_COMPLETE"
    )

    resource_ids = {r["LogicalResourceId"] for r in cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]}
    assert resource_ids == {"Anchor"}, f"cancelled update should have reverted to just Anchor, got {resource_ids!r}"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
