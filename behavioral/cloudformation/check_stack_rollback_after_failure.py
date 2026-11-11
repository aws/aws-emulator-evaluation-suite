"""stack-rollback-after-failure."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "stack-rollback-after-failure"
GROUP = "state-machine"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A stack left in CREATE_FAILED (via DisableRollback) transitions to
    ROLLBACK_COMPLETE only once RollbackStack is explicitly invoked."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-rollback-")

    # a WaitCondition with a short timeout and no signaller fails deterministically and fast
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Wait": {
                "Type": "AWS::CloudFormation::WaitCondition",
                "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "5", "Count": 1},
            },
        },
    }
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        DisableRollback=True,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    failed_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda status: status in ("CREATE_FAILED", "CREATE_COMPLETE"),
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert failed_status == "CREATE_FAILED", f"expected the wait condition to time out, got {failed_status}"

    cfn.rollback_stack(StackName=stack_name)
    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda status: status in ("ROLLBACK_COMPLETE", "ROLLBACK_FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final_status == "ROLLBACK_COMPLETE", f"RollbackStack ended in {final_status}"

    # a catalog-level read independent of both the mutating call and the direct describe above
    listed = cfn.list_stacks(StackStatusFilter=["ROLLBACK_COMPLETE"])["StackSummaries"]
    assert any(s["StackName"] == stack_name for s in listed), (
        f"{stack_name} not visible via ListStacks(StackStatusFilter=[ROLLBACK_COMPLETE]): {listed}"
    )


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
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
