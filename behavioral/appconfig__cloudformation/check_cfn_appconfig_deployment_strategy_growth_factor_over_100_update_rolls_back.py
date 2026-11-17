"""cfn-appconfig-deployment-strategy-growth-factor-over-100-update-rolls-back."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "cfn-appconfig-deployment-strategy-growth-factor-over-100-update-rolls-back"
GROUP = "deploy"
SERVICES = ["appconfig", "cloudformation"]

# The resource-handler wrapping CloudFormation puts around the service error it forwards; the
# request id and SDK attempt count vary per call.
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)


def _template(ds_name: str, growth_factor: int) -> str:
    """One DeploymentStrategy carrying ``growth_factor``, its only variable property."""
    resources = {
        "DS": {
            "Type": "AWS::AppConfig::DeploymentStrategy",
            "Properties": {
                "Name": ds_name,
                "DeploymentDurationInMinutes": 3,
                "GrowthFactor": growth_factor,
                "ReplicateTo": "NONE",
            },
        },
    }
    outputs = {"StrategyRef": {"Value": {"Ref": "DS"}}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


def _wait_terminal(cf, stack_id, terminal: frozenset, timeout_s: float = 300.0) -> str:
    """Poll DescribeStacks every 2 s until a status in ``terminal``; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def _update_failed_reason(cf, stack_id, logical_id: str) -> str:
    """The ResourceStatusReason of ``logical_id``'s single UPDATE_FAILED event."""
    events = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    reasons = [
        e.get("ResourceStatusReason", "")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "UPDATE_FAILED"
    ]
    assert len(reasons) == 1, f"expected one UPDATE_FAILED event for {logical_id}, got {reasons!r}"
    return reasons[0]


def _delete_stack(cf, stack_id) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; any other outcome raises."""
    cf.delete_stack(StackName=stack_id)
    status = _wait_terminal(cf, stack_id, frozenset({"DELETE_COMPLETE", "DELETE_FAILED"}))
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation update that raises an AWS::AppConfig::DeploymentStrategy's GrowthFactor
    past 100 rolls the stack back and leaves the strategy's prior GrowthFactor in place, while
    the identical update at GrowthFactor 100 reaches UPDATE_COMPLETE.
    """
    cf = ctx.client("cloudformation")
    appconfig = ctx.client("appconfig")

    stack = ctx.unique_name("sim2real-cfnacfg-dsgrowth-")
    ds_name = ctx.unique_name("sim2real-cfnacfg-ds-")

    stack_id = cf.create_stack(StackName=stack, TemplateBody=_template(ds_name, 10))["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))

    status = _wait_terminal(cf, stack_id, frozenset({"CREATE_COMPLETE", "CREATE_FAILED"}))
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"

    ds_id = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"][0]["OutputValue"]
    got = appconfig.get_deployment_strategy(DeploymentStrategyId=ds_id)
    assert got["GrowthFactor"] == 10, f"GrowthFactor after create was {got['GrowthFactor']!r}, expected 10"

    cf.update_stack(StackName=stack_id, TemplateBody=_template(ds_name, 101))
    status = _wait_terminal(
        cf, stack_id, frozenset({"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"})
    )
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"a GrowthFactor-101 update ended {status!r}, expected UPDATE_ROLLBACK_COMPLETE"
    )

    reason = _update_failed_reason(cf, stack_id, "DS")
    match = _HANDLER_REASON.match(reason)
    assert match is not None, f"UPDATE_FAILED reason is not a resource-handler message: {reason!r}"
    got_error = (match["message"], match["service"], match["status"], match["handler"])
    want_error = (
        "1 validation error detected: Value '101.0' at 'growthFactor' failed to satisfy constraint: "
        "Member must have value less than or equal to 100.0",
        "AppConfig",
        "400",
        "InvalidRequest",
    )
    assert got_error == want_error, f"UPDATE_FAILED reason: expected {want_error!r}, got {got_error!r}"

    got_after_rollback = appconfig.get_deployment_strategy(DeploymentStrategyId=ds_id)
    assert got_after_rollback["GrowthFactor"] == 10, (
        f"GrowthFactor after the rolled-back update was {got_after_rollback['GrowthFactor']!r}, "
        f"expected the pre-update 10"
    )

    cf.update_stack(StackName=stack_id, TemplateBody=_template(ds_name, 100))
    status = _wait_terminal(cf, stack_id, frozenset({"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE"}))
    assert status == "UPDATE_COMPLETE", f"a GrowthFactor-100 update ended {status!r}"

    got_at_limit = appconfig.get_deployment_strategy(DeploymentStrategyId=ds_id)
    assert got_at_limit["GrowthFactor"] == 100, (
        f"GrowthFactor after the at-limit update was {got_at_limit['GrowthFactor']!r}, expected 100"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
