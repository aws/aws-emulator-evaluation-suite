"""deploy-cfn-appconfig-deployment-strategy-growth-factor-over-100-rejected."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-appconfig-deployment-strategy-growth-factor-over-100-rejected"
GROUP = "deploy"
SERVICES = ["appconfig", "cloudformation"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  StrategyName:
    Type: String
  GrowthFactorValue:
    Type: Number
Resources:
  Strategy:
    Type: AWS::AppConfig::DeploymentStrategy
    Properties:
      Name: !Ref StrategyName
      DeploymentDurationInMinutes: 0
      GrowthFactor: !Ref GrowthFactorValue
      FinalBakeTimeInMinutes: 0
      ReplicateTo: NONE
Outputs:
  StrategyId:
    Value: !Ref Strategy
"""

# CloudFormation's resource-handler wrapping of the service error; the request id and token vary.
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::AppConfig::DeploymentStrategy whose GrowthFactor exceeds 100 fails with
    AppConfig's range error and is never created, while GrowthFactor 100 (the fastest
    AppConfig allows) deploys through the identical template."""
    cfn = ctx.client("cloudformation")
    appconfig = ctx.client("appconfig")

    good_name = ctx.unique_name("sim2real-behav-cfnok-")
    bad_name = ctx.unique_name("sim2real-behav-cfnbad-")
    good_stack = ctx.unique_name("sim2real-behav-stack-ok-")
    bad_stack = ctx.unique_name("sim2real-behav-stack-bad-")

    # Positive control: the identical template with the fastest legal GrowthFactor, 100.
    _create(ctx, cfn, good_stack, good_name, 100, disable_rollback=False)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=good_stack, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    good_strategy_id = cfn.describe_stack_resource(StackName=good_stack, LogicalResourceId="Strategy")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]
    got = appconfig.get_deployment_strategy(DeploymentStrategyId=good_strategy_id)
    assert got["Name"] == good_name, (
        f"positive control: expected deployment strategy Name {good_name!r}, got {got['Name']!r}"
    )
    assert got["GrowthFactor"] == 100, (
        f"positive control: expected GrowthFactor 100, got {got['GrowthFactor']!r}"
    )

    # The one thing broken: the same template with GrowthFactor 101, one past the legal maximum.
    _create(ctx, cfn, bad_stack, bad_name, 101, disable_rollback=True)
    status = _poll_until_terminal(cfn, bad_stack, timeout_s=180.0)
    assert status == "CREATE_FAILED", f"expected stack status CREATE_FAILED, got {status!r}"
    reason = _failed_reason(cfn, bad_stack, "Strategy")
    match = _REASON.match(reason)
    assert match is not None, f"CREATE_FAILED reason is not a resource-handler message: {reason!r}"
    got_error = (match["message"], match["service"], match["status"], match["handler"])
    want_error = (
        "1 validation error detected: Value '101.0' at 'growthFactor' failed to satisfy constraint: "
        "Member must have value less than or equal to 100.0",
        "AppConfig",
        "400",
        "InvalidRequest",
    )
    assert got_error == want_error, f"CREATE_FAILED reason: expected {want_error!r}, got {got_error!r}"

    names = set()
    for page in appconfig.get_paginator("list_deployment_strategies").paginate():
        names.update(item["Name"] for item in page["Items"])
    assert bad_name not in names, f"the over-range strategy {bad_name!r} was minted into a deployment strategy"

    for stack_name in (bad_stack, good_stack):
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )
        got_gone = _error(lambda stack_name=stack_name: cfn.describe_stacks(StackName=stack_name))
        assert got_gone == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
            f"DescribeStacks after the delete of {stack_name}: {got_gone!r}"
        )
    got_strategy = _error(lambda: appconfig.get_deployment_strategy(DeploymentStrategyId=good_strategy_id))
    want_strategy = (
        "ResourceNotFoundException",
        f"DeploymentStrategy with Id {good_strategy_id} could not be found.",
    )
    assert got_strategy == want_strategy, (
        f"GetDeploymentStrategy after the control stack's delete: {got_strategy!r}"
    )


def _create(ctx, cfn, stack_name: str, strategy_name: str, growth_factor: int, *, disable_rollback: bool) -> None:
    """CreateStack with its delete registered at once."""
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "StrategyName", "ParameterValue": strategy_name},
            {"ParameterKey": "GrowthFactorValue", "ParameterValue": str(growth_factor)},
        ],
        DisableRollback=disable_rollback,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))


def _poll_until_terminal(cfn, stack_name: str, *, timeout_s: float) -> str:
    terminal = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status in {timeout_s}s, last {status!r}")


def _failed_reason(cfn, stack_name: str, logical_id: str) -> str:
    """The ResourceStatusReason of ``logical_id``'s single CREATE_FAILED event."""
    events = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        events.extend(page["StackEvents"])
    reasons = [
        e.get("ResourceStatusReason", "")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(reasons) == 1, f"expected one CREATE_FAILED event for {logical_id}, got {reasons!r}"
    return reasons[0]


def _delete_stack(cfn, stack_name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
