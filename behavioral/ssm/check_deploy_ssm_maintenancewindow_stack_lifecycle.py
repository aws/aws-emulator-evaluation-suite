"""deploy-ssm-maintenancewindow-stack-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ssm-maintenancewindow-stack-lifecycle"
GROUP = "state-machine"
SERVICES = ["ssm"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Window:
    Type: AWS::SSM::MaintenanceWindow
    Properties:
      Name: !Sub "${AWS::StackName}-window"
      Schedule: "cron(0 2 ? * SUN *)"
      Duration: 2
      Cutoff: 1
      AllowUnassociatedTargets: false
  Target:
    Type: AWS::SSM::MaintenanceWindowTarget
    Properties:
      WindowId: !Ref Window
      ResourceType: INSTANCE
      Targets:
        - Key: "tag:sim2real-mw-target"
          Values:
            - "true"
Outputs:
  WindowId:
    Value: !Ref Window
  TargetId:
    Value: !Ref Target
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::SSM::MaintenanceWindow with an attached target is enabled
    and its target listed via DescribeMaintenanceWindowTargets; deleting the stack removes the
    window so GetMaintenanceWindow subsequently 404s."""
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    stack_name = ctx.unique_name("sim2real-ssm-mw-stack-")

    cfn.create_stack(StackName=stack_name, TemplateBody=_TEMPLATE)
    ctx.on_cleanup(lambda: _delete_stack_if_exists(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    window_id = outputs["WindowId"]
    target_id = outputs["TargetId"]

    window = ssm.get_maintenance_window(WindowId=window_id)
    assert window["Enabled"] is True, f"expected window {window_id} enabled, got {window!r}"

    targets = ssm.describe_maintenance_window_targets(WindowId=window_id)["Targets"]
    matched = [t for t in targets if t["WindowTargetId"] == target_id]
    assert len(matched) == 1, f"target {target_id} not found in {targets}"
    expected_targets = [{"Key": "tag:sim2real-mw-target", "Values": ["true"]}]
    assert matched[0]["Targets"] == expected_targets, (
        f"expected target filter {expected_targets}, got {matched[0]['Targets']!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    code, message = _error(lambda: ssm.get_maintenance_window(WindowId=window_id))
    assert code == "DoesNotExistException", code
    assert message == f"Maintenance window {window_id} does not exist", message


def _delete_stack_if_exists(cfn, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, so an
    emulator that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
