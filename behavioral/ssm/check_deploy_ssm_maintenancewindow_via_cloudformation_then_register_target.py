"""deploy-ssm-maintenancewindow-via-cloudformation-then-register-target."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-ssm-maintenancewindow-via-cloudformation-then-register-target"
GROUP = "deploy"
SERVICES = ["ssm"]

_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {"WindowName": {"Type": "String"}},
    "Resources": {
        "MW": {
            "Type": "AWS::SSM::MaintenanceWindow",
            "Properties": {
                "Name": {"Ref": "WindowName"},
                "Schedule": "cron(0 10 * * ? *)",
                "Duration": 2,
                "Cutoff": 1,
                "AllowUnassociatedTargets": True,
            },
        }
    },
    "Outputs": {"WindowId": {"Value": {"Ref": "MW"}}},
}


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CFN-deployed AWS::SSM::MaintenanceWindow accepts, lists, and removes a registered target.

    The target reads back from DescribeMaintenanceWindowTargets with its id, type and instance id,
    is gone after deregistration, and a repeat deregister succeeds as an idempotent no-op.
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    stack_name = ctx.unique_name("sim2real-ssmmw-stack-")
    window_name = ctx.unique_name("sim2real-ssmmw-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_TEMPLATE),
        Parameters=[{"ParameterKey": "WindowName", "ParameterValue": window_name}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    outputs = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    window_id = next(o["OutputValue"] for o in outputs if o["OutputKey"] == "WindowId")

    described = ssm.describe_maintenance_windows(
        Filters=[{"Key": "Name", "Values": [window_name]}]
    )["WindowIdentities"]
    assert len(described) == 1 and described[0]["WindowId"] == window_id, (
        f"expected exactly one window named {window_name!r} with id {window_id!r}, got {described}"
    )

    reg = ssm.register_target_with_maintenance_window(
        WindowId=window_id,
        ResourceType="INSTANCE",
        Targets=[{"Key": "InstanceIds", "Values": ["i-0123456789abcdef0"]}],
        OwnerInformation="sim2real-owner",
    )
    target_id = reg["WindowTargetId"]

    targets = ssm.describe_maintenance_window_targets(WindowId=window_id)["Targets"]
    assert len(targets) == 1, f"expected exactly one registered target, got {targets}"
    assert targets[0]["WindowTargetId"] == target_id, (
        f"expected WindowTargetId {target_id!r}, got {targets[0]['WindowTargetId']!r}"
    )
    assert targets[0]["ResourceType"] == "INSTANCE", (
        f"expected ResourceType INSTANCE, got {targets[0]['ResourceType']!r}"
    )
    assert targets[0]["Targets"] == [{"Key": "InstanceIds", "Values": ["i-0123456789abcdef0"]}], (
        f"expected Targets to echo the registered instance id, got {targets[0]['Targets']!r}"
    )

    ssm.deregister_target_from_maintenance_window(
        WindowId=window_id, WindowTargetId=target_id, Safe=False
    )
    remaining = ssm.describe_maintenance_window_targets(WindowId=window_id)["Targets"]
    assert not any(t["WindowTargetId"] == target_id for t in remaining), (
        f"deregistered target {target_id!r} still present in {remaining}"
    )
    # DeregisterTargetFromMaintenanceWindow is idempotent: re-deregistering an already-removed
    # target is a no-op success, so any ClientError here fails the check.
    ssm.deregister_target_from_maintenance_window(
        WindowId=window_id, WindowTargetId=target_id, Safe=False
    )


# ===== helpers =====
def _delete_stack(cfn, stack_name: str) -> None:
    # DeleteStack on a deleted stack is a no-op and the waiter counts "does not exist" as done.
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
