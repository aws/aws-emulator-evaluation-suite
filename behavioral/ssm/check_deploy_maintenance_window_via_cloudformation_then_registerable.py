"""deploy-maintenance-window-via-cloudformation-then-registerable."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-maintenance-window-via-cloudformation-then-registerable"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::SSM::MaintenanceWindow accepts target registration, and
    GetMaintenanceWindow reflects the deployed schedule/duration/cutoff configuration exactly
    (not just default values)."""
    ssm = ctx.client("ssm")
    window_name = ctx.unique_name("sim2real-cfn-mw-")
    template = json.dumps(
        {
            "Resources": {
                "MW": {
                    "Type": "AWS::SSM::MaintenanceWindow",
                    "Properties": {
                        "Name": window_name,
                        "Schedule": "cron(0 10 * * ? *)",
                        "Duration": 2,
                        "Cutoff": 1,
                        "AllowUnassociatedTargets": True,
                        "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
                    },
                }
            },
            "Outputs": {"WindowId": {"Value": {"Ref": "MW"}}},
        }
    )
    outputs = _deploy_cfn_stack(ctx, template)
    window_id = outputs["WindowId"]

    window = ssm.get_maintenance_window(WindowId=window_id)
    assert window["Name"] == window_name, f"expected Name={window_name!r}, got {window['Name']!r}"
    assert window["Schedule"] == "cron(0 10 * * ? *)", (
        f"expected Schedule='cron(0 10 * * ? *)', got {window['Schedule']!r}"
    )
    assert window["Duration"] == 2, f"expected Duration=2, got {window['Duration']!r}"
    assert window["Cutoff"] == 1, f"expected Cutoff=1, got {window['Cutoff']!r}"
    assert window["AllowUnassociatedTargets"] is True, (
        f"expected AllowUnassociatedTargets=True, got {window['AllowUnassociatedTargets']!r}"
    )

    reg = ssm.register_target_with_maintenance_window(
        WindowId=window_id,
        ResourceType="INSTANCE",
        Targets=[{"Key": "InstanceIds", "Values": ["i-0123456789abcdef0"]}],
    )
    target_id = reg["WindowTargetId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ssm.deregister_target_from_maintenance_window(
                WindowId=window_id, WindowTargetId=target_id
            )
        )
    )

    targets = ssm.describe_maintenance_window_targets(WindowId=window_id)["Targets"]
    matched = [t for t in targets if t["WindowTargetId"] == target_id]
    assert len(matched) == 1, f"expected exactly one target {target_id!r} in {targets}"
    assert matched[0]["ResourceType"] == "INSTANCE", (
        f"expected ResourceType='INSTANCE', got {matched[0]['ResourceType']!r}"
    )
    assert matched[0]["Targets"] == [{"Key": "InstanceIds", "Values": ["i-0123456789abcdef0"]}], (
        f"expected Targets=[InstanceIds=[i-0123456789abcdef0]], got {matched[0]['Targets']!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DoesNotExistException":
            raise


def _deploy_cfn_stack(ctx, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ssm-cfn-")

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    resp = cfn.describe_stacks(StackName=stack_name)
    return {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
