"""cfn-appconfig-description-only-update-reaches-complete-with-refs-unchanged."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cfn-appconfig-description-only-update-reaches-complete-with-refs-unchanged"
GROUP = "deploy"
SERVICES = ["appconfig", "cloudformation"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})


def _wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks every 2 s until a status in ``terminal``; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def _delete_stack(cf, stack_id):
    """Delete the stack and wait for DELETE_COMPLETE; any other outcome raises."""
    cf.delete_stack(StackName=stack_id)
    status = _wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


def _stack_outputs(cf, stack_id) -> dict:
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _template(app_name: str, env_name: str, cp_name: str, ds_name: str, description: str) -> str:
    """One Application plus one Environment, ConfigurationProfile and DeploymentStrategy under
    it, each carrying ``description`` as its Description property."""
    resources = {
        "App": {
            "Type": "AWS::AppConfig::Application",
            "Properties": {"Name": app_name},
        },
        "Env": {
            "Type": "AWS::AppConfig::Environment",
            "Properties": {
                "ApplicationId": {"Ref": "App"},
                "Name": env_name,
                "Description": description,
            },
        },
        "CP": {
            "Type": "AWS::AppConfig::ConfigurationProfile",
            "Properties": {
                "ApplicationId": {"Ref": "App"},
                "Name": cp_name,
                "LocationUri": "hosted",
                "Type": "AWS.Freeform",
                "Description": description,
            },
        },
        "DS": {
            "Type": "AWS::AppConfig::DeploymentStrategy",
            "Properties": {
                "Name": ds_name,
                "Description": description,
                "DeploymentDurationInMinutes": 3,
                "GrowthFactor": 10,
                "ReplicateTo": "NONE",
            },
        },
    }
    outputs = {k: {"Value": {"Ref": r}} for k, r in
               {"EnvRef": "Env", "CPRef": "CP", "DSRef": "DS"}.items()}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation update changing only Description on an AppConfig Environment,
    ConfigurationProfile and DeploymentStrategy reaches UPDATE_COMPLETE with every Ref
    unchanged, and each resource's Get call returns the new Description.
    """
    cf = ctx.client("cloudformation")
    appconfig = ctx.client("appconfig")

    stack = ctx.unique_name("sim2real-cfnacfg-desc-")
    app_name = ctx.unique_name("sim2real-cfnacfg-app-")
    env_name = ctx.unique_name("sim2real-cfnacfg-env-")
    cp_name = ctx.unique_name("sim2real-cfnacfg-cp-")
    ds_name = ctx.unique_name("sim2real-cfnacfg-ds-")

    description_v1 = "sim2real cfn appconfig description update check v1"
    description_v2 = "sim2real cfn appconfig description update check v2"

    stack_id = cf.create_stack(
        StackName=stack,
        TemplateBody=_template(app_name, env_name, cp_name, ds_name, description_v1),
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))

    status = _wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"

    out1 = _stack_outputs(cf, stack_id)
    app_id = cf.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="App"
    )["StackResourceDetail"]["PhysicalResourceId"]
    env_id, cp_id, ds_id = out1["EnvRef"], out1["CPRef"], out1["DSRef"]

    got_env = appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    assert got_env["Description"] == description_v1, (
        f"environment Description after create was {got_env['Description']!r}, "
        f"expected {description_v1!r}"
    )
    got_cp = appconfig.get_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    assert got_cp["Description"] == description_v1, (
        f"configuration profile Description after create was {got_cp['Description']!r}, "
        f"expected {description_v1!r}"
    )
    got_ds = appconfig.get_deployment_strategy(DeploymentStrategyId=ds_id)
    assert got_ds["Description"] == description_v1, (
        f"deployment strategy Description after create was {got_ds['Description']!r}, "
        f"expected {description_v1!r}"
    )

    cf.update_stack(
        StackName=stack_id,
        TemplateBody=_template(app_name, env_name, cp_name, ds_name, description_v2),
    )
    status = _wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"description-only update ended {status!r}"

    out2 = _stack_outputs(cf, stack_id)
    assert (out2["EnvRef"], out2["CPRef"], out2["DSRef"]) == (env_id, cp_id, ds_id), (
        f"a Description-only update changed a physical id: {out2!r} vs "
        f"{{'EnvRef': {env_id!r}, 'CPRef': {cp_id!r}, 'DSRef': {ds_id!r}}}"
    )

    got_env2 = appconfig.get_environment(ApplicationId=app_id, EnvironmentId=env_id)
    assert got_env2["Description"] == description_v2, (
        f"environment Description after update was {got_env2['Description']!r}, "
        f"expected {description_v2!r}"
    )
    got_cp2 = appconfig.get_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    assert got_cp2["Description"] == description_v2, (
        f"configuration profile Description after update was {got_cp2['Description']!r}, "
        f"expected {description_v2!r}"
    )
    got_ds2 = appconfig.get_deployment_strategy(DeploymentStrategyId=ds_id)
    assert got_ds2["Description"] == description_v2, (
        f"deployment strategy Description after update was {got_ds2['Description']!r}, "
        f"expected {description_v2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
