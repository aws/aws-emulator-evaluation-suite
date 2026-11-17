"""deploy-cfn-appconfig-resources-tag-updates-round-trip-through-tag-resource."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-appconfig-resources-tag-updates-round-trip-through-tag-resource"
GROUP = "deploy"
SERVICES = ["appconfig", "cloudformation"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks every 2 s until a status in ``terminal``; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete the stack and wait for DELETE_COMPLETE; any other outcome raises."""
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _template(app_name: str, env_name: str, cp_name: str, ds_name: str, tag_map: dict) -> str:
    """One Application, Environment, hosted/AWS.Freeform ConfigurationProfile and
    DeploymentStrategy, all carrying ``tag_map`` as their AppConfig Tags property."""
    tag_list = [{"Key": k, "Value": v} for k, v in tag_map.items()]
    resources = {
        "App": {
            "Type": "AWS::AppConfig::Application",
            "Properties": {"Name": app_name, "Tags": tag_list},
        },
        "Env": {
            "Type": "AWS::AppConfig::Environment",
            "Properties": {"ApplicationId": {"Ref": "App"}, "Name": env_name, "Tags": tag_list},
        },
        "CP": {
            "Type": "AWS::AppConfig::ConfigurationProfile",
            "Properties": {
                "ApplicationId": {"Ref": "App"},
                "Name": cp_name,
                "LocationUri": "hosted",
                "Type": "AWS.Freeform",
                "Tags": tag_list,
            },
        },
        "DS": {
            "Type": "AWS::AppConfig::DeploymentStrategy",
            "Properties": {
                "Name": ds_name,
                "DeploymentDurationInMinutes": 3,
                "GrowthFactor": 10,
                "ReplicateTo": "NONE",
                "Tags": tag_list,
            },
        },
    }
    outputs = {k: {"Value": {"Ref": r}} for k, r in
               {"AppRef": "App", "EnvRef": "Env", "CPRef": "CP", "DSRef": "DS"}.items()}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


def _own_tags(appconfig, arn: str) -> dict:
    """``ListTagsForResource`` on ``arn``, excluding CloudFormation's own ``aws:`` system tags."""
    got = appconfig.list_tags_for_resource(ResourceArn=arn)["Tags"]
    return {k: v for k, v in got.items() if not k.startswith("aws:")}


def _assert_tags(appconfig, arns: dict, expected: dict, where: str) -> None:
    for label, arn in arns.items():
        got = _own_tags(appconfig, arn)
        assert got == expected, f"{where}: {label} tags {got!r}, expected {expected!r}"


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation update that changes only an AWS::AppConfig resource's Tags leaves its
    physical id unchanged, and ListTagsForResource reflects exactly the current Tags, down to
    none once Tags is removed."""
    cf = ctx.client("cloudformation")
    appconfig = ctx.client("appconfig")

    stack = ctx.unique_name("sim2real-cfnacfg-tags-")
    app_name = ctx.unique_name("sim2real-cfnacfg-app-")
    env_name = ctx.unique_name("sim2real-cfnacfg-env-")
    cp_name = ctx.unique_name("sim2real-cfnacfg-cp-")
    ds_name = ctx.unique_name("sim2real-cfnacfg-ds-")

    tags_v1 = {"sim2real-stage": "beta"}
    tags_v2 = {"sim2real-stage": "prod", "sim2real-owner": "payments"}
    tags_v3: dict = {}

    stack_id = cf.create_stack(
        StackName=stack, TemplateBody=_template(app_name, env_name, cp_name, ds_name, tags_v1),
    )["StackId"]
    ctx.on_cleanup(lambda: delete_stack(cf, stack_id))

    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"

    out = stack_outputs(cf, stack_id)
    app_id, env_id, cp_id, ds_id = out["AppRef"], out["EnvRef"], out["CPRef"], out["DSRef"]

    partition = stack_id.split(":")[1]
    app_arn = f"arn:{partition}:appconfig:{ctx.region}:{ctx.account}:application/{app_id}"
    arns = {
        "application": app_arn,
        "environment": f"{app_arn}/environment/{env_id}",
        "configuration profile": f"{app_arn}/configurationprofile/{cp_id}",
        "deployment strategy": f"arn:{partition}:appconfig:{ctx.region}:{ctx.account}"
                                f":deploymentstrategy/{ds_id}",
    }
    _assert_tags(appconfig, arns, tags_v1, "after create")

    cf.update_stack(
        StackName=stack_id, TemplateBody=_template(app_name, env_name, cp_name, ds_name, tags_v2),
    )
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"tag-value-change update ended {status!r}"

    out2 = stack_outputs(cf, stack_id)
    assert (out2["AppRef"], out2["EnvRef"], out2["CPRef"], out2["DSRef"]) == (
        app_id, env_id, cp_id, ds_id,
    ), f"a Tags-only update changed a physical id: {out2!r} vs {out!r}"
    _assert_tags(appconfig, arns, tags_v2, "after changing a value and adding a key")

    cf.update_stack(
        StackName=stack_id, TemplateBody=_template(app_name, env_name, cp_name, ds_name, tags_v3),
    )
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"tag-removing update ended {status!r}"

    out3 = stack_outputs(cf, stack_id)
    assert (out3["AppRef"], out3["EnvRef"], out3["CPRef"], out3["DSRef"]) == (
        app_id, env_id, cp_id, ds_id,
    ), f"the tag-removing update changed a physical id: {out3!r} vs {out!r}"
    _assert_tags(appconfig, arns, tags_v3, "after removing Tags")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
