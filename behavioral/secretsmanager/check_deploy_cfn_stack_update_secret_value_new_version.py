"""deploy-cfn-stack-update-secret-value-new-version."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-cfn-stack-update-secret-value-new-version"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]

_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"SecretName": {"Type": "String"}, "SecretValue": {"Type": "String"}},
        "Resources": {
            "MySecret": {
                "Type": "AWS::SecretsManager::Secret",
                "Properties": {"Name": {"Ref": "SecretName"}, "SecretString": {"Ref": "SecretValue"}},
            }
        },
        "Outputs": {"SecretArn": {"Value": {"Ref": "MySecret"}}},
    }
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Updating a CFN stack's secret value creates a new AWSCURRENT version; the prior value survives as AWSPREVIOUS."""
    secret_name = ctx.unique_name("sim2real-behav-cfnupd-")
    stack_name = _deploy_stack(ctx, _TEMPLATE, {"SecretName": secret_name, "SecretValue": "v1-initial-value"})
    secret_arn = _stack_output(ctx, stack_name, "SecretArn")

    sm = ctx.client("secretsmanager")
    before = sm.describe_secret(SecretId=secret_arn)
    version1 = next(v for v, stages in before["VersionIdsToStages"].items() if "AWSCURRENT" in stages)
    initial_value = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert initial_value == "v1-initial-value", f"expected initial secret value v1-initial-value, got {initial_value!r}"

    _update_stack(ctx, stack_name, {"SecretName": secret_name, "SecretValue": "v2-updated-value"})

    after = sm.describe_secret(SecretId=secret_arn)
    version2 = next(v for v, stages in after["VersionIdsToStages"].items() if "AWSCURRENT" in stages)

    assert version2 != version1, f"CFN stack update must mint a new version, but AWSCURRENT is still {version1}"
    previous_stages = after["VersionIdsToStages"].get(version1, [])
    assert "AWSPREVIOUS" in previous_stages, f"prior AWSCURRENT version {version1} must be demoted to AWSPREVIOUS, has stages {previous_stages}"
    current_value = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")["SecretString"]
    assert current_value == "v2-updated-value", f"expected AWSCURRENT value v2-updated-value after stack update, got {current_value!r}"
    previous_value = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSPREVIOUS")["SecretString"]
    assert previous_value == "v1-initial-value", f"expected AWSPREVIOUS value v1-initial-value to survive the update, got {previous_value!r}"


# ===== helpers =====
_SIM2REAL_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


def _deploy_stack(ctx, template_body: str, parameters: dict) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-secmgr-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM"],
        Tags=_SIM2REAL_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 225})
    return stack_name


def _update_stack(ctx, stack_name: str, parameters: dict) -> None:
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM"],
    )
    waiter = cfn.get_waiter("stack_update_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 225})


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 225})


def _stack_output(ctx, stack_name: str, key: str) -> str:
    cfn = ctx.client("cloudformation")
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}
    return outputs[key]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
