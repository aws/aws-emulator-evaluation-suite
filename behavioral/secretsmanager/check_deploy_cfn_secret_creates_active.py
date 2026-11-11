"""deploy-cfn-secret-creates-active."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-cfn-secret-creates-active"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed AWS::SecretsManager::Secret reaches ACTIVE and its value round-trips via GetSecretValue."""
    secret_value = {"username": "admin", "password": "initial-pw-12345"}
    template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"SecretName": {"Type": "String"}},
            "Resources": {
                "MySecret": {
                    "Type": "AWS::SecretsManager::Secret",
                    "Properties": {
                        "Name": {"Ref": "SecretName"},
                        "SecretString": json.dumps(secret_value),
                    },
                }
            },
            "Outputs": {"SecretArn": {"Value": {"Ref": "MySecret"}}},
        }
    )
    secret_name = ctx.unique_name("sim2real-behav-cfnsecret-")
    stack_name = _deploy_stack(ctx, template_body, {"SecretName": secret_name})
    secret_arn = _stack_output(ctx, stack_name, "SecretArn")

    sm = ctx.client("secretsmanager")
    desc = sm.describe_secret(SecretId=secret_arn)
    assert desc["Name"] == secret_name, f"expected Name={secret_name!r}, got {desc.get('Name')!r}"
    assert "DeletedDate" not in desc, f"expected no DeletedDate on an active secret, got {desc.get('DeletedDate')!r}"

    value = sm.get_secret_value(SecretId=secret_arn)
    assert json.loads(value["SecretString"]) == secret_value, (
        f"expected SecretString={secret_value!r}, got {value.get('SecretString')!r}"
    )
    assert "AWSCURRENT" in value["VersionStages"], (
        f"expected AWSCURRENT in VersionStages, got {value.get('VersionStages')!r}"
    )


# ===== helpers =====
def _deploy_stack(ctx, template_body: str, parameters: dict) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-secmgr-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 225})
    return stack_name


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
