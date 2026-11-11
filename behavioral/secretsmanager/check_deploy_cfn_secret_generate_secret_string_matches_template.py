"""deploy-cfn-secret-generate-secret-string-matches-template."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "deploy-cfn-secret-generate-secret-string-matches-template"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]

_EXCLUDED = "\"@/\\'iIlL1oO0"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN GenerateSecretString secret produces a value matching the template and excluded-character rules."""
    template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"SecretName": {"Type": "String"}},
            "Resources": {
                "MySecret": {
                    "Type": "AWS::SecretsManager::Secret",
                    "Properties": {
                        "Name": {"Ref": "SecretName"},
                        "GenerateSecretString": {
                            "SecretStringTemplate": json.dumps({"username": "admin"}),
                            "GenerateStringKey": "password",
                            "PasswordLength": 24,
                            "ExcludeCharacters": _EXCLUDED,
                        },
                    },
                }
            },
            "Outputs": {"SecretArn": {"Value": {"Ref": "MySecret"}}},
        }
    )
    secret_name = ctx.unique_name("sim2real-behav-cfngen-")
    stack_name = _deploy_stack(ctx, template_body, {"SecretName": secret_name})
    secret_arn = _stack_output(ctx, stack_name, "SecretArn")

    sm = ctx.client("secretsmanager")
    value = json.loads(sm.get_secret_value(SecretId=secret_arn)["SecretString"])

    assert value["username"] == "admin", f"expected username='admin', got {value.get('username')!r}"
    password = value["password"]
    assert len(password) == 24, f"expected a 24-char generated password, got {len(password)} chars: {password!r}"
    for ch in _EXCLUDED:
        assert ch not in password, f"excluded character {ch!r} found in generated password"


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
