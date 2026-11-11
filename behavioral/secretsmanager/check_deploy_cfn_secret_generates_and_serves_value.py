"""deploy-cfn-secret-generates-and-serves-value."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-secret-generates-and-serves-value"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed Secret with GenerateSecretString produces a value matching the generation spec."""
    cfn = ctx.client("cloudformation")
    secretsmanager = ctx.client("secretsmanager")
    stack_name = ctx.unique_name("sim2real-cfn-gensecret-")
    secret_name = ctx.unique_name("sim2real-gensecret-")

    template = {
        "Resources": {
            "GenSecret": {
                "Type": "AWS::SecretsManager::Secret",
                "Properties": {
                    "Name": secret_name,
                    "Description": "sim2real cfn generated secret",
                    "GenerateSecretString": {
                        "SecretStringTemplate": json.dumps({"username": "admin"}),
                        "GenerateStringKey": "password",
                        "PasswordLength": 24,
                        "ExcludePunctuation": True,
                    },
                },
            }
        },
        "Outputs": {"SecretArn": {"Value": {"Ref": "GenSecret"}}},
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    _wait_stack_complete(cfn, stack_name, "create")

    secret_arn = _stack_outputs(cfn, stack_name)["SecretArn"]

    described = secretsmanager.describe_secret(SecretId=secret_arn)
    assert described["Name"] == secret_name, f"expected secret name {secret_name!r}, got {described['Name']!r}"

    value = secretsmanager.get_secret_value(SecretId=secret_arn)
    payload = json.loads(value["SecretString"])
    assert payload["username"] == "admin", f"expected username 'admin', got {payload.get('username')!r}"
    password = payload["password"]
    assert len(password) == 24, f"expected a 24-char generated password, got {len(password)}"
    assert password.isalnum(), f"generated password contains excluded punctuation: {password!r}"

    # The stack is the only creator of this secret, so its teardown is a free negative:
    # CFN stack deletion purges a GenerateSecretString-managed secret outright (unlike a
    # direct DeleteSecret call, which only schedules it) -- assert that purge here rather
    # than leaving the delete in cleanup unasserted.
    cfn.delete_stack(StackName=stack_name)
    _wait_stack_complete(cfn, stack_name, "delete")
    try:
        secretsmanager.describe_secret(SecretId=secret_arn)
        raise AssertionError(f"expected secret {secret_arn} to be purged after CFN stack deletion")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        message = exc.response["Error"].get("Message")
        assert message == "Secrets Manager can't find the specified secret.", (
            f"unexpected not-found message for the purged secret: {message!r}"
        )


# ===== helpers =====

def _wait_stack_complete(cfn, stack_name: str, action: str, timeout_s: float = 180.0) -> None:
    waiter_name = "stack_create_complete" if action == "create" else "stack_delete_complete"
    waiter = cfn.get_waiter(waiter_name)
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(timeout_s // 2))})


def _stack_outputs(cfn, stack_name: str) -> dict:
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    outputs = {}
    for o in stacks[0].get("Outputs", []):
        outputs[o["OutputKey"]] = o["OutputValue"]
    return outputs


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    _wait_stack_complete(cfn, stack_name, "delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
