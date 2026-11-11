"""deploy-secret-cfn-stack-behaves."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-secret-cfn-stack-behaves"
GROUP = "deploy"
SERVICES = ["secretsmanager"]

_EXCLUDED_CHARS = '"@/\\'
_PASSWORD_LENGTH = 40

_TEMPLATE = f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  MySecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      GenerateSecretString:
        SecretStringTemplate: '{{"username": "admin"}}'
        GenerateStringKey: password
        PasswordLength: {_PASSWORD_LENGTH}
        ExcludeCharacters: '{_EXCLUDED_CHARS}'
        RequireEachIncludedType: true
Outputs:
  SecretArn:
    Value: !Ref MySecret
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed secret's GenerateSecretString constraints (length, excluded chars,
    per-category requirement) are honored by the value actually stored and retrievable."""
    stack_name = ctx.unique_name("sim2real-sm-cfn-")
    outputs = _deploy_stack(ctx, _TEMPLATE, stack_name)
    secret_arn = outputs["SecretArn"]

    sm = ctx.client("secretsmanager")
    value = sm.get_secret_value(SecretId=secret_arn)
    payload = json.loads(value["SecretString"])
    assert payload["username"] == "admin"
    password = payload["password"]

    assert len(password) == _PASSWORD_LENGTH, f"expected length {_PASSWORD_LENGTH}, got {len(password)}"
    for bad_char in _EXCLUDED_CHARS:
        assert bad_char not in password, f"excluded character {bad_char!r} found in generated password"

    # RequireEachIncludedType (default true, no category fully excluded) guarantees at
    # least one character from each of: uppercase, lowercase, digit, punctuation.
    import string

    allowed_punct = "".join(c for c in string.punctuation if c not in _EXCLUDED_CHARS)
    assert any(c.isupper() for c in password), "no uppercase character in generated password"
    assert any(c.islower() for c in password), "no lowercase character in generated password"
    assert any(c.isdigit() for c in password), "no digit character in generated password"
    assert any(c in allowed_punct for c in password), "no punctuation character in generated password"

    # Tear the stack down here (not just via ctx.on_cleanup) so the teardown itself is
    # asserted: the secret must actually become unusable, not merely have delete_stack
    # fired-and-forgotten.
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )
    err = _error(lambda: sm.get_secret_value(SecretId=secret_arn))
    assert err.get("Code") == "ResourceNotFoundException", (
        "after the CFN stack that owned it is torn down, the secret must be gone "
        f"(GetSecretValue not-found), got {err!r}"
    )
    assert err.get("Message") == "Secrets Manager can't find the specified secret.", (
        f"unexpected not-found message for the torn-down secret: {err.get('Message')!r}"
    )


def _error(fn):
    """Call fn(); return the botocore Error dict if a ClientError was raised.

    An unexpected SUCCESS raises, because an emulator ACCEPTING a call real AWS refuses (here:
    reading a secret whose owning stack was already torn down) is the strongest signal available.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected GetSecretValue to be rejected, but it SUCCEEDED: {result!r}")


def _deploy_stack(ctx, template_body: str, stack_name: str, timeout_minutes: int = 10) -> dict:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        OnFailure="DELETE",
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(
        StackName=stack_name,
        WaiterConfig={"Delay": 2, "MaxAttempts": max(6, timeout_minutes * 6) * 10 // 2},
    )
    resp = cfn.describe_stacks(StackName=stack_name)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}
    return outputs


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
