"""deploy-cfn-secret-value-ssm-reference-and-post-delete-refusals."""
from __future__ import annotations

import json
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-secret-value-ssm-reference-and-post-delete-refusals"
GROUP = "deploy"
SERVICES = ["cloudformation", "secretsmanager", "ssm"]

_PASSWORD_LENGTH = 40
_ALPHABET = set(string.ascii_uppercase + string.ascii_lowercase + string.digits)


def _outcome(fn):
    """``(True, value)`` on success or ``(False, (code, message))`` on a ClientError."""
    try:
        return True, fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return False, (err.get("Code"), err.get("Message"))


def _wait_stack(cfn, stack_name: str, waiter_name: str) -> None:
    cfn.get_waiter(waiter_name).wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CFN-generated secret's value has the declared length and character set and matches its
    SSM dynamic reference, which refuses WithDecryption=False; once the stack is deleted,
    GetSecretValue and the reference both refuse with their own not-found errors.
    """
    cfn = ctx.client("cloudformation")
    sm = ctx.client("secretsmanager")
    ssm = ctx.client("ssm")

    stack_name = ctx.unique_name("sim2real-xsvc-cfnsecret-")
    secret_name = ctx.unique_name("sim2real-xsvc-cfnsecret-value-")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Secret": {
                "Type": "AWS::SecretsManager::Secret",
                "Properties": {
                    "Name": secret_name,
                    "GenerateSecretString": {
                        "PasswordLength": _PASSWORD_LENGTH,
                        "ExcludePunctuation": True,
                    },
                },
            }
        },
        "Outputs": {"SecretArn": {"Value": {"Ref": "Secret"}}},
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    _wait_stack(cfn, stack_name, "stack_create_complete")

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    secret_arn = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}["SecretArn"]
    reference_name = f"/aws/reference/secretsmanager/{secret_name}"

    # --- The generated value has the declared length and character set. ------------------------
    generated = sm.get_secret_value(SecretId=secret_arn)["SecretString"]
    assert len(generated) == _PASSWORD_LENGTH, (
        f"expected a {_PASSWORD_LENGTH}-character generated value, got {len(generated)}"
    )
    extra = set(generated) - _ALPHABET
    assert not extra, (
        f"ExcludePunctuation=True must draw only from letters and digits; found {sorted(extra)!r} "
        f"in {generated!r}"
    )

    # --- The SSM reference decrypts to the same value Secrets Manager holds. ---------------------
    decrypted = ssm.get_parameter(Name=reference_name, WithDecryption=True)["Parameter"]
    assert decrypted["Value"] == generated, (
        f"the SSM reference served {decrypted['Value']!r}, which does not match the secret's own "
        f"value {generated!r}"
    )

    # --- A reference to a Secrets Manager value cannot be read undecrypted. ----------------------
    ok, result = _outcome(lambda: ssm.get_parameter(Name=reference_name, WithDecryption=False))
    assert not ok, (
        f"GetParameter with WithDecryption=False on a Secrets Manager reference must be refused, "
        f"not return {result!r}"
    )
    code, message = result
    assert code == "ValidationException", (
        f"expected ValidationException for WithDecryption=False on a secret reference, got "
        f"{code}: {message!r}"
    )
    assert message == (
        "WithDecryption flag must be True for retrieving a Secret Manager secret."
    ), f"unexpected ValidationException message: {message!r}"

    # --- Break the one thing: the stack that owns both the secret and the reference. -------------
    cfn.delete_stack(StackName=stack_name)
    _wait_stack(cfn, stack_name, "stack_delete_complete")

    # --- GetSecretValue refuses once CFN has purged the secret outright. -------------------------
    ok, result = _outcome(lambda: sm.get_secret_value(SecretId=secret_arn))
    assert not ok, f"GetSecretValue on a stack-deleted secret must be refused, got {result!r}"
    code, message = result
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the deleted secret, got {code}: {message!r}"
    )
    assert message == "Secrets Manager can't find the specified secret.", (
        f"unexpected not-found message for the deleted secret: {message!r}"
    )

    # --- The reference stops resolving once its backing secret no longer exists. -----------------
    code, message = _poll_until_refused(
        lambda: _outcome(lambda: ssm.get_parameter(Name=reference_name, WithDecryption=True)),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert code == "ParameterNotFound", (
        f"expected ParameterNotFound once the secret behind the reference is gone, got "
        f"{code}: {message!r}"
    )
    expected_message = (
        f"An error occurred (ParameterNotFound) when referencing Secrets Manager: Secret "
        f"{reference_name.lstrip('/')} not found. Secrets Manager can't find the specified "
        f"secret."
    )
    assert message == expected_message, (
        f"unexpected ParameterNotFound message for the orphaned reference: {message!r}, "
        f"expected {expected_message!r}"
    )


def _poll_until_refused(outcome, *, timeout_s: float, interval_s: float):
    """Poll ``outcome()`` (an ``_outcome``-shaped callable) until it reports a refusal.

    Raises on timeout rather than returning the last success, so a reference that never stops
    resolving fails loudly instead of appearing to pass on a stale read.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        ok, result = outcome()
        if not ok:
            return result
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for the orphaned reference to stop resolving; it still "
                f"returned {result!r}"
            )
        time.sleep(interval_s)


def _delete_stack(cfn, stack_name: str) -> None:
    cfn.delete_stack(StackName=stack_name)
    _wait_stack(cfn, stack_name, "stack_delete_complete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
