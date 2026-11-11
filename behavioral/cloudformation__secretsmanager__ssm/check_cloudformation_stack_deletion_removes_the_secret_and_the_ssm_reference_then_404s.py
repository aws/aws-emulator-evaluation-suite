"""cloudformation-stack-deletion-removes-the-secret-and-the-ssm-reference-then-404s."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudformation-stack-deletion-removes-the-secret-and-the-ssm-reference-then-404s"
GROUP = "deploy"
SERVICES = ["cloudformation", "secretsmanager", "ssm"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Secret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: !Sub "${AWS::StackName}-secret"
      GenerateSecretString:
        PasswordLength: 20
        ExcludePunctuation: true
Outputs:
  SecretArn:
    Value: !Ref Secret
"""


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Deleting the stack that provisioned a secret removes it outright (DescribeSecret 404s, no
    scheduled-deletion window), and the SSM reference to it refuses with ParameterNotFound at once.
    """
    cfn = ctx.client("cloudformation")
    sm = ctx.client("secretsmanager")
    ssm = ctx.client("ssm")

    stack_name = ctx.unique_name("sim2real-xsvc-ssmrefdel-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_if_exists(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    secret_arn = outputs["SecretArn"]
    secret_name = f"{stack_name}-secret"
    ref = f"/aws/reference/secretsmanager/{secret_name}"

    # --- Positive control: the reference resolves BEFORE anything is torn down. -------------------
    before = _poll(
        lambda: _get_parameter(ssm, ref, decrypt=True),
        lambda r: r[0] == "OK",
        timeout_s=90.0,
        interval_s=3.0,
        description=f"the Parameter Store reference {ref!r} to become resolvable before teardown",
    )
    assert before[1]["Value"], (
        "sanity: the reference must resolve to a non-empty value before the stack is deleted, or "
        "the refusal asserted below would prove nothing"
    )

    # --- Break the one thing: delete the stack that owns the secret. -------------------------------
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    # --- Effect: the secret itself is gone, not merely scheduled for deletion. ---------------------
    secret_code, secret_message = _error(lambda: sm.describe_secret(SecretId=secret_arn))
    assert (secret_code, secret_message) == (
        "ResourceNotFoundException", "Secrets Manager can't find the specified secret."), (
        f"a CloudFormation-deleted secret must be gone outright (DescribeSecret 404s), not left in "
        f"a scheduled-deletion state with a DeletedDate; got {secret_code!r}: {secret_message!r}"
    )

    # --- Effect, observed at the CONSUMER: the reference refuses, not a cached stale value. --------
    ref_code, ref_message = _poll(
        lambda: _get_parameter(ssm, ref, decrypt=True),
        lambda r: r[0] != "OK",
        timeout_s=30.0,
        interval_s=3.0,
        description=(
            f"the reference {ref!r} to stop resolving once its backing secret is deleted"
        ),
    )
    assert ref_code == "ParameterNotFound", (
        f"once the backing secret is gone, GetParameter on the reference must fail with "
        f"ParameterNotFound (SSM's own code for an unresolvable reference), not surface a "
        f"Secrets-Manager-flavoured code or keep serving a cached value; got {ref_code!r}: "
        f"{ref_message!r}"
    )
    expected_ref_message = (
        f"An error occurred (ParameterNotFound) when referencing Secrets Manager: Secret "
        f"{ref.lstrip('/')} not found. Secrets Manager can't find the specified secret."
    )
    assert ref_message == expected_ref_message, (
        f"the ParameterNotFound message should be {expected_ref_message!r}, got {ref_message!r}"
    )


def _delete_stack_if_exists(cfn, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 840})
    except ClientError as exc:
        raise RuntimeError(
            f"delete_stack({stack_name}) -> {exc.response.get('Error', {}).get('Code')}"
        ) from exc


def _get_parameter(ssm, name: str, *, decrypt: bool):
    """(code_or_'OK', Parameter_dict_or_error_message) -- one call, two observations, so a refusal
    and a delivered value can never be confused."""
    try:
        resp = ssm.get_parameter(Name=name, WithDecryption=decrypt)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    return "OK", resp["Parameter"]


def _error(fn):
    """The captured AWS (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """A bounded retry that RAISES on timeout, never returning its last observation."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {description}; last observation was {last!r}"
            )
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
