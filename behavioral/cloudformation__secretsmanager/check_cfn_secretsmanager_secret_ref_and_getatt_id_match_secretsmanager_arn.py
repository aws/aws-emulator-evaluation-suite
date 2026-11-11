"""cfn-secretsmanager-secret-ref-and-getatt-id-match-secretsmanager-arn."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-secretsmanager-secret-ref-and-getatt-id-match-secretsmanager-arn"
GROUP = "deploy"
SERVICES = ["cloudformation", "secretsmanager"]

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
_DELETE_TERMINAL = {"DELETE_COMPLETE", "DELETE_FAILED"}


def _poll(cf, stack_id: str, terminal: set, *, timeout_s: float = 240.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::SecretsManager::Secret: Ref and Fn::GetAtt Id both equal the ARN Secrets
    Manager reports for the named secret, its Name and SecretString read back from Secrets Manager,
    and the stack delete removes it.
    """
    cf = ctx.client("cloudformation")
    sm = ctx.client("secretsmanager")

    stack_name = ctx.unique_name("sim2real-behav-secid-stk-")
    secret_name = ctx.unique_name("sim2real-behav-secid-")
    secret_value = "sim2real-behav-secret-value"

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Secret": {
                    "Type": "AWS::SecretsManager::Secret",
                    "Properties": {"Name": secret_name, "SecretString": secret_value},
                },
            },
            "Outputs": {
                "SecretRef": {"Value": {"Ref": "Secret"}},
                "SecretGetAttId": {"Value": {"Fn::GetAtt": ["Secret", "Id"]}},
            },
        }
    )

    stack_id = cf.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))

    status = _poll(cf, stack_id, _CREATE_TERMINAL)
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cf.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}

    # Secrets Manager's own answer for the secret by its name, independent of Ref.
    described = sm.describe_secret(SecretId=secret_name)
    assert described["Name"] == secret_name, (
        f"Secrets Manager reports Name {described['Name']!r}, expected {secret_name!r}"
    )
    assert (outputs["SecretRef"], outputs["SecretGetAttId"]) == (described["ARN"], described["ARN"]), (
        f"Ref/Fn::GetAtt Id {(outputs['SecretRef'], outputs['SecretGetAttId'])!r} are not the ARN "
        f"Secrets Manager reports for {secret_name!r}: {described['ARN']!r}"
    )

    live_value = sm.get_secret_value(SecretId=secret_name)["SecretString"]
    assert live_value == secret_value, (
        f"SecretString read back as {live_value!r}, expected {secret_value!r}"
    )

    _delete_stack(cf, stack_id)
    code, message = _error(lambda: sm.describe_secret(SecretId=secret_name))
    assert (code, message) == (
        "ResourceNotFoundException", "Secrets Manager can't find the specified secret."
    ), f"DescribeSecret after the stack delete returned {(code, message)!r}"


def _delete_stack(cf, stack_id: str) -> None:
    cf.delete_stack(StackName=stack_id)
    status = _poll(cf, stack_id, _DELETE_TERMINAL)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} ended {status!r}, expected DELETE_COMPLETE")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
