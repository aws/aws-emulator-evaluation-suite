"""resource-policy-and-rotation-calls-on-a-missing-secret-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-and-rotation-calls-on-a-missing-secret-rejected"
GROUP = "error-semantics"
SERVICES = ["secretsmanager"]

_NOT_FOUND = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) that ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _force_delete(sm, secret_id: str) -> None:
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy, PutResourcePolicy, DeleteResourcePolicy and CancelRotateSecret on a name
    no secret ever used fail ResourceNotFoundException, while the identical calls succeed on a
    secret that exists; ValidateResourcePolicy alone needs no existing SecretId.
    """
    sm = ctx.client("secretsmanager")
    missing = ctx.unique_name("sim2real-behav-smrpmiss-")
    ctx.on_cleanup(lambda: _force_delete(sm, missing))

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": "*",
                }
            ],
        }
    )

    calls = {
        "GetResourcePolicy": lambda sid: sm.get_resource_policy(SecretId=sid),
        "PutResourcePolicy": lambda sid: sm.put_resource_policy(SecretId=sid, ResourcePolicy=policy_doc),
        "DeleteResourcePolicy": lambda sid: sm.delete_resource_policy(SecretId=sid),
        "CancelRotateSecret": lambda sid: sm.cancel_rotate_secret(SecretId=sid),
    }
    for op, call in calls.items():
        got = _error(lambda call=call: call(missing))
        assert got == _NOT_FOUND, f"{op} on a never-created secret returned {got!r}, expected {_NOT_FOUND!r}"

    # ValidateResourcePolicy takes SecretId only to attribute the validation; it does not require
    # the name to resolve, so the identical name still gets a syntax verdict rather than a refusal.
    validated = sm.validate_resource_policy(SecretId=missing, ResourcePolicy=policy_doc)
    assert validated.get("PolicyValidationPassed") is True, (
        f"ValidateResourcePolicy against a name no secret ever used returned "
        f"PolicyValidationPassed={validated.get('PolicyValidationPassed')!r}, expected True"
    )

    # Effect absent: the refused calls created nothing under the missing name.
    after = _error(lambda: sm.describe_secret(SecretId=missing))
    assert after == _NOT_FOUND, (
        f"after four refused resource-policy/rotation calls DescribeSecret on the name returned "
        f"{after!r}: a refused call created a secret"
    )

    control = ctx.unique_name("sim2real-behav-smrpctl-")
    created = sm.create_secret(
        Name=control,
        SecretString="sim2real-not-a-real-secret",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _force_delete(sm, created["ARN"]))

    # Positive control: the identical calls now succeed on the existing secret.
    sm.put_resource_policy(SecretId=control, ResourcePolicy=policy_doc)
    policy = sm.get_resource_policy(SecretId=control)
    assert json.loads(policy.get("ResourcePolicy", "{}")) == json.loads(policy_doc), (
        f"GetResourcePolicy on the control secret returned {policy.get('ResourcePolicy')!r}, "
        f"expected the policy just attached"
    )
    report = sm.validate_resource_policy(SecretId=control, ResourcePolicy=policy_doc)
    assert report.get("PolicyValidationPassed") is True, (
        f"ValidateResourcePolicy on the control secret's own policy returned "
        f"PolicyValidationPassed={report.get('PolicyValidationPassed')!r}"
    )
    sm.delete_resource_policy(SecretId=control)
    cleared = sm.get_resource_policy(SecretId=control)
    assert not cleared.get("ResourcePolicy"), (
        f"GetResourcePolicy on the control secret after DeleteResourcePolicy returned "
        f"{cleared.get('ResourcePolicy')!r}, expected none"
    )
    cancelled = sm.cancel_rotate_secret(SecretId=control)
    assert cancelled["ARN"] == created["ARN"], (
        f"CancelRotateSecret on the control secret returned ARN {cancelled['ARN']!r}, "
        f"expected {created['ARN']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
