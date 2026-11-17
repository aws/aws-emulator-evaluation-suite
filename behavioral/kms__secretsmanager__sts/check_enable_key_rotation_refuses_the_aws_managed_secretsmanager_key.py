"""enable-key-rotation-refuses-the-aws-managed-secretsmanager-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enable-key-rotation-refuses-the-aws-managed-secretsmanager-key"
GROUP = "overly-permissive"
SERVICES = ["kms", "secretsmanager", "sts"]

_MANAGED_ALIAS = "alias/aws/secretsmanager"


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _reap_secret(sm, secret_id, *, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"secret {secret_id} still present {timeout_s}s after ForceDeleteWithoutRecovery"
            )
        time.sleep(interval_s)


def _disable_rotation(kms, key_id: str) -> None:
    try:
        kms.disable_key_rotation(KeyId=key_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"waited {timeout_s}s for {description}; last observation was {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data", "plane:control")
def run(ctx) -> None:
    """A secret with no KmsKeyId is encrypted under the AWS managed key alias/aws/secretsmanager,
    which this account never created; EnableKeyRotation refuses to let any caller touch that key's
    rotation, while the identical call succeeds on a customer managed key used the same way.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html
    Reference: https://docs.aws.amazon.com/kms/latest/APIReference/API_EnableKeyRotation.html
    """
    kms = ctx.client("kms")
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")

    # Create a secret with no KmsKeyId, the way a customer triggers the managed key into
    # existence on first use, and confirm its representation names no key.
    plaintext = "sim2real-trigger-default-key"
    name = ctx.unique_name("sim2real-behav-rotaterefuse-")
    created = sm.create_secret(
        Name=name, SecretString=plaintext, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    arn = created["ARN"]
    ctx.on_cleanup(lambda: _reap_secret(sm, arn))
    desc = sm.describe_secret(SecretId=arn)
    assert "KmsKeyId" not in desc, (
        f"DescribeSecret must omit KmsKeyId for a secret encrypted under the default managed key; "
        f"got {desc.get('KmsKeyId')!r}"
    )
    read_back = sm.get_secret_value(SecretId=arn)
    assert read_back["SecretString"] == plaintext, (
        f"the secret must decrypt back to the stored value under the default managed key; got "
        f"{read_back['SecretString']!r}"
    )

    managed_key_meta = kms.describe_key(KeyId=_MANAGED_ALIAS)["KeyMetadata"]
    managed_key_id = managed_key_meta["KeyId"]
    managed_key_arn = managed_key_meta["Arn"]
    assert managed_key_meta["KeyManager"] == "AWS", (
        f"{_MANAGED_ALIAS} must be an AWS managed key this account never created; got "
        f"KeyManager={managed_key_meta['KeyManager']!r}"
    )
    aliases = {a["AliasName"] for a in kms.list_aliases(KeyId=managed_key_id)["Aliases"]}
    assert _MANAGED_ALIAS in aliases, (
        f"ListAliases for key {managed_key_id} must include {_MANAGED_ALIAS}; got {sorted(aliases)!r}"
    )
    caller_arn = sts.get_caller_identity()["Arn"]
    status_before = kms.get_key_rotation_status(KeyId=managed_key_id)["KeyRotationEnabled"]

    # Positive control: the identical call succeeds on a customer managed key used the same way.
    control = kms.create_key(
        Description="sim2real behavioral check: EnableKeyRotation positive control",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
    control_key_id = control["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=control_key_id, PendingWindowInDays=7))
    kms.enable_key_rotation(KeyId=control_key_id)
    ctx.on_cleanup(lambda: _disable_rotation(kms, control_key_id))
    control_status = _poll_until(
        lambda: kms.get_key_rotation_status(KeyId=control_key_id),
        lambda status: status["KeyRotationEnabled"] is True,
        timeout_s=60.0,
        interval_s=3.0,
        description="EnableKeyRotation on the customer managed key to take effect",
    )

    code, message = _error_code(lambda: kms.enable_key_rotation(KeyId=managed_key_id))
    assert code == "AccessDeniedException", (
        f"EnableKeyRotation on the AWS managed key {_MANAGED_ALIAS} must be refused with "
        f"AccessDeniedException -- its key policy, fixed by the service, grants the action to no "
        f"principal; got {code!r}: {message!r}"
    )
    expected_message = (
        f"User: {caller_arn} is not authorized to perform: kms:EnableKeyRotation on resource: "
        f"{managed_key_arn} because no resource-based policy allows the kms:EnableKeyRotation action"
    )
    assert message == expected_message, f"unexpected refusal message: {message!r}"

    status_after = kms.get_key_rotation_status(KeyId=managed_key_id)["KeyRotationEnabled"]
    assert status_after == status_before, (
        f"the refused EnableKeyRotation call must not change the managed key's rotation status; "
        f"it was {status_before!r} before the refused call and {status_after!r} after"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
