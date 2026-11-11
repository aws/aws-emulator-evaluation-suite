"""op-contract-get-ebs-default-kms-key-id-dup."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-ebs-default-kms-key-id-dup"
GROUP = "error-semantics"
SERVICES = ["ec2"]

DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ebs-default-encryption")
def run(ctx) -> None:
    """GetEbsDefaultKmsKeyId returns the KMS key the account/Region default was set to,
    stably across reads, and honors DryRun as a distinct permission-check error boundary."""
    ec2 = ctx.client("ec2")
    kms = ctx.client("kms")

    # The check owns the default it reads: a customer-managed key it creates and sets.
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-ebs-default-get-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: _schedule_key_deletion(kms, key_id))
    original_key = ec2.get_ebs_default_kms_key_id()["KmsKeyId"]
    ctx.on_cleanup(lambda: _restore_default_key(ec2, kms, original_key))

    ec2.modify_ebs_default_kms_key_id(KmsKeyId=key_arn)

    first = ec2.get_ebs_default_kms_key_id()
    assert first.get("KmsKeyId") == key_arn, (
        f"GetEbsDefaultKmsKeyId must return the key the default was set to: "
        f"expected {key_arn!r}, got {first!r}"
    )

    # Idempotent read: a second call must return the same default key.
    second = ec2.get_ebs_default_kms_key_id()
    assert second["KmsKeyId"] == key_arn, (
        f"GetEbsDefaultKmsKeyId is not idempotent: {key_arn!r} then {second['KmsKeyId']!r}"
    )

    # Independent terminal read at the destination: the id EC2 reports must resolve to the
    # enabled key the check created when read back through KMS.
    described = kms.describe_key(KeyId=second["KmsKeyId"])["KeyMetadata"]
    assert described["KeyId"] == key_id and described["KeyState"] == "Enabled", (
        f"default EBS KMS key {key_arn!r} does not resolve to the enabled key the check created: "
        f"KeyId={described['KeyId']!r} KeyState={described['KeyState']!r}"
    )

    code, message = _error(lambda: ec2.get_ebs_default_kms_key_id(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _restore_default_key(ec2, kms, original: str) -> None:
    """Point the account's default EBS key back at ``original``; the AWS managed key is a reset."""
    managed = kms.describe_key(KeyId="alias/aws/ebs")["KeyMetadata"]["Arn"]
    if original == managed or original.endswith(":alias/aws/ebs"):
        ec2.reset_ebs_default_kms_key_id()
    else:
        ec2.modify_ebs_default_kms_key_id(KmsKeyId=original)


def _schedule_key_deletion(kms, key_id: str) -> None:
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
