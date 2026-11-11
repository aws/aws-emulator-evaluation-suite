"""op-contract-modify-ebs-default-kms-key-id."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-ebs-default-kms-key-id"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ebs-default-encryption")
def run(ctx) -> None:
    """ModifyEbsDefaultKmsKeyId sets the account/Region default EBS KMS key; DryRun rejects first."""
    kms = ctx.client("kms")
    ec2 = ctx.client("ec2")

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-ebs-default-kms-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: _schedule_key_deletion(kms, key_id))

    original_key = ec2.get_ebs_default_kms_key_id()["KmsKeyId"]

    ctx.on_cleanup(lambda: _restore_default_key(ec2, kms, original_key))

    # --- error boundary: DryRun must reject before changing the default key ---
    code, msg = _error(lambda: ec2.modify_ebs_default_kms_key_id(KmsKeyId=key_arn, DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert msg == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {msg!r}"

    unchanged = ec2.get_ebs_default_kms_key_id()["KmsKeyId"]
    assert unchanged == original_key, (
        f"DryRun must not change the default EBS KMS key: expected {original_key!r}, got {unchanged!r}"
    )

    # --- success path: set the customer-managed key as the account default and read it back ---
    resp = ec2.modify_ebs_default_kms_key_id(KmsKeyId=key_arn)
    assert resp["KmsKeyId"] == key_arn, (
        f"unexpected default key echoed back: expected {key_arn!r}, got {resp!r}"
    )

    current = ec2.get_ebs_default_kms_key_id()["KmsKeyId"]
    assert current == key_arn, f"default EBS KMS key not updated: expected {key_arn!r}, got {current!r}"

    # reset back to the AWS-managed key and confirm the change takes effect; on real AWS the
    # AWS-managed alias resolves to a concrete key ARN in both ResetEbsDefaultKmsKeyId's response
    # and the subsequent GetEbsDefaultKmsKeyId, so assert against that resolved ARN exactly.
    managed_key_arn = kms.describe_key(KeyId="alias/aws/ebs")["KeyMetadata"]["Arn"]
    reset_resp = ec2.reset_ebs_default_kms_key_id()
    assert reset_resp["KmsKeyId"] == managed_key_arn, (
        f"unexpected reset KmsKeyId: expected {managed_key_arn!r}, got {reset_resp['KmsKeyId']!r}"
    )

    reset_key = ec2.get_ebs_default_kms_key_id()["KmsKeyId"]
    assert reset_key == managed_key_arn, (
        f"ResetEbsDefaultKmsKeyId did not clear the customer-managed key: "
        f"expected {managed_key_arn!r}, got {reset_key!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
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
        kms.disable_key(KeyId=key_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
