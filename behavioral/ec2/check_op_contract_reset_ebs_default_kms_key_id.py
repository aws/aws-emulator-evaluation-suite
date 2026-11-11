"""op-contract-reset-ebs-default-kms-key-id."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-reset-ebs-default-kms-key-id"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ebs-default-encryption")
def run(ctx) -> None:
    """ResetEbsDefaultKmsKeyId with DryRun fails with DryRunOperation and leaves the customized default
    key in place; without DryRun it returns the AWS managed alias/aws/ebs key ARN, which
    GetEbsDefaultKmsKeyId then reports. The original setting is restored on cleanup."""
    ec2 = ctx.client("ec2")
    kms = ctx.client("kms")

    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-rekki-"),
        Tags=[{"TagKey": "Name", "TagValue": ctx.unique_name("sim2real-rekki-")}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    original_key = ec2.get_ebs_default_kms_key_id()["KmsKeyId"]
    ec2.modify_ebs_default_kms_key_id(KmsKeyId=key_id)
    # Registered after the key's own cleanup so it runs first (LIFO): the account/Region
    # default goes back to the key it named before, never left on a key about to disappear.
    ctx.on_cleanup(lambda: _restore_default_key(ec2, kms, original_key))

    customized = ec2.get_ebs_default_kms_key_id()["KmsKeyId"]
    assert key_id in customized, f"expected default key to be customized to {key_id}, got {customized}"

    code, message = _error(lambda: ec2.reset_ebs_default_kms_key_id(DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message {message!r}")

    # DryRun must not have reset anything.
    still_customized = ec2.get_ebs_default_kms_key_id()["KmsKeyId"]
    assert key_id in still_customized, (
        f"DryRun must not change the default key, but it is now {still_customized}")

    # The AWS managed key's alias resolves to a concrete key ARN; on real AWS,
    # ResetEbsDefaultKmsKeyId's response (and the subsequent
    # GetEbsDefaultKmsKeyId) surface that resolved ARN rather than the
    # literal alias string "alias/aws/ebs".
    managed_key_arn = kms.describe_key(KeyId="alias/aws/ebs")["KeyMetadata"]["Arn"]

    reset_resp = ec2.reset_ebs_default_kms_key_id()
    assert reset_resp["KmsKeyId"] == managed_key_arn, (
        f"unexpected reset KmsKeyId: {reset_resp['KmsKeyId']} (expected {managed_key_arn})")

    after = ec2.get_ebs_default_kms_key_id()["KmsKeyId"]
    assert after == managed_key_arn, f"default key was not actually reset, still {after}"


def _restore_default_key(ec2, kms, original: str) -> None:
    """Point the account's default EBS key back at ``original``; the AWS managed key is a reset."""
    managed = kms.describe_key(KeyId="alias/aws/ebs")["KeyMetadata"]["Arn"]
    if original == managed or original.endswith(":alias/aws/ebs"):
        ec2.reset_ebs_default_kms_key_id()
    else:
        ec2.modify_ebs_default_kms_key_id(KmsKeyId=original)


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a call that
    succeeds raises AssertionError."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
