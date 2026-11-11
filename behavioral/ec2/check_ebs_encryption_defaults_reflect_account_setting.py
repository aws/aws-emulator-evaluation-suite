"""ebs-encryption-defaults-reflect-account-setting."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ebs-encryption-defaults-reflect-account-setting"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ebs-default-encryption")
def run(ctx) -> None:
    """After enabling EBS encryption-by-default with a specific KMS key, both getters reflect
    it exactly, and — the actual data-plane consequence the setting exists for — a volume
    created with no Encrypted/KmsKeyId of its own comes back encrypted under that key."""
    ec2 = ctx.client("ec2")
    kms = ctx.client("kms")

    original_enabled = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
    original_kms_key_id = ec2.get_ebs_default_kms_key_id()["KmsKeyId"]

    key = kms.create_key(Description=ctx.unique_name("sim2real-ebs-default-key-"))["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    # Registered before the account-setting restores below so it runs LAST (LIFO), after the
    # account has already been pointed away from this key.
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    def _restore_defaults():
        _restore_default_key(ec2, kms, original_kms_key_id)
        if original_enabled:
            ec2.enable_ebs_encryption_by_default()
        else:
            ec2.disable_ebs_encryption_by_default()

    ctx.on_cleanup(_restore_defaults)

    ec2.modify_ebs_default_kms_key_id(KmsKeyId=key_arn)
    ec2.enable_ebs_encryption_by_default()

    enabled = _poll_until(
        lambda: ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"],
        lambda v: v is True,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert enabled is True, "GetEbsEncryptionByDefault never reflected the enabled state"

    reflected_key_id = _poll_until(
        lambda: ec2.get_ebs_default_kms_key_id()["KmsKeyId"],
        lambda v: v in (key_arn, key_id),
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert reflected_key_id in (key_arn, key_id), (
        f"GetEbsDefaultKmsKeyId returned {reflected_key_id!r}, expected the key just configured "
        f"({key_arn!r})"
    )

    # The getters echoing back what was just set is necessary but not sufficient: a stub that
    # merely stores the two settings would pass everything above without ever wiring them into
    # actual volume creation. Prove the consequence at the destination — CreateVolume with no
    # Encrypted/KmsKeyId of its own must inherit both from the account default.
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    name = ctx.unique_name("sim2real-ebs-default-vol-")
    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": name}]}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, volume_id))

    described = _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0],
        lambda v: v["State"] in ("available", "error"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert described["State"] == "available", f"volume ended in {described['State']}"
    assert described["Encrypted"] is True, (
        "a volume created with no Encrypted of its own must inherit True from the account "
        f"default, got {described['Encrypted']!r}"
    )
    assert described["KmsKeyId"] in (key_arn, key_id), (
        f"DescribeVolumes KmsKeyId={described['KmsKeyId']!r}, expected the account default "
        f"({key_arn!r})"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _restore_default_key(ec2, kms, original: str) -> None:
    """Point the account's default EBS key back at ``original``; the AWS managed key is a reset."""
    managed = kms.describe_key(KeyId="alias/aws/ebs")["KeyMetadata"]["Arn"]
    if original == managed or original.endswith(":alias/aws/ebs"):
        ec2.reset_ebs_default_kms_key_id()
    else:
        ec2.modify_ebs_default_kms_key_id(KmsKeyId=original)


def _delete_volume(ec2, volume_id: str) -> None:
    try:
        ec2.delete_volume(VolumeId=volume_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
