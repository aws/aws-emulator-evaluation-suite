"""sep-kms-key-scope-ebs-volume-under-a-disabled-key-never-becomes-available-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sep-kms-key-scope-ebs-volume-under-a-disabled-key-never-becomes-available-rejected"
GROUP = "key-separation"
SERVICES = ["ec2", "kms"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """CreateVolume under a disabled customer key is accepted ("creating") but the volume never becomes
    available (InvalidVolume.NotFound), while the same request under an enabled sibling key, and under the
    re-enabled key, reaches "available" carrying that key's ARN."""
    ec2 = ctx.client("ec2")
    kms = ctx.client("kms")
    key_a = _new_key(ctx, kms, "a")
    key_b = _new_key(ctx, kms, "b")
    zones = sorted(
        z["ZoneName"] for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]},
                     {"Name": "zone-type", "Values": ["availability-zone"]}],
        )["AvailabilityZones"]
    )
    assert zones, f"region {ctx.region!r} reports no available availability zone"
    zone = zones[0]

    kms.disable_key(KeyId=key_a)
    ctx.on_cleanup(lambda: kms.enable_key(KeyId=key_a))
    state = kms.describe_key(KeyId=key_a)["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"key A must be Disabled before the volume is requested, got {state!r}"

    # Positive control: the sibling key yields a usable encrypted volume.
    vol_b = _create_volume(ctx, ec2, zone, key_b)
    got_b = _poll(
        lambda: _volume_state(ec2, vol_b),
        lambda s: s in ("available", "InvalidVolume.NotFound", "error"),
        timeout_s=300,
        interval_s=5,
        description="the enabled-key volume settles",
    )
    assert got_b == "available", f"a volume under enabled key B must become available, got {got_b!r}"
    desc_b = ec2.describe_volumes(VolumeIds=[vol_b])["Volumes"][0]
    assert (desc_b["Encrypted"], desc_b["KmsKeyId"]) == (True, key_b), (
        f"the available volume must be encrypted under key B; got "
        f"{(desc_b['Encrypted'], desc_b.get('KmsKeyId'))!r}"
    )

    # The break: the same request under the disabled key A is accepted...
    vol_a = _create_volume(ctx, ec2, zone, key_a)
    # ...and then never becomes available: it is withdrawn.
    fate_a, message = _poll(
        lambda: _volume_fate(ec2, vol_a),
        lambda s: s[0] in ("available", "InvalidVolume.NotFound", "error"),
        timeout_s=300,
        interval_s=5,
        description="the disabled-key volume settles",
    )
    assert fate_a == "InvalidVolume.NotFound", (
        f"a volume requested under the disabled key A must be withdrawn (DescribeVolumes -> "
        f"InvalidVolume.NotFound), got {fate_a!r}"
    )
    assert message == f"The volume '{vol_a}' does not exist.", f"DescribeVolumes said {message!r}"

    # Repair exactly one thing: re-enable A; the identical request now yields an A-encrypted volume.
    kms.enable_key(KeyId=key_a)
    vol_a2 = _create_volume(ctx, ec2, zone, key_a)
    got_a2 = _poll(
        lambda: _volume_state(ec2, vol_a2),
        lambda s: s in ("available", "InvalidVolume.NotFound", "error"),
        timeout_s=300,
        interval_s=5,
        description="the re-enabled-key volume settles",
    )
    assert got_a2 == "available", (
        f"after EnableKey the identical request under key A must become available, got {got_a2!r}"
    )
    desc_a2 = ec2.describe_volumes(VolumeIds=[vol_a2])["Volumes"][0]
    assert desc_a2["KmsKeyId"] == key_a, (
        f"the repaired volume must be encrypted under key A, got {desc_a2.get('KmsKeyId')!r}"
    )


# ===== helpers =====
def _new_key(ctx, kms, label):
    """A fresh symmetric key; its 7-day scheduled deletion is registered before it is returned."""
    meta = kms.create_key(
        Description=ctx.unique_name(f"sim2real-sep-ebs-{label}-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    arn = meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=arn, PendingWindowInDays=7))
    return arn


def _create_volume(ctx, ec2, zone, key_arn):
    """A 1 GiB gp3 volume encrypted under ``key_arn``, TAGGED IN THE SAME CALL (the only cleanup
    handle on an EBS volume) and with its delete registered before anything else happens."""
    vol = ec2.create_volume(
        AvailabilityZone=zone, Size=1, VolumeType="gp3", Encrypted=True, KmsKeyId=key_arn,
        TagSpecifications=[{"ResourceType": "volume", "Tags": [
            {"Key": "sim2real", "Value": "sep-kms-ebs"},
            {"Key": "Name", "Value": ctx.unique_name("sim2real-sep-ebs-")},
        ]}],
    )
    vid = vol["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, vid))
    return vid


def _delete_volume(ec2, vid):
    """Delete the volume; one EC2 has already withdrawn (InvalidVolume.NotFound) is already gone."""
    try:
        ec2.delete_volume(VolumeId=vid)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidVolume.NotFound":
            raise


def _volume_state(ec2, vid):
    """The volume's State, or the DescribeVolumes error code when EC2 no longer knows it."""
    return _volume_fate(ec2, vid)[0]


def _volume_fate(ec2, vid):
    """(State, "") of the volume, or the DescribeVolumes error (code, message) once EC2 no longer
    knows it."""
    try:
        return ec2.describe_volumes(VolumeIds=[vid])["Volumes"][0]["State"], ""
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code") or "NO_ERROR_CODE", err.get("Message", "")


def _poll(probe, predicate, *, timeout_s, interval_s, description):
    """Bounded poll to an observable condition. RAISES on timeout, never returns a failing value."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not observed within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
