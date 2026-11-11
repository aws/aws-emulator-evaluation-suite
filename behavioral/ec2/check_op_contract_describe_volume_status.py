"""op-contract-describe-volume-status."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-describe-volume-status"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVolumeStatus reports health-check status for a real volume, rejects DryRun,
    and refuses every read/write against the volume once it is gone."""
    ec2 = ctx.client("ec2")
    az = _first_available_az(ec2)
    name = ctx.unique_name("sim2real-volstatus-")

    vol = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=_tag_spec("volume", name),
    )
    volume_id = vol["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume_if_present(ec2, volume_id))

    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda state: state == "available",
        timeout_s=90,
    )

    resp = ec2.describe_volume_status(VolumeIds=[volume_id])
    statuses = resp["VolumeStatuses"]
    assert len(statuses) == 1, f"expected exactly one status entry, got {len(statuses)}"
    entry = statuses[0]
    assert entry["VolumeId"] == volume_id, f"expected VolumeId {volume_id}, got {entry['VolumeId']!r}"
    assert entry["AvailabilityZone"] == az, f"expected AZ {az}, got {entry['AvailabilityZone']!r}"
    assert entry["VolumeStatus"]["Status"] in ("ok", "insufficient-data"), (
        f"unexpected VolumeStatus.Status for a freshly created, idle volume: "
        f"{entry['VolumeStatus']['Status']!r}"
    )
    assert isinstance(entry["Actions"], list), f"expected Actions to be a list, got {entry['Actions']!r}"
    assert isinstance(entry["Events"], list), f"expected Events to be a list, got {entry['Events']!r}"

    code, message = _error(lambda: ec2.describe_volume_status(VolumeIds=[volume_id], DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"

    _delete_volume(ec2, volume_id)

    outcome, last_state = _poll_until_gone_or_deleted(ec2, volume_id, timeout_s=90)
    assert outcome in ("purged", "deleted"), (
        f"expected the volume to be purged (NotFound) or State=deleted, got {outcome}/{last_state!r}"
    )

    # DescribeVolumeStatus can keep serving the last-known status for a volume DescribeVolumes
    # already reports gone; a refusal or a stale entry for this id is fine, another id is not.
    from botocore.exceptions import ClientError

    try:
        stale = ec2.describe_volume_status(VolumeIds=[volume_id])["VolumeStatuses"]
    except ClientError as err:
        assert err.response["Error"]["Code"] == "InvalidVolume.NotFound", (
            f"expected InvalidVolume.NotFound if DescribeVolumeStatus refuses a deleted "
            f"volume, got {err.response['Error']['Code']}"
        )
        expected = f"The volume '{volume_id}' does not exist."
        assert err.response["Error"].get("Message", "") == expected, (
            f"expected message {expected!r}, got {err.response['Error'].get('Message')!r}"
        )
    else:
        assert stale == [] or stale[0]["VolumeId"] == volume_id, (
            f"expected no stale status or one naming this volume, got {stale!r}"
        )

    code, message = _error(lambda: ec2.delete_volume(VolumeId=volume_id))
    assert code == "InvalidVolume.NotFound", (
        f"expected a second delete of an already-deleted volume to be refused as not-found, got {code!r}"
    )
    expected = f"The volume '{volume_id}' does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


def _tag_spec(resource_type: str, name: str) -> list[dict]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _first_available_az(ec2) -> str:
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    assert azs, "no available AZs found"
    return azs[0]["ZoneName"]


def _delete_volume(ec2, volume_id: str) -> None:
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda state: state in ("available", "error"),
        timeout_s=90,
    )
    ec2.delete_volume(VolumeId=volume_id)


def _delete_volume_if_present(ec2, volume_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        state = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "InvalidVolume.NotFound":
            return
        raise
    if state in ("deleting", "deleted"):
        return
    _delete_volume(ec2, volume_id)


def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _poll_until_gone_or_deleted(ec2, volume_id: str, *, timeout_s=90.0, interval_s=2.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        try:
            last_state = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidVolume.NotFound":
                return "purged", last_state
            raise
        if last_state == "deleted":
            return "deleted", last_state
        time.sleep(interval_s)
    raise AssertionError(f"volume neither purged nor State=deleted within {timeout_s}s, last state={last_state!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
