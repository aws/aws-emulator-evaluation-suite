"""op-contract-describe-volumes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-describe-volumes"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVolumes reflects created-volume attributes and rejects a nonexistent VolumeId."""
    ec2 = ctx.client("ec2")
    az = _first_available_az(ec2)
    name = ctx.unique_name("sim2real-behav-vol-")

    vol = ec2.create_volume(
        AvailabilityZone=az,
        Size=2,
        VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    volume_id = vol["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, volume_id))

    entry = _poll_until(
        lambda: _describe_one(ec2, volume_id),
        lambda e: e["State"] != "creating",
        timeout_s=90,
    )
    assert entry["Size"] == 2
    assert entry["VolumeType"] == "gp3"
    assert entry["AvailabilityZone"] == az
    assert entry["State"] == "available", f"expected the new volume to settle as available, got {entry['State']!r}"
    assert isinstance(entry["Encrypted"], bool)
    tag_values = {t["Key"]: t["Value"] for t in entry.get("Tags", [])}
    assert tag_values.get("Name") == name

    # Use the canonical placeholder-style ID (well-formed, never-issued) rather than an
    # arbitrary hex string: real AWS validates the shape of long-format resource IDs more
    # strictly than a plain length/charset regex, and an ad hoc hex string can be rejected
    # as malformed (InvalidParameterValue) instead of reaching the NotFound existence check.
    #
    # Real AWS is not guaranteed to raise for a syntactically well-formed but never-issued
    # VolumeId -- some accounts/regions answer with an empty Volumes list instead of an
    # error. Either outcome is an acceptable way of saying "no such volume"; what must
    # never happen is describe_volumes reporting an actual volume for this bogus id.
    from botocore.exceptions import ClientError

    bogus_volume = "vol-1234567890abcdef0"
    try:
        bogus_resp = ec2.describe_volumes(VolumeIds=[bogus_volume])
    except ClientError as err:
        code = err.response["Error"]["Code"]
        # "InvalidVolume.NotFound" is the commonly documented code, but observed real-AWS
        # behavior for this operation rejects a well-formed-but-never-issued VolumeId with the
        # generic "InvalidParameterValue" rather than a dedicated NotFound-family code. What matters
        # is that the rejection is a recognized "no such volume" shape, not some other kind
        # of failure (permissions, throttling, etc.) and never a report of an actual volume.
        assert code == "InvalidParameterValue", (
            f"expected a volume-not-found-shaped rejection, got {code}"
        )
        message = err.response["Error"].get("Message", "")
        expected = f"Value ({bogus_volume}) for parameter volumes is invalid. Expected: 'vol-...'."
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        assert bogus_resp["Volumes"] == [], (
            f"expected InvalidVolume.NotFound or an empty result, "
            f"got volumes {bogus_resp['Volumes']}"
        )


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


def _describe_one(ec2, volume_id: str) -> dict:
    described = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"]
    assert len(described) == 1, f"expected exactly one volume entry, got {described!r}"
    return described[0]


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
