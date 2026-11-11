"""copy-volumes-undersized-target-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-volumes-undersized-target-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CopyVolumes with a Size below the source volume's is refused with InvalidParameterValue and its exact message
    and creates no copy, while an equal Size yields an available copy of the source's size.
    """
    ec2 = ctx.client("ec2")

    az = _pick_availability_zone(ec2)
    source_size_gib = 2
    source_volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=source_size_gib,
        VolumeType="gp3",
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-copyvol-src-")}]}
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=source_volume_id))
    ec2.get_waiter("volume_available").wait(VolumeIds=[source_volume_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    marker_key = "sim2real-copyvol-marker"

    def _copy_ids() -> set:
        resp = ec2.describe_volumes(Filters=[{"Name": "tag-key", "Values": [marker_key]}])
        return {v["VolumeId"] for v in resp["Volumes"]}

    before = _copy_ids()

    # --- Negative: Size smaller than the source is rejected ---
    code, message = _error_detail(
        lambda: ec2.copy_volumes(
            SourceVolumeId=source_volume_id,
            Size=source_size_gib - 1,
            TagSpecifications=[
                {"ResourceType": "volume", "Tags": [{"Key": marker_key, "Value": "undersized"}]}
            ],
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r} ({message})"
    assert message == (
        "The size of the volume copy must be greater than or equal to the source volume. "
        "Specify a larger volume size and try again."
    ), f"unexpected error message {message!r}"

    # Effect absent: no new (tagged) volume was created.
    assert _copy_ids() == before, "an undersized CopyVolumes request created a volume anyway"

    # --- Positive control: an equal-sized target succeeds ---
    result = ec2.copy_volumes(
        SourceVolumeId=source_volume_id,
        Size=source_size_gib,
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": marker_key, "Value": "equal-size"}]}
        ],
    )
    new_volumes = result["Volumes"]
    assert new_volumes, f"CopyVolumes with a valid size returned no volumes: {result}"
    new_volume_id = new_volumes[0]["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=new_volume_id))

    final = _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[new_volume_id])["Volumes"][0],
        lambda v: v["State"] in ("available", "error"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final["State"] == "available", f"copied volume never became available: {final}"
    assert final["Size"] == source_size_gib, f"expected copied volume Size={source_size_gib}, got {final['Size']!r}"


def _pick_availability_zone(ec2) -> str:
    zones = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    assert zones, "no available Availability Zones in this region"
    return zones[0]["ZoneName"]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not observed within {timeout_s}s; last saw {value!r}")


def _error_detail(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
