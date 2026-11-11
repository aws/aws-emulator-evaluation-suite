"""op-contract-restore-volume-from-recycle-bin."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-restore-volume-from-recycle-bin"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A volume deleted under a matching Recycle Bin retention rule is restored by
    RestoreVolumeFromRecycleBin and becomes available again; a malformed volume id fails with
    InvalidVolumeID.Malformed and its exact message."""
    ec2 = ctx.client("ec2")
    rbin = ctx.client("rbin")

    # The "...1234567890abcdef0" long-format id is the placeholder AWS's own docs/SDK
    # examples use for a syntactically valid resource id, but on real AWS it does not clear
    # RestoreVolumeFromRecycleBin's own id-format validator (distinct from, and stricter
    # than, the existence check): the service rejects it with InvalidVolumeID.Malformed
    # before ever reaching the NotFound existence boundary.
    err = _error(
        lambda: ec2.restore_volume_from_recycle_bin(VolumeId="vol-1234567890abcdef0")
    )
    assert err["Code"] == "InvalidVolumeID.Malformed", f"unexpected error code for unknown id: {err!r}"
    assert err.get("Message") == "The volume ID 'vol-1234567890abcdef0' is malformed", (
        f"unexpected message: {err.get('Message')!r}"
    )

    tag_key = "sim2real-rbin"
    tag_value = ctx.unique_name("vol-")

    rule_id = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 1, "RetentionPeriodUnit": "DAYS"},
        ResourceTags=[{"ResourceTagKey": tag_key, "ResourceTagValue": tag_value}],
    )["Identifier"]
    ctx.on_cleanup(lambda: rbin.delete_rule(Identifier=rule_id))

    if not _poll_until(
        lambda: rbin.get_rule(Identifier=rule_id)["Status"],
        lambda status: status == "available",
        timeout_s=120,
        interval_s=5,
    ):
        raise AssertionError(
            "unreachable: Recycle Bin retention rule never became available",
        )

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]

    # A rule that reads "available" can still lag before it retains deletions, and a
    # volume deleted inside that lag is gone for good rather than binned. So the
    # create/delete pair is retried with a fresh volume (bounded) until one lands in
    # the bin; every attempt's volume stays registered for cleanup.
    def _make_volume() -> str:
        vid = ec2.create_volume(
            Size=1,
            AvailabilityZone=az,
            VolumeType="gp3",
            TagSpecifications=[
                {"ResourceType": "volume", "Tags": [{"Key": tag_key, "Value": tag_value}]}
            ],
        )["VolumeId"]
        # Deleting a binned or restored volume re-enters/leaves it via the Recycle Bin
        # (the rule matches its tag), so a plain delete_volume at cleanup time is safe.
        ctx.on_cleanup(lambda: _delete_volume_quiet(ec2, vid))
        ec2.get_waiter("volume_available").wait(
            VolumeIds=[vid], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
        return vid

    attempts: list[str] = []
    volume_id = None
    deadline = time.monotonic() + 480
    while volume_id is None and time.monotonic() < deadline:
        attempts.append(_make_volume())
        ec2.delete_volume(VolumeId=attempts[-1])
        volume_id = _poll_until(
            lambda: _first_binned(ec2.list_volumes_in_recycle_bin, "Volumes", "VolumeId", attempts),
            lambda found: bool(found),
            timeout_s=90,
            interval_s=5,
        ) or None
    if volume_id is None:
        raise AssertionError(
            f"unreachable: none of the deleted volumes {attempts} appeared in Recycle Bin "
            "within the test window",
        )

    ec2.restore_volume_from_recycle_bin(VolumeId=volume_id)

    def _restored() -> bool:
        try:
            resp = ec2.describe_volumes(VolumeIds=[volume_id])
        except Exception:
            return False
        vols = resp.get("Volumes", [])
        return bool(vols) and vols[0]["State"] == "available"

    assert _poll_until(_restored, lambda ok: ok, timeout_s=60, interval_s=5), (
        "volume was not visible/available again after RestoreVolumeFromRecycleBin"
    )


def _error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        try:
            result = probe()
        except Exception:
            result = None
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result if predicate(result) else False


def _first_binned(list_fn, items_key, id_key, wanted):
    """Return the first id from ``wanted`` that the recycle bin lists, or None. The bin is
    listed unfiltered, so an id that was never binned cannot fail the whole read."""
    kwargs: dict = {}
    while True:
        page = list_fn(**kwargs)
        for entry in page.get(items_key, []):
            if entry[id_key] in wanted:
                return entry[id_key]
        if not page.get("NextToken"):
            return None
        kwargs["NextToken"] = page["NextToken"]


def _delete_volume_quiet(ec2, volume_id):
    """Cleanup: delete the volume, tolerating one already deleted (or binned) by the check."""
    from botocore.exceptions import ClientError

    try:
        ec2.delete_volume(VolumeId=volume_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
