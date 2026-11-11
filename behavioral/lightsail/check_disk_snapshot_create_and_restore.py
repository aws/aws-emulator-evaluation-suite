"""disk-snapshot-create-and-restore."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "disk-snapshot-create-and-restore"
GROUP = "state"
SERVICES = ["lightsail"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDiskSnapshot->CreateDiskFromSnapshot restores a snapshot into a larger disk, and the
    restored disk's lineage and size trace back to the original disk and the explicit request rather
    than to a size the target merely echoed."""
    ls = ctx.client("lightsail")
    zone = _pick_zone(ctx)
    disk_name = ctx.unique_name("sim2real-ls-disk-")
    snapshot_name = ctx.unique_name("sim2real-ls-disksnap-")
    restored_name = ctx.unique_name("sim2real-ls-diskrst-")
    check_tag = [{"key": "sim2real-check", "value": CHECK}]

    ls.create_disk(diskName=disk_name, availabilityZone=zone, sizeInGb=8, tags=check_tag)
    ctx.on_cleanup(lambda: ls.delete_disk(diskName=disk_name, forceDeleteAddOns=True))
    _wait_disk_state(ctx, disk_name, "available", timeout_s=120.0)

    ls.create_disk_snapshot(diskName=disk_name, diskSnapshotName=snapshot_name, tags=check_tag)
    ctx.on_cleanup(lambda: ls.delete_disk_snapshot(diskSnapshotName=snapshot_name))
    snapshot = _wait_disk_snapshot_state(ctx, snapshot_name, "completed", timeout_s=300.0)
    assert snapshot["state"] == "completed", f"expected snapshot state completed, got {snapshot['state']!r}"
    assert snapshot["fromDiskName"] == disk_name, (
        f"expected snapshot lineage fromDiskName={disk_name!r}, got {snapshot['fromDiskName']!r}"
    )
    assert snapshot["sizeInGb"] == 8, f"expected snapshot sizeInGb=8 (source disk size), got {snapshot['sizeInGb']!r}"

    # Restore into a disk LARGER than the source: sizeInGb is only valid >= the snapshot's own
    # size, so a restored size that matches this request (and not the source disk's 8 GB) proves
    # the target honors the explicit request instead of echoing the size it recorded earlier.
    ls.create_disk_from_snapshot(
        diskName=restored_name,
        diskSnapshotName=snapshot_name,
        availabilityZone=zone,
        sizeInGb=16,
        tags=check_tag,
    )
    ctx.on_cleanup(lambda: ls.delete_disk(diskName=restored_name, forceDeleteAddOns=True))
    _wait_disk_state(ctx, restored_name, "available", timeout_s=180.0)

    restored = ls.get_disk(diskName=restored_name)["disk"]
    original = ls.get_disk(diskName=disk_name)["disk"]
    assert restored["state"] == "available", f"expected restored disk state available, got {restored['state']!r}"
    assert original["sizeInGb"] == 8, f"expected source disk sizeInGb unchanged at 8, got {original['sizeInGb']!r}"
    assert restored["sizeInGb"] == 16, (
        f"expected restored disk sizeInGb=16 (the requested resize), got {restored['sizeInGb']!r}"
    )


def _pick_zone(ctx):
    ls = ctx.client("lightsail")
    resp = ls.get_regions(includeAvailabilityZones=True)
    for r in resp["regions"]:
        if r["name"] == ctx.region:
            zones = r.get("availabilityZones") or []
            if zones:
                return zones[0]["zoneName"]
    raise AssertionError(f"no availability zone found for region {ctx.region}")


def _wait_disk_state(ctx, disk_name, target, timeout_s=120.0, interval_s=3.0):
    ls = ctx.client("lightsail")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ls.get_disk(diskName=disk_name)["disk"]["state"]
        if last == target:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"disk {disk_name} state never reached {target!r}, last={last!r}")


def _wait_disk_snapshot_state(ctx, snapshot_name, target, timeout_s=300.0, interval_s=5.0):
    ls = ctx.client("lightsail")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ls.get_disk_snapshot(diskSnapshotName=snapshot_name)["diskSnapshot"]
        if last["state"] == target:
            return last
        time.sleep(interval_s)
    last_state = last["state"] if last else None
    raise AssertionError(f"disk snapshot {snapshot_name} state never reached {target!r}, last={last_state!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
